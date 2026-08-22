"""Homework check: combines MyCourseVille + ClassDeeDee into one per-user view.

Each platform is queried independently and a failure on one never blocks the
other (mirrors the reference Google Apps Script's cddError/mcvError pattern) —
a user with only a ClassDeeDee login still gets MCV results and vice versa.

Local test harness:
    python -m attendance_bot.homework.check --uid <discord_user_id>
"""
from __future__ import annotations

import re
import sys
import argparse
from datetime import datetime, timezone

import requests as http_requests

from attendance_bot.config import log, registered_users, is_homework_suppressed
from attendance_bot.security.crypto import decrypt_password
from attendance_bot.mcv.attendance import (
    AttendanceLogger,
    TZ_BANGKOK,
    WrongCredentialsError as McvWrongCredentialsError,
    LoginError as McvLoginError,
)
from attendance_bot.mcv.homework import fetch_upcoming_items, items_for_subjects
from attendance_bot.classdeedee.attendance import resolve_cdd_credentials
from attendance_bot.classdeedee.homework import check_homework_for_user as cdd_check_homework
from attendance_bot.classdeedee.login import (
    WrongCredentialsError as CddWrongCredentialsError,
    LoginError as CddLoginError,
)

_MCV_DUE_RE = re.compile(r"(\d+)\s*(day|hour|minute)", re.IGNORECASE)


def _mcv_days_remaining(due_text: str) -> float | None:
    """Best-effort days-remaining from MCV's relative due string (e.g. "3 days").

    Returns None when the text doesn't match a recognized shape — callers
    should treat that as "unknown urgency", not "not urgent".
    """
    text = (due_text or "").strip().lower()
    if not text:
        return None
    if "today" in text:
        return 0.0
    if "tomorrow" in text:
        return 1.0
    m = _MCV_DUE_RE.search(text)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit == "day":
        return float(n)
    if unit == "hour":
        return n / 24.0
    return n / (24.0 * 60.0)  # minute


def _cdd_days_remaining(deadline: str | None) -> float | None:
    if not deadline:
        return None
    try:
        dt = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ_BANGKOK)
    now = datetime.now(timezone.utc)
    return (dt - now).total_seconds() / 86400.0


def urgency_dot(days: float | None) -> str:
    if days is None:
        return "⚪"
    if days <= 1:
        return "🔴"
    if days <= 3:
        return "🟡"
    return "🟢"


def _sort_key(days: float | None) -> float:
    # unknown-urgency items sort last, not first
    return days if days is not None else float("inf")


def resolve_mcv_credentials(info: dict) -> tuple[str, str, str]:
    """Return (username, password, login_method) for MCV, decrypting as needed."""
    return info["username"], decrypt_password(info["password"]), info.get("login_method", "cu_net")


def check_homework_for_user(uid: str) -> dict:
    """Homework check for one registered Discord user, across both platforms.

    Returns {"groups": [...], "mcv_error": str|None, "cdd_error": str|None,
    "cdd_skipped": bool, "cdd_disabled": bool}. Each group: {"course_code",
    "course_name", "items", "days"} where "days" is the group's most-urgent
    item's days-remaining (for sorting groups), and each item is {"platform",
    "title", "due_text", "days", "link"}.

    "cdd_disabled" (user turned it off with /classdeedee off) and
    "cdd_skipped" (no usable login at all — resolve_cdd_credentials returned
    None for some other reason, e.g. a platform account with no
    /deedeeregister) are kept distinct so the DM can nudge one case
    ("set one up") without nagging the other ("you chose this").
    """
    info = registered_users.get(uid)
    if not info:
        raise ValueError(f"No registered user with uid {uid!r}")
    subjects = info.get("subjects", [])
    cdd_disabled = not info.get("classdeedee_enabled", True)

    raw_items: list[dict] = []
    mcv_error = None
    cdd_error = None
    cdd_skipped = False

    # ---------------- MyCourseVille ----------------
    try:
        username, password, login_method = resolve_mcv_credentials(info)
        logger = AttendanceLogger()
        session = logger._new_session()
        try:
            logger.login(session, username, password, login_method=login_method)
            items = items_for_subjects(fetch_upcoming_items(session), subjects)
        finally:
            session.close()
        for item in items:
            days = _mcv_days_remaining(item["due"])
            raw_items.append({
                "platform": "mcv",
                "course_code": item["course_code"] or "?",
                "course_name": item.get("course_name"),
                "title": item["title"],
                "due_text": item["due"] or "due date unclear",
                "days": days,
                "link": item["link"],
                "item_key": item["item_key"],
            })
    except McvWrongCredentialsError:
        mcv_error = "wrong username or password"
    except McvLoginError as exc:
        mcv_error = f"login failed ({exc})"
    except http_requests.RequestException as exc:
        mcv_error = f"network error ({exc})"

    # ---------------- ClassDeeDee ----------------
    try:
        creds = resolve_cdd_credentials(info)
    except ValueError:
        creds = None
        cdd_error = "failed to decrypt ClassDeeDee credentials"

    if creds is None and cdd_error is None and not cdd_disabled:
        cdd_skipped = True  # no usable ClassDeeDee login (MCV-only account, no /deedeeregister)
    elif creds is not None:
        try:
            username, password = creds
            for a in cdd_check_homework(username, password, subjects):
                due_dt = a["deadline"]
                days = _cdd_days_remaining(due_dt)
                raw_items.append({
                    "platform": "classdeedee",
                    "course_code": a["course_code"] or "?",
                    "course_name": a["course"],
                    "title": a["title"],
                    "due_text": due_dt or "due date unclear",
                    "days": days,
                    "link": a["link"],
                    "item_key": a["uuid"] or a["link"],
                })
        except CddWrongCredentialsError:
            cdd_error = "wrong username or password"
        except CddLoginError as exc:
            cdd_error = f"login failed ({exc})"
        except http_requests.RequestException as exc:
            cdd_error = f"network error ({exc})"

    # ---------------- group by course, most-urgent course first ----------------
    groups_by_code: dict[str, dict] = {}
    for item in raw_items:
        code = item["course_code"]
        group = groups_by_code.setdefault(code, {
            "course_code": code,
            "course_name": item["course_name"],
            "items": [],
        })
        if not group["course_name"] and item["course_name"]:
            group["course_name"] = item["course_name"]
        group["items"].append(item)

    groups = list(groups_by_code.values())
    for group in groups:
        group["items"].sort(key=lambda it: _sort_key(it["days"]))
        group["days"] = group["items"][0]["days"] if group["items"] else None
    groups.sort(key=lambda g: _sort_key(g["days"]))

    return {
        "groups": groups,
        "mcv_error": mcv_error,
        "cdd_error": cdd_error,
        "cdd_skipped": cdd_skipped,
        "cdd_disabled": cdd_disabled,
    }


def filter_suppressed(uid: str, groups: list[dict]) -> list[dict]:
    """Drop items the user has already clicked "Handed in" on, and any group
    that becomes empty as a result. Kept separate from check_homework_for_user
    so the CLI harness can still show everything, unfiltered, for debugging.
    """
    out = []
    for group in groups:
        items = [
            it for it in group["items"]
            if not is_homework_suppressed(uid, it["platform"], group["course_code"], it["item_key"])
        ]
        if items:
            out.append({**group, "items": items})
    return out


# ---------------------------------------------------------------------------
# Local CLI test harness
# ---------------------------------------------------------------------------
def _print_report(uid: str, result: dict) -> None:
    display_name = registered_users.get(uid, {}).get("display_name", uid)
    print(f"\n=== Homework check for {display_name} ({uid}) ===")

    if result["mcv_error"]:
        print(f"  [MCV error] {result['mcv_error']}")
    if result["cdd_error"]:
        print(f"  [ClassDeeDee error] {result['cdd_error']}")
    if result["cdd_disabled"]:
        print("  [ClassDeeDee] disabled (use /classdeedee on to re-enable)")
    elif result["cdd_skipped"]:
        print("  [ClassDeeDee] skipped — no usable login (use /deedeeregister)")

    if not result["groups"]:
        print("  Nothing outstanding. 🎉")
        return

    for group in result["groups"]:
        dot = urgency_dot(group["days"])
        name = group["course_name"] or "(course name unknown)"
        print(f"\n{dot} {group['course_code']} — {name}")
        for item in group["items"]:
            idot = urgency_dot(item["days"])
            tag = "MCV" if item["platform"] == "mcv" else "CDD"
            print(f"   {idot} [{tag}] {item['title']} — {item['due_text']}")
            print(f"        {item['link']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a homework check for one registered user.")
    parser.add_argument("--uid", required=True, help="Discord user id (must already be in users.json)")
    args = parser.parse_args()

    if args.uid not in registered_users:
        log.error("No registered user with uid %s in users.json", args.uid)
        return 1

    try:
        result = check_homework_for_user(args.uid)
    except ValueError as exc:
        log.error(str(exc))
        return 1

    _print_report(args.uid, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
