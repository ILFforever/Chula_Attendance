"""ClassDeeDee attendance check-in.

The attendance QR an instructor displays encodes JSON:  {"sid": <sessionid>,
"n": <nonce>}.  The student's browser scans it and POSTs
{sessionid, nonce} to /api/attendants/checkin using their ClassDeeDee session.
The nonce rotates every ~5 seconds, so check-ins must happen promptly after a
scan.

This module mirrors attendance.py (MCV) but for ClassDeeDee:
  - parse_attendance_qr()  — turn scanned QR text into (sid, nonce)
  - check_in_one()         — log one user in and post the check-in
  - check_in_all()         — do it for every registered user, in parallel

The nonce rotates roughly every 8 seconds. Each login is ~4 SSO round-trips
(~1 s), so a whole class must log in concurrently to land inside that window.
check_in_all() fans the per-user work out across the shared bounded pool in
attendance_bot/checkin/: the cap keeps wall-clock ~= one login (not N logins)
while limiting how many sessions/connections exist at once, which matters on a
small Fly instance. Tune with the CHECKIN_CONCURRENCY env var (default 16).
"""
import json
import time
from datetime import datetime

import requests as http_requests

from attendance_bot.config import log, registered_users
# How many users log in at once is bounded in attendance_bot/checkin/ and shared
# with MyCourseVille, so two overlapping scans can't each open a full class's
# worth of sessions.
from attendance_bot.checkin import collect_targets, run_batch
from attendance_bot.checkin.bench import run_login_bench
from attendance_bot.security.crypto import decrypt_password
from attendance_bot.mcv.attendance import TZ_BANGKOK
from attendance_bot.classdeedee.login import (
    login_classdeedee,
    CDD,
    REQUEST_TIMEOUT,
    WrongCredentialsError as CddWrongCredentialsError,
    LoginError as CddLoginError,
)

CDD_CHECKIN = f"{CDD}/api/attendants/checkin"

# The instructor's QR nonce lives ~8 s; used only to warn when a run overruns.
NONCE_WINDOW_SECONDS = 8


def classdeedee_purpose_enabled(info: dict, purpose: str) -> bool:
    """Whether this user wants their ClassDeeDee login used for `purpose`
    ("checkin" or "homework") — separate flags so a user can, say, keep
    ClassDeeDee check-in on while skipping it in the homework digest, or
    vice versa. Falls back to the older single `classdeedee_enabled` flag
    for accounts that toggled it before the two were split, then to True.
    """
    return info.get(f"classdeedee_{purpose}_enabled", info.get("classdeedee_enabled", True))


def resolve_cdd_credentials(info: dict, purpose: str) -> tuple[str, str] | None:
    """Return (username, password) to use for ClassDeeDee, or None if the user
    has no usable ClassDeeDee login, or has turned it off for this `purpose`
    ("checkin" or "homework" — see classdeedee_purpose_enabled).

    Priority:
      1. an explicit `chulasso` sub-credential (added via /deedeeregister), else
      2. a cu_net main credential — a CU Net account IS a ChulaSSO account.
    A MyCourseVille "platform" account with no `chulasso` returns None (it can't
    authenticate against ChulaSSO). May raise ValueError if decryption fails.

    This is the single choke point both check-in (check_in_all) and the
    homework check (homework/check.py) go through, so the /classdeedee /
    /settings toggles only need to be respected here.
    """
    if not classdeedee_purpose_enabled(info, purpose):
        return None
    cs = info.get("chulasso")
    if cs and cs.get("username") and cs.get("password"):
        return cs["username"], decrypt_password(cs["password"])
    if info.get("login_method", "cu_net") == "cu_net":
        return info["username"], decrypt_password(info["password"])
    return None


def _resolve_target(info: dict) -> tuple[str, str, str] | None:
    """collect_targets() resolver for ClassDeeDee. None when the user has no
    usable ChulaSSO login (an MCV-only account with no /deedeeregister).

    Shared by check_in_all and bench_logins so the benchmark always measures
    exactly the set of users a real check-in would attempt.
    """
    creds = resolve_cdd_credentials(info, "checkin")
    if creds is None:
        return None
    username, password = creds
    return username, password, "chulasso"


def parse_attendance_qr(text: str) -> tuple[str, str] | None:
    """Return (sessionid, nonce) from a scanned ClassDeeDee attendance QR.

    The QR text is JSON like {"sid": "...", "n": "..."}; returns None for
    anything that isn't a valid attendance QR.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict) and data.get("sid") and data.get("n"):
        return str(data["sid"]), str(data["n"])
    return None


def check_in_one(
    username: str,
    password: str,
    sid: str,
    nonce: str,
    display_name: str = "",
) -> str:
    """Log one user into ClassDeeDee and submit an attendance check-in.

    `username`/`password` are the resolved ChulaSSO credentials
    (see resolve_cdd_credentials).
    """
    name = display_name or username

    log.debug("ClassDeeDee check-in START: %s (%s)", name, username)
    login_started = time.perf_counter()
    try:
        session = login_classdeedee(username, password)
    except CddWrongCredentialsError:
        log.warning("%s — wrong credentials", name)
        return f"🔑 **[{name}]** — wrong username or password, use `/register` to update"
    except CddLoginError as exc:
        log.warning("%s — login failed: %s", name, exc)
        return f"🔒 **[{name}]** — ClassDeeDee login failed, try again"
    except http_requests.RequestException as exc:
        log.warning("%s — network error on login: %s", name, exc)
        return f"🌐 **[{name}]** — network error during login"
    log.debug("%s — logged in in %.2fs", name, time.perf_counter() - login_started)

    try:
        r = session.post(
            CDD_CHECKIN,
            json={"sessionid": sid, "nonce": nonce},
            headers={"Content-Type": "application/json", "Origin": CDD},
            timeout=REQUEST_TIMEOUT,
        )
        data = {}
        try:
            data = r.json()
        except ValueError:
            pass
        info = str(data.get("info", "")).lower()

        if r.ok and info in ("checked_in", "checked"):
            ts = datetime.now(TZ_BANGKOK).strftime("%I:%M %p")
            log.info("%s — checked in", name)
            return f"✅ **[{name}]** — checked in at `{ts}` 🎉"
        if info == "already":
            log.info("%s — already checked in", name)
            return f"✅ **[{name}]** — already checked in"

        detail = data.get("info") or f"HTTP {r.status_code}"
        log.warning("%s — check-in not accepted: %s", name, detail)
        return f"⚠️ **[{name}]** — {detail}"
    except http_requests.RequestException as exc:
        log.warning("%s — network error on check-in: %s", name, exc)
        return f"🌐 **[{name}]** — network error during check-in"
    finally:
        session.close()
        log.debug("ClassDeeDee check-in END: %s", name)


def _attempt_login(target) -> str | None:
    """One ClassDeeDee login for the benchmark. None on success, else a reason."""
    try:
        login_classdeedee(target.username, target.password).close()
        return None
    except CddWrongCredentialsError:
        return "wrong credentials"
    except CddLoginError as exc:
        return f"login failed ({exc})"[:80]
    except http_requests.RequestException as exc:
        return f"network ({exc})"[:80]


def bench_logins() -> dict:
    """Log every eligible user into ClassDeeDee in parallel; time it and
    measure RAM. Login only — no attendance is recorded."""
    return run_login_bench(_resolve_target, _attempt_login, label="classdeedee")


def check_in_all(sid: str, nonce: str) -> list[tuple[str, str]]:
    """Check in every registered user for one scanned attendance QR.

    Logins run concurrently under the shared check-in bound so the whole class
    lands inside the ~8 s nonce window while capping how many sessions exist at
    once. Returns (discord_user_id, result_message) tuples.

    NOTE: unlike the MyCourseVille path this does no /enroll subject filtering —
    every opted-in user with a ClassDeeDee login is checked into whatever QR was
    scanned. A ClassDeeDee QR carries only {sid, nonce}, with no course code to
    match a user's subjects against, and resolving one would cost an extra
    round trip inside a window that is already tight. Deliberate, not an
    oversight.
    """
    if not registered_users:
        return [("", "No users registered. Use `/register` to add users.")]

    # Users with no ClassDeeDee login (MCV-only, no /deedeeregister) resolve to
    # None and are skipped silently so scan results stay clean.
    collected = collect_targets(_resolve_target)
    if not collected.targets:
        return collected.skipped

    log.info("ClassDeeDee check-in for sid=%s", sid)
    return collected.skipped + run_batch(
        collected.targets,
        lambda t: check_in_one(t.username, t.password, sid, nonce, display_name=t.display_name),
        platform="classdeedee",
        label="cdd_checkin",
        deadline_seconds=NONCE_WINDOW_SECONDS,
    )
