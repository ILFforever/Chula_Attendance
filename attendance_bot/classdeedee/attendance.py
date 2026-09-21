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
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as http_requests

from attendance_bot.config import log, registered_users
# How many users log in at once is bounded in attendance_bot/checkin/ and shared
# with MyCourseVille, so two overlapping scans can't each open a full class's
# worth of sessions. CHECKIN_CONCURRENCY is used by bench_logins below.
from attendance_bot.checkin import CHECKIN_CONCURRENCY, collect_targets, run_batch
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


def _read_rss_mb() -> tuple[float | None, float | None]:
    """Return (current_rss_mb, peak_rss_mb). Dependency-free on Linux/Fly.

    Reads VmRSS/VmHWM from /proc/self/status (VmHWM is the process's peak RSS,
    so we get the high-water mark without a sampler thread). Falls back to
    psutil, then to (None, None) on platforms without either (e.g. Windows).
    """
    try:
        cur = peak = None
        with open("/proc/self/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    cur = int(line.split()[1]) / 1024  # kB → MB
                elif line.startswith("VmHWM:"):
                    peak = int(line.split()[1]) / 1024
        if cur is not None:
            return cur, peak
    except OSError:
        pass
    try:
        import psutil  # optional
        return psutil.Process().memory_info().rss / 1e6, None
    except Exception:
        return None, None


def bench_logins() -> dict:
    """Log in every registered user in parallel; measure timing and RAM.

    Does login-only (no check-in) — this is the stress/timing test for the
    concurrent-login path. Logs a full breakdown to the bot log (Fly logs) and
    returns a stats dict for a Discord summary.
    """
    if not registered_users:
        return {"error": "No users registered. Use `/register` first."}

    per: list[dict] = []
    targets: list[tuple[str, str, str]] = []  # (display_name, username, password)
    for uid, info in registered_users.items():
        name = info.get("display_name", info.get("username", uid))
        try:
            creds = resolve_cdd_credentials(info, "checkin")
        except ValueError:
            per.append({"name": name, "ok": False, "seconds": 0.0, "error": "decrypt failed"})
            continue
        if creds is None:
            per.append({"name": name, "ok": False, "seconds": 0.0, "error": "no ClassDeeDee login (use /deedeeregister)"})
            continue
        username, pw = creds
        targets.append((name, username, pw))

    workers = min(CHECKIN_CONCURRENCY, len(targets)) if targets else 1
    waves = -(-len(targets) // workers) if targets else 0  # ceil division

    rss_before, _ = _read_rss_mb()
    started = time.perf_counter()

    def _login(t: tuple[str, str, str]) -> dict:
        name, username, pw = t
        t0 = time.perf_counter()
        try:
            login_classdeedee(username, pw).close()
            return {"name": name, "ok": True, "seconds": time.perf_counter() - t0, "error": None}
        except CddWrongCredentialsError:
            return {"name": name, "ok": False, "seconds": time.perf_counter() - t0, "error": "wrong credentials"}
        except CddLoginError as exc:
            return {"name": name, "ok": False, "seconds": time.perf_counter() - t0, "error": f"login failed ({exc})"[:80]}
        except http_requests.RequestException as exc:
            return {"name": name, "ok": False, "seconds": time.perf_counter() - t0, "error": f"network ({exc})"[:80]}
        except Exception as exc:  # noqa: BLE001 - benchmark must never crash the caller
            return {"name": name, "ok": False, "seconds": time.perf_counter() - t0, "error": f"unexpected ({exc})"[:80]}

    if targets:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cdd_bench") as pool:
            for future in as_completed([pool.submit(_login, t) for t in targets]):
                per.append(future.result())

    wall = time.perf_counter() - started
    rss_after, rss_peak = _read_rss_mb()
    ok = sum(1 for r in per if r["ok"])
    login_times = [r["seconds"] for r in per if r["ok"]]

    stats = {
        "total": len(per),
        "attempted": len(targets),
        "ok": ok,
        "failed": len(per) - ok,
        "wall": wall,
        "workers": workers,
        "waves": waves,
        "slowest": max(login_times) if login_times else 0.0,
        "fastest": min(login_times) if login_times else 0.0,
        "rss_before": rss_before,
        "rss_after": rss_after,
        "rss_peak": rss_peak,
        "per": per,
    }

    # Fly logs: one summary line + per-user detail.
    def _f(v):
        return f"{v:.1f}" if isinstance(v, (int, float)) else "n/a"
    log.info(
        "BENCH logins: %d/%d ok in %.2fs | %d worker(s), %d wave(s) | RSS before=%s after=%s peak=%s MB",
        ok, len(targets), wall, workers, waves, _f(rss_before), _f(rss_after), _f(rss_peak),
    )
    for r in per:
        log.info("  BENCH %-24s %-4s %5.2fs  %s", r["name"], "OK" if r["ok"] else "FAIL", r["seconds"], r["error"] or "")

    return stats


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
    def _resolve(info: dict) -> tuple[str, str, str] | None:
        creds = resolve_cdd_credentials(info, "checkin")
        if creds is None:
            return None
        username, password = creds
        return username, password, "chulasso"

    collected = collect_targets(_resolve)
    if not collected.targets:
        return collected.skipped

    log.info("ClassDeeDee check-in for sid=%s", sid)
    return collected.skipped + run_batch(
        collected.targets,
        lambda t: check_in_one(t.username, t.password, sid, nonce, display_name=t.display_name),
        label="cdd_checkin",
        deadline_seconds=NONCE_WINDOW_SECONDS,
    )
