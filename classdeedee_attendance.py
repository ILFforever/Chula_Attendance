"""ClassDeeDee attendance check-in.

The attendance QR an instructor displays encodes JSON:  {"sid": <sessionid>,
"n": <nonce>}.  The student's browser scans it and POSTs
{sessionid, nonce} to /api/attendants/checkin using their ClassDeeDee session.
The nonce rotates every ~5 seconds, so check-ins must happen promptly after a
scan.

This module mirrors attendance.py (MCV) but for ClassDeeDee:
  - parse_attendance_qr()  — turn scanned QR text into (sid, nonce)
  - check_in_one()         — log one user in and post the check-in
  - check_in_all()         — do it for every registered user

NOTE: check_in_all() is currently sequential. Because each login is ~4 SSO
round-trips and the nonce only lives ~5 s, this won't scale to a big class yet
— parallel/async logins are a planned follow-up.
"""
import json
from datetime import datetime

import requests as http_requests

from config import log, registered_users
from password_crypto import decrypt_password
from attendance import TZ_BANGKOK
from classdeedee_login import (
    login_classdeedee,
    CDD,
    REQUEST_TIMEOUT,
    WrongCredentialsError as CddWrongCredentialsError,
    LoginError as CddLoginError,
)

CDD_CHECKIN = f"{CDD}/api/attendants/checkin"


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
    login_method: str = "cu_net",
) -> str:
    """Log one user into ClassDeeDee and submit an attendance check-in."""
    name = display_name or username

    # ClassDeeDee auth is ChulaSSO — a MyCourseVille "platform" account can't use it.
    if login_method == "platform":
        return f"⚠️ **[{name}]** — MCV platform account can't use ClassDeeDee (needs ChulaSSO)"

    log.info("ClassDeeDee check-in START: %s (%s)", name, username)
    try:
        session = login_classdeedee(username, password)
    except CddWrongCredentialsError:
        log.error("%s — wrong credentials", name)
        return f"🔑 **[{name}]** — wrong username or password, use `/register` to update"
    except CddLoginError:
        log.error("%s — login failed", name)
        return f"🔒 **[{name}]** — ClassDeeDee login failed, try again"
    except http_requests.RequestException as exc:
        log.error("%s — network error on login: %s", name, exc)
        return f"🌐 **[{name}]** — network error during login"

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
        log.error("%s — network error on check-in: %s", name, exc)
        return f"🌐 **[{name}]** — network error during check-in"
    finally:
        session.close()
        log.info("ClassDeeDee check-in END: %s", name)


def check_in_all(sid: str, nonce: str) -> list[tuple[str, str]]:
    """Check in every registered user for one scanned attendance QR.

    Returns a list of (discord_user_id, result_message) tuples.
    Sequential for now — see the module note about async logins.
    """
    if not registered_users:
        return [("", "No users registered. Use `/register` to add users.")]

    results: list[tuple[str, str]] = []
    for uid, info in registered_users.items():
        display_name = info.get("display_name", info["username"])
        try:
            password = decrypt_password(info["password"])
        except ValueError:
            log.error("Failed to decrypt password for %s", info["username"])
            results.append((uid, f"❌ **{display_name}** — failed to decrypt password (re-register)"))
            continue

        msg = check_in_one(
            info["username"], password, sid, nonce,
            display_name=display_name,
            login_method=info.get("login_method", "cu_net"),
        )
        results.append((uid, msg))

    return results
