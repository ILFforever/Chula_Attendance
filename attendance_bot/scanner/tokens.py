"""Per-user scanner tokens.

The scanner page used to be gated by one shared secret handed to everyone, so a
scan carried no identity: results could not be attributed, one person could not
be revoked, and anyone who ever opened the link kept access forever.

A token is instead minted per Discord user by ``/scanner``:

    <uid>.<issued_at>.<signature>

where the signature is an HMAC-SHA256 of ``<uid>.<issued_at>`` keyed on
``SCAN_SECRET``, truncated to 16 bytes and base64url-encoded. Nothing is stored
server-side — the signature is self-validating, so tokens survive restarts and
cost no disk. Rotating ``SCAN_SECRET`` invalidates every token at once.

``issued_at`` is carried so a maximum age can be enforced later without changing
the format; it is not currently used to expire anything.
"""

import base64
import hashlib
import hmac
import time

from attendance_bot.config import SCAN_SECRET

_SIG_BYTES = 16


def _sign(payload: str) -> str:
    digest = hmac.new(SCAN_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:_SIG_BYTES]).decode().rstrip("=")


def mint_scan_token(user_id: int | str, issued_at: int | None = None) -> str:
    """Return a signed scanner token for one Discord user."""
    payload = f"{user_id}.{issued_at if issued_at is not None else int(time.time())}"
    return f"{payload}.{_sign(payload)}"


def verify_scan_token(token: str) -> str | None:
    """Return the Discord user id a token was minted for, or None if invalid.

    Also accepts the bare ``SCAN_SECRET`` — links handed out before per-user
    tokens existed are still live in people's bookmarks and localStorage, and
    breaking them would lock the group out mid-semester. Those scans verify
    with no identity attached (``""``), which every caller treats as anonymous.
    """
    if not SCAN_SECRET or not token:
        return None

    if hmac.compare_digest(token, SCAN_SECRET):
        return ""  # legacy shared-secret link — valid, but anonymous

    parts = token.split(".")
    if len(parts) != 3:
        return None
    uid, issued_at, sig = parts
    if not uid.isdigit() or not issued_at.isdigit():
        return None
    if not hmac.compare_digest(sig, _sign(f"{uid}.{issued_at}")):
        return None
    return uid
