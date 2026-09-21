"""Minimal web server serving an on-device QR scanner (proof of concept).

The phone's browser decodes the QR code locally — via the native
BarcodeDetector API where available, jsQR everywhere else — and POSTs only the
decoded URL back here. No image data ever leaves the device.

Access is gated by a per-user signed token (see ``tokens.py``) carried in the
URL *fragment* (``/scan#t=<token>``), so it is never sent to the server as part
of a request line and never lands in Fly's access logs.
"""

import os

from aiohttp import web

from attendance_bot.config import log, SCAN_SECRET, WEB_PORT
from attendance_bot.mcv.attendance import extract_attendance_url
from attendance_bot.classdeedee.attendance import parse_attendance_qr
from attendance_bot.scanner.tokens import verify_scan_token

# repo_root/attendance_bot/scanner/webserver.py -> repo_root/web
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(REPO_ROOT, "web")

# Codes currently being processed, keyed the same way the leaderboard dedups
# them (an MCV URL, or "classdeedee:<sid>").
#
# This replaces a single global lock. That lock made every scan wait for every
# other one, which was harmless while check_in_all ran on a single-worker
# executor — but it meant a slow MyCourseVille run could 429 an incoming
# ClassDeeDee scan, and ClassDeeDee is the one path that genuinely cannot wait,
# since its nonce dies in ~8 s. Tracking per code keeps the original purpose
# (an impatient double-tap of the *same* QR doesn't queue duplicate logins)
# while letting two different codes proceed at once. Total load stays bounded
# by the shared semaphore in attendance_bot/checkin/runner.py rather than by
# serializing whole scans.
_inflight: set[str] = set()


async def _index(request: web.Request) -> web.Response:
    return web.FileResponse(os.path.join(WEB_DIR, "scan.html"))


async def _health(request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def _authorize(request: web.Request) -> tuple[dict, str] | web.Response:
    """Parse the JSON body and check its token.

    Returns ``(body, user_id)`` — ``user_id`` is ``""`` for a legacy
    shared-secret link, which is valid but carries no identity — or the error
    response to send back.
    """
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "malformed request"}, status=400)

    user_id = verify_scan_token(str(data.get("secret", "")))
    if user_id is None:
        log.warning("Rejected %s with bad token from %s", request.path, request.remote)
        return web.json_response({"error": "unauthorized — bad or missing scanner link"}, status=403)
    return data, user_id


async def _api_me(request: web.Request) -> web.Response:
    """Who does this token belong to? Drives the identity chip on the page."""
    auth = await _authorize(request)
    if isinstance(auth, web.Response):
        return auth
    _, user_id = auth

    if not user_id:
        # Legacy shared-secret link — nobody to name.
        return web.json_response({"anonymous": True})

    identify = request.app.get("on_identify")
    if identify is None:
        return web.json_response({"anonymous": True})
    try:
        who = await identify(user_id)
    except Exception:
        log.exception("Identity lookup failed for uid=%s", user_id)
        return web.json_response({"anonymous": True})
    return web.json_response(who or {"anonymous": True})


async def _api_scan(request: web.Request) -> web.Response:
    auth = await _authorize(request)
    if isinstance(auth, web.Response):
        return auth
    data, user_id = auth

    raw = str(data.get("url", ""))

    # Channel this scanner link was bound to (from /scanner). Results post there;
    # if absent/unparseable, the handler falls back to DM-only.
    channel_raw = data.get("channel")
    try:
        channel_id = int(channel_raw) if channel_raw else None
    except (ValueError, TypeError):
        channel_id = None

    scanner_id = user_id or None

    # A ClassDeeDee attendance QR is JSON {"sid","n"}; an MCV QR is a URL. Try
    # the ClassDeeDee shape first, then fall back to the MyCourseVille link.
    cdd = parse_attendance_qr(raw)
    if cdd:
        if request.app.get("on_scan_cdd") is None:
            return web.json_response({"error": "ClassDeeDee check-in isn't configured"}, status=400)
        sid, nonce = cdd
        return await _dispatch(
            f"classdeedee:{sid}",
            lambda: request.app["on_scan_cdd"](sid, nonce, channel_id, scanner_id),
            what=f"sid={sid}",
        )

    url = extract_attendance_url(raw)
    if not url:
        return web.json_response({"error": "that QR code is not an attendance code"}, status=400)

    return await _dispatch(
        url,
        lambda: request.app["on_scan"](url, channel_id, scanner_id),
        what=url,
    )


async def _dispatch(key: str, run, *, what: str) -> web.Response:
    """Run one scan, refusing a second scan of the same code while it's live.

    A different code scanned at the same time runs concurrently — see the note
    on _inflight above.
    """
    if key in _inflight:
        return web.json_response(
            {"error": "that code is already being checked in — hold on"}, status=429
        )

    _inflight.add(key)
    try:
        return web.json_response(await run())
    except Exception:
        log.exception("Scan handler blew up for %s", what)
        return web.json_response({"error": "check-in failed, see bot logs"}, status=500)
    finally:
        _inflight.discard(key)


async def start_web_server(on_scan, on_scan_cdd=None, on_identify=None,
                           port: int | None = None, ssl_context=None) -> web.AppRunner:
    """Start the scanner server on the current event loop.

    ``on_scan`` is an async callable ``(attendance_url, channel_id, scanner_id)``
    returning a JSON-serialisable summary dict. ``on_scan_cdd`` is the
    ClassDeeDee equivalent ``(sessionid, nonce, channel_id, scanner_id)``.
    ``channel_id`` is the Discord channel the scanner link was bound to (or None
    → DM-only); ``scanner_id`` is the Discord user whose token was used (or None
    for a legacy shared-secret link). ``on_identify`` is ``(user_id)`` returning
    a ``{"name", "avatar"}`` dict for the page's identity chip.

    ``ssl_context`` is only used for local testing — in production Fly
    terminates TLS in front of us.
    """
    app = web.Application()
    app["on_scan"] = on_scan
    app["on_scan_cdd"] = on_scan_cdd
    app["on_identify"] = on_identify
    app.router.add_get("/", _index)
    app.router.add_get("/scan", _index)
    app.router.add_get("/health", _health)
    app.router.add_post("/api/scan", _api_scan)
    app.router.add_post("/api/me", _api_me)
    app.router.add_static("/static", WEB_DIR)

    port = port or WEB_PORT
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port, ssl_context=ssl_context).start()
    log.info("Scanner web server listening on :%d (%s)", port, "https" if ssl_context else "http")
    if not SCAN_SECRET:
        log.warning("SCAN_SECRET is not set — /api/scan will reject everything")
    return runner
