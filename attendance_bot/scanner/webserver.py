"""Minimal web server serving an on-device QR scanner (proof of concept).

The phone's browser decodes the QR code locally — via the native
BarcodeDetector API where available, jsQR everywhere else — and POSTs only the
decoded URL back here. No image data ever leaves the device.

Access is gated by a single shared secret carried in the URL *fragment*
(``/scan#t=<secret>``), so it is never sent to the server as part of a request
line and never lands in Fly's access logs.
"""

import asyncio
import hmac
import os

from aiohttp import web

from attendance_bot.config import log, SCAN_SECRET, WEB_PORT
from attendance_bot.mcv.attendance import extract_attendance_url
from attendance_bot.classdeedee.attendance import parse_attendance_qr

# repo_root/attendance_bot/scanner/webserver.py -> repo_root/web
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(REPO_ROOT, "web")

# Only one scan is processed at a time — check_in_all runs on a single-worker
# executor anyway, and this keeps an impatient double-tap from queueing up
# duplicate logins behind each other.
_scan_lock = asyncio.Lock()


async def _index(request: web.Request) -> web.Response:
    return web.FileResponse(os.path.join(WEB_DIR, "scan.html"))


async def _health(request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def _api_scan(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "malformed request"}, status=400)

    if not SCAN_SECRET or not hmac.compare_digest(str(data.get("secret", "")), SCAN_SECRET):
        log.warning("Rejected /api/scan with bad secret from %s", request.remote)
        return web.json_response({"error": "unauthorized — bad or missing scanner link"}, status=403)

    raw = str(data.get("url", ""))

    # Channel this scanner link was bound to (from /scanner). Results post there;
    # if absent/unparseable, the handler falls back to DM-only.
    channel_raw = data.get("channel")
    try:
        channel_id = int(channel_raw) if channel_raw else None
    except (ValueError, TypeError):
        channel_id = None

    # A ClassDeeDee attendance QR is JSON {"sid","n"}; an MCV QR is a URL. Try
    # the ClassDeeDee shape first, then fall back to the MyCourseVille link.
    cdd = parse_attendance_qr(raw)
    if cdd:
        if request.app.get("on_scan_cdd") is None:
            return web.json_response({"error": "ClassDeeDee check-in isn't configured"}, status=400)
        if _scan_lock.locked():
            return web.json_response({"error": "another scan is still processing — hold on"}, status=429)
        sid, nonce = cdd
        async with _scan_lock:
            try:
                summary = await request.app["on_scan_cdd"](sid, nonce, channel_id)
            except Exception:
                log.exception("ClassDeeDee scan handler blew up for sid=%s", sid)
                return web.json_response({"error": "check-in failed, see bot logs"}, status=500)
        return web.json_response(summary)

    url = extract_attendance_url(raw)
    if not url:
        return web.json_response({"error": "that QR code is not an attendance code"}, status=400)

    if _scan_lock.locked():
        return web.json_response({"error": "another scan is still processing — hold on"}, status=429)

    async with _scan_lock:
        try:
            summary = await request.app["on_scan"](url, channel_id)
        except Exception:
            log.exception("Scan handler blew up for %s", url)
            return web.json_response({"error": "check-in failed, see bot logs"}, status=500)

    return web.json_response(summary)


async def start_web_server(on_scan, on_scan_cdd=None, port: int | None = None, ssl_context=None) -> web.AppRunner:
    """Start the scanner server on the current event loop.

    ``on_scan`` is an async callable ``(attendance_url, channel_id)`` returning a
    JSON-serialisable summary dict. ``on_scan_cdd`` is the ClassDeeDee equivalent
    ``(sessionid, nonce, channel_id)``. ``channel_id`` is the Discord channel the
    scanner link was bound to (or None → DM-only). ``ssl_context`` is only used
    for local testing — in production Fly terminates TLS in front of us.
    """
    app = web.Application()
    app["on_scan"] = on_scan
    app["on_scan_cdd"] = on_scan_cdd
    app.router.add_get("/", _index)
    app.router.add_get("/scan", _index)
    app.router.add_get("/health", _health)
    app.router.add_post("/api/scan", _api_scan)
    app.router.add_static("/static", WEB_DIR)

    port = port or WEB_PORT
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port, ssl_context=ssl_context).start()
    log.info("Scanner web server listening on :%d (%s)", port, "https" if ssl_context else "http")
    if not SCAN_SECRET:
        log.warning("SCAN_SECRET is not set — /api/scan will reject everything")
    return runner
