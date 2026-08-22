"""Local test harness for the QR scanner — no Discord token needed.

    python devserver.py           # http://localhost:8080/scan  (desktop webcam)
    python devserver.py --https   # https://<your-LAN-IP>:8443  (phone camera)

Scanned links are printed to the console instead of triggering a real check-in,
so you can point a phone at a QR code and watch what the bot would receive.

Why --https: browsers only expose the camera in a "secure context". That
includes plain http on *localhost*, but NOT http://192.168.x.x — so testing on
a phone over your LAN needs TLS. This generates a throwaway self-signed cert
covering your LAN IP; your phone will show a scary warning that you can accept
(Advanced -> Proceed). The cert lives in a temp dir and is regenerated each run.
"""

import argparse
import asyncio
import datetime
import ipaddress
import os
import secrets
import socket
import ssl
import sys
import tempfile

# Must be set before webserver/config are imported — they read env at import.
os.environ.setdefault("SCAN_SECRET", "devsecret")

from webserver import start_web_server  # noqa: E402
from config import SCAN_SECRET, log  # noqa: E402


def lan_ip() -> str:
    """Best-effort local address that a phone on the same Wi-Fi can reach."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the route
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def self_signed_cert(host_ip: str) -> ssl.SSLContext:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_ip)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(host_ip)),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    tmp = tempfile.mkdtemp(prefix="scanner-cert-")
    cert_path, key_path = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


async def fake_scan(url: str) -> dict:
    """Stand-in for the real check-in — prints instead of logging anyone in."""
    print("\n" + "=" * 70)
    print("  SCAN RECEIVED")
    print("  " + url)
    print("=" * 70 + "\n")
    await asyncio.sleep(1)  # pretend the check-in takes a moment
    return {"message": "✅ Dev mode — bot received the link.\nCheck the terminal.",
            "attempted": 0, "succeeded": 0, "duplicate": False}


async def main(use_https: bool, port: int) -> None:
    ip = lan_ip()
    ctx = self_signed_cert(ip) if use_https else None
    await start_web_server(fake_scan, port=port, ssl_context=ctx)

    scheme = "https" if use_https else "http"
    print("\n  Scanner running in DEV mode — no check-ins will happen.\n")
    print(f"  Desktop webcam:  {scheme}://localhost:{port}/scan#t={SCAN_SECRET}")
    if use_https:
        print(f"  Phone (same Wi-Fi): https://{ip}:{port}/scan#t={SCAN_SECRET}")
        print("\n  Your phone will warn about the self-signed certificate.")
        print("  Tap Advanced -> Proceed. The camera needs HTTPS to work at all.")
    else:
        print(f"\n  For phone testing you need HTTPS — rerun with:  python devserver.py --https")
    print("\n  Ctrl-C to stop.\n")

    await asyncio.Event().wait()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--https", action="store_true", help="serve TLS with a throwaway self-signed cert")
    p.add_argument("--port", type=int, default=0, help="override the port")
    args = p.parse_args()

    sys.stdout.reconfigure(line_buffering=True)  # keep scan output live when piped

    if not SCAN_SECRET:
        log.error("SCAN_SECRET resolved empty")
        sys.exit(1)

    try:
        asyncio.run(main(args.https, args.port or (8443 if args.https else 8080)))
    except KeyboardInterrupt:
        print("\n  Stopped.")
