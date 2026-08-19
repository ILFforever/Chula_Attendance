"""
ClassDeeDee (classdeedee.cloud.cp.eng.chula.ac.th) login adapter.

ClassDeeDee authenticates through Chula's ChulaSSO (account.it.chula.ac.th),
which is a CAS-style ticket service. Unlike MyCourseVille (which serves its own
HTML login form that this bot scrapes in attendance.py), ChulaSSO is a JS SPA
with a JSON API — so we drive the API directly rather than scraping a form.

Flow (reverse-engineered from the ChulaSSO + ClassDeeDee JS bundles):

  1. GET  account.it.chula.ac.th/login?serviceName=<name>&service=<callback>
        → server sets the `SSO_requestService` cookie describing the pending
          service request. (The SPA only *reads* this cookie; it is set
          server-side, so a plain cookie jar is enough — no browser needed.)
  2. POST account.it.chula.ac.th/api/auth/json  {username, password}
        → on success, sets the ChulaSSO session cookie (TGT).
  3. POST account.it.chula.ac.th/api/tickets/grantTicket   (empty body)
        → the "Grant" consent action. Reads the pending service from cookies
          and 302-redirects to  <callback>?ticket=ST-...
  4. POST classdeedee.cloud.cp.eng.chula.ac.th/api/auth/   {"ssoTicket": "ST-..."}
        → ClassDeeDee redeems the ticket (its backend calls ChulaSSO
          /serviceValidation) and sets the ClassDeeDee session cookie.

After step 4 the returned requests.Session is authenticated to ClassDeeDee.

Usage:
    CDD_USERNAME=6xxxxxxx21 CDD_PASSWORD='...' python classdeedee_login.py
    # or reuse a registered bot user (needs ENCRYPTION_KEY + users.json):
    python classdeedee_login.py --uid <discord_user_id>
"""
from __future__ import annotations

import os
import sys
import json
import argparse
import logging
from urllib.parse import urlparse, parse_qs

import requests as http_requests

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("classdeedee")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SSO = "https://account.it.chula.ac.th"
SSO_LOGIN = f"{SSO}/login"
SSO_AUTH_JSON = f"{SSO}/api/auth/json"
SSO_GRANT = f"{SSO}/api/tickets/grantTicket"

CDD = "https://classdeedee.cloud.cp.eng.chula.ac.th"
CDD_SERVICE = f"{CDD}/login/chulasso/"
CDD_REDEEM = f"{CDD}/api/auth/"          # POST {"ssoTicket": ...}
CDD_ABOUT = f"{CDD}/api/about"

SERVICE_NAME = "ClassDeeDee by Krerk"
REQUEST_TIMEOUT = 30
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class WrongCredentialsError(Exception):
    """ChulaSSO rejected the username/password."""


class LoginError(Exception):
    """Login failed for a non-credential reason."""


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
def _new_session() -> http_requests.Session:
    s = http_requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    })
    return s


def _extract_ticket(url: str) -> str | None:
    try:
        return (parse_qs(urlparse(url).query).get("ticket") or [None])[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Step 1+2: authenticate to ChulaSSO
# ---------------------------------------------------------------------------
def _sso_authenticate(session: http_requests.Session, username: str, password: str) -> None:
    # 1. Prime the service request cookie (SSO_requestService set server-side).
    log.info("GET %s (service=%s)", SSO_LOGIN, CDD_SERVICE)
    r = session.get(
        SSO_LOGIN,
        params={"serviceName": SERVICE_NAME, "service": CDD_SERVICE},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    log.debug("  → HTTP %d, cookies now: %s", r.status_code, list(session.cookies.keys()))

    # If SSO already had a live session it might bounce straight to a ticket.
    tk = _extract_ticket(r.url)
    if tk:
        log.info("SSO returned a ticket immediately (existing session).")
        return  # caller re-checks; grant step will no-op

    # 2. Submit credentials to the JSON auth endpoint.
    log.info("POST %s", SSO_AUTH_JSON)
    r = session.post(
        SSO_AUTH_JSON,
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json", "Origin": SSO, "Referer": f"{SSO}/html/index.html"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    body = r.text[:300].replace("\n", " ")
    log.info("  → HTTP %d | %s", r.status_code, body)

    if r.status_code in (401, 403):
        raise WrongCredentialsError("ChulaSSO rejected the credentials")
    if r.status_code >= 400:
        # Some APIs return 400 with an {info: ...} message on bad login.
        low = r.text.lower()
        if any(k in low for k in ("incorrect", "invalid", "password", "credential")):
            raise WrongCredentialsError(f"Login failed: {body}")
        raise LoginError(f"Auth endpoint returned HTTP {r.status_code}: {body}")

    log.info("ChulaSSO authenticated. Session cookies: %s", list(session.cookies.keys()))


# ---------------------------------------------------------------------------
# Step 3: grant → obtain the CAS ticket
# ---------------------------------------------------------------------------
def _sso_grant_ticket(session: http_requests.Session) -> str:
    log.info("POST %s (grant)", SSO_GRANT)
    r = session.post(
        SSO_GRANT,
        headers={"Origin": SSO, "Referer": f"{SSO}/html/index.html"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,   # we want to read the Location ourselves
    )
    log.info("  → HTTP %d | Location: %s", r.status_code, r.headers.get("Location"))

    # Preferred: ticket in the 302 Location header.
    loc = r.headers.get("Location", "")
    tk = _extract_ticket(loc)
    if tk:
        log.info("Got CAS ticket from grant redirect.")
        return tk

    # Fallback: some deployments return the ticket/redirect URL in a JSON body.
    if r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            data = r.json()
            for key in ("ticket", "ticket_id", "redirect", "location", "url"):
                v = data.get(key)
                if v:
                    tk = v if str(v).startswith("ST") else _extract_ticket(str(v))
                    if tk:
                        log.info("Got CAS ticket from grant JSON (%s).", key)
                        return tk
        except (ValueError, AttributeError):
            pass

    raise LoginError(
        f"Grant step did not yield a ticket (HTTP {r.status_code}, "
        f"Location={loc!r}, body={r.text[:200]!r})"
    )


# ---------------------------------------------------------------------------
# Step 4: redeem the ticket at ClassDeeDee
# ---------------------------------------------------------------------------
def _cdd_redeem(session: http_requests.Session, ticket: str) -> None:
    log.info("POST %s  {ssoTicket: %s...}", CDD_REDEEM, ticket[:12])
    r = session.post(
        CDD_REDEEM,
        data=json.dumps({"ssoTicket": ticket}),
        headers={
            "Content-Type": "application/json",
            "Origin": CDD,
            "Referer": f"{CDD_SERVICE}?ticket={ticket}",
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    body = r.text[:300].replace("\n", " ")
    log.info("  → HTTP %d | %s", r.status_code, body)
    if not r.ok:
        info = ""
        try:
            info = r.json().get("info", "")
        except (ValueError, AttributeError):
            pass
        raise LoginError(f"ClassDeeDee rejected the ticket (HTTP {r.status_code}): {info or body}")
    log.info("ClassDeeDee session established. Cookies: %s", list(session.cookies.keys()))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def login_classdeedee(username: str, password: str) -> http_requests.Session:
    """Full ClassDeeDee login; returns an authenticated requests.Session."""
    session = _new_session()
    _sso_authenticate(session, username, password)
    ticket = _sso_grant_ticket(session)
    log.info("CAS ticket: %s", ticket)
    _cdd_redeem(session, ticket)
    log.info("ClassDeeDee login OK for %s", username)
    return session


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------
def _resolve_credentials(uid: str | None) -> tuple[str, str]:
    if uid:
        from config import registered_users
        from password_crypto import decrypt_password
        info = registered_users.get(uid)
        if not info:
            raise SystemExit(f"No registered user with uid {uid!r} in users.json")
        return info["username"], decrypt_password(info["password"])

    username = os.environ.get("CDD_USERNAME", "")
    password = os.environ.get("CDD_PASSWORD", "")
    if not username or not password:
        raise SystemExit(
            "Provide CDD_USERNAME + CDD_PASSWORD env vars, or --uid <discord_user_id>."
        )
    return username, password


def main() -> int:
    parser = argparse.ArgumentParser(description="Log into ClassDeeDee via ChulaSSO.")
    parser.add_argument("--uid", help="Reuse a registered bot user's stored credentials.")
    args = parser.parse_args()

    username, password = _resolve_credentials(args.uid)

    try:
        session = login_classdeedee(username, password)
    except WrongCredentialsError:
        log.error("Wrong username or password.")
        return 2
    except LoginError as exc:
        log.error("Login failed: %s", exc)
        return 1

    # Prove the session works.
    r = session.get(CDD_ABOUT, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
    log.info("Authenticated %s → HTTP %d: %s", CDD_ABOUT, r.status_code, r.text[:400])
    return 0


if __name__ == "__main__":
    sys.exit(main())
