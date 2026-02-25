import re
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

import requests as http_requests
from bs4 import BeautifulSoup

from config import log, registered_users
from password_crypto import decrypt_password

# ---------------------------------------------------------------------------
# URL patterns
# ---------------------------------------------------------------------------
# Full valid attendance URL: .../attendance_qr_selfcheck/<id>/<code>
MCV_URL_PATTERN = re.compile(
    r"https?://(?:www\.)?mycourseville\.com/\?q=courseville/course/\d+/attendance_qr_selfcheck/\d+/[A-Za-z0-9]+"
)
# Partial / incomplete attendance URL (missing id or code)
MCV_URL_PARTIAL = re.compile(
    r"https?://(?:www\.)?mycourseville\.com/\?q=courseville/course/\d+/attendance[^\s]*"
)


def extract_attendance_url(text: str) -> str | None:
    """Extract a MyCourseVille attendance URL from message text."""
    match = MCV_URL_PATTERN.search(text)
    if match:
        return match.group(0)
    return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MCV_HOME_URL = "https://www.mycourseville.com/"
MCV_OAUTH_CU = (
    "https://www.mycourseville.com/api/oauth/authorize"
    "?response_type=code&client_id=mycourseville.com"
    "&redirect_uri=https://www.mycourseville.com&login_page=itchula"
)
MCV_OAUTH_PLATFORM = (
    "https://www.mycourseville.com/api/oauth/authorize"
    "?response_type=code&client_id=mycourseville.com"
    "&redirect_uri=https://www.mycourseville.com"
)
REQUEST_TIMEOUT = 30
TZ_BANGKOK = timezone(timedelta(hours=7))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class WrongCredentialsError(Exception):
    """Raised when login fails due to incorrect username or password."""


class LoginError(Exception):
    """Raised when login fails (network / unexpected page)."""


# ---------------------------------------------------------------------------
# Attendance Logger (HTTP requests)
# ---------------------------------------------------------------------------
class AttendanceLogger:
    """Check in to MyCourseVille using plain HTTP requests (no browser)."""

    def _new_session(self) -> http_requests.Session:
        """Create a fresh requests session with a realistic User-Agent."""
        s = http_requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        })
        return s

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    def login(
        self,
        session: http_requests.Session,
        username: str,
        password: str,
        login_method: str = "cu_net",
        max_attempts: int = 3,
    ):
        """Log into MyCourseVille via Chula SSO or platform account.

        On success the *session* object holds the authenticated cookies.
        """
        for attempt in range(1, max_attempts + 1):
            log.info("Login attempt %d/%d for %s (method=%s) …", attempt, max_attempts, username, login_method)

            # 1. Visit homepage first to establish session cookies / referer
            session.get(MCV_HOME_URL, timeout=REQUEST_TIMEOUT)

            # 2. Use hardcoded OAuth URL (avoids needing to parse JS-rendered page)
            oauth_url = MCV_OAUTH_PLATFORM if login_method == "platform" else MCV_OAUTH_CU
            log.debug("OAuth authorize URL: %s", oauth_url)

            # 2. Follow OAuth URL → lands on the SSO login form
            resp = session.get(oauth_url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            # Find the login form and its action URL
            form = soup.find("form", id="cv-login-cvecologin-form")
            if not form:
                form = soup.find("form", attrs={"action": True})
            if not form:
                log.error("Could not find login form (attempt %d), URL: %s", attempt, resp.url)
                continue

            action_url = form.get("action", "")
            if action_url and not action_url.startswith("http"):
                action_url = urljoin(resp.url, action_url)

            # 3. Collect all form fields (hidden, default values, etc.)
            form_data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                if inp_type in ("submit", "button", "image"):
                    continue
                if inp_type in ("radio", "checkbox"):
                    if inp.has_attr("checked"):
                        form_data[name] = inp.get("value", "on")
                    continue
                form_data[name] = inp.get("value", "")

            # Override with our credentials
            username_input = form.find("input", id="username")
            password_input = form.find("input", id="password")
            username_field = username_input.get("name", "username") if username_input else "username"
            password_field = password_input.get("name", "password") if password_input else "password"
            form_data[username_field] = username
            form_data[password_field] = password

            # For platform login, select email vs username radio
            if login_method == "platform":
                email_radio = form.find("input", id="loginfield_email")
                name_radio = form.find("input", id="loginfield_name")
                radio_field = "loginfield"
                if email_radio and email_radio.get("name"):
                    radio_field = email_radio["name"]
                elif name_radio and name_radio.get("name"):
                    radio_field = name_radio["name"]

                if "@" in username:
                    form_data[radio_field] = email_radio.get("value", "email") if email_radio else "email"
                else:
                    form_data[radio_field] = name_radio.get("value", "name") if name_radio else "name"

            # 4. POST the login form
            log.debug("POSTing credentials to %s", action_url)
            resp = session.post(
                action_url,
                data=form_data,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

            # 5. Check for credential errors on the POST response itself
            page_text = resp.text
            page_lower = page_text.lower()
            error_markers = [
                "incorrect", "invalid",
                "ไม่ถูกต้อง", "ผิดพลาด",
                "ไม่สามารถเข้าสู่ระบบได้เนื่องจาก",
                "ชื่อบัญชี หรือ รหัสผ่านผิดพลาด",
                "username or password is incorrect",
            ]
            if any(m in (page_lower if m.isascii() else page_text) for m in error_markers):
                log.error("Wrong credentials for %s!", username)
                raise WrongCredentialsError("Login failed: wrong credentials")

            # 6. Handle redirect manually
            if resp.is_redirect or resp.is_permanent_redirect:
                redirect_url = resp.headers.get("Location", "")
                log.debug("Login POST redirected to: %s", redirect_url)
                if redirect_url:
                    redirect_url = urljoin(resp.url, redirect_url)
                    if (redirect_url.rstrip("/").endswith("/login")
                            or "/api/login" in redirect_url
                            or "/chulalogin" in redirect_url):
                        resp = session.get(redirect_url, timeout=REQUEST_TIMEOUT)
                        page_after = resp.text
                        page_after_lower = page_after.lower()

                        if any(m in (page_after_lower if m.isascii() else page_after) for m in error_markers):
                            log.error("Wrong credentials for %s (detected after redirect)", username)
                            raise WrongCredentialsError("Login failed: wrong credentials")
                        log.error("Wrong credentials for %s (redirected back to login: %s, status=%d)", username, redirect_url, resp.status_code)
                        raise WrongCredentialsError("Login failed: wrong credentials")
                    resp = session.get(redirect_url, timeout=REQUEST_TIMEOUT)
                log.info("Login OK for %s (redirected → %s)", username, resp.url)
                return

            if resp.status_code >= 400:
                log.warning("Login POST returned %d (attempt %d)", resp.status_code, attempt)
                continue

            page_text = resp.text
            if "courseville-userMenuTrigger" in page_text or "mycourseville.com" in resp.url:
                log.info("Login OK for %s → %s", username, resp.url)
                return

            if "/chulalogin" in resp.url or "/api/login" in resp.url or resp.url.rstrip("/").endswith("/login"):
                log.warning("Still on login page after attempt %d, URL: %s", attempt, resp.url)
                continue

            log.info("Login redirected for %s → %s (accepting)", username, resp.url)
            return

        raise LoginError(f"Login failed after {max_attempts} attempts for {username}")

    # ------------------------------------------------------------------
    # Check-in
    # ------------------------------------------------------------------
    def check_in(
        self,
        attendance_url: str,
        username: str,
        password: str,
        display_name: str = "",
        login_method: str = "cu_net",
    ) -> str:
        """Log in and visit the attendance URL for a single user."""
        name = display_name or username
        log.info("Check-in START: %s (%s) method=%s", name, username, login_method)
        session = self._new_session()
        try:
            self.login(session, username, password, login_method=login_method)

            resp = session.get(attendance_url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            page_source = resp.text.lower()

            if "invalid or expired" in page_source or "หมดอายุ" in page_source:
                log.warning("%s — link expired or invalid", name)
                return f"🕐 **[{name}]** — link expired or invalid"

            if "not a member of this course" in page_source:
                log.warning("%s — not a course member", name)
                return f"🚫 **[{name}]** — not a member of this course"

            success_keywords = [
                "success", "สำเร็จ", "checked", "เช็คชื่อแล้ว",
                "completed", "บันทึกแล้ว",
                "has been recorded", "your attendance for",
            ]
            matched_kw = [kw for kw in success_keywords if kw in page_source]
            if matched_kw:
                log.info("%s — SUCCESS (matched: %s)", name, matched_kw)
                timestamp = datetime.now(TZ_BANGKOK).strftime("%I:%M %p")
                return f"✅ **[{name}]** — checked in at `{timestamp}` 🎉"

            if "courseville-usermenutrigger" in page_source:
                log.info("%s — on course page (likely OK)", name)
                timestamp = datetime.now(TZ_BANGKOK).strftime("%I:%M %p")
                return f"✅ **[{name}]** — checked in at `{timestamp}` (unconfirmed)"

            timestamp = datetime.now(TZ_BANGKOK).strftime("%I:%M %p")
            log.warning("%s — uncertain result", name)
            return f"⚠️ **[{name}]** — uncertain at `{timestamp}`, please verify manually"

        except WrongCredentialsError:
            log.error("%s — wrong credentials", name)
            return f"🔑 **[{name}]** — wrong username or password, use `/register` to update"
        except LoginError:
            log.error("%s — login failed", name)
            return f"🔒 **[{name}]** — login failed, try again later"
        except http_requests.RequestException as exc:
            log.error("%s — request error: %s", name, exc)
            return f"🌐 **[{name}]** — network error, MCV might be down"
        except Exception as exc:
            log.exception("%s — unexpected error", name)
            return f"💥 **[{name}]** — something went wrong"
        finally:
            session.close()
            log.info("Check-in END: %s", name)

    def check_in_all(self, attendance_url: str) -> list[tuple[str, str]]:
        """Check in every registered user for a given attendance URL.

        Returns a list of (discord_user_id, result_message) tuples.
        """
        if not registered_users:
            return [("", "No users registered. Use `/register` to add users.")]

        results = []
        for uid, info in registered_users.items():
            display_name = info.get("display_name", info["username"])
            encrypted_password = info["password"]

            try:
                password = decrypt_password(encrypted_password)
            except ValueError as e:
                log.error("Failed to decrypt password for %s: %s", info["username"], e)
                results.append((uid, f"❌ **{display_name}** — failed to decrypt password (may need to re-register)"))
                continue

            login_method = info.get("login_method", "cu_net")
            result = self.check_in(attendance_url, info["username"], password, display_name, login_method=login_method)
            results.append((uid, result))
        return results

    def cleanup(self):
        """No persistent resources to clean up with requests."""
        log.info("Cleanup called (no-op for HTTP client)")
