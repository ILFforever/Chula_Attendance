import enum
import os
import re
import json
import logging
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
load_dotenv()

import discord
from discord import app_commands
import requests as http_requests
from bs4 import BeautifulSoup

# Password encryption module
from password_crypto import (
    encrypt_password,
    decrypt_password,
    is_encrypted,
    migrate_plaintext_to_encrypted,
    get_encryption_key,
)


class WrongCredentialsError(Exception):
    """Raised when login fails due to incorrect username or password."""
    pass

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Silence noisy libraries — only show our bot logs + warnings from others
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("discord").setLevel(logging.WARNING)
log = logging.getLogger("attendance-bot")
log.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = os.environ.get("DATA_DIR", ".")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# Full valid attendance URL: .../attendance_qr_selfcheck/<id>/<code>
MCV_URL_PATTERN = re.compile(
    r"https?://(?:www\.)?mycourseville\.com/\?q=courseville/course/\d+/attendance_qr_selfcheck/\d+/[A-Za-z0-9]+"
)
# Partial / incomplete attendance URL (missing id or code)
MCV_URL_PARTIAL = re.compile(
    r"https?://(?:www\.)?mycourseville\.com/\?q=courseville/course/\d+/attendance[^\s]*"
)


def load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


config = load_json(CONFIG_FILE)

DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "")

# Monitored channels — persisted in config.json
monitored_channels: set[int] = set()
_raw = config.get("monitored_channels", [])
if _raw:
    monitored_channels = {int(c) for c in _raw}

# Registered users — persisted in users.json
# Format: { "discord_user_id": { "username": "...", "password": "...", "display_name": "..." } }
registered_users: dict[str, dict] = load_json(USERS_FILE)

# ---------------------------------------------------------------------------
# Password Migration (plaintext -> encrypted)
# ---------------------------------------------------------------------------
def _migrate_passwords():
    """Migrate any plaintext passwords to encrypted format on startup."""
    try:
        migrated, count = migrate_plaintext_to_encrypted(registered_users)
        if count > 0:
            log.warning("Migrated %d user(s) from plaintext to encrypted passwords", count)
            # Update the global dict and persist
            registered_users.clear()
            registered_users.update(migrated)
            save_json(USERS_FILE, registered_users)
            log.info("Password migration saved to %s", USERS_FILE)
    except ValueError as e:
        # ENCRYPTION_KEY not set - this is OK if running without encryption
        log.info("Password encryption not available: %s", e)

_migrate_passwords()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def _persist_channels():
    config["monitored_channels"] = list(monitored_channels)
    save_json(CONFIG_FILE, config)


def _persist_users():
    save_json(USERS_FILE, registered_users)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------
def extract_attendance_url(text: str) -> str | None:
    """Extract a MyCourseVille attendance URL from message text."""
    match = MCV_URL_PATTERN.search(text)
    if match:
        return match.group(0)
    return None


# ---------------------------------------------------------------------------
# Attendance Logger (HTTP requests)
# ---------------------------------------------------------------------------
MCV_HOME_URL = "https://www.mycourseville.com/"
# Hardcoded OAuth URLs (extracted from MCV homepage buttons)
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


class LoginError(Exception):
    """Raised when login fails (network / unexpected page)."""


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
                # Try any form that contains the username field
                form = soup.find("form", attrs={"action": True})
            if not form:
                log.error("Could not find login form (attempt %d), URL: %s", attempt, resp.url)
                continue

            action_url = form.get("action", "")
            if action_url and not action_url.startswith("http"):
                # Relative URL — resolve against current page
                from urllib.parse import urljoin
                action_url = urljoin(resp.url, action_url)

            # 3. Collect all form fields (hidden, default values, etc.)
            form_data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                # Skip submit buttons
                if inp_type in ("submit", "button", "image"):
                    continue
                # For radio/checkbox, only include if checked by default
                if inp_type in ("radio", "checkbox"):
                    if inp.has_attr("checked"):
                        form_data[name] = inp.get("value", "on")
                    continue
                form_data[name] = inp.get("value", "")

            # Override with our credentials — find the actual name attributes
            # (the input id="username" may have name="name" on the platform form)
            username_input = form.find("input", id="username")
            password_input = form.find("input", id="password")
            username_field = username_input.get("name", "username") if username_input else "username"
            password_field = password_input.get("name", "password") if password_input else "password"
            form_data[username_field] = username
            form_data[password_field] = password

            # For platform login, select email vs username radio
            if login_method == "platform":
                # Find the radio button to determine the correct field name
                email_radio = form.find("input", id="loginfield_email")
                name_radio = form.find("input", id="loginfield_name")
                radio_field = "loginfield"  # fallback
                if email_radio and email_radio.get("name"):
                    radio_field = email_radio["name"]
                elif name_radio and name_radio.get("name"):
                    radio_field = name_radio["name"]

                if "@" in username:
                    form_data[radio_field] = email_radio.get("value", "email") if email_radio else "email"
                else:
                    form_data[radio_field] = name_radio.get("value", "name") if name_radio else "name"

            # 4. POST the login form (don't auto-follow redirects —
            #    the server may redirect POST → GET to a path that 404s)
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

            # 6. Handle redirect manually — cookies are already set by the 302
            if resp.is_redirect or resp.is_permanent_redirect:
                redirect_url = resp.headers.get("Location", "")
                log.debug("Login POST redirected to: %s", redirect_url)
                if redirect_url:
                    from urllib.parse import urljoin
                    redirect_url = urljoin(resp.url, redirect_url)
                    # Check if redirected back to a login page (= failed)
                    if (redirect_url.rstrip("/").endswith("/login")
                            or "/api/login" in redirect_url
                            or "/chulalogin" in redirect_url):
                        # Follow the redirect to check for error messages
                        resp = session.get(redirect_url, timeout=REQUEST_TIMEOUT)
                        page_after = resp.text
                        page_after_lower = page_after.lower()

                        # Check for credential error on the redirected page
                        if any(m in (page_after_lower if m.isascii() else page_after) for m in error_markers):
                            log.error("Wrong credentials for %s (detected after redirect)", username)
                            raise WrongCredentialsError("Login failed: wrong credentials")
                        # SSO redirects back to login page on wrong password —
                        # this is never a transient error, always bad credentials
                        log.error("Wrong credentials for %s (redirected back to login: %s, status=%d)", username, redirect_url, resp.status_code)
                        raise WrongCredentialsError("Login failed: wrong credentials")
                    # Follow the redirect
                    resp = session.get(redirect_url, timeout=REQUEST_TIMEOUT)
                log.info("Login OK for %s (redirected → %s)", username, resp.url)
                return

            # No redirect — check the response page
            if resp.status_code >= 400:
                log.warning("Login POST returned %d (attempt %d)", resp.status_code, attempt)
                continue

            page_text = resp.text
            if "courseville-userMenuTrigger" in page_text or "mycourseville.com" in resp.url:
                log.info("Login OK for %s → %s", username, resp.url)
                return

            # Still on a login page?
            if "/chulalogin" in resp.url or "/api/login" in resp.url or resp.url.rstrip("/").endswith("/login"):
                log.warning("Still on login page after attempt %d, URL: %s", attempt, resp.url)
                continue

            # Redirected somewhere — probably OK
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

            # Visit the attendance URL (cookies are carried automatically)
            resp = session.get(attendance_url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            page_source = resp.text.lower()

            # Check for expired / invalid code
            if "invalid or expired" in page_source or "หมดอายุ" in page_source:
                log.warning("%s — link expired or invalid", name)
                return f"🕐 **[{name}]** — link expired or invalid"

            # Check for not a course member
            if "not a member of this course" in page_source:
                log.warning("%s — not a course member", name)
                return f"🚫 **[{name}]** — not a member of this course"

            # Check for success indicators
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

            # If user menu is present, page loaded while logged in
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

            # Decrypt password before use
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


# ---------------------------------------------------------------------------
# Discord Bot
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True

bot = discord.Client(intents=intents)
tree = app_commands.CommandTree(bot)
attendance = AttendanceLogger()
bot_start_time = datetime.now(timezone.utc)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="checkin_")


# URL extraction is now the only trigger - keywords removed


# ---------------------------------------------------------------------------
# Slash Commands — User Management
# ---------------------------------------------------------------------------
class LoginMethod(enum.Enum):
    CU_Net = "cu_net"
    MyCourseVille = "platform"


@tree.command(name="register", description="Register your MyCourseVille credentials")
@app_commands.describe(
    login_method="How you log in: CU Net account or MyCourseVille platform account",
    username="Your MyCourseVille / university username",
    password="Your password",
)
async def cmd_register(
    interaction: discord.Interaction,
    login_method: LoginMethod,
    username: str,
    password: str,
):
    if login_method == LoginMethod.CU_Net:
        if not re.fullmatch(r"\d{10}", username):
            await interaction.response.send_message(
                "❌ Username must be exactly 10 digits (e.g. `6799999999`).",
                ephemeral=True,
            )
            return

    # Encrypt password before storing
    try:
        encrypted_password = encrypt_password(password)
    except ValueError as e:
        log.error("Password encryption failed: %s", e)
        await interaction.response.send_message(
            "❌ Failed to securely store your password. Please contact the admin.",
            ephemeral=True,
        )
        return

    uid = str(interaction.user.id)
    registered_users[uid] = {
        "username": username,
        "password": encrypted_password,
        "display_name": interaction.user.display_name,
        "encrypted": True,
        "login_method": login_method.value,
    }
    _persist_users()
    method_label = "CU Net" if login_method == LoginMethod.CU_Net else "MyCourseVille platform"
    log.info("User registered: %s (%s) via %s", interaction.user.display_name, username, method_label)
    await interaction.response.send_message(
        f"✅ Registered **{interaction.user.display_name}** with username `{username}` "
        f"(login via **{method_label}**).\n"
        "Your credentials are stored and this message is only visible to you.",
        ephemeral=True,
    )


@tree.command(name="unregister", description="Remove your saved credentials")
async def cmd_unregister(interaction: discord.Interaction):
    uid = str(interaction.user.id)
    if uid not in registered_users:
        await interaction.response.send_message(
            "You are not registered.", ephemeral=True
        )
        return

    del registered_users[uid]
    _persist_users()
    log.info("User unregistered: %s", interaction.user.display_name)
    await interaction.response.send_message(
        "✅ Your credentials have been removed.", ephemeral=True
    )


@tree.command(name="users", description="List all registered users")
async def cmd_users(interaction: discord.Interaction):
    if not registered_users:
        await interaction.response.send_message(
            "No users registered yet.", ephemeral=True
        )
        return

    lines = []
    for uid, info in registered_users.items():
        lines.append(f"• **{info['display_name']}** (`{info['username']}`)")

    await interaction.response.send_message(
        f"**Registered users ({len(lines)}):**\n" + "\n".join(lines),
        ephemeral=True,
    )


# ---------------------------------------------------------------------------
# Slash Commands — Help
# ---------------------------------------------------------------------------
@tree.command(name="help", description="Show all bot commands and how to use them")
async def cmd_help(interaction: discord.Interaction):
    await interaction.response.send_message(
        "📖 **Attendance Bot — Help**\n"
        "\n"
        "**User Management**\n"
        "`/register <username> <password>` — Register your MyCourseVille credentials (only you see the response)\n"
        "`/unregister` — Remove your saved credentials\n"
        "`/users` — List all registered users\n"
        "\n"
        "**Channel Management**\n"
        "`/monitor [channel]` — Start monitoring a channel for attendance links\n"
        "`/unmonitor [channel]` — Stop monitoring a channel\n"
        "`/channels` — List all monitored channels\n"
        "\n"
        "**Attendance**\n"
        "`/test <url>` — Manually test check-in with a MyCourseVille attendance URL\n"
        "`/status` — Show bot uptime, registered users, and monitored channels\n"
        "\n"
        "**How it works**\n"
        "When a MyCourseVille attendance link is posted in a monitored channel, "
        "the bot automatically opens it for every registered user and checks them in.",
        ephemeral=True,
    )


# ---------------------------------------------------------------------------
# Slash Commands — Channel Management
# ---------------------------------------------------------------------------
@tree.command(name="monitor", description="Start monitoring this channel for attendance links")
@app_commands.describe(channel="Channel to monitor (defaults to the current channel)")
async def cmd_monitor(interaction: discord.Interaction, channel: discord.TextChannel | None = None):
    target = channel or interaction.channel
    if target.id in monitored_channels:
        await interaction.response.send_message(
            f"Already monitoring <#{target.id}>.", ephemeral=True
        )
        return

    monitored_channels.add(target.id)
    _persist_channels()
    log.info("Now monitoring channel %s (%s)", target.name, target.id)
    await interaction.response.send_message(
        f"✅ Now monitoring <#{target.id}> for attendance links."
    )


@tree.command(name="unmonitor", description="Stop monitoring this channel")
@app_commands.describe(channel="Channel to stop monitoring (defaults to the current channel)")
async def cmd_unmonitor(interaction: discord.Interaction, channel: discord.TextChannel | None = None):
    target = channel or interaction.channel
    if target.id not in monitored_channels:
        await interaction.response.send_message(
            f"<#{target.id}> is not being monitored.", ephemeral=True
        )
        return

    monitored_channels.discard(target.id)
    _persist_channels()
    log.info("Stopped monitoring channel %s (%s)", target.name, target.id)
    await interaction.response.send_message(
        f"🛑 Stopped monitoring <#{target.id}>."
    )


@tree.command(name="channels", description="List all channels currently being monitored")
async def cmd_channels(interaction: discord.Interaction):
    if not monitored_channels:
        await interaction.response.send_message("No channels are being monitored.", ephemeral=True)
        return

    lines = [f"• <#{cid}>" for cid in sorted(monitored_channels)]
    await interaction.response.send_message(
        "**Monitored channels:**\n" + "\n".join(lines), ephemeral=True
    )


# ---------------------------------------------------------------------------
# Slash Commands — Testing & Status
# ---------------------------------------------------------------------------
@tree.command(name="checkin", description="Manually trigger check-in with an attendance URL")
@app_commands.describe(url="MyCourseVille attendance URL")
async def cmd_checkin(interaction: discord.Interaction, url: str):
    if not MCV_URL_PATTERN.search(url):
        if MCV_URL_PARTIAL.search(url):
            await interaction.response.send_message(
                "❌ Incomplete attendance link — missing check-in code.\n"
                "URL should look like: `.../attendance_qr_selfcheck/<id>/<code>`",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "❌ Invalid URL. Must be a MyCourseVille attendance link.", ephemeral=True
            )
        return

    log.info("Manual check-in triggered by %s with URL: %s", interaction.user, url)
    await interaction.response.send_message(
        f"⏳ Checking in {len(registered_users)} user(s) …"
    )
    results = await run_check_in_async(url)
    await interaction.followup.send("\n".join(r for _, r in results))
    await dm_results(results)


@tree.command(name="status", description="Show bot uptime and status")
async def cmd_status(interaction: discord.Interaction):
    uptime = datetime.now(timezone.utc) - bot_start_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)

    channel_list = ", ".join(f"<#{cid}>" for cid in sorted(monitored_channels)) or "None"
    user_count = len(registered_users)
    await interaction.response.send_message(
        f"🤖 **Bot Status**\n"
        f"• Uptime: {hours}h {minutes}m {seconds}s\n"
        f"• Engine: HTTP requests (lightweight)\n"
        f"• Registered users: {user_count}\n"
        f"• Monitoring: {channel_list}",
        ephemeral=True,
    )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    await tree.sync()  # global sync (takes up to 1h)
    for guild in bot.guilds:
        tree.copy_global_to(guild=guild)
        await tree.sync(guild=guild)  # guild sync (instant)
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="👀 for attendance links | 🔗 github.com/ILFforever/Chula_Attendance",
    ))
    log.info("Bot is online as %s (ID: %s)", bot.user, bot.user.id)
    log.info("Slash commands synced")
    log.info("Monitoring channels: %s", monitored_channels or "(none)")
    log.info("Registered users: %d", len(registered_users))


async def run_check_in_async(attendance_url: str) -> list[tuple[str, str]]:
    """Run blocking HTTP check-in operations in a thread pool to avoid blocking the event loop."""
    loop = bot.loop
    return await loop.run_in_executor(executor, attendance.check_in_all, attendance_url)


async def dm_results(results: list[tuple[str, str]]):
    """Send each user a DM with their own check-in result."""
    for uid, result in results:
        if not uid:
            continue
        try:
            user = await bot.fetch_user(int(uid))
            await user.send(f"📋 **Attendance result:**\n{result}")
        except Exception as e:
            log.warning("Could not DM user %s: %s", uid, e)


@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    if message.channel.id not in monitored_channels:
        return

    # Try to extract a MyCourseVille attendance URL from the message
    attendance_url = extract_attendance_url(message.content)

    if attendance_url:
        log.info(
            "Attendance URL detected from %s: %s",
            message.author,
            attendance_url,
        )
        # React to acknowledge detection
        await message.add_reaction("⏳")

        status_msg = await message.channel.send(
            f"⏳ Attendance link detected! Checking in {len(registered_users)} user(s) …"
        )
        results = await run_check_in_async(attendance_url)
        await status_msg.edit(content="\n".join(r for _, r in results))
        await dm_results(results)

        # Swap the hourglass for a checkmark on the original message
        await message.remove_reaction("⏳", bot.user)
        await message.add_reaction("✅")

    elif MCV_URL_PARTIAL.search(message.content):
        # Incomplete attendance link (missing code/id)
        log.warning("Incomplete attendance URL from %s: %s", message.author, message.content)
        await message.add_reaction("❌")
        await message.channel.send(
            "❌ Incomplete attendance link — missing check-in code. "
            "The URL should look like: `.../attendance_qr_selfcheck/<id>/<code>`"
        )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        log.error("DISCORD_TOKEN environment variable is not set!")
        raise SystemExit(1)
    if not monitored_channels:
        log.warning("No channels configured – use /monitor in Discord to add one")
    if not registered_users:
        log.warning("No users registered – use /register in Discord to add credentials")

    try:
        bot.run(DISCORD_TOKEN, log_handler=None)
    finally:
        attendance.cleanup()
