import os
import re
import json
import time
import shutil
import tempfile
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from dotenv import load_dotenv
load_dotenv()

import discord
from discord import app_commands
from selenium import webdriver

# Password encryption module
from password_crypto import (
    encrypt_password,
    decrypt_password,
    is_encrypted,
    migrate_plaintext_to_encrypted,
    get_encryption_key,
)
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
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
logging.getLogger("selenium").setLevel(logging.WARNING)
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
# Attendance Logger (Selenium)
# ---------------------------------------------------------------------------
MCV_LOGIN_URL = "https://www.mycourseville.com/api/chulalogin"


class AttendanceLogger:
    def __init__(self):
        self.driver = None
        self._tmp_profile_dir = None

    def setup_driver(self):
        """Initialize headless Chrome with options suitable for containers."""
        if self.driver is not None:
            return

        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--window-size=1920,1080")

        # Use a fresh temp profile to avoid conflicts with running Chrome instances
        self._tmp_profile_dir = tempfile.mkdtemp(prefix="attendance_chrome_")
        chrome_options.add_argument(f"--user-data-dir={self._tmp_profile_dir}")

        chrome_bin = os.environ.get("CHROME_BIN")
        if chrome_bin:
            chrome_options.binary_location = chrome_bin

        chromedriver_path = os.environ.get("CHROMEDRIVER_PATH")
        if chromedriver_path:
            service = Service(executable_path=chromedriver_path)
        else:
            service = Service()

        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.driver.implicitly_wait(5)
        log.info("Chrome driver initialised")

    def _clear_session(self):
        """Delete all cookies so the next login starts fresh."""
        self.driver.delete_all_cookies()

    def _is_on_login_page(self) -> bool:
        """Check if the browser is on ANY MCV login/chooser page."""
        current = self.driver.current_url
        if "chulalogin" in current or "/api/login" in current:
            return True
        # CU login form
        try:
            self.driver.find_element(By.ID, "cv-login-cvecologin-form")
            return True
        except NoSuchElementException:
            pass
        # Login method chooser ("Log in with CU account", etc.)
        try:
            self.driver.find_element(By.XPATH, "//a[contains(@href,'chulalogin')]")
            return True
        except NoSuchElementException:
            pass
        # Also check for "Please login" text on the page
        try:
            self.driver.find_element(By.XPATH, "//*[contains(text(),'Please login')]")
            return True
        except NoSuchElementException:
            return False

    def _is_logged_in(self) -> bool:
        """Verify we're actually logged in by checking for user menu."""
        try:
            self.driver.find_element(By.ID, "courseville-userMenuTrigger")
            return True
        except NoSuchElementException:
            return False

    def login(self, username: str, password: str, max_attempts: int = 3):
        """Log into MyCourseVille via Chula SSO with verification."""
        for attempt in range(1, max_attempts + 1):
            log.info("Login attempt %d/%d for %s …", attempt, max_attempts, username)

            # Follow the same flow as clicking "Log in with CU account" button
            # First visit main page to establish proper Referer header
            self.driver.get("https://www.mycourseville.com/")
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "courseville-login-w-platform-cu-button"))
            )

            # Find the "Log in with CU account" button by its ID and get its OAuth URL
            login_button = self.driver.find_element(By.ID, "courseville-login-w-platform-cu-button")
            oauth_url = login_button.get_attribute("href")
            log.debug("OAuth authorize URL: %s", oauth_url)
            # Navigate to the OAuth URL (same as clicking the button)
            self.driver.get(oauth_url)

            # Wait for username field - this confirms page is loaded
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "username"))
            )

            wait = WebDriverWait(self.driver, 20)

            # Fill credentials
            try:
                username_field = wait.until(
                    EC.presence_of_element_located((By.ID, "username"))
                )
            except TimeoutException:
                log.error("TIMEOUT waiting for username field! URL: %s", self.driver.current_url)
                continue

            username_field.clear()
            username_field.send_keys(username)

            password_field = self.driver.find_element(By.ID, "password")
            password_field.clear()
            password_field.send_keys(password)

            # Click login
            login_button = self.driver.find_element(By.ID, "cv-login-cvecologinbutton")
            login_button.click()

            # Wait a moment for the page to update (error may appear immediately)
            time.sleep(1)

            # Check for credential errors FIRST (before waiting for redirect)
            # Thai error: "ไม่สามารถเข้าสู่ระบบได้เนื่องจาก ชื่อบัญชี หรือ รหัสผ่านผิดพลาด"
            page_src = self.driver.page_source
            page_src_lower = page_src.lower()
            if ("incorrect" in page_src_lower or "invalid" in page_src_lower or
                "ไม่ถูกต้อง" in page_src or "ผิดพลาด" in page_src or
                "ไม่สามารถเข้าสู่ระบบได้เนื่องจาก" in page_src or
                "ชื่อบัญชี หรือ รหัสผ่านผิดพลาด" in page_src or
                "username or password is incorrect" in page_src_lower):
                log.error("Wrong credentials for %s!", username)
                raise WrongCredentialsError("Login failed: wrong credentials")

            # Wait for redirect away from login page
            try:
                wait.until(lambda d: "chulalogin" not in d.current_url and "/api/login" not in d.current_url)
            except TimeoutException:
                log.warning("Login redirect timeout (attempt %d), URL: %s", attempt, self.driver.current_url)
                continue

            # Wait for either login success (user menu) or course page
            try:
                WebDriverWait(self.driver, 10).until(
                    lambda d: self._is_logged_in() or "courseville" in d.current_url
                )
            except TimeoutException:
                log.debug("No immediate login confirmation, proceeding...")

            # VERIFY: are we actually logged in?
            if self._is_logged_in():
                log.info("Login VERIFIED for %s → %s", username, self.driver.current_url)
                return

            # Still on login page somehow?
            if self._is_on_login_page():
                log.warning("Still on login page after attempt %d", attempt)
                continue

            # Redirected somewhere but can't confirm login — accept it
            log.info("Login redirected for %s → %s (no user menu yet)", username, self.driver.current_url)
            return

        # All attempts failed
        raise TimeoutException(f"Login failed after {max_attempts} attempts for {username}")

    def check_in(self, attendance_url: str, username: str, password: str, display_name: str = "") -> str:
        """Navigate to the attendance URL for a single user and check in."""
        name = display_name or username
        log.info("Check-in START: %s (%s)", name, username)
        try:
            self.setup_driver()
            self._clear_session()

            # Log in first, then visit attendance URL
            self.login(username, password)
    
            self.driver.get(attendance_url)

            # Wait for page to load - check for various possible states
            try:
                WebDriverWait(self.driver, 10).until(
                    lambda d: (
                        "invalid" in d.page_source.lower() or
                        d.find_elements(By.ID, "courseville-userMenuTrigger") or
                        "attendance" in d.page_source.lower()
                    )
                )
            except TimeoutException:
                log.debug("Page load timeout, checking current state...")

            page_source = self.driver.page_source.lower()

            # Check for expired / invalid code
            if "invalid or expired" in page_source or "หมดอายุ" in page_source:
                log.warning("%s — link expired or invalid", name)
                return f"⚠️ **{name}** — link expired or invalid"

            # Check for success indicators
            success_keywords = [
                "success", "สำเร็จ", "checked", "เช็คชื่อแล้ว",
                "completed", "บันทึกแล้ว", "attendance_qr_selfcheck",
                "has been recorded", "your attendance for",
            ]
            matched_kw = [kw for kw in success_keywords if kw in page_source]
            if matched_kw:
                log.info("%s — SUCCESS (matched: %s)", name, matched_kw)
                timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                return f"✅ **{name}** — checked in at {timestamp}"

            # If we landed on a course page, the check-in likely went through
            try:
                self.driver.find_element(By.ID, "courseville-userMenuTrigger")
                log.info("%s — on course page (likely OK)", name)
                timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                return f"✅ **{name}** — page loaded at {timestamp}"
            except NoSuchElementException:
                pass

            timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            log.warning("%s — uncertain result", name)
            return f"⚠️ **{name}** — page loaded at {timestamp} (verify manually)"

        except WrongCredentialsError:
            log.error("%s — wrong credentials", name)
            return f"❌ **{name}** — wrong username or password"
        except TimeoutException:
            log.error("%s — timeout", name)
            return f"❌ **{name}** — timed out waiting for page"
        except NoSuchElementException as exc:
            log.error("%s — element not found: %s", name, exc.msg)
            return f"❌ **{name}** — element not found: {exc.msg}"
        except WebDriverException as exc:
            log.error("%s — browser error: %s", name, exc.msg)
            return f"❌ **{name}** — browser error"
        except Exception as exc:
            log.exception("%s — unexpected error", name)
            return f"❌ **{name}** — unexpected error: {exc}"
        finally:
            log.info("Check-in END: %s", name)

    def check_in_all(self, attendance_url: str) -> list[str]:
        """Check in every registered user for a given attendance URL."""
        if not registered_users:
            return ["No users registered. Use `/register` to add users."]

        results = []
        for uid, info in registered_users.items():
            display_name = info.get("display_name", info["username"])
            encrypted_password = info["password"]

            # Decrypt password before use
            try:
                password = decrypt_password(encrypted_password)
            except ValueError as e:
                log.error("Failed to decrypt password for %s: %s", info["username"], e)
                results.append(f"❌ **{display_name}** — failed to decrypt password (may need to re-register)")
                continue

            result = self.check_in(attendance_url, info["username"], password, display_name)
            results.append(result)
        return results

    def cleanup(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
            log.info("Browser closed")
        if self._tmp_profile_dir and os.path.isdir(self._tmp_profile_dir):
            try:
                shutil.rmtree(self._tmp_profile_dir, ignore_errors=True)
                log.debug("Temp profile cleaned up: %s", self._tmp_profile_dir)
            except Exception:
                pass
            self._tmp_profile_dir = None


# ---------------------------------------------------------------------------
# Discord Bot
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True

bot = discord.Client(intents=intents)
tree = app_commands.CommandTree(bot)
attendance = AttendanceLogger()
bot_start_time = datetime.now(timezone.utc)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="selenium_")


# URL extraction is now the only trigger - keywords removed


# ---------------------------------------------------------------------------
# Slash Commands — User Management
# ---------------------------------------------------------------------------
@tree.command(name="register", description="Register your MyCourseVille credentials")
@app_commands.describe(
    username="Your MyCourseVille / university username",
    password="Your password",
)
async def cmd_register(interaction: discord.Interaction, username: str, password: str):
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
    }
    _persist_users()
    log.info("User registered: %s (%s)", interaction.user.display_name, username)
    await interaction.response.send_message(
        f"✅ Registered **{interaction.user.display_name}** with username `{username}`.\n"
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
    await interaction.followup.send("\n".join(results))


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
        f"• Browser active: {'Yes' if attendance.driver else 'No'}\n"
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
        name="for attendance links | github.com/ILFforever/Chula_Attendance",
    ))
    log.info("Bot is online as %s (ID: %s)", bot.user, bot.user.id)
    log.info("Slash commands synced")
    log.info("Monitoring channels: %s", monitored_channels or "(none)")
    log.info("Registered users: %d", len(registered_users))


async def run_check_in_async(attendance_url: str) -> list[str]:
    """Run blocking Selenium operations in a thread pool to avoid blocking the event loop."""
    loop = bot.loop
    return await loop.run_in_executor(executor, attendance.check_in_all, attendance_url)


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
        await status_msg.edit(content="\n".join(results))

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
