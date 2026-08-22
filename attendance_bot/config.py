import os
import json
import logging
from datetime import datetime, timezone, timedelta

from dotenv import load_dotenv
load_dotenv()

from attendance_bot.security.crypto import migrate_plaintext_to_encrypted

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("discord").setLevel(logging.WARNING)
log = logging.getLogger("attendance-bot")
log.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BOT_VERSION = "3.0.0"

DATA_DIR = os.environ.get("DATA_DIR", ".")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
LEADERBOARD_FILE = os.path.join(DATA_DIR, "leaderboard.json")
HOMEWORK_FILE = os.path.join(DATA_DIR, "homework.json")
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "")

# QR scanner web server — shared secret gating /api/scan, and the port Fly
# routes public HTTPS traffic to.
SCAN_SECRET = os.environ.get("SCAN_SECRET", "")
WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))
SCAN_BASE_URL = os.environ.get("SCAN_BASE_URL", "").rstrip("/")

# How many users' homework check can run at once. Unlike ClassDeeDee check-in,
# a daily scan has no nonce-window deadline forcing concurrency, so this stays
# low by default to be gentle on ChulaSSO/MCV and keep RAM flat.
HOMEWORK_CONCURRENCY = max(1, int(os.environ.get("HOMEWORK_CONCURRENCY", "4")))

# How long a posted link is remembered for duplicate detection. Attendance
# codes are valid for at most a day, so anything older than this can never
# be a "real" duplicate — safe to forget it and keep the file tiny forever.
SEEN_LINK_TTL = timedelta(hours=48)


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

# Monitored channels — persisted in config.json
monitored_channels: set[int] = set()
_raw = config.get("monitored_channels", [])
if _raw:
    monitored_channels = {int(c) for c in _raw}

# Registered users — persisted in users.json
# Format: { "discord_user_id": { "username": "...", "password": "...", "display_name": "..." } }
registered_users: dict[str, dict] = load_json(USERS_FILE)

# Leaderboard — persisted in leaderboard.json
# "counts": { "discord_user_id": { "display_name": "...", "count": N } }
# "seen_links": { "attendance_url": "iso_timestamp_first_seen" } — dedup cache
_leaderboard_data = load_json(LEADERBOARD_FILE)
leaderboard_counts: dict[str, dict] = _leaderboard_data.get("counts", {})
seen_links: dict[str, str] = _leaderboard_data.get("seen_links", {})

# Homework check — persisted in homework.json
# "suppressed": { "uid:platform:course_code:item_key": "iso_timestamp_marked" }
#   — assignments a user clicked "Handed in" on; skipped until pruned.
# "last_run": { "discord_user_id": "YYYY-MM-DD" } (Bangkok-local date) — guards
#   the hourly scheduler tick from re-sending the same user's DM twice in one day.
_homework_data = load_json(HOMEWORK_FILE)
homework_suppressed: dict[str, str] = _homework_data.get("suppressed", {})
homework_last_run: dict[str, str] = _homework_data.get("last_run", {})


# ---------------------------------------------------------------------------
# Password Migration (plaintext -> encrypted)
# ---------------------------------------------------------------------------
def _migrate_passwords():
    """Migrate any plaintext passwords to encrypted format on startup."""
    try:
        migrated, count = migrate_plaintext_to_encrypted(registered_users)
        if count > 0:
            log.warning("Migrated %d user(s) from plaintext to encrypted passwords", count)
            registered_users.clear()
            registered_users.update(migrated)
            save_json(USERS_FILE, registered_users)
            log.info("Password migration saved to %s", USERS_FILE)
    except ValueError as e:
        log.info("Password encryption not available: %s", e)

_migrate_passwords()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def persist_channels():
    config["monitored_channels"] = list(monitored_channels)
    save_json(CONFIG_FILE, config)


def persist_users():
    save_json(USERS_FILE, registered_users)


def persist_leaderboard():
    save_json(LEADERBOARD_FILE, {"counts": leaderboard_counts, "seen_links": seen_links})


def persist_homework():
    save_json(HOMEWORK_FILE, {"suppressed": homework_suppressed, "last_run": homework_last_run})


# ---------------------------------------------------------------------------
# Leaderboard / duplicate-link helpers
# ---------------------------------------------------------------------------
def prune_seen_links():
    """Drop dedup entries older than SEEN_LINK_TTL so the file never grows unbounded."""
    cutoff = datetime.now(timezone.utc) - SEEN_LINK_TTL
    stale = [
        url for url, ts in seen_links.items()
        if _parse_iso(ts) is None or _parse_iso(ts) < cutoff
    ]
    for url in stale:
        del seen_links[url]
    if stale:
        persist_leaderboard()


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def is_duplicate_link(url: str) -> bool:
    """True if this exact attendance URL has already been processed recently."""
    prune_seen_links()
    return url in seen_links


def mark_link_seen(url: str):
    seen_links[url] = datetime.now(timezone.utc).isoformat()
    persist_leaderboard()


# ---------------------------------------------------------------------------
# Homework check helpers
# ---------------------------------------------------------------------------
# Safety-valve TTL only — a suppressed assignment normally just stops being
# "outstanding" (submitted/expired) long before this, so it never reappears
# to check against. This just keeps the file from growing forever if that
# never happens for some reason.
HOMEWORK_SUPPRESS_TTL = timedelta(days=45)


def homework_key(uid: str, platform: str, course_code: str, item_key: str) -> str:
    return f"{uid}:{platform}:{course_code}:{item_key}"


def _suppressed_marked_at(entry) -> str:
    # Entries are {"marked_at": iso, "title": ..., "course_name": ..., ...};
    # a bare iso string is also accepted for backwards compat with entries
    # written before metadata was added.
    return entry["marked_at"] if isinstance(entry, dict) else entry


def prune_homework_suppressed():
    cutoff = datetime.now(timezone.utc) - HOMEWORK_SUPPRESS_TTL
    stale = [
        key for key, entry in homework_suppressed.items()
        if _parse_iso(_suppressed_marked_at(entry)) is None or _parse_iso(_suppressed_marked_at(entry)) < cutoff
    ]
    for key in stale:
        del homework_suppressed[key]
    if stale:
        persist_homework()


def is_homework_suppressed(uid: str, platform: str, course_code: str, item_key: str) -> bool:
    prune_homework_suppressed()
    return homework_key(uid, platform, course_code, item_key) in homework_suppressed


def mark_homework_suppressed(uid: str, platform: str, course_code: str, item_key: str, *, title: str = "", course_name: str = ""):
    homework_suppressed[homework_key(uid, platform, course_code, item_key)] = {
        "marked_at": datetime.now(timezone.utc).isoformat(),
        "title": title,
        "course_name": course_name,
        "platform": platform,
    }
    persist_homework()


def list_suppressed_for_user(uid: str) -> list[tuple[str, dict]]:
    """(storage_key, entry) pairs for everything this user has marked
    finished — legacy plain-string entries (pre-metadata) are skipped since
    there's nothing displayable in them.
    """
    prune_homework_suppressed()
    prefix = f"{uid}:"
    return [
        (key, entry) for key, entry in homework_suppressed.items()
        if key.startswith(prefix) and isinstance(entry, dict)
    ]


def unmark_homework_suppressed(storage_key: str) -> bool:
    if storage_key in homework_suppressed:
        del homework_suppressed[storage_key]
        persist_homework()
        return True
    return False


def homework_already_ran_today(uid: str, today_str: str) -> bool:
    return homework_last_run.get(uid) == today_str


def mark_homework_ran_today(uid: str, today_str: str):
    homework_last_run[uid] = today_str
    persist_homework()


def record_leaderboard_post(uid: str, display_name: str):
    entry = leaderboard_counts.setdefault(uid, {"display_name": display_name, "count": 0})
    entry["display_name"] = display_name
    entry["count"] += 1
    persist_leaderboard()
