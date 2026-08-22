import asyncio
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import discord
from discord import app_commands

from config import (
    log,
    BOT_VERSION,
    DISCORD_TOKEN,
    SCAN_SECRET,
    monitored_channels,
    registered_users,
    is_duplicate_link,
    mark_link_seen,
    record_leaderboard_post,
)
from attendance import (
    AttendanceLogger,
    MCV_URL_PARTIAL,
    extract_attendance_url,
    fetch_public_course_info,
)
from webserver import start_web_server
from classdeedee_attendance import check_in_all as cdd_check_in_all
import commands

# ---------------------------------------------------------------------------
# Discord Bot
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True


class AttendanceBot(discord.Client):
    async def setup_hook(self):
        # The scanner server shares the bot's event loop, so a scan can reach
        # straight into the same check-in helpers the message handler uses.
        if SCAN_SECRET:
            await start_web_server(handle_web_scan, on_scan_cdd=handle_web_scan_cdd)
        else:
            log.info("SCAN_SECRET not set — QR scanner web server disabled")


bot = AttendanceBot(intents=intents)
tree = app_commands.CommandTree(bot)
attendance = AttendanceLogger()
bot_start_time = datetime.now(timezone.utc)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="checkin_")

# asyncio only holds a weak reference to a running task, so a fire-and-forget
# task can be garbage-collected mid-flight. Parking them here keeps them alive
# until they finish.
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task

# Register all slash commands and get helpers back
run_check_in_async, dm_results = commands.setup(bot, tree, attendance, executor, bot_start_time)


# ---------------------------------------------------------------------------
# Shared check-in flow (used by both the message handler and the QR scanner)
# ---------------------------------------------------------------------------
async def process_attendance_link(attendance_url: str, channel, note: str = "") -> dict:
    """Run a check-in for one attendance URL and report into `channel`.

    Returns a summary suitable for handing back to the scanner page.
    """
    started = time.perf_counter()
    is_dupe = is_duplicate_link(attendance_url)
    if is_dupe:
        log.info("Duplicate attendance link, re-checking in without leaderboard credit: %s", attendance_url)

    course_info = await bot.loop.run_in_executor(executor, fetch_public_course_info, attendance_url)
    course_id = course_info["code"] if course_info else None

    enrolled_count = sum(
        1 for info in registered_users.values()
        if not info.get("subjects") or course_id in info.get("subjects", [])
    )
    course_label = f"**{course_info['title']}**" if course_info else "an attendance link (couldn't identify the course)"
    # channel may be None (QR scan with no bound results channel) → DM-only.
    status_msg = None
    if channel is not None:
        status_msg = await channel.send(
            f"⏳ {note}Detected {course_label}! Checking in {enrolled_count} user(s) …"
        )

    check_in_started = time.perf_counter()
    results = await run_check_in_async(attendance_url, course_id)
    log.info("Checked in %d user(s) in %.1fs", len(results), time.perf_counter() - check_in_started)

    results_header = f"📋 **{course_info['title']}**\n" if course_info else "📋 **Attendance Check-in**\n"
    if is_dupe:
        results_header += "_(this link was already posted before — no leaderboard credit for this post)_\n"
    if status_msg is not None:
        await status_msg.edit(content=results_header + "\n".join(r for _, r in results))

    # Fire-and-forget: the results are already in the channel, and nothing below
    # depends on the DMs landing. Awaiting them here is what made the QR scanner
    # hang for ~20s — its HTTP response was blocked behind the whole DM run.
    _spawn(dm_results(results, course_info["title"] if course_info else None))

    mark_link_seen(attendance_url)

    succeeded = sum(1 for _, r in results if "✅" in r)
    log.info("Attendance link fully handled in %.1fs (%d/%d ok)", time.perf_counter() - started, succeeded, len(results))
    return {
        "course": course_info["title"] if course_info else None,
        "attempted": len(results),
        "succeeded": succeeded,
        "duplicate": is_dupe,
        "message": (
            f"✅ {course_info['title'] if course_info else 'Attendance'}\n"
            f"{succeeded} of {len(results)} user(s) checked in. Results posted in Discord."
        ),
    }


async def handle_web_scan(attendance_url: str, channel_id: int | None = None) -> dict:
    """Entry point for a QR code scanned on the web page.

    `channel_id` is the channel the scanner link was bound to (from /scanner);
    results post there, or DM-only if it's missing/unreachable.
    """
    channel = bot.get_channel(channel_id) if channel_id else None

    log.info("Attendance URL received from QR scanner: %s (channel=%s)", attendance_url, channel_id)
    # No leaderboard credit — a scan carries no Discord identity to award it to.
    return await process_attendance_link(attendance_url, channel, note="📷 Scanned via QR scanner — ")


async def handle_web_scan_cdd(sid: str, nonce: str, channel_id: int | None = None) -> dict:
    """Entry point for a scanned ClassDeeDee attendance QR ({sid, nonce}).

    `channel_id` is the channel the scanner link was bound to (from /scanner);
    results post there, or DM-only if it's missing/unreachable.
    """
    channel = bot.get_channel(channel_id) if channel_id else None

    log.info("ClassDeeDee attendance QR received from scanner: sid=%s (channel=%s)", sid, channel_id)
    started = time.perf_counter()

    # Kick the logins/check-in off IMMEDIATELY — the nonce is time-sensitive, so
    # nothing (Discord post included) should sit in front of it. run_in_executor
    # submits to the pool right away; check_in_all fans logins out across its own
    # bounded pool.
    checkin_task = bot.loop.run_in_executor(executor, cdd_check_in_all, sid, nonce)

    status_msg = None
    if channel is not None:
        try:
            status_msg = await channel.send(
                "📷 Scanned a **ClassDeeDee** attendance QR — checking everyone in …"
            )
        except Exception as e:  # a failed status post must never abort the check-in
            log.warning("Could not post ClassDeeDee scan status: %s", e)

    results = await checkin_task
    log.info("ClassDeeDee checked in %d user(s) in %.1fs", len(results), time.perf_counter() - started)

    if channel is not None:
        report = "📋 **ClassDeeDee Check-in**\n" + "\n".join(r for _, r in results)
        try:
            if status_msg is not None:
                await status_msg.edit(content=report)
            else:
                await channel.send(report)
        except Exception as e:
            log.warning("Could not post ClassDeeDee results: %s", e)
    _spawn(dm_results(results, "ClassDeeDee attendance"))

    succeeded = sum(1 for _, r in results if "✅" in r)
    where = "Results posted in Discord." if channel is not None else "Results sent to each user via DM."
    return {
        "message": f"✅ ClassDeeDee\n{succeeded} of {len(results)} user(s) checked in. {where}",
    }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    for guild in bot.guilds:
        tree.copy_global_to(guild=guild)
        await tree.sync(guild=guild)
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name=f"👀 for attendance links | v{BOT_VERSION} | 🔗 github.com/ILFforever/Chula_Attendance",
    ))
    log.info("Bot is online as %s (ID: %s) — v%s", bot.user, bot.user.id, BOT_VERSION)
    log.info("Slash commands synced")
    log.info("Monitoring channels: %s", monitored_channels or "(none)")
    log.info("Registered users: %d", len(registered_users))


@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    if message.channel.id not in monitored_channels:
        return

    attendance_url = extract_attendance_url(message.content)

    if attendance_url:
        log.info("Attendance URL detected from %s: %s", message.author, attendance_url)
        await message.add_reaction("⏳")

        summary = await process_attendance_link(attendance_url, message.channel)

        # A link only "counts" for the leaderboard the first time it's posted,
        # and only if it actually produced a real successful check-in —
        # filters out both re-posts and stale/expired/fake links.
        if not summary["duplicate"] and summary["succeeded"]:
            record_leaderboard_post(str(message.author.id), message.author.display_name)

        await message.remove_reaction("⏳", bot.user)
        await message.add_reaction("✅")

    elif MCV_URL_PARTIAL.search(message.content):
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
