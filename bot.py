from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import discord
from discord import app_commands

from config import (
    log,
    BOT_VERSION,
    DISCORD_TOKEN,
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
import commands

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

# Register all slash commands and get helpers back
run_check_in_async, dm_results = commands.setup(bot, tree, attendance, executor, bot_start_time)


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
        is_dupe = is_duplicate_link(attendance_url)
        if is_dupe:
            log.info("Duplicate attendance link from %s, re-checking in without leaderboard credit: %s", message.author, attendance_url)

        course_info = await bot.loop.run_in_executor(executor, fetch_public_course_info, attendance_url)
        course_id = course_info["code"] if course_info else None
        log.info(
            "Attendance URL detected from %s: %s (course %s)",
            message.author,
            attendance_url,
            course_info["title"] if course_info else "unknown",
        )
        await message.add_reaction("⏳")

        enrolled_count = sum(
            1 for info in registered_users.values()
            if not info.get("subjects") or course_id in info.get("subjects", [])
        )
        course_label = f"**{course_info['title']}**" if course_info else "an attendance link (couldn't identify the course)"
        status_msg = await message.channel.send(
            f"⏳ Detected {course_label}! Checking in {enrolled_count} user(s) …"
        )
        results = await run_check_in_async(attendance_url, course_id)
        results_header = f"📋 **{course_info['title']}**\n" if course_info else "📋 **Attendance Check-in**\n"
        if is_dupe:
            results_header += "_(this link was already posted before — no leaderboard credit for this post)_\n"
        await status_msg.edit(content=results_header + "\n".join(r for _, r in results))
        await dm_results(results, course_info["title"] if course_info else None)

        # A link only "counts" for the leaderboard the first time it's posted,
        # and only if it actually produced a real successful check-in —
        # filters out both re-posts and stale/expired/fake links.
        mark_link_seen(attendance_url)
        if not is_dupe and any("✅" in r for _, r in results):
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
