from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import discord
from discord import app_commands

from config import (
    log,
    DISCORD_TOKEN,
    monitored_channels,
    registered_users,
)
from attendance import (
    AttendanceLogger,
    MCV_URL_PARTIAL,
    extract_attendance_url,
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
        name="👀 for attendance links | 🔗 github.com/ILFforever/Chula_Attendance",
    ))
    log.info("Bot is online as %s (ID: %s)", bot.user, bot.user.id)
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
        log.info(
            "Attendance URL detected from %s: %s",
            message.author,
            attendance_url,
        )
        await message.add_reaction("⏳")

        status_msg = await message.channel.send(
            f"⏳ Attendance link detected! Checking in {len(registered_users)} user(s) …"
        )
        results = await run_check_in_async(attendance_url)
        await status_msg.edit(content="\n".join(r for _, r in results))
        await dm_results(results)

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
