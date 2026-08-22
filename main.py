"""Entry point — runs the Discord bot.

    python main.py
"""
from attendance_bot.client import bot, attendance, DISCORD_TOKEN, monitored_channels, registered_users, log

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
