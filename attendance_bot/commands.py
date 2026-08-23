import asyncio
import enum
import re
import time

import discord
from discord import app_commands
import requests as http_requests

from attendance_bot.config import (
    log,
    BOT_VERSION,
    registered_users,
    monitored_channels,
    persist_channels,
    persist_users,
    leaderboard_counts,
    SCAN_SECRET,
    SCAN_BASE_URL,
)
from attendance_bot.homework.dm import (
    run_homework_check_for_user,
    DEFAULT_HOMEWORK_HOUR,
    DEFAULT_DEADLINE_REMINDER_HOURS,
    MIN_DEADLINE_REMINDER_HOURS,
    MAX_DEADLINE_REMINDER_HOURS,
)
from attendance_bot.settings_panel import build_settings_view
from attendance_bot.release_notes import RELEASE_MESSAGES
from attendance_bot.security.crypto import encrypt_password, decrypt_password
from attendance_bot.mcv.attendance import (
    MCV_URL_PATTERN,
    WrongCredentialsError,
    LoginError,
    fetch_public_course_info,
)
from attendance_bot.classdeedee.login import (
    login_classdeedee,
    fetch_profile,
    full_name,
    WrongCredentialsError as CddWrongCredentialsError,
    LoginError as CddLoginError,
)
from attendance_bot.classdeedee.attendance import bench_logins, resolve_cdd_credentials
from attendance_bot.mcv.cugetreg import fetch_course_name


def _parse_course_id(raw: str) -> str | None:
    """Accept either a raw public course code (e.g. 2110405) or a MyCourseVille
    URL, in which case the public course code is fetched from its metadata."""
    raw = raw.strip()
    if raw.isdigit():
        return raw
    if MCV_URL_PATTERN.search(raw):
        info = fetch_public_course_info(raw)
        return info["code"] if info else None
    return None


# How many result DMs to have in flight at once. Discord rate-limits DM channel
# creation per-bucket, so this is about overlapping latency, not brute force.
DM_CONCURRENCY = 8


def setup(bot: discord.Client, tree: app_commands.CommandTree, attendance, executor, bot_start_time, homework_executor):
    """Register all slash commands on the given tree."""

    # -------------------------------------------------------------------
    # Helper: run check-in in thread pool
    # -------------------------------------------------------------------
    async def run_check_in_async(attendance_url: str, course_id: str | None = None) -> list[tuple[str, str]]:
        return await bot.loop.run_in_executor(executor, attendance.check_in_all, attendance_url, course_id)

    async def dm_results(results: list[tuple[str, str]], course_title: str | None = None):
        """DM each user their own result.

        Sent concurrently — one DM per user is 2-3 REST calls, and walking a
        class-sized roster serially took ~1s per user (20s for 18 people), which
        is why the QR scanner used to sit there spinning. The semaphore keeps us
        from opening the floodgates on Discord's DM-channel rate limit.
        """
        header = f"📋 **Attendance result — {course_title}**\n" if course_title else "📋 **Attendance result:**\n"
        recipients = [(uid, result) for uid, result in results if uid]
        if not recipients:
            return

        sem = asyncio.Semaphore(DM_CONCURRENCY)

        async def send_one(uid: str, result: str):
            async with sem:
                try:
                    # get_user is a cache hit; fetch_user costs a REST round trip.
                    user = bot.get_user(int(uid)) or await bot.fetch_user(int(uid))
                    await user.send(f"{header}{result}")
                except Exception as e:
                    log.warning("Could not DM user %s: %s", uid, e)

        started = time.perf_counter()
        await asyncio.gather(*(send_one(uid, result) for uid, result in recipients))
        log.info("DMed %d user(s) in %.1fs", len(recipients), time.perf_counter() - started)

    # -------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------
    class LoginMethod(enum.Enum):
        CU_Net = "cu_net"
        MyCourseVille = "platform"

    @tree.command(name="register", description="Register your MyCourseVille credentials")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
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
        is_new_user = uid not in registered_users
        registered_users[uid] = {
            "username": username,
            "password": encrypted_password,
            "display_name": interaction.user.display_name,
            "encrypted": True,
            "login_method": login_method.value,
        }
        persist_users()
        method_label = "CU Net" if login_method == LoginMethod.CU_Net else "MyCourseVille platform"
        log.info("User registered: %s (%s) via %s", interaction.user.display_name, username, method_label)
        await interaction.response.send_message(
            f"✅ Registered **{interaction.user.display_name}** with username `{username}` "
            f"(login via **{method_label}**).\n"
            "Your credentials are stored and this message is only visible to you.\n\n"
            "You can use `/logincheck` to verify your credentials with the MCV website",
            ephemeral=True,
        )

        # Best-effort — a closed-DMs user shouldn't have registration itself fail.
        # Only a genuinely new registration gets this, not a credential update.
        if is_new_user:
            try:
                for msg in RELEASE_MESSAGES:
                    await interaction.user.send(msg)
            except discord.HTTPException as exc:
                log.info("Could not DM release notes to %s: %s", interaction.user.display_name, exc)

    @tree.command(name="unregister", description="Remove your saved credentials")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_unregister(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "You are not registered.", ephemeral=True
            )
            return

        del registered_users[uid]
        persist_users()
        log.info("User unregistered: %s", interaction.user.display_name)
        await interaction.response.send_message(
            "✅ Your credentials have been removed.", ephemeral=True
        )

    @tree.command(name="users", description="List all registered users")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
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

    # -------------------------------------------------------------------
    # Subject / Course Enrollment
    # -------------------------------------------------------------------
    @tree.command(name="enroll", description="Enroll in a course so you're only checked in for its attendance links")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(course_id="Your course code (e.g. 2110405, from CU Get Reg / your registration), or paste an MCV link")
    async def cmd_enroll(interaction: discord.Interaction, course_id: str):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)
        parsed = await bot.loop.run_in_executor(executor, _parse_course_id, course_id)
        if not parsed:
            await interaction.followup.send(
                "❌ Couldn't find a course code. Enter the course code (e.g. `2110405`) or paste an MCV course/attendance link.",
                ephemeral=True,
            )
            return

        subjects = registered_users[uid].setdefault("subjects", [])
        if parsed in subjects:
            await interaction.followup.send(
                f"ℹ️ You're already enrolled in course `{parsed}`.", ephemeral=True
            )
            return

        course_info = await bot.loop.run_in_executor(executor, fetch_course_name, parsed)

        subjects.append(parsed)
        persist_users()
        log.info("User %s enrolled in course %s", interaction.user.display_name, parsed)

        if course_info:
            header = f"✅ Enrolled in `{parsed}` — **{course_info['name_short']}**"
            details = f"> {course_info['name_th']}\n> {course_info['name_en']}\n\n"
        else:
            header = f"✅ Enrolled in `{parsed}`"
            details = (
                "⚠️ _Couldn't verify this code on CU Get Reg — that's normal for a course from a past "
                "term, but if you mistyped the code, check-in matching happens silently against real "
                "attendance links, so you won't be notified of a typo until you're simply not checked in. "
                "Double check `/subjects` shows the code you meant._\n\n"
            )

        await interaction.followup.send(
            f"{header}\n{details}"
            "You'll now only be checked in for attendance links from this course (and any others you enroll in). "
            "Use `/subjects` to view your list, `/unenroll` to remove one.",
            ephemeral=True,
        )

    @tree.command(name="unenroll", description="Remove a course from your enrollment list")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(course_id="Course code to remove, exactly as you entered it with /enroll")
    async def cmd_unenroll(interaction: discord.Interaction, course_id: str):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered.", ephemeral=True
            )
            return

        parsed = course_id.strip()
        subjects = registered_users[uid].get("subjects", [])
        if parsed not in subjects:
            await interaction.response.send_message(
                f"ℹ️ You're not enrolled in course `{parsed}`. Use `/subjects` to see your current list.",
                ephemeral=True,
            )
            return

        subjects.remove(parsed)
        persist_users()
        log.info("User %s unenrolled from course %s", interaction.user.display_name, parsed)

        message = f"🛑 Unenrolled from course `{parsed}`."
        if not subjects:
            message += "\n\nYou have no courses enrolled anymore, so you'll be checked in for **all** attendance links again."
        await interaction.response.send_message(message, ephemeral=True)

    @tree.command(name="unenrollall", description="Remove every course from your enrollment list")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_unenrollall(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered.", ephemeral=True
            )
            return

        subjects = registered_users[uid].get("subjects", [])
        if not subjects:
            await interaction.response.send_message(
                "ℹ️ You have no courses enrolled already.", ephemeral=True
            )
            return

        count = len(subjects)
        registered_users[uid]["subjects"] = []
        persist_users()
        log.info("User %s unenrolled from all %d course(s)", interaction.user.display_name, count)
        await interaction.response.send_message(
            f"🛑 Unenrolled from all {count} course(s). You'll be checked in for **all** attendance links again.",
            ephemeral=True,
        )

    @tree.command(name="subjects", description="List the courses you're enrolled in for check-in filtering")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_subjects(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered.", ephemeral=True
            )
            return

        subjects = registered_users[uid].get("subjects", [])
        if not subjects:
            await interaction.response.send_message(
                "📚 You have no courses enrolled — you'll be checked in for **all** attendance links.\n"
                "Use `/enroll <course_code>` to restrict check-ins to specific courses.",
                ephemeral=True,
            )
            return

        lines = "\n".join(f"• `{c}`" for c in subjects)
        await interaction.response.send_message(
            f"📚 **Your enrolled courses ({len(subjects)}):**\n{lines}\n\n"
            "Use `/enroll` to add another, `/unenroll` to remove one, or `/unenrollall` to clear the whole list.",
            ephemeral=True,
        )

    # -------------------------------------------------------------------
    # Homework Check
    # -------------------------------------------------------------------
    class HomeworkToggle(enum.Enum):
        On = "on"
        Off = "off"

    @tree.command(
        name="homework",
        description="Enable or disable your daily homework reminder DM (MyCourseVille + ClassDeeDee)",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(action="Turn the daily homework check on or off")
    async def cmd_homework(interaction: discord.Interaction, action: HomeworkToggle):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        if action == HomeworkToggle.On:
            registered_users[uid]["homework_check"] = True
            persist_users()
            hour = registered_users[uid].get("homework_check_hour", DEFAULT_HOMEWORK_HOUR)
            log.info("User %s enabled homework check", interaction.user.display_name)
            await interaction.response.send_message(
                f"✅ Daily homework check enabled — you'll get a DM around **{hour:02d}:00** (Bangkok time) "
                "on any day you have outstanding work across MyCourseVille and ClassDeeDee.\n"
                "Use `/homeworktime` to change when it arrives, or `/homeworkcheck` to run it right now.\n"
                "Want a heads-up right before something's due too? Try `/deadlinereminder on` (off by default).\n"
                "_Note: MyCourseVille only reports items due within the next 7 days — anything further out "
                "won't show up until it's inside that window._",
                ephemeral=True,
            )
        else:
            registered_users[uid]["homework_check"] = False
            persist_users()
            log.info("User %s disabled homework check", interaction.user.display_name)
            await interaction.response.send_message(
                "✅ Daily homework check disabled.", ephemeral=True
            )

    @tree.command(
        name="homeworkcheck",
        description="Run your homework check right now and DM the results (doesn't require /homework to be on)",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_homeworkcheck(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            "⏳ Running your homework check now — check your DMs in a moment.", ephemeral=True
        )
        await run_homework_check_for_user(bot, homework_executor, uid)

    @tree.command(
        name="homeworktime",
        description="Set what hour your daily homework reminder DM arrives",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(hour="Hour of day, 0-23, Bangkok time (e.g. 8 for 8am, 20 for 8pm)")
    async def cmd_homeworktime(interaction: discord.Interaction, hour: app_commands.Range[int, 0, 23]):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        registered_users[uid]["homework_check_hour"] = hour
        persist_users()
        log.info("User %s set homework check hour to %d", interaction.user.display_name, hour)

        enabled = registered_users[uid].get("homework_check", False)
        note = "" if enabled else "\n⚠️ Your daily homework check is currently **off** — use `/homework on` to enable it."
        await interaction.response.send_message(
            f"✅ Homework reminder time set to **{hour:02d}:00** (Bangkok time).{note}",
            ephemeral=True,
        )

    @tree.command(
        name="deadlinereminder",
        description="Enable or disable a heads-up DM shortly before an unfinished item is due (off by default)",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(action="Turn the deadline reminder on or off")
    async def cmd_deadlinereminder(interaction: discord.Interaction, action: HomeworkToggle):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        if action == HomeworkToggle.On:
            registered_users[uid]["deadline_reminder_enabled"] = True
            persist_users()
            hours = registered_users[uid].get("deadline_reminder_hours", DEFAULT_DEADLINE_REMINDER_HOURS)
            log.info("User %s enabled deadline reminder", interaction.user.display_name)
            await interaction.response.send_message(
                f"✅ Deadline reminder enabled — you'll get a DM about **{hours}h** before anything you "
                "haven't marked finished is due (MyCourseVille + ClassDeeDee).\n"
                "Use `/deadlinereminderhours` to change the window.\n"
                "_Note: MyCourseVille only reports items due within the next 7 days — anything further out "
                "won't show up until it's inside that window._",
                ephemeral=True,
            )
        else:
            registered_users[uid]["deadline_reminder_enabled"] = False
            persist_users()
            log.info("User %s disabled deadline reminder", interaction.user.display_name)
            await interaction.response.send_message(
                "✅ Deadline reminder disabled.", ephemeral=True
            )

    @tree.command(
        name="deadlinereminderhours",
        description="Set how many hours before something's due the deadline reminder DM arrives",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(
        hours=f"Hours before due time, {MIN_DEADLINE_REMINDER_HOURS}-{MAX_DEADLINE_REMINDER_HOURS} (default {DEFAULT_DEADLINE_REMINDER_HOURS})"
    )
    async def cmd_deadlinereminderhours(
        interaction: discord.Interaction,
        hours: app_commands.Range[int, MIN_DEADLINE_REMINDER_HOURS, MAX_DEADLINE_REMINDER_HOURS],
    ):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        registered_users[uid]["deadline_reminder_hours"] = hours
        persist_users()
        log.info("User %s set deadline reminder window to %dh", interaction.user.display_name, hours)

        enabled = registered_users[uid].get("deadline_reminder_enabled", False)
        note = "" if enabled else "\n⚠️ Your deadline reminder is currently **off** — use `/deadlinereminder on` to enable it."
        await interaction.response.send_message(
            f"✅ Deadline reminder window set to **{hours}h** before due.{note}",
            ephemeral=True,
        )

    @tree.command(
        name="settings",
        description="Open your settings panel — notifications and course enrollment, all in one place",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_settings(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return
        await interaction.response.send_message(view=build_settings_view(interaction.user), ephemeral=True)

    # -------------------------------------------------------------------
    # Help
    # -------------------------------------------------------------------
    @tree.command(name="help", description="Show all bot commands and how to use them")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_help(interaction: discord.Interaction):
        # Split across several messages — the full command list grew past
        # Discord's 2000-char single-message limit (a plain send_message()
        # 400s with "content: Must be 2000 or fewer" once it does), same
        # multi-part response+followup pattern /release already uses.
        parts = [
            (
                f"📖 **Attendance Bot — Help** (v{BOT_VERSION})\n"
                "\n"
                "**User Management**\n"
                "`/register <username> <password>` — Register your MyCourseVille credentials (only you see the response)\n"
                "`/deedeeregister <username> <password>` — **MyCourseVille users only:** add a ClassDeeDee (ChulaSSO) login\n"
                "`/deedeeunregister` — Remove just that ClassDeeDee login, keep your MyCourseVille account\n"
                "`/unregister` — Remove everything — MyCourseVille, ClassDeeDee, and all your settings\n"
                "`/users` — List all registered users\n"
                "`/settings` — One panel for notifications, attendance, ClassDeeDee, and account management\n"
                "\n"
                "**Course Enrollment**\n"
                "`/enroll <course_code>` — Only get checked in for this course's links (e.g. `2110405`)\n"
                "`/unenroll <course_code>` — Remove a course from your enrollment list\n"
                "`/unenrollall` — Remove every course from your enrollment list\n"
                "`/subjects` — List the courses you're enrolled in\n"
                "\n"
                "**Channel Management**\n"
                "`/monitor [channel]` — Start monitoring a channel for attendance links\n"
                "`/unmonitor [channel]` — Stop monitoring a channel\n"
                "`/channels` — List all monitored channels\n"
            ),
            (
                "**Attendance**\n"
                "`/checkin <url>` — Manually trigger check-in with a MyCourseVille attendance URL\n"
                "`/scanner` — DM yourself a phone-camera QR scanner that checks everyone in\n"
                "`/autocheckin off` — Stop being auto checked-in (MyCourseVille + ClassDeeDee); Homework Check is unaffected\n"
                "`/logincheck` — Test if your saved credentials can log in\n"
                "`/deedeecheck` — Test if your saved credentials can log into ClassDeeDee (ChulaSSO)\n"
                "`/deedeebench` — (temp) Benchmark logging in all users to ClassDeeDee (timing & RAM)\n"
                "`/status` — Show bot uptime, registered users, and monitored channels\n"
                "`/leaderboard` — See who's posted the most attendance links\n"
                "\n"
                "**Homework Check**\n"
                "`/homework on` — Get a daily DM listing outstanding work (MyCourseVille + ClassDeeDee)\n"
                "`/homework off` — Stop the daily DM\n"
                "`/homeworktime <hour>` — Set what hour it arrives, 0-23 Bangkok time (default 8am)\n"
                "`/homeworkcheck` — Run it once right now, without needing `/homework on` first\n"
                "`/deadlinereminder on` — Separate, off-by-default DM shortly before an unfinished item is due\n"
                "`/deadlinereminder off` — Stop that DM\n"
                "`/deadlinereminderhours <hours>` — How many hours before due, "
                f"{MIN_DEADLINE_REMINDER_HOURS}-{MAX_DEADLINE_REMINDER_HOURS} (default {DEFAULT_DEADLINE_REMINDER_HOURS})\n"
                "_MyCourseVille only reports items due within 7 days — anything further out won't appear until then._\n"
            ),
            (
                "**How it works**\n"
                "When a MyCourseVille attendance link is posted in a monitored channel, "
                "the bot automatically opens it and checks in every registered user — or, if you've "
                "used `/enroll`, only those enrolled in that course.\n"
                "\n"
                "**ClassDeeDee (ChulaSSO)**\n"
                "Scanning a ClassDeeDee attendance QR (via `/scanner`) checks everyone in there too. "
                "If you registered with **CU Net** you already work on ClassDeeDee — nothing to do. "
                "If you registered a **MyCourseVille** account, add your ChulaSSO login once with "
                "`/deedeeregister`, then `/deedeecheck` to confirm it.\n"
                "`/classdeedee off` — Skip ClassDeeDee entirely (check-in + homework together), on by default. "
                "`/classdeedee on` to re-enable — or use `/settings` to control check-in and homework separately.\n"
                "\n"
                "Use `/release` to see what's new in the latest version."
            ),
        ]
        await interaction.response.send_message(parts[0], ephemeral=True)
        for part in parts[1:]:
            await interaction.followup.send(part, ephemeral=True)

    @tree.command(name="release", description="Show what's new in the latest version")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_release(interaction: discord.Interaction):
        await interaction.response.send_message(RELEASE_MESSAGES[0], ephemeral=True)
        for msg in RELEASE_MESSAGES[1:]:
            await interaction.followup.send(msg, ephemeral=True)

    # -------------------------------------------------------------------
    # Channel Management
    # -------------------------------------------------------------------
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
        persist_channels()
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
        persist_channels()
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

    # -------------------------------------------------------------------
    # Attendance & Status
    # -------------------------------------------------------------------
    @tree.command(name="checkin", description="Manually trigger check-in with an attendance URL")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(url="MyCourseVille attendance URL")
    async def cmd_checkin(interaction: discord.Interaction, url: str):
        from attendance_bot.mcv.attendance import MCV_URL_PARTIAL

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

        await interaction.response.defer()
        course_info = await bot.loop.run_in_executor(executor, fetch_public_course_info, url)
        course_id = course_info["code"] if course_info else None
        course_label = f"`{course_id}`" if course_id else "(unknown course)"
        log.info("Manual check-in triggered by %s with URL: %s (course %s)", interaction.user, url, course_id)
        await interaction.followup.send(
            f"⏳ Checking in registered user(s) for course {course_label} …"
        )
        results = await run_check_in_async(url, course_id)
        results_header = f"📋 **{course_info['title']}**\n" if course_info else "📋 **Attendance Check-in**\n"
        await interaction.followup.send(results_header + "\n".join(r for _, r in results))
        await dm_results(results, course_info["title"] if course_info else None)

    class AutoCheckinToggle(enum.Enum):
        On = "on"
        Off = "off"

    @tree.command(
        name="autocheckin",
        description="Enable or disable automatic attendance check-in for your account (default: on)",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(action="Turn automatic check-in on or off")
    async def cmd_autocheckin(interaction: discord.Interaction, action: AutoCheckinToggle):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        enabled = action == AutoCheckinToggle.On
        registered_users[uid]["checkin_enabled"] = enabled
        persist_users()
        log.info("User %s turned automatic check-in %s", interaction.user.display_name, "on" if enabled else "off")

        if enabled:
            await interaction.response.send_message(
                "✅ Automatic check-in re-enabled — you'll be checked in again when an attendance link/QR is posted.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "✅ Automatic check-in disabled — the bot will no longer log in and check you into attendance "
                "links or QRs. Homework Check is unaffected (it only reads your outstanding work, never submits "
                "anything). Use `/autocheckin on` to turn it back on.",
                ephemeral=True,
            )

    @tree.command(name="logincheck", description="Test if your saved credentials can log in")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_logincheck(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered. Use `/register` first.", ephemeral=True
            )
            return

        info = registered_users[uid]
        display_name = info.get("display_name", info["username"])

        try:
            password = decrypt_password(info["password"])
        except ValueError:
            await interaction.response.send_message(
                "❌ Failed to decrypt your password. Please re-register with `/register`.",
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            f"⏳ Testing login for **{display_name}** …", ephemeral=True
        )

        login_method = info.get("login_method", "cu_net")

        def _try_login():
            session = attendance._new_session()
            try:
                attendance.login(session, info["username"], password, login_method=login_method)
                return True, None
            except WrongCredentialsError:
                return False, "wrong_credentials"
            except LoginError:
                return False, "login_failed"
            except http_requests.RequestException as exc:
                return False, f"network_error: {exc}"
            except Exception as exc:
                return False, f"unexpected: {exc}"
            finally:
                session.close()

        success, error = await bot.loop.run_in_executor(executor, _try_login)

        if success:
            await interaction.followup.send(
                f"✅ **{display_name}** — login successful!", ephemeral=True
            )
        elif error == "wrong_credentials":
            await interaction.followup.send(
                f"🔑 **{display_name}** — wrong username or password. Use `/register` to update.",
                ephemeral=True,
            )
        elif error == "login_failed":
            await interaction.followup.send(
                f"🔒 **{display_name}** — login failed after retries. Try again later.",
                ephemeral=True,
            )
        else:
            await interaction.followup.send(
                f"💥 **{display_name}** — error: {error}", ephemeral=True
            )

    class ClassDeeDeeToggle(enum.Enum):
        On = "on"
        Off = "off"

    @tree.command(
        name="classdeedee",
        description="Enable/disable ClassDeeDee check-in and homework together (default: on; see /settings for separate)",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(action="Turn ClassDeeDee on or off for your account")
    async def cmd_classdeedee(interaction: discord.Interaction, action: ClassDeeDeeToggle):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You need to `/register` first.", ephemeral=True
            )
            return

        enabled = action == ClassDeeDeeToggle.On
        # A master switch for both — flips the same two flags /settings
        # exposes individually (classdeedee_checkin_enabled /
        # classdeedee_homework_enabled), so a user who only wants one on
        # should use /settings instead of this command.
        registered_users[uid]["classdeedee_checkin_enabled"] = enabled
        registered_users[uid]["classdeedee_homework_enabled"] = enabled
        persist_users()
        log.info("User %s turned ClassDeeDee %s", interaction.user.display_name, "on" if enabled else "off")

        if enabled:
            await interaction.response.send_message(
                "✅ ClassDeeDee re-enabled — you'll be included in ClassDeeDee QR check-ins and homework checks again.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "✅ ClassDeeDee disabled — your account will be skipped for ClassDeeDee QR check-ins and homework "
                "checks (MyCourseVille is unaffected). Use `/classdeedee on` to turn it back on.",
                ephemeral=True,
            )

    @tree.command(
        name="deedeeregister",
        description="Add a ClassDeeDee (ChulaSSO) login — only required if you registered with a MyCourseVille account",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(
        username="Your ChulaSSO login (10-digit student ID)",
        password="Your ChulaSSO / CU IT (email) password",
    )
    async def cmd_deedeeregister(interaction: discord.Interaction, username: str, password: str):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ Register your MyCourseVille account with `/register` first, then add your ClassDeeDee login here.",
                ephemeral=True,
            )
            return

        info = registered_users[uid]
        display_name = info.get("display_name", info.get("username", uid))

        # This command is ONLY for MyCourseVille-account users. A CU Net login is
        # already a ChulaSSO login, so those users must not run this.
        if info.get("login_method", "cu_net") == "cu_net":
            await interaction.response.send_message(
                "ℹ️ This command is **only for users who registered a MyCourseVille account**.\n"
                "You registered with **CU Net**, which *is* your ChulaSSO login — it already works on "
                "ClassDeeDee, so there's nothing to add here.",
                ephemeral=True,
            )
            return

        if not re.fullmatch(r"\d{10}", username):
            await interaction.response.send_message(
                "❌ Your ChulaSSO username should be your 10-digit student ID (e.g. `6799999999`).",
                ephemeral=True,
            )
            return

        try:
            encrypted = encrypt_password(password)
        except ValueError as e:
            log.error("Password encryption failed: %s", e)
            await interaction.response.send_message(
                "❌ Failed to securely store your password. Please contact the admin.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"⏳ Verifying your ClassDeeDee login (`{username}`) …", ephemeral=True
        )

        # Verify BEFORE saving so a wrong credential is never persisted.
        def _verify():
            try:
                session = login_classdeedee(username, password)
                try:
                    profile = fetch_profile(session)
                finally:
                    session.close()
                return True, profile
            except CddWrongCredentialsError:
                return False, "wrong_credentials"
            except CddLoginError as exc:
                return False, f"login_failed: {exc}"
            except http_requests.RequestException as exc:
                return False, f"network_error: {exc}"
            except Exception as exc:  # noqa: BLE001
                return False, f"unexpected: {exc}"

        ok, result = await bot.loop.run_in_executor(executor, _verify)
        if not ok:
            if result == "wrong_credentials":
                msg = "🔑 Wrong student ID or password — **nothing saved**. Double-check and try again."
            elif str(result).startswith("login_failed"):
                msg = f"🔒 ClassDeeDee login failed — **nothing saved**. {str(result).split(': ', 1)[-1]}"
            else:
                msg = f"💥 Couldn't verify — **nothing saved**. ({result})"
            await interaction.followup.send(msg, ephemeral=True)
            return

        # Verified — persist the ChulaSSO credential alongside the existing one.
        info["chulasso"] = {"username": username, "password": encrypted}
        persist_users()
        profile = result
        name = full_name(profile) or display_name
        student_id = profile.get("studentid") or username
        log.info("ClassDeeDee credential added for %s (%s)", display_name, username)
        await interaction.followup.send(
            "✅ ClassDeeDee login saved and verified!\n"
            f"> **Name:** {name}\n"
            f"> **Student ID:** `{student_id}`\n"
            "You'll now be checked in on ClassDeeDee attendance scans too.",
            ephemeral=True,
        )

    @tree.command(
        name="deedeeunregister",
        description="Remove your separate ClassDeeDee (ChulaSSO) login, keeping your MyCourseVille account",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_deedeeunregister(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered.", ephemeral=True
            )
            return

        info = registered_users[uid]

        # A CU Net login IS a ChulaSSO login — same credential, not a separate
        # one — so there's nothing here to unlink independently of the whole
        # account. `/classdeedee off` is the right tool for "stop using my
        # account on ClassDeeDee" without deleting anything.
        if info.get("login_method", "cu_net") == "cu_net":
            await interaction.response.send_message(
                "ℹ️ You registered with **CU Net**, which *is* your ChulaSSO login — there's no separate "
                "ClassDeeDee credential to remove. Use `/classdeedee off` if you want to stop being checked "
                "in on ClassDeeDee without deleting your MyCourseVille account.",
                ephemeral=True,
            )
            return

        if "chulasso" not in info:
            await interaction.response.send_message(
                "ℹ️ You don't have a separate ClassDeeDee login saved.", ephemeral=True
            )
            return

        del info["chulasso"]
        persist_users()
        log.info("ClassDeeDee credential removed for %s", interaction.user.display_name)
        await interaction.response.send_message(
            "✅ Your ClassDeeDee login has been removed. Your MyCourseVille account is untouched — "
            "use `/deedeeregister` again any time to re-add it.",
            ephemeral=True,
        )

    @tree.command(name="deedeecheck", description="Test if your saved credentials can log into ClassDeeDee")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_deedeecheck(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered. Use `/register` first.", ephemeral=True
            )
            return

        info = registered_users[uid]
        display_name = info.get("display_name", info["username"])

        # Resolve the ClassDeeDee (ChulaSSO) credential — cu_net main cred, or a
        # `chulasso` added via /deedeeregister. Platform-only users have none.
        try:
            creds = resolve_cdd_credentials(info, "checkin")
        except ValueError:
            await interaction.response.send_message(
                "❌ Failed to decrypt your password. Please re-register.", ephemeral=True
            )
            return

        if creds is None:
            await interaction.response.send_message(
                f"⚠️ **{display_name}** — you registered a **MyCourseVille** account, which can't log "
                "into ClassDeeDee. Add your ChulaSSO login with `/deedeeregister` first.",
                ephemeral=True,
            )
            return

        cdd_username, cdd_password = creds

        await interaction.response.send_message(
            f"⏳ Testing ClassDeeDee login for **{display_name}** …", ephemeral=True
        )

        def _try_login():
            try:
                session = login_classdeedee(cdd_username, cdd_password)
                try:
                    profile = fetch_profile(session)
                finally:
                    session.close()
                return True, profile
            except CddWrongCredentialsError:
                return False, "wrong_credentials"
            except CddLoginError as exc:
                return False, f"login_failed: {exc}"
            except http_requests.RequestException as exc:
                return False, f"network_error: {exc}"
            except Exception as exc:
                return False, f"unexpected: {exc}"

        success, error = await bot.loop.run_in_executor(executor, _try_login)

        if success:
            profile = error  # on success the second value is the profile dict
            name = full_name(profile) or display_name
            student_id = profile.get("studentid") or profile.get("username") or "—"
            name_th = " ".join(
                p for p in (profile.get("firstnameth"), profile.get("lastnameth")) if p
            ).strip()
            lines = [
                f"✅ **{display_name}** — ClassDeeDee login successful!",
                f"> **Name:** {name}" + (f" ({name_th})" if name_th else ""),
                f"> **Student ID:** `{student_id}`",
            ]
            await interaction.followup.send("\n".join(lines), ephemeral=True)
        elif error == "wrong_credentials":
            await interaction.followup.send(
                f"🔑 **{display_name}** — wrong username or password. Use `/register` to update.",
                ephemeral=True,
            )
        elif error.startswith("login_failed"):
            await interaction.followup.send(
                f"🔒 **{display_name}** — ClassDeeDee login failed. {error.split(': ', 1)[-1]}",
                ephemeral=True,
            )
        else:
            await interaction.followup.send(
                f"💥 **{display_name}** — error: {error}", ephemeral=True
            )

    @tree.command(name="deedeebench", description="(temp) Benchmark logging in ALL users to ClassDeeDee — timing & RAM")
    async def cmd_deedeebench(interaction: discord.Interaction):
        # NOTE: intentionally ungated — this is a temporary test command; remove it
        # (and this handler) once the ClassDeeDee login timing/RAM is confirmed.
        await interaction.response.send_message(
            "⏳ Benchmarking ClassDeeDee logins for **all** users … (full breakdown also in the Fly logs)",
            ephemeral=True,
        )

        stats = await bot.loop.run_in_executor(executor, bench_logins)
        if stats.get("error"):
            await interaction.followup.send(f"❌ {stats['error']}", ephemeral=True)
            return

        def mb(v):
            return f"{v:.1f} MB" if isinstance(v, (int, float)) else "n/a"

        lines = [
            "🧪 **ClassDeeDee login benchmark**",
            f"• Users: {stats['total']} → ✅ {stats['ok']} ok · ❌ {stats['failed']} failed",
            f"• Wall time: **{stats['wall']:.2f}s** (cap {stats['workers']} workers, {stats['waves']} wave(s))",
            f"• Per-login: fastest {stats['fastest']:.2f}s · slowest {stats['slowest']:.2f}s",
        ]
        if stats["rss_peak"] is not None:
            lines.append(f"• RAM: {mb(stats['rss_before'])} → {mb(stats['rss_after'])} (peak **{mb(stats['rss_peak'])}**)")
        elif stats["rss_before"] is not None:
            lines.append(f"• RAM: {mb(stats['rss_before'])} → {mb(stats['rss_after'])} (peak n/a here)")
        else:
            lines.append("• RAM: not measurable on this platform (works on Fly/Linux)")

        if stats["wall"] > 8:
            lines.append(f"⚠️ Wall {stats['wall']:.1f}s > ~8s nonce window — a real check-in would drop late users.")

        fails = [r for r in stats["per"] if not r["ok"]]
        if fails:
            lines.append("\n**Failures:**")
            lines.extend(f"• {r['name']} — {r['error']}" for r in fails[:15])
            if len(fails) > 15:
                lines.append(f"…and {len(fails) - 15} more (see Fly logs)")

        await interaction.followup.send("\n".join(lines), ephemeral=True)

    @tree.command(name="status", description="Show bot uptime and status")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_status(interaction: discord.Interaction):
        from datetime import datetime, timezone
        uptime = datetime.now(timezone.utc) - bot_start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        channel_list = ", ".join(f"<#{cid}>" for cid in sorted(monitored_channels)) or "None"
        user_count = len(registered_users)
        enrolled_count = sum(1 for info in registered_users.values() if info.get("subjects"))
        await interaction.response.send_message(
            f"🤖 **Bot Status**\n"
            f"• Version: v{BOT_VERSION}\n"
            f"• Uptime: {hours}h {minutes}m {seconds}s\n"
            f"• Engine: HTTP requests (lightweight)\n"
            f"• Registered users: {user_count} ({enrolled_count} using course enrollment)\n"
            f"• Monitoring: {channel_list}\n"
            "\n"
            "🛠️ Made by **Tanabodhi Mukura** (@ILFforever)\n"
            "🔗 <https://github.com/ILFforever/Chula_Attendance>",
            ephemeral=True,
        )

    @tree.command(name="scanner", description="DM yourself a link to the on-device QR scanner")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_scanner(interaction: discord.Interaction):
        if not SCAN_SECRET or not SCAN_BASE_URL:
            await interaction.response.send_message(
                "📷 The QR scanner isn't configured — the host needs to set `SCAN_SECRET` and `SCAN_BASE_URL`.",
                ephemeral=True,
            )
            return

        # Encode the channel this was run in, so scan results post back here —
        # only meaningful for a real guild text channel; bot.get_channel()
        # never resolves a DM channel for posting, so a DM/private-channel
        # run just gets the DM-only fallback (see handle_web_scan).
        in_guild_channel = interaction.guild is not None
        channel_id = interaction.channel_id if in_guild_channel else None
        link = f"{SCAN_BASE_URL}/scan#t={SCAN_SECRET}&c={channel_id or ''}"
        where = f"posted in <#{channel_id}> (and DMed to each user)" if channel_id else "DMed to each user"
        await interaction.response.send_message(
            f"📷 **Attendance QR Scanner**\n"
            f"{link}\n"
            "\n"
            "Open it on your phone, allow camera access, and point it at the classroom QR code. "
            "The code is decoded on your device — only the link reaches the bot, which then checks in "
            "everyone registered.\n"
            f"Results will be {where}.\n"
            "⚠️ Anyone with this link can trigger a check-in, so don't share it outside the group.",
            ephemeral=True,
        )

    @tree.command(name="leaderboard", description="See who's posted the most attendance links")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def cmd_leaderboard(interaction: discord.Interaction):
        if not leaderboard_counts:
            await interaction.response.send_message(
                "🏆 No one's posted an attendance link yet — be the first!", ephemeral=True
            )
            return

        ranked = sorted(leaderboard_counts.items(), key=lambda kv: kv[1]["count"], reverse=True)
        medals = ["🥇", "🥈", "🥉"]
        lines = []
        for i, (uid, entry) in enumerate(ranked[:10]):
            rank = medals[i] if i < len(medals) else f"`#{i + 1}`"
            lines.append(f"{rank} **{entry['display_name']}** — {entry['count']} link(s)")

        uid = str(interaction.user.id)
        if uid not in dict(ranked[:10]) and uid in leaderboard_counts:
            own_rank = next(i for i, (u, _) in enumerate(ranked) if u == uid) + 1
            own_entry = leaderboard_counts[uid]
            lines.append(f"...\n`#{own_rank}` **{own_entry['display_name']}** (you) — {own_entry['count']} link(s)")

        await interaction.response.send_message(
            "🏆 **Attendance Link Leaderboard**\n" + "\n".join(lines)
        )

    # Return helpers so bot.py can use them for on_message
    return run_check_in_async, dm_results
