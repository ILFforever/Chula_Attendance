import asyncio
import enum
import re
import time

import discord
from discord import app_commands
import requests as http_requests

from config import (
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
from password_crypto import encrypt_password, decrypt_password
from attendance import (
    MCV_URL_PATTERN,
    WrongCredentialsError,
    LoginError,
    fetch_public_course_info,
)
from classdeedee_login import (
    login_classdeedee,
    fetch_profile,
    full_name,
    WrongCredentialsError as CddWrongCredentialsError,
    LoginError as CddLoginError,
)
from cugetreg import fetch_course_name


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


def setup(bot: discord.Client, tree: app_commands.CommandTree, attendance, executor, bot_start_time):
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

    @tree.command(name="unregister", description="Remove your saved credentials")
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
    # Help
    # -------------------------------------------------------------------
    @tree.command(name="help", description="Show all bot commands and how to use them")
    async def cmd_help(interaction: discord.Interaction):
        await interaction.response.send_message(
            f"📖 **Attendance Bot — Help** (v{BOT_VERSION})\n"
            "\n"
            "**User Management**\n"
            "`/register <username> <password>` — Register your MyCourseVille credentials (only you see the response)\n"
            "`/unregister` — Remove your saved credentials\n"
            "`/users` — List all registered users\n"
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
            "\n"
            "**Attendance**\n"
            "`/checkin <url>` — Manually trigger check-in with a MyCourseVille attendance URL\n"
            "`/scanner` — DM yourself a phone-camera QR scanner that checks everyone in\n"
            "`/logincheck` — Test if your saved credentials can log in\n"
            "`/deedeecheck` — Test if your saved credentials can log into ClassDeeDee (ChulaSSO)\n"
            "`/status` — Show bot uptime, registered users, and monitored channels\n"
            "`/leaderboard` — See who's posted the most attendance links\n"
            "\n"
            "**How it works**\n"
            "When a MyCourseVille attendance link is posted in a monitored channel, "
            "the bot automatically opens it and checks in every registered user — or, if you've "
            "used `/enroll`, only those enrolled in that course.",
            ephemeral=True,
        )

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
    @app_commands.describe(url="MyCourseVille attendance URL")
    async def cmd_checkin(interaction: discord.Interaction, url: str):
        from attendance import MCV_URL_PARTIAL

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

    @tree.command(name="logincheck", description="Test if your saved credentials can log in")
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

    @tree.command(name="deedeecheck", description="Test if your saved credentials can log into ClassDeeDee")
    async def cmd_deedeecheck(interaction: discord.Interaction):
        uid = str(interaction.user.id)
        if uid not in registered_users:
            await interaction.response.send_message(
                "❌ You are not registered. Use `/register` first.", ephemeral=True
            )
            return

        info = registered_users[uid]
        display_name = info.get("display_name", info["username"])

        # ClassDeeDee authenticates via ChulaSSO (the CU IT / student-ID account).
        # A MyCourseVille "platform" account can't log into ChulaSSO, so flag it.
        if info.get("login_method") == "platform":
            await interaction.response.send_message(
                f"⚠️ **{display_name}** — your credentials are a **MyCourseVille platform** account, "
                "but ClassDeeDee uses **ChulaSSO** (your CU IT / student-ID account). "
                "This test needs a CU Net account to work.",
                ephemeral=True,
            )
            return

        try:
            password = decrypt_password(info["password"])
        except ValueError:
            await interaction.response.send_message(
                "❌ Failed to decrypt your password. Please re-register with `/register`.",
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            f"⏳ Testing ClassDeeDee login for **{display_name}** …", ephemeral=True
        )

        def _try_login():
            try:
                session = login_classdeedee(info["username"], password)
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

    @tree.command(name="status", description="Show bot uptime and status")
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
    async def cmd_scanner(interaction: discord.Interaction):
        if not SCAN_SECRET or not SCAN_BASE_URL:
            await interaction.response.send_message(
                "📷 The QR scanner isn't configured — the host needs to set `SCAN_SECRET` and `SCAN_BASE_URL`.",
                ephemeral=True,
            )
            return

        link = f"{SCAN_BASE_URL}/scan#t={SCAN_SECRET}"
        await interaction.response.send_message(
            f"📷 **Attendance QR Scanner**\n"
            f"{link}\n"
            "\n"
            "Open it on your phone, allow camera access, and point it at the classroom QR code. "
            "The code is decoded on your device — only the link reaches the bot, which then checks in "
            "everyone registered.\n"
            "⚠️ Anyone with this link can trigger a check-in, so don't share it outside the group.",
            ephemeral=True,
        )

    @tree.command(name="leaderboard", description="See who's posted the most attendance links")
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
