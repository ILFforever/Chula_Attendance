import enum
import re

import discord
from discord import app_commands
import requests as http_requests

from config import (
    log,
    registered_users,
    monitored_channels,
    persist_channels,
    persist_users,
)
from password_crypto import encrypt_password, decrypt_password
from attendance import (
    MCV_URL_PATTERN,
    WrongCredentialsError,
    LoginError,
)


def setup(bot: discord.Client, tree: app_commands.CommandTree, attendance, executor, bot_start_time):
    """Register all slash commands on the given tree."""

    # -------------------------------------------------------------------
    # Helper: run check-in in thread pool
    # -------------------------------------------------------------------
    async def run_check_in_async(attendance_url: str) -> list[tuple[str, str]]:
        return await bot.loop.run_in_executor(executor, attendance.check_in_all, attendance_url)

    async def dm_results(results: list[tuple[str, str]]):
        for uid, result in results:
            if not uid:
                continue
            try:
                user = await bot.fetch_user(int(uid))
                await user.send(f"📋 **Attendance result:**\n{result}")
            except Exception as e:
                log.warning("Could not DM user %s: %s", uid, e)

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
    # Help
    # -------------------------------------------------------------------
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
            "`/checkin <url>` — Manually trigger check-in with a MyCourseVille attendance URL\n"
            "`/logincheck` — Test if your saved credentials can log in\n"
            "`/status` — Show bot uptime, registered users, and monitored channels\n"
            "\n"
            "**How it works**\n"
            "When a MyCourseVille attendance link is posted in a monitored channel, "
            "the bot automatically opens it for every registered user and checks them in.",
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

        log.info("Manual check-in triggered by %s with URL: %s", interaction.user, url)
        await interaction.response.send_message(
            f"⏳ Checking in {len(registered_users)} user(s) …"
        )
        results = await run_check_in_async(url)
        await interaction.followup.send("\n".join(r for _, r in results))
        await dm_results(results)

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

    @tree.command(name="status", description="Show bot uptime and status")
    async def cmd_status(interaction: discord.Interaction):
        from datetime import datetime, timezone
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

    # Return helpers so bot.py can use them for on_message
    return run_check_in_async, dm_results
