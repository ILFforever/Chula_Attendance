import asyncio
import time
from datetime import datetime, time as dt_time, timezone
from concurrent.futures import ThreadPoolExecutor

import discord
from discord import app_commands
from discord.ext import tasks

from attendance_bot.config import (
    log,
    BOT_VERSION,
    DISCORD_TOKEN,
    SCAN_SECRET,
    HOMEWORK_CONCURRENCY,
    monitored_channels,
    registered_users,
    is_duplicate_link,
    mark_link_seen,
    record_leaderboard_post,
    leaderboard_counts,
)
from attendance_bot.mcv.attendance import (
    AttendanceLogger,
    MCV_URL_PARTIAL,
    TZ_BANGKOK,
    extract_attendance_url,
    fetch_public_course_info,
)
from attendance_bot.scanner.webserver import start_web_server
from attendance_bot.classdeedee.attendance import check_in_all as cdd_check_in_all
from attendance_bot.homework.dm import handle_homework_button, run_homework_scheduler_tick, run_deadline_reminder_tick
from attendance_bot.homework.custom import handle_custom_assignment_button
from attendance_bot.settings_panel import handle_settings_interaction
from attendance_bot import commands

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
            await start_web_server(
                handle_web_scan,
                on_scan_cdd=handle_web_scan_cdd,
                on_identify=identify_scanner,
            )
        else:
            log.info("SCAN_SECRET not set — QR scanner web server disabled")

        homework_scheduler_loop.start()
        deadline_reminder_loop.start()


bot = AttendanceBot(intents=intents)
tree = app_commands.CommandTree(bot)
attendance = AttendanceLogger()
bot_start_time = datetime.now(timezone.utc)
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="checkin_")

# Separate, low-concurrency pool for the homework check — unlike ClassDeeDee
# check-in there's no nonce window forcing everyone in at once, so this stays
# small by default to be gentle on ChulaSSO/MCV (see config.HOMEWORK_CONCURRENCY).
homework_executor = ThreadPoolExecutor(max_workers=HOMEWORK_CONCURRENCY, thread_name_prefix="hw_")

# `tasks.loop(minutes=15)` runs relative to whenever the bot happened to
# become ready — not aligned to the wall clock — so a user who set
# /homeworktime 8 could get their DM anywhere from 8:00 to 8:59 depending on
# the process's restart offset (this is what caused a report of "set to
# 7:00, arrived at 7:45"). Pinning this loop to `time=` instead makes it
# fire at exactly :00 past every hour, Bangkok time, regardless of restarts.
_HOURLY_BANGKOK_TIMES = [dt_time(hour=h, minute=0, tzinfo=TZ_BANGKOK) for h in range(24)]

# Same reasoning, same fix, applied to the deadline-reminder scan too — pinned
# to fixed half-hour checkpoints (Bangkok time) instead of a relative cadence,
# so its timing is predictable and independent of restarts as well. The tick is
# a pure "is anything inside the user's window yet" scan with a per-item
# reminded flag, so the cadence only sets worst-case latency: a reminder lands
# at most 30 minutes after its window opens.
_HALF_HOURLY_BANGKOK_TIMES = [
    dt_time(hour=h, minute=m, tzinfo=TZ_BANGKOK) for h in range(24) for m in (0, 30)
]


@tasks.loop(time=_HOURLY_BANGKOK_TIMES)
async def homework_scheduler_loop():
    await run_homework_scheduler_tick(bot, homework_executor)


@homework_scheduler_loop.before_loop
async def _before_homework_scheduler_loop():
    await bot.wait_until_ready()


@tasks.loop(time=_HALF_HOURLY_BANGKOK_TIMES)
async def deadline_reminder_loop():
    await run_deadline_reminder_tick(bot)


@deadline_reminder_loop.before_loop
async def _before_deadline_reminder_loop():
    await bot.wait_until_ready()

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
run_check_in_async, dm_results = commands.setup(bot, tree, attendance, executor, bot_start_time, homework_executor)


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


async def award_scan_credit(scanner_id: str | None) -> None:
    """Give the scanner leaderboard credit for a check-in they triggered.

    Callers apply the same bar a posted link has to clear: first sighting of
    this code, and it actually checked somebody in. A legacy shared-secret link
    carries no identity, so there is nobody to credit.
    """
    if not scanner_id:
        return

    name = None
    try:
        user = bot.get_user(int(scanner_id)) or await bot.fetch_user(int(scanner_id))
        name = user.display_name
    except Exception as e:
        # Never lose the credit over a failed name lookup — fall back to the
        # name already on the board, and only then to something readable.
        log.warning("Could not resolve scanner %s for leaderboard credit: %s", scanner_id, e)
        existing = leaderboard_counts.get(scanner_id)
        name = existing["display_name"] if existing else f"User {scanner_id}"

    record_leaderboard_post(scanner_id, name)
    log.info("Leaderboard credit to %s (%s) for a scanned check-in", name, scanner_id)


async def identify_scanner(user_id: str) -> dict | None:
    """Name and avatar for the scanner page's identity chip.

    Called once when the page loads, so whoever is holding the phone can see
    which Discord account their saved token belongs to — and notice immediately
    if it is somebody else's.
    """
    try:
        # get_user is a cache hit; fetch_user costs a REST round trip.
        user = bot.get_user(int(user_id)) or await bot.fetch_user(int(user_id))
    except Exception as e:
        log.warning("Could not resolve scanner identity for %s: %s", user_id, e)
        return None
    return {
        "id": str(user.id),
        "name": user.display_name,
        "avatar": user.display_avatar.replace(size=128).url,
        "registered": str(user.id) in registered_users,
    }


async def handle_web_scan(attendance_url: str, channel_id: int | None = None,
                          scanner_id: str | None = None) -> dict:
    """Entry point for a QR code scanned on the web page.

    `channel_id` is the channel the scanner link was bound to (from /scanner);
    results post there, or DM-only if it's missing/unreachable. `scanner_id` is
    the Discord user whose token was used, or None for a legacy shared-secret
    link — tokens minted before per-user tokens existed carry no identity.
    """
    channel = bot.get_channel(channel_id) if channel_id else None

    log.info("Attendance URL received from QR scanner: %s (channel=%s, scanner=%s)",
             attendance_url, channel_id, scanner_id or "anonymous")
    note = f"📷 Scanned by <@{scanner_id}> — " if scanner_id else "📷 Scanned via QR scanner — "
    summary = await process_attendance_link(attendance_url, channel, note=note)

    # Same rule as posting the link in a channel: credit only a first sighting
    # that produced a real check-in. process_attendance_link has already marked
    # the URL seen, so re-scanning the same QR comes back duplicate=True and a
    # stale or expired code never counts.
    if not summary["duplicate"] and summary["succeeded"]:
        await award_scan_credit(scanner_id)
    return summary


async def handle_web_scan_cdd(sid: str, nonce: str, channel_id: int | None = None,
                              scanner_id: str | None = None) -> dict:
    """Entry point for a scanned ClassDeeDee attendance QR ({sid, nonce}).

    `channel_id` is the channel the scanner link was bound to (from /scanner);
    results post there, or DM-only if it's missing/unreachable. `scanner_id` is
    the Discord user whose token was used, or None for a legacy link.
    """
    channel = bot.get_channel(channel_id) if channel_id else None

    log.info("ClassDeeDee attendance QR received from scanner: sid=%s (channel=%s, scanner=%s)",
             sid, channel_id, scanner_id or "anonymous")
    started = time.perf_counter()

    # Kick the logins/check-in off IMMEDIATELY — the nonce is time-sensitive, so
    # nothing (Discord post included) should sit in front of it. run_in_executor
    # submits to the pool right away; check_in_all fans logins out across its own
    # bounded pool.
    checkin_task = bot.loop.run_in_executor(executor, cdd_check_in_all, sid, nonce)

    # Leaderboard dedup key. A ClassDeeDee QR has no URL to remember, and its
    # nonce rotates every few seconds — only the session id is stable, so that
    # is what identifies "this class, already scanned". Namespaced so it can
    # never collide with a real MCV URL in the same seen_links store.
    dedupe_key = f"classdeedee:{sid}"
    is_dupe = is_duplicate_link(dedupe_key)
    if is_dupe:
        log.info("ClassDeeDee session %s already scanned recently - no leaderboard credit", sid)

    status_msg = None
    if channel is not None:
        try:
            by = f" by <@{scanner_id}>" if scanner_id else ""
            status_msg = await channel.send(
                f"📷 Scanned{by} a **ClassDeeDee** attendance QR — checking everyone in …"
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

    mark_link_seen(dedupe_key)
    if not is_dupe and succeeded:
        await award_scan_credit(scanner_id)

    where = "Results posted in Discord." if channel is not None else "Results sent to each user via DM."
    return {
        "message": f"✅ ClassDeeDee\n{succeeded} of {len(results)} user(s) checked in. {where}",
    }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@bot.event
async def on_ready():
    # Global sync only — no per-guild copy_global_to()/sync(guild=...).
    # Two reasons:
    #  1. Mixing global and per-guild registration for the same commands is
    #     exactly what caused a duplicate-command bug (Discord shows both
    #     the global entry and the guild-scoped copy). Picking one strategy
    #     avoids that permanently.
    #  2. Some commands are now DM/user-installable (see the
    #     allowed_installs/allowed_contexts decorators throughout
    #     commands.py) — that requires global registration, since a DM
    #     isn't tied to any guild a guild-scoped command could live in.
    # Trade-off: new/changed commands can take up to ~1 hour to propagate
    # globally (existing, unchanged commands are unaffected) — acceptable
    # for a bot whose command set doesn't change every restart, unlike the
    # per-guild path this replaces which updated instantly.
    await tree.sync()
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name=f"👀 for attendance links | v{BOT_VERSION} | 🔗 github.com/ILFforever/Chula_Attendance",
    ))
    log.info("Bot is online as %s (ID: %s) — v%s", bot.user, bot.user.id, BOT_VERSION)
    log.info("Slash commands synced")
    log.info("Monitoring channels: %s", monitored_channels or "(none)")
    log.info("Registered users: %d", len(registered_users))


@bot.event
async def on_interaction(interaction: discord.Interaction):
    # discord.py routes app-command and component interactions itself
    # (CommandTree, view stores) regardless of this handler — dispatch('interaction', ...)
    # fires unconditionally alongside that, which is what lands here. Not a
    # View callback — see homework/dm.py's module docstring for why a click
    # needs to keep working even after a restart.
    await handle_homework_button(interaction)
    await handle_custom_assignment_button(interaction)
    await handle_settings_interaction(interaction)


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
