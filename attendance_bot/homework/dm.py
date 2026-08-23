"""Discord DM delivery for the homework check: message formatting, the
per-item "Handed in" buttons, and the scheduler that drives it all.

Design (settled after mocking up alternatives — see docs/ discussion):
  - Built with Components V2 (discord.ui.LayoutView / Container / ActionRow /
    TextDisplay), not classic embeds. The win: each item gets its own
    ActionRow (an "Open in web" link button + a "Mark as finished" button)
    directly under its own two text lines — genuinely adjacent, not just
    "below the whole message" the way a View's buttons are forced to be with
    embeds. Once IS_COMPONENTS_V2 is set on a message, `content`/`embeds` stop
    working entirely — the whole message body has to be built as components.
  - Still one message per course, most-urgent course first — NOT collapsed
    into a single message. Components V2 has a hard 40-components-per-message
    cap (Container + per-item 2×TextDisplay+ActionRow(2 buttons) = 4
    components each), which a user with several courses/items outstanding —
    exactly the ones who most need the reminder — could realistically blow
    past in one message. Splitting by course keeps each message's component
    count small regardless of how much total work someone has.
  - Urgency is carried by the course's own Container accent color (🔴 <=1
    day, 🟡 <=3 days, 🟢 otherwise, ⚪ unknown — see check.py's
    urgency_dot()/_urgency_color()) plus the due text's own wording ("in 2
    days"), not repeated per-item with a dot — that read as clutter duplicating
    a signal the container already gives.
  - The date + outstanding-count header is two plain TextDisplay lines above
    the first course's Container (not inside it) — a bot-authored date needs
    to be unambiguous (Bangkok-local, spelled out), which is also why this
    isn't using an embed timestamp (those silently re-render per viewer).
  - Clicking "Handed in" doesn't tell ClassDeeDee/MCV anything — it's a
    self-report that just suppresses future reminders for that one item
    (attendance_bot/config.py's homework_suppressed store), independent of
    whatever the platform's own submission state says.
  - No View-based button callbacks are registered (those don't survive a
    restart unless explicitly re-added). Instead a single raw `on_interaction`
    listener (registered in client.py) catches every component click by its
    "hw:" custom_id prefix, so a click always works even days after the
    message was sent and the bot has restarted in between.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

import discord
from discord import ui

from attendance_bot.config import (
    log,
    registered_users,
    persist_users,
    mark_homework_suppressed,
    list_suppressed_for_user,
    unmark_homework_suppressed,
    is_homework_suppressed,
    pending_deadline_items,
    mark_deadline_reminded,
)
from attendance_bot.mcv.attendance import TZ_BANGKOK
from attendance_bot.homework.check import check_homework_for_user, filter_suppressed, cache_deadlines

_PLATFORM_TAG = {"mcv": "MyCourseVille", "classdeedee": "ClassDeeDee"}


def _item_custom_id(uid: str, item: dict, course_code: str) -> str:
    key = item["item_key"]
    custom_id = f"hw:{uid}:{item['platform']}:{course_code}:{key}"
    if len(custom_id) > 100:  # Discord's hard limit on custom_id length
        key = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        custom_id = f"hw:{uid}:{item['platform']}:{course_code}:{key}"
    return custom_id


def _truncate(text: str, limit: int) -> str:
    """Guard against Discord's hard per-component character caps — a long
    assignment or course name would otherwise 400 the whole send.
    """
    return text if len(text) <= limit else text[: limit - 1] + "…"


_MD_HEADING_RE = re.compile(r"^#+\s*")


def _plain_text(markdown: str) -> str:
    """Strip the light markdown build_course_container wraps text in (##
    headings, ** bold) back to plain text, for storage/display elsewhere
    (the suppressed-items list, "Handed in" click handling).
    """
    return _MD_HEADING_RE.sub("", markdown).strip("*").strip()


def _urgency_color(days: float | None) -> discord.Color:
    if days is None:
        return discord.Color.light_grey()
    if days <= 1:
        return discord.Color.red()
    if days <= 3:
        return discord.Color.gold()
    return discord.Color.green()


def _relative_days_text(days: float) -> str:
    if days < 0:
        return "overdue"
    if days < 1:
        return "today"
    n = round(days)
    return "tomorrow" if n <= 1 else f"in {n} days"


def _pretty_due_text(item: dict) -> str:
    """Human-friendly due text: relative phrasing ("in 3 days") inside a
    week, an absolute date beyond that. MCV's due text is already relative
    (e.g. "4 days") straight from its own "due soon" panel — left as-is.
    """
    if item["platform"] != "classdeedee" or "T" not in (item["due_text"] or ""):
        return item["due_text"]

    days = item.get("days")
    if days is not None and days < 7:
        return _relative_days_text(days)

    try:
        dt = datetime.fromisoformat(item["due_text"].replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return item["due_text"]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ_BANGKOK)
    return dt.astimezone(TZ_BANGKOK).strftime("%b %d, %I:%M %p")


def build_course_container(uid: str, group: dict) -> ui.Container:
    """Build one course's Container: a large `##` title, then per item.

    A single-item course has room to spare — its item gets a full-width row
    below with both "Open in web" and "Mark as finished" buttons. A
    multi-item course instead keeps each row compact: the finish button sits
    to the right as a Section accessory (Discord only allows one accessory
    per Section, so "Open in web" is dropped there — finishing is the action
    people actually reach for on a list; opening the assignment isn't worth
    doubling every row's height for).
    """
    name = group["course_name"] or "course name unavailable"
    container = ui.Container(
        ui.TextDisplay(_truncate(f"## {group['course_code']} — {name}", 256)),
        accent_colour=_urgency_color(group["days"]),
    )

    spacious = len(group["items"]) == 1
    for item in group["items"]:
        tag = _PLATFORM_TAG.get(item["platform"], item["platform"])
        title_text = ui.TextDisplay(_truncate(f"**{item['title']}**", 4000))
        detail_text = ui.TextDisplay(f"{tag} · Due {_pretty_due_text(item)}")
        finish_button = ui.Button(
            style=discord.ButtonStyle.secondary,
            label="✅ Mark as finished",
            custom_id=_item_custom_id(uid, item, group["course_code"]),
        )

        if spacious:
            container.add_item(title_text)
            container.add_item(detail_text)
            container.add_item(ui.ActionRow(
                ui.Button(style=discord.ButtonStyle.link, label="Open in web", url=item["link"]),
                finish_button,
            ))
        else:
            container.add_item(ui.Section(title_text, detail_text, accessory=finish_button))
    return container


def _control_custom_id(kind: str, uid: str) -> str:
    return f"hwctl:{kind}:{uid}"


def _toggle_label_style(enabled: bool) -> tuple[str, discord.ButtonStyle]:
    if enabled:
        return "🔕 Turn off daily reminders", discord.ButtonStyle.danger
    return "🔔 Turn on daily reminders", discord.ButtonStyle.success


def _append_controls(layout: ui.LayoutView, uid: str) -> None:
    """Append a "manage this subscription" row to the last message of a run —
    toggle reminders on/off, change the hour, or review/undo past "Mark as
    finished" clicks — without a slash command.

    Reads the user's *actual* current homework_check state to render the
    toggle button correctly — this row is sent regardless of that state
    (including from /homeworkcheck, which never turns anything on), so it
    can't just assume "on".
    """
    enabled = registered_users.get(uid, {}).get("homework_check", False)
    toggle_label, toggle_style = _toggle_label_style(enabled)

    layout.add_item(ui.Separator())
    layout.add_item(ui.ActionRow(
        ui.Button(style=toggle_style, label=toggle_label, custom_id=_control_custom_id("toggle", uid)),
        ui.Button(
            style=discord.ButtonStyle.secondary,
            label="🕒 Change reminder time",
            custom_id=_control_custom_id("time", uid),
        ),
        ui.Button(
            style=discord.ButtonStyle.secondary,
            label="📋 View finished items",
            custom_id=_control_custom_id("view", uid),
        ),
    ))


def build_course_view(uid: str, group: dict, header_lines: list[str] | None = None) -> ui.LayoutView:
    """Build the full LayoutView for one course's message.

    `header_lines` (only passed for the first message of a run) render as
    plain TextDisplay lines above the course's Container.
    """
    view = ui.LayoutView(timeout=None)
    if header_lines:
        for line in header_lines:
            view.add_item(ui.TextDisplay(line))
        view.add_item(ui.Separator())
    view.add_item(build_course_container(uid, group))
    return view


async def send_homework_dm_for_user(bot: discord.Client, uid: str, result: dict) -> None:
    """Send one DM per outstanding course to `uid`, most urgent first.

    Silently sends nothing if there's nothing outstanding and no platform
    errors — a clean daily "you're all caught up" DM would just be noise.
    """
    groups = filter_suppressed(uid, result["groups"])

    today_str = datetime.now(TZ_BANGKOK).strftime("%A, %B %d, %Y")
    item_count = sum(len(g["items"]) for g in groups)
    header_lines = [
        "# 📚 Homework Check",
        f"-# {today_str} · {len(groups)} course(s), {item_count} item(s) outstanding",
    ]
    if result["mcv_error"]:
        header_lines.append(f"⚠️ MyCourseVille check failed — {result['mcv_error']}")
    if result["cdd_error"]:
        header_lines.append(f"⚠️ ClassDeeDee check failed — {result['cdd_error']}")
    if result["cdd_skipped"]:
        header_lines.append("ℹ️ ClassDeeDee wasn't checked — no login on file, use `/deedeeregister` to add one")
    has_errors = bool(result["mcv_error"] or result["cdd_error"])

    if not groups and not has_errors:
        log.debug("Homework check for %s: nothing outstanding, no DM sent", uid)
        return

    try:
        user = bot.get_user(int(uid)) or await bot.fetch_user(int(uid))
    except (discord.NotFound, discord.HTTPException) as exc:
        log.warning("Homework check: could not resolve Discord user %s: %s", uid, exc)
        return

    if not groups:
        no_work_view = ui.LayoutView(timeout=None)
        for line in header_lines:
            no_work_view.add_item(ui.TextDisplay(line))
        no_work_view.add_item(ui.TextDisplay("Nothing outstanding to report right now."))
        _append_controls(no_work_view, uid)
        try:
            await user.send(view=no_work_view)
        except discord.HTTPException as exc:
            log.warning("Homework check: could not DM %s: %s", uid, exc)
        return

    for i, group in enumerate(groups):
        layout = build_course_view(uid, group, header_lines if i == 0 else None)
        if i == len(groups) - 1:
            _append_controls(layout, uid)
        try:
            await user.send(view=layout)
        except discord.HTTPException as exc:
            log.warning("Homework check: could not DM %s: %s", uid, exc)
            return  # further messages would fail the same way (DMs closed, user left, etc.)

    log.info("Homework check DM sent to %s (%d course(s))", uid, len(groups))


# ---------------------------------------------------------------------------
# Button click handling
# ---------------------------------------------------------------------------
async def handle_homework_button(interaction: discord.Interaction) -> None:
    """Route a component-click interaction whose custom_id starts with "hw:".

    Registered as a raw listener (not a View callback) so it keeps working
    across bot restarts — see the module docstring for why.
    """
    if interaction.type != discord.InteractionType.component:
        return
    custom_id = (interaction.data or {}).get("custom_id", "")

    if custom_id.startswith("hwctl:"):
        await _handle_controls_click(interaction, custom_id)
        return

    if custom_id.startswith("hwrestore:"):
        await _handle_restore_click(interaction, custom_id)
        return

    if not custom_id.startswith("hw:"):
        return

    parts = custom_id.split(":", 4)
    if len(parts) != 5:
        await interaction.response.defer()
        return
    _, uid, platform, course_code, item_key = parts

    if str(interaction.user.id) != uid:
        await interaction.response.send_message("This isn't your homework reminder.")
        return

    layout = ui.LayoutView.from_message(interaction.message)
    clicked = next(
        (item for item in layout.walk_children()
         if isinstance(item, ui.Button) and item.custom_id == custom_id),
        None,
    )
    if clicked is None:
        await interaction.response.defer()
        return

    # Two possible shapes per item (see build_course_container):
    #   spacious (1-item course): [TextDisplay, TextDisplay, ActionRow] as
    #     direct Container children — the button's parent is the ActionRow.
    #   compact (multi-item course): Section(TextDisplay, TextDisplay,
    #     accessory=button) — the button's parent is the Section.
    parent = clicked.parent
    container = parent.parent if isinstance(parent, (ui.ActionRow, ui.Section)) else None

    # Grab the item's own title text (and the course header) before mutating
    # anything below — this is what the "View finished items" list shows.
    item_title = ""
    if isinstance(parent, ui.Section):
        title_display = next((c for c in parent.children if isinstance(c, ui.TextDisplay)), None)
        item_title = _plain_text(title_display.content) if title_display else ""
    elif isinstance(parent, ui.ActionRow) and container is not None and parent in container.children:
        idx = container.children.index(parent)
        preceding = [c for c in container.children[max(0, idx - 2):idx] if isinstance(c, ui.TextDisplay)]
        if preceding:
            item_title = _plain_text(preceding[0].content)
    course_name = ""
    if container is not None and container.children and isinstance(container.children[0], ui.TextDisplay):
        course_name = _plain_text(container.children[0].content)

    mark_homework_suppressed(uid, platform, course_code, item_key, title=item_title, course_name=course_name)

    clicked.disabled = True
    clicked.label = "✓ Marked done"

    if isinstance(parent, ui.Section):
        for text_item in parent.children:
            if isinstance(text_item, ui.TextDisplay):
                text_item.content = f"~~{text_item.content}~~"
    elif isinstance(parent, ui.ActionRow) and container is not None and parent in container.children:
        idx = container.children.index(parent)
        for text_item in container.children[max(0, idx - 2):idx]:
            if isinstance(text_item, ui.TextDisplay):
                text_item.content = f"~~{text_item.content}~~"

    if container is not None:
        finish_buttons = [
            item for item in container.walk_children()
            if isinstance(item, ui.Button) and item.custom_id  # skip the "Open in web" link button (no custom_id)
        ]
        if finish_buttons and all(b.disabled for b in finish_buttons):
            container.clear_items()
            container.add_item(ui.TextDisplay("✅ All caught up"))
            container.accent_colour = discord.Color.teal()

    await interaction.response.edit_message(view=layout)


class HomeworkTimeModal(ui.Modal, title="Set homework reminder time"):
    """Short-lived — created fresh on each "Change reminder time" click and
    only needs to survive until the user submits it, unlike the item buttons,
    so this can safely use discord.py's normal Modal.on_submit callback.
    """
    hour_input = ui.TextInput(label="Hour (0-23, Bangkok time)", placeholder="e.g. 8 for 8am, 20 for 8pm", min_length=1, max_length=2)

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        raw = self.hour_input.value.strip()
        try:
            hour = int(raw)
            if not (0 <= hour <= 23):
                raise ValueError
        except ValueError:
            await interaction.response.send_message(f'❌ "{raw}" isn\'t a whole number 0-23.')
            return

        registered_users[self.uid]["homework_check_hour"] = hour
        persist_users()
        log.info("User %s set homework check hour to %d (via DM control)", self.uid, hour)
        await interaction.response.send_message(
            f"✅ Homework reminder time set to **{hour:02d}:00** (Bangkok time)."
        )


async def _handle_controls_click(interaction: discord.Interaction, custom_id: str) -> None:
    """Route a click on the trailing "manage this subscription" row."""
    parts = custom_id.split(":", 2)
    if len(parts) != 3:
        await interaction.response.defer()
        return
    _, kind, uid = parts

    if str(interaction.user.id) != uid:
        await interaction.response.send_message("This isn't your homework reminder.")
        return

    if kind == "time":
        await interaction.response.send_modal(HomeworkTimeModal(uid))
        return

    if kind == "toggle":
        current = registered_users.get(uid, {}).get("homework_check", False)
        new_state = not current
        registered_users.setdefault(uid, {})["homework_check"] = new_state
        persist_users()
        log.info("User %s %s homework check (via DM control)", uid, "enabled" if new_state else "disabled")

        layout = ui.LayoutView.from_message(interaction.message)
        toggle_btn = next(
            (b for b in layout.walk_children() if isinstance(b, ui.Button) and b.custom_id == custom_id),
            None,
        )
        if toggle_btn is not None:
            toggle_btn.label, toggle_btn.style = _toggle_label_style(new_state)
        await interaction.response.edit_message(view=layout)
        return

    if kind == "view":
        entries = list_suppressed_for_user(uid)
        if not entries:
            await interaction.response.send_message(
                "You haven't marked anything as finished yet."
            )
            return

        view = ui.LayoutView(timeout=None)
        view.add_item(ui.TextDisplay(f"-# {len(entries)} item(s) marked finished — tap Restore to bring one back"))
        for storage_key, entry in entries:
            title = entry.get("title") or "Untitled"
            subtitle = entry.get("course_name") or _PLATFORM_TAG.get(entry.get("platform", ""), entry.get("platform", ""))
            view.add_item(ui.Section(
                ui.TextDisplay(_truncate(f"**{title}**", 4000)),
                ui.TextDisplay(subtitle or "​"),
                accessory=ui.Button(
                    style=discord.ButtonStyle.secondary,
                    label="↩️ Restore",
                    custom_id=f"hwrestore:{storage_key}",
                ),
            ))
        await interaction.response.send_message(view=view)
        return

    await interaction.response.defer()


async def _handle_restore_click(interaction: discord.Interaction, custom_id: str) -> None:
    """Route a click on a "Restore" button from the "View finished items" list."""
    storage_key = custom_id[len("hwrestore:"):]
    owner_uid = storage_key.split(":", 1)[0]

    if str(interaction.user.id) != owner_uid:
        await interaction.response.send_message("This isn't your list.")
        return

    unmark_homework_suppressed(storage_key)
    log.info("User %s restored a suppressed homework item", owner_uid)

    layout = ui.LayoutView.from_message(interaction.message)
    clicked = next(
        (b for b in layout.walk_children() if isinstance(b, ui.Button) and b.custom_id == custom_id),
        None,
    )
    if clicked is not None:
        clicked.disabled = True
        clicked.label = "✓ Restored"
        section = clicked.parent
        if isinstance(section, ui.Section):
            for text_item in section.children:
                if isinstance(text_item, ui.TextDisplay):
                    text_item.content = f"~~{text_item.content}~~"

    await interaction.response.edit_message(view=layout)


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
DEFAULT_HOMEWORK_HOUR = 8  # Bangkok-local, used when a user hasn't set one


async def run_homework_check_for_user(bot: discord.Client, executor, uid: str) -> None:
    loop = bot.loop
    try:
        result = await loop.run_in_executor(executor, check_homework_for_user, uid)
    except Exception:
        log.exception("Homework check crashed for %s", uid)
        return
    cache_deadlines(uid, result["groups"])
    await send_homework_dm_for_user(bot, uid, result)


async def run_homework_scheduler_tick(bot: discord.Client, executor) -> None:
    """Called on every scheduler tick — client.py's homework_scheduler_loop
    fires exactly once per hour (pinned to fixed Bangkok-time checkpoints),
    so matching a user's target hour against the current hour already sends
    each user at most once a day without any extra bookkeeping. No
    "already ran today" guard: one used to sit here, but it caused a worse
    problem than the one it prevented — moving your digest hour later the
    same day (or a transient login failure marking the day as "done" with
    nothing actually sent) silently ate the rest of the day with no way to
    tell from the user's side. A duplicate send from this loop firing twice
    in the same hour isn't realistically possible (see the loop's own
    docstring in client.py), so there's nothing left worth guarding against.
    """
    now = datetime.now(TZ_BANGKOK)

    due_uids = []
    for uid, info in registered_users.items():
        if not info.get("homework_check"):
            continue
        target_hour = info.get("homework_check_hour", DEFAULT_HOMEWORK_HOUR)
        if target_hour != now.hour:
            continue
        due_uids.append(uid)

    if not due_uids:
        return

    log.info("Homework check: running for %d user(s) at hour=%d", len(due_uids), now.hour)
    for uid in due_uids:
        await run_homework_check_for_user(bot, executor, uid)


# ---------------------------------------------------------------------------
# "Deadline approaching" reminder — opt-in, per-user customizable window
# ---------------------------------------------------------------------------
# Off by default (registered_users["deadline_reminder_enabled"]) — separate
# switch from the daily digest above, since this fires at whatever time of
# day an item actually crosses the user's chosen window, not at their
# digest hour. It reads only the deadline cache populated by
# check.cache_deadlines (last refreshed on that user's most recent
# daily/manual homework check) — it never logs into MCV/ClassDeeDee itself,
# so running it on every 15-min scheduler tick costs nothing beyond a dict
# scan regardless of how many users have it on.
#
# A live re-check wouldn't buy anything here anyway: MCV/ClassDeeDee's "still
# outstanding" list doesn't reflect submission status either way, so a
# platform re-fetch is no more authoritative than the cache. The only real
# source of truth for "done" is the user's own "Mark as finished" click
# (is_homework_suppressed) — checked fresh below regardless of cache age.
DEFAULT_DEADLINE_REMINDER_HOURS = 12
MIN_DEADLINE_REMINDER_HOURS = 1
MAX_DEADLINE_REMINDER_HOURS = 72


async def _send_deadline_reminder(bot: discord.Client, uid: str, entries: list[tuple[str, dict]]) -> None:
    """DM one user about the item(s) that just entered their reminder window.

    Reuses build_course_container so each item keeps its normal "Open in
    web" / "Mark as finished" controls, behaving exactly like the daily
    digest's buttons.
    """
    try:
        user = bot.get_user(int(uid)) or await bot.fetch_user(int(uid))
    except (discord.NotFound, discord.HTTPException) as exc:
        log.warning("Deadline reminder: could not resolve Discord user %s: %s", uid, exc)
        return

    now = datetime.now(timezone.utc)
    by_course: dict[str, dict] = {}
    for key, entry in entries:
        item_key = key.split(":", 3)[3]
        due_dt = datetime.fromisoformat(entry["due_dt"])
        days_left = max(0.0, (due_dt - now).total_seconds() / 86400.0)
        group = by_course.setdefault(entry["course_code"], {
            "course_code": entry["course_code"],
            "course_name": entry.get("course_name"),
            "items": [],
        })
        group["items"].append({
            "platform": entry.get("platform", ""),
            "title": entry.get("title") or "Untitled",
            "due_text": _relative_days_text(days_left),
            "days": days_left,
            "link": entry.get("link", ""),
            "item_key": item_key,
        })

    view = ui.LayoutView(timeout=None)
    view.add_item(ui.TextDisplay("# Deadline approaching"))
    view.add_item(ui.Separator())
    for group in by_course.values():
        view.add_item(build_course_container(uid, group))

    try:
        await user.send(view=view)
    except discord.HTTPException as exc:
        log.warning("Deadline reminder: could not DM %s: %s", uid, exc)


async def run_deadline_reminder_tick(bot: discord.Client) -> None:
    """Called on every scheduler tick (see client.py). Pure cache lookup —
    see the module comment above for why this needs no platform login.

    Gated per-user: skipped entirely for anyone who hasn't opted in with
    `/deadlinereminder on`, and measured against that user's own configured
    window (`/deadlinereminderhours`, default 12).
    """
    pending = pending_deadline_items()
    if not pending:
        return

    now = datetime.now(timezone.utc)
    by_uid: dict[str, list[tuple[str, dict]]] = {}
    for uid, key, entry in pending:
        info = registered_users.get(uid)
        if not info or not info.get("deadline_reminder_enabled"):
            continue
        hours = info.get("deadline_reminder_hours", DEFAULT_DEADLINE_REMINDER_HOURS)
        due_dt = datetime.fromisoformat(entry["due_dt"])
        if due_dt - now > timedelta(hours=hours):
            continue

        item_key = key.split(":", 3)[3]
        if is_homework_suppressed(uid, entry.get("platform", ""), entry.get("course_code", "?"), item_key):
            mark_deadline_reminded(key)  # already handled — stop re-checking it every tick
            continue
        by_uid.setdefault(uid, []).append((key, entry))

    if not by_uid:
        return

    for uid, entries in by_uid.items():
        await _send_deadline_reminder(bot, uid, entries)
        for key, _ in entries:
            mark_deadline_reminded(key)

    log.info("Deadline reminder: sent to %d user(s)", len(by_uid))
