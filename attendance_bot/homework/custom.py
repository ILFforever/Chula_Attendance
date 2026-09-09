"""User-added ("custom") assignments — a third source of homework items
alongside MyCourseVille and ClassDeeDee.

Everything downstream of check.py's grouping step is platform-agnostic: it
works off a flat list of item dicts, keyed by (platform, course_code,
item_key). So a custom assignment doesn't need a parallel reminder path — it
enters that same list with `platform: "custom"` and inherits course
grouping, urgency sorting/colours, the deadline cache, the "Mark as
finished" suppression store and its Restore list, all unchanged. This module
is therefore only three things: the store's item shape, a deadline parser,
and the /homeworklist management view.

Two things a custom item does NOT inherit, both handled here or in config.py:
  - It has no URL, so `link` is "" and build_course_container has to omit
    the "Open in web" button (a link Button with url="" 400s the send).
  - It has no platform to stop reporting it once it's done, so it's deleted
    explicitly (/homeworklist) or aged out 5 days past due
    (config.prune_custom_assignments), and deleting it must also purge the
    suppression/deadline rows derived from it.

Deadline input is parsed here rather than taken as separate numeric fields:
"date + time" typed the way a person actually writes it is the whole point
of the feature being faster than opening the platform. Everything is
Bangkok-local on the way in and stored UTC, matching the rest of the
homework code.
"""
from __future__ import annotations

import asyncio
import re
from datetime import date, datetime, time, timedelta, timezone

import discord
from discord import ui

from attendance_bot.config import (
    log,
    MAX_CUSTOM_ASSIGNMENTS,
    MAX_CUSTOM_COURSE,
    MAX_CUSTOM_DESC,
    add_custom_assignment,
    list_custom_assignments,
    remove_custom_assignment,
)
from attendance_bot.mcv.attendance import TZ_BANGKOK
from attendance_bot.mcv.cugetreg import fetch_course_name

# A deadline typed with no time means the end of that day, not the start of
# it — "due Friday" is about handing something in by Friday, and defaulting
# to 00:00 would silently make everything a day early.
DEFAULT_DUE_TIME = time(23, 59)

# Typo guard. Nothing legitimate is due more than two years out, but a
# mistyped year ("2206") otherwise sails through as a valid date and sits in
# the store until someone notices.
MAX_DEADLINE_HORIZON = timedelta(days=730)


class AssignmentError(ValueError):
    """Raised with a user-facing message when an assignment can't be added.

    Every message is written to be shown to the user verbatim, so both entry
    points (the /homeworkadd command and the /settings modal) can render it
    without knowing what went wrong.
    """


class DeadlineError(AssignmentError):
    """Specifically: the date/time couldn't be read."""


_WEEKDAYS = {
    "mon": 0, "monday": 0,
    "tue": 1, "tues": 1, "tuesday": 1,
    "wed": 2, "weds": 2, "wednesday": 2,
    "thu": 3, "thur": 3, "thurs": 3, "thursday": 3,
    "fri": 4, "friday": 4,
    "sat": 5, "saturday": 5,
    "sun": 6, "sunday": 6,
}

_ISO_DATE_RE = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$")
# Day-first (12/09 = 12 September), the convention here — NOT US month-first.
_DMY_RE = re.compile(r"^(\d{1,2})[/.-](\d{1,2})(?:[/.-](\d{2}|\d{4}))?$")
_TIME_RE = re.compile(r"^(\d{1,2})(?::(\d{2}))?(am|pm)?$")

DATE_HELP = "`2026-09-12`, `12/09`, `today`, `tomorrow`, or a weekday like `fri`"
TIME_HELP = "`23:59`, `5pm`, `17:30`, `noon` — leave blank for end of day"


def _safe_date(year: int, month: int, day: int) -> date:
    try:
        return date(year, month, day)
    except ValueError:
        raise DeadlineError(f"`{day:02d}/{month:02d}/{year}` isn't a real date.") from None


def _parse_date(raw: str, today: date) -> date:
    text = raw.strip().lower()
    if not text:
        raise DeadlineError(f"No date given. Try {DATE_HELP}.")

    if text == "today":
        return today
    if text in ("tomorrow", "tmr", "tmrw"):
        return today + timedelta(days=1)

    if text in _WEEKDAYS:
        # A weekday that IS today means today, not a week out — someone
        # typing "fri" on a Friday means the deadline they're staring at.
        return today + timedelta(days=(_WEEKDAYS[text] - today.weekday()) % 7)

    m = _ISO_DATE_RE.match(text)
    if m:
        return _safe_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))

    m = _DMY_RE.match(text)
    if m:
        day, month, year_raw = int(m.group(1)), int(m.group(2)), m.group(3)
        if year_raw is None:
            # No year given: this year, unless that's already behind us — a
            # bare "05/01" typed in December means next January.
            candidate = _safe_date(today.year, month, day)
            return candidate if candidate >= today else _safe_date(today.year + 1, month, day)
        year = int(year_raw)
        return _safe_date(year + 2000 if year < 100 else year, month, day)

    raise DeadlineError(f"Couldn't read `{raw}` as a date. Try {DATE_HELP}.")


def _parse_time(raw: str) -> time:
    text = raw.strip().lower().replace(" ", "").replace(".", "")
    if not text:
        return DEFAULT_DUE_TIME
    if text == "noon":
        return time(12, 0)
    if text == "midnight":
        return time(0, 0)

    m = _TIME_RE.match(text)
    if not m:
        raise DeadlineError(f"Couldn't read `{raw}` as a time. Try {TIME_HELP}.")

    hour, minute, meridiem = int(m.group(1)), int(m.group(2) or 0), m.group(3)
    if meridiem:
        if not 1 <= hour <= 12:
            raise DeadlineError(f"`{raw}` isn't a valid 12-hour time.")
        hour = hour % 12 + (12 if meridiem == "pm" else 0)
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise DeadlineError(f"`{raw}` isn't a valid time of day.")
    return time(hour, minute)


def parse_deadline(date_raw: str, time_raw: str = "") -> datetime:
    """Read a typed date (+ optional time) as Bangkok-local, return it UTC.

    Raises DeadlineError with a message that's safe to show the user as-is.
    """
    now = datetime.now(TZ_BANGKOK)
    due_local = datetime.combine(_parse_date(date_raw, now.date()), _parse_time(time_raw), tzinfo=TZ_BANGKOK)

    if due_local <= now:
        raise DeadlineError(
            f"**{due_local.strftime('%a %d %b %Y, %H:%M')}** is in the past — "
            "a reminder for it would never fire."
        )
    if due_local - now > MAX_DEADLINE_HORIZON:
        raise DeadlineError(
            f"**{due_local.strftime('%a %d %b %Y')}** is more than two years away — check the year."
        )
    return due_local.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Creating one — shared by /homeworkadd and the /settings modal
# ---------------------------------------------------------------------------
def validate_new_assignment(uid: str, *, course: str, desc: str, due_date: str, due_time: str):
    """Check one proposed assignment, returning (course_code, desc, due_dt).

    Raises AssignmentError with a message meant for the user. Both callers
    take free text from someone typing in a hurry, so this lives here rather
    than being duplicated at each entry point.
    """
    course_code, desc_text = course.strip(), desc.strip()
    if not course_code or not desc_text:
        raise AssignmentError("Both a course and a description are required.")

    # Both course rules are about the button custom_id the code ends up
    # inside ("hw:<uid>:custom:<course>:<item>"): Discord caps that at 100
    # characters, and the click handler splits it on ":" positionally, so a
    # colon in the label would shift every field after it and quietly break
    # "Mark as finished" for the item.
    if ":" in course_code:
        raise AssignmentError("The course can't contain a colon (`:`). Try a space or a dash instead.")
    if len(course_code) > MAX_CUSTOM_COURSE:
        raise AssignmentError(
            f"Keep the course under {MAX_CUSTOM_COURSE} characters — it's used as the heading "
            "your assignment is grouped under."
        )
    if len(desc_text) > MAX_CUSTOM_DESC:
        raise AssignmentError(
            f"That description is {len(desc_text)} characters — keep it under {MAX_CUSTOM_DESC} "
            "so it fits on one line in your digest."
        )
    if len(list_custom_assignments(uid)) >= MAX_CUSTOM_ASSIGNMENTS:
        raise AssignmentError(
            f"You've got the maximum {MAX_CUSTOM_ASSIGNMENTS} assignments added. "
            "Use `/homeworklist` to delete one first."
        )

    return course_code, desc_text, parse_deadline(due_date, due_time)


async def create_assignment(uid: str, *, course: str, desc: str, due_date: str, due_time: str) -> dict:
    """Validate, resolve the course's real name if it's a course code, store.

    Returns the stored record. Raises AssignmentError (already user-facing).

    The CU Get Reg lookup runs on asyncio's default thread pool rather than
    the bot's check-in executor: that pool has a single worker reserved for
    time-critical attendance check-ins, and a cosmetic name lookup has no
    business queueing behind one.
    """
    course_code, desc_text, due_dt = validate_new_assignment(
        uid, course=course, desc=desc, due_date=due_date, due_time=due_time
    )

    course_name = ""
    if course_code.isdigit():
        try:
            info = await asyncio.to_thread(fetch_course_name, course_code)
            course_name = (info or {}).get("name_short", "")
        except Exception as exc:  # noqa: BLE001 - a missing name must never fail the add
            log.info("Course name lookup failed for %s: %s", course_code, exc)

    add_custom_assignment(
        uid, desc=desc_text, course_code=course_code, course_name=course_name, due_dt=due_dt,
    )
    log.info("User %s added a custom assignment for %s", uid, course_code)
    return {"course_code": course_code, "course_name": course_name, "desc": desc_text, "due_dt": due_dt}


def format_due(due_dt_iso: str) -> str:
    """Absolute Bangkok-local rendering for the management view.

    Deliberately not the digest's relative phrasing ("in 3 days"): this list
    is where someone checks whether they typed the deadline in correctly, and
    only the absolute date answers that.
    """
    try:
        dt = datetime.fromisoformat(due_dt_iso)
    except (ValueError, TypeError):
        return "unknown"
    return dt.astimezone(TZ_BANGKOK).strftime("%a %d %b, %H:%M")


def custom_items_for_user(uid: str) -> list[dict]:
    """This user's custom assignments, shaped exactly like the MCV/ClassDeeDee
    items check.py builds, so they can be appended to the same raw list.

    `due_text` is the raw ISO string on purpose — dm.py's _pretty_due_text
    renders any ISO due text into relative/absolute wording, so custom items
    read identically to ClassDeeDee's.
    """
    now = datetime.now(timezone.utc)
    items = []
    for item_id, rec in list_custom_assignments(uid):
        try:
            due_dt = datetime.fromisoformat(rec.get("due_dt", ""))
        except (ValueError, TypeError):
            continue
        items.append({
            "platform": "custom",
            "course_code": rec.get("course_code") or "?",
            "course_name": rec.get("course_name") or "",
            "title": rec.get("desc") or "Untitled",
            "due_text": rec["due_dt"],
            "days": (due_dt - now).total_seconds() / 86400.0,
            "due_dt": due_dt,
            "link": "",
            "item_key": item_id,
        })
    return items


# ---------------------------------------------------------------------------
# /homeworklist — management view
# ---------------------------------------------------------------------------
# Custom items only, deliberately: every row here carries a Delete button,
# and a MyCourseVille/ClassDeeDee item can't be deleted — half the list would
# be dead buttons. The all-platforms view is the digest itself
# (/homeworkcheck), which the footer line points at.
def _delete_id(uid: str, item_id: str) -> str:
    return f"hwc:del:{uid}:{item_id}"


def build_assignment_list_view(uid: str) -> ui.LayoutView:
    entries = list_custom_assignments(uid)
    view = ui.LayoutView(timeout=None)

    if not entries:
        view.add_item(ui.TextDisplay(
            "# Your added assignments\n"
            "Nothing added yet — use `/homeworkadd` to add one with your own deadline.\n"
            "-# They show up in your homework digest next to MyCourseVille and ClassDeeDee work."
        ))
        return view

    view.add_item(ui.TextDisplay(
        f"# Your added assignments\n"
        f"-# {len(entries)} of {MAX_CUSTOM_ASSIGNMENTS} · shown in your digest alongside MyCourseVille and ClassDeeDee"
    ))
    for item_id, rec in entries:
        course = rec.get("course_code") or "?"
        # Both lines in ONE TextDisplay, not two: Discord's 40-component cap
        # counts every component recursively, and at 4 per row (Section + 2
        # TextDisplay + Button) a full list of MAX_CUSTOM_ASSIGNMENTS blew
        # past it. TextDisplay renders multi-line Markdown natively, so this
        # is the same trick settings_panel.py uses to fit its cards.
        view.add_item(ui.Section(
            ui.TextDisplay(
                f"**{rec.get('desc') or 'Untitled'}**\n"
                f"`{course}` · Due {format_due(rec.get('due_dt', ''))}"
            ),
            accessory=ui.Button(
                style=discord.ButtonStyle.danger,
                label="🗑️ Delete",
                custom_id=_delete_id(uid, item_id),
            ),
        ))
    view.add_item(ui.TextDisplay(
        "-# Deleting one here removes it everywhere, including any reminder already queued for it. "
        "`/homeworkcheck` shows these together with your MyCourseVille and ClassDeeDee work."
    ))
    return view


async def handle_custom_assignment_button(interaction: discord.Interaction) -> None:
    """Route an "hwc:" component click.

    A raw listener registered in client.py, not a View callback — same
    reasoning as homework/dm.py's "hw:" handler: the list message has to
    keep working after a restart.
    """
    if interaction.type != discord.InteractionType.component:
        return
    custom_id = (interaction.data or {}).get("custom_id", "")
    if not custom_id.startswith("hwc:"):
        return

    parts = custom_id.split(":", 3)
    if len(parts) != 4 or parts[1] != "del":
        await interaction.response.defer()
        return
    _, _, uid, item_id = parts

    if str(interaction.user.id) != uid:
        await interaction.response.send_message("This isn't your assignment list.", ephemeral=True)
        return

    if remove_custom_assignment(uid, item_id) is not None:
        log.info("User %s deleted a custom assignment", uid)

    # Rebuilt rather than struck through in place: the header carries a
    # live "N of MAX" count, so the whole view has to re-render anyway.
    await interaction.response.edit_message(view=build_assignment_list_view(uid))
