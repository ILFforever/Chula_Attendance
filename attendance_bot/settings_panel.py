"""Consolidated /settings panel — one Components V2 message covering the
personal controls that would otherwise need their own slash command to
check or change: notification preferences (homework digest, deadline
reminder), the user's own added assignments, automatic check-in + course
enrollment, ClassDeeDee (its own card — see _build_classdeedee_card for why
it doesn't fit under either of the other two), and account management. Server/channel-scoped commands
(/monitor, /leaderboard, etc.) stay out of scope — this is about the
individual user's own account.

Discord modals only support text inputs — no toggle buttons or dropdowns —
so this can't be a single modal (see the /settings design discussion).
Instead it's a LayoutView: toggle buttons flip in place via edit_message,
and free-text fields (digest hour, reminder window, a course code to add)
each open a short-lived modal from their own button, mirroring
homework/dm.py's existing "Change reminder time" control. Removing a course
opens a short second ephemeral message with one "Remove" button per
enrolled course — deliberately not a Select, so this stays consistent with
homework/dm.py's own "View finished items" list pattern.

The five sections are tabs, not one long scroll: a nav ActionRow lives in
the always-pinned identity card, and clicking a tab edits the message in
place to swap the single section card below it (see build_settings_view).

Custom IDs use a "cfg:" prefix and are routed by a raw on_interaction
listener (not View callbacks), so a click keeps working even after a bot
restart — same reasoning as homework/dm.py's "hw:"/"hwctl:" listener.
"""
from __future__ import annotations

import discord
from discord import ui

from attendance_bot.config import (
    log,
    registered_users,
    persist_users,
    purge_custom_assignments_for_user,
    list_custom_assignments,
    MAX_CUSTOM_ASSIGNMENTS,
    MAX_CUSTOM_COURSE,
    MAX_CUSTOM_DESC,
)
from attendance_bot.homework.dm import (
    DEFAULT_HOMEWORK_HOUR,
    DEFAULT_DEADLINE_REMINDER_HOURS,
    MIN_DEADLINE_REMINDER_HOURS,
    MAX_DEADLINE_REMINDER_HOURS,
)
from attendance_bot.classdeedee.attendance import classdeedee_purpose_enabled
from attendance_bot.homework.custom import (
    AssignmentError,
    build_assignment_list_view,
    create_assignment,
    format_due,
)


# The bot's own brand pink (matches docs/index.html's --pink token) — used as
# every card's accent bar so the panel reads as one cohesive, branded surface
# rather than a stack of unrelated Discord-default-grey message blocks.
BRAND_ACCENT = discord.Color(0xC31569)


def _cfg_id(kind: str, uid: str) -> str:
    return f"cfg:{kind}:{uid}"


def _on_off(flag: bool) -> str:
    return "ON" if flag else "OFF"


def _toggle_button(*, enabled: bool, label_suffix: str = "", custom_id: str) -> ui.Button:
    label = "Turn off" if enabled else "Turn on"
    if label_suffix:
        label += " " + label_suffix
    return ui.Button(
        style=discord.ButtonStyle.danger if enabled else discord.ButtonStyle.success,
        label=label,
        custom_id=custom_id,
    )


# The panel is paginated rather than one long scroll: the identity card and
# its nav row are always rendered, and exactly one section card below them.
# Four sections at ~10 components each would sit near Discord's 40-component
# ceiling (see the note below) with no room left for the nav row itself, so
# tabs buy headroom as well as legibility.
# Five tabs is the ceiling here, not a coincidence: an ActionRow holds at
# most 5 buttons, so a sixth section would need a second nav row.
_PAGES: list[tuple[str, str, str]] = [
    ("notifications", "Notifications", "🔔"),
    ("assignments", "Assignments", "📌"),
    ("attendance", "Attendance", "📝"),
    ("classdeedee", "ClassDeeDee", "🎓"),
    ("account", "Account", "⚙"),
]
DEFAULT_PAGE = _PAGES[0][0]

# Which page each "cfg:" control lives on, so flipping a toggle or submitting
# a modal re-renders the page the user was already on instead of bouncing
# them back to the default one.
_PAGE_FOR_KIND = {
    "hwtoggle": "notifications",
    "hwtime": "notifications",
    "drtoggle": "notifications",
    "drtime": "notifications",
    "addassignment": "assignments",
    "manageassignments": "assignments",
    "checkintoggle": "attendance",
    "addcourse": "attendance",
    "managecourses": "attendance",
    "cddcheckintoggle": "classdeedee",
    "cddhwtoggle": "classdeedee",
    "unlinkcdd": "account",
    "delaccount": "account",
}


def _build_nav_row(uid: str, active: str) -> ui.ActionRow:
    """The tab strip. The active tab renders primary + disabled — "you are
    here", and a click on it would only re-send the page already on screen.
    Page lives in a 4th custom_id segment (like "cfg:rmcourse:"), so the nav
    survives a restart the same way every other control here does.
    """
    return ui.ActionRow(*[
        ui.Button(
            style=discord.ButtonStyle.primary if key == active else discord.ButtonStyle.secondary,
            label=label,
            emoji=emoji,
            disabled=key == active,
            custom_id=f"cfg:nav:{uid}:{key}",
        )
        for key, label, emoji in _PAGES
    ])


# Discord's message-component budget is a flat 40 components per message,
# counted recursively across the whole view — a Container, a Section, and
# each TextDisplay/Button/Separator inside one all count individually. With
# 4 cards, splitting every line of text into its own TextDisplay blew past
# that (43 vs. the 40 cap). TextDisplay natively renders multi-line Markdown
# in one component, so every card below joins its lines with "\n" into as
# few TextDisplay components as layout allows, instead of one per line.
def _build_identity_card(user: discord.abc.User, info: dict, active_page: str) -> ui.Container:
    """The pinned header: avatar, display name, @handle, Discord ID,
    (when registered) the MyCourseVille username/login method, and the nav
    row. Always on screen, so the user keeps their bearings while the
    section card below them changes.
    """
    lines = [f"# {user.display_name}", f"-# @{user.name} · ID `{user.id}`"]
    mcv_username = info.get("username")
    if mcv_username:
        method = "CU Net" if info.get("login_method", "cu_net") == "cu_net" else "MCV account"
        lines.append(f"-# MyCourseVille: `{mcv_username}` ({method})")

    identity = ui.Section(
        ui.TextDisplay("\n".join(lines)),
        accessory=ui.Thumbnail(media=user.display_avatar.url),
    )
    return ui.Container(
        identity,
        ui.Separator(),
        _build_nav_row(str(user.id), active_page),
        accent_colour=BRAND_ACCENT,
    )


def _build_notifications_card(uid: str, info: dict) -> ui.Container:
    """DM preferences only. ClassDeeDee deliberately lives in its own card
    (see _build_classdeedee_card) — it's not just a notification toggle, it
    also gates check-in (classdeedee.attendance.check_in_all), so grouping
    it here alongside two DM-only settings undersold what it actually does.
    """
    hw_on = info.get("homework_check", False)
    hw_hour = info.get("homework_check_hour", DEFAULT_HOMEWORK_HOUR)
    dr_on = info.get("deadline_reminder_enabled", False)
    dr_hours = info.get("deadline_reminder_hours", DEFAULT_DEADLINE_REMINDER_HOURS)

    # The toggle button's own label ("Turn off X" / "Turn on X") already says
    # whether a setting is on or off — a status line is only worth adding
    # when it carries information the button doesn't (a configured time/window).
    hw_lines = ["## Homework digest", "-# Daily DM listing outstanding work, sorted by urgency"]
    if hw_on:
        hw_lines.append(f"Arrives **{hw_hour:02d}:00** Bangkok")

    dr_lines = ["## Deadline reminder", "-# Heads-up DM shortly before something unfinished is due"]
    if dr_on:
        dr_lines.append(f"**{dr_hours}h** before due")

    return ui.Container(
        ui.TextDisplay("# Notifications\n-# Daily digest and deadline reminder"),
        ui.Separator(),
        ui.TextDisplay("\n".join(hw_lines)),
        ui.ActionRow(
            _toggle_button(enabled=hw_on, custom_id=_cfg_id("hwtoggle", uid)),
            ui.Button(style=discord.ButtonStyle.secondary, label="Set digest time", custom_id=_cfg_id("hwtime", uid)),
        ),
        ui.TextDisplay("\n".join(dr_lines)),
        ui.ActionRow(
            _toggle_button(enabled=dr_on, custom_id=_cfg_id("drtoggle", uid)),
            ui.Button(style=discord.ButtonStyle.secondary, label="Set reminder window", custom_id=_cfg_id("drtime", uid)),
        ),
        accent_colour=BRAND_ACCENT,
    )


def _build_classdeedee_card(uid: str, info: dict) -> ui.Container:
    """Its own card, not folded into Notifications or Attendance — check-in
    and homework are separate flags now (classdeedee_checkin_enabled /
    classdeedee_homework_enabled, see classdeedee_purpose_enabled), each
    gating a different consumer, so this card needs its own two toggles
    rather than fitting cleanly under either of the other cards.
    """
    checkin_on = classdeedee_purpose_enabled(info, "checkin")
    homework_on = classdeedee_purpose_enabled(info, "homework")
    return ui.Container(
        ui.TextDisplay("# ClassDeeDee\n-# Separate switches for check-in and homework"),
        ui.Separator(),
        ui.ActionRow(
            _toggle_button(enabled=checkin_on, label_suffix="Check-in", custom_id=_cfg_id("cddcheckintoggle", uid)),
            _toggle_button(enabled=homework_on, label_suffix="Homework", custom_id=_cfg_id("cddhwtoggle", uid)),
        ),
        accent_colour=BRAND_ACCENT,
    )


def _build_attendance_card(uid: str, info: dict) -> ui.Container:
    """Automatic check-in and course enrollment together — both are about
    what the bot does when a link/QR is posted, not a DM preference (that's
    the separate Notifications card), so they share one card.
    """
    checkin_on = info.get("checkin_enabled", True)
    subjects = info.get("subjects", [])
    courses_text = ", ".join(f"`{c}`" for c in subjects) if subjects else "None — checked in for **all** courses"

    course_buttons = [
        ui.Button(style=discord.ButtonStyle.secondary, label="Add course", custom_id=_cfg_id("addcourse", uid)),
    ]
    if subjects:
        course_buttons.append(
            ui.Button(style=discord.ButtonStyle.secondary, label="Manage courses", custom_id=_cfg_id("managecourses", uid))
        )

    return ui.Container(
        ui.TextDisplay(
            "# Attendance\n-# Whether the bot checks you in automatically, and for which courses"
        ),
        ui.Separator(),
        ui.TextDisplay("## Automatic check-in\n-# MyCourseVille + ClassDeeDee, on by default"),
        ui.ActionRow(
            _toggle_button(enabled=checkin_on, custom_id=_cfg_id("checkintoggle", uid)),
        ),
        ui.TextDisplay(f"## Courses\n{courses_text}"),
        ui.ActionRow(*course_buttons),
        accent_colour=BRAND_ACCENT,
    )


def _build_assignments_card(uid: str, info: dict) -> ui.Container:
    """Assignments the user typed in themselves (/homeworkadd).

    Summary + two buttons rather than the list itself, mirroring the
    Attendance card's "Add course"/"Manage courses" pair: the full list
    with its per-item Delete buttons opens as a second ephemeral message
    (build_assignment_list_view), which keeps this page's component count
    flat no matter how many assignments someone has.
    """
    entries = list_custom_assignments(uid)

    lines = [
        "# Assignments",
        "-# Your own deadlines, shown in the digest next to MyCourseVille and ClassDeeDee work",
    ]
    if entries:
        _, soonest = entries[0]
        lines.append(f"**{len(entries)} of {MAX_CUSTOM_ASSIGNMENTS}** added")
        lines.append(
            f"-# Next up: {soonest.get('desc') or 'Untitled'} · "
            f"`{soonest.get('course_code') or '?'}` · {format_due(soonest.get('due_dt', ''))}"
        )
    else:
        lines.append("-# Nothing added yet — anything with a deadline the platforms don't list.")

    buttons = [
        ui.Button(
            style=discord.ButtonStyle.secondary, label="Add assignment",
            custom_id=_cfg_id("addassignment", uid),
            disabled=len(entries) >= MAX_CUSTOM_ASSIGNMENTS,
        ),
    ]
    if entries:
        buttons.append(ui.Button(
            style=discord.ButtonStyle.secondary, label="Manage assignments",
            custom_id=_cfg_id("manageassignments", uid),
        ))

    return ui.Container(
        ui.TextDisplay("\n".join(lines)),
        ui.Separator(),
        ui.ActionRow(*buttons),
        accent_colour=BRAND_ACCENT,
    )


def _build_account_card(uid: str, info: dict) -> ui.Container:
    """Destructive actions only — both gated behind a type-to-confirm modal
    (see ConfirmUnlinkClassDeeDeeModal / ConfirmDeleteAccountModal) since a
    stray click on a plain button would otherwise delete something with no
    way back. Both buttons always render, so the panel's layout doesn't
    shift around; "Unlink ClassDeeDee" is greyed out (disabled) instead of
    hidden when there's no separate `chulasso` sub-credential to remove — a
    cu_net login IS its ClassDeeDee login, so there's nothing to unlink
    without deleting the whole account (see /deedeeunregister).
    """
    has_chulasso = bool(info.get("chulasso"))
    unlink_button = ui.Button(
        style=discord.ButtonStyle.danger,
        label="Unlink ClassDeeDee",
        custom_id=_cfg_id("unlinkcdd", uid),
        disabled=not has_chulasso,
    )
    delete_button = ui.Button(
        style=discord.ButtonStyle.danger, label="Delete account", custom_id=_cfg_id("delaccount", uid)
    )

    lines = ["# Account", "-# Destructive — each asks you to type a word to confirm first"]
    if not has_chulasso:
        lines.append("-# Unlink ClassDeeDee is greyed out — no separate ClassDeeDee login on file to remove")

    return ui.Container(
        ui.TextDisplay("\n".join(lines)),
        ui.Separator(),
        ui.ActionRow(unlink_button, delete_button),
        accent_colour=BRAND_ACCENT,
    )


# Keys must match _PAGES; every builder takes (uid, info) so the dispatch in
# build_settings_view stays a plain lookup.
_PAGE_BUILDERS = {
    "notifications": _build_notifications_card,
    "assignments": _build_assignments_card,
    "attendance": _build_attendance_card,
    "classdeedee": _build_classdeedee_card,
    "account": _build_account_card,
}


def build_settings_view(user: discord.abc.User, page: str = DEFAULT_PAGE) -> ui.LayoutView:
    """Rebuilt fresh on every render (initial send, and after every click)
    so it always reflects registered_users' current state. Two Container
    cards — the pinned identity/nav header and whichever section the nav row
    currently has selected — both carrying the same brand-pink accent bar so
    the panel reads as one surface, not a stack of unrelated message blocks.
    """
    uid = str(user.id)
    info = registered_users.get(uid, {})
    # An unknown page (a stale custom_id from before a page was renamed)
    # falls back rather than raising — the click still shows something.
    if page not in _PAGE_BUILDERS:
        page = DEFAULT_PAGE

    view = ui.LayoutView(timeout=None)
    view.add_item(_build_identity_card(user, info, page))
    view.add_item(_PAGE_BUILDERS[page](uid, info))
    return view


def build_manage_courses_view(uid: str) -> ui.LayoutView:
    """A short second message: one "Remove" button per enrolled course."""
    subjects = registered_users.get(uid, {}).get("subjects", [])
    view = ui.LayoutView(timeout=None)
    if not subjects:
        view.add_item(ui.TextDisplay("You have no courses enrolled."))
        return view

    view.add_item(ui.TextDisplay("-# Tap Remove to drop a course from your enrollment list."))
    for code in subjects:
        view.add_item(ui.Section(
            ui.TextDisplay(f"`{code}`"),
            ui.TextDisplay("​"),
            accessory=ui.Button(
                style=discord.ButtonStyle.danger, label="Remove",
                custom_id=f"cfg:rmcourse:{uid}:{code}",
            ),
        ))
    return view


class HomeworkTimeSettingsModal(ui.Modal, title="Homework digest time"):
    hour_input = ui.TextInput(label="Hour (0-23, Bangkok time)", placeholder="e.g. 8 for 8am", min_length=1, max_length=2)

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
            await interaction.response.send_message(f'❌ "{raw}" isn\'t a whole number 0-23.', ephemeral=True)
            return

        registered_users.setdefault(self.uid, {})["homework_check_hour"] = hour
        persist_users()
        log.info("User %s set homework check hour to %d (via /settings)", self.uid, hour)
        await interaction.response.edit_message(
            view=build_settings_view(interaction.user, _PAGE_FOR_KIND["hwtime"])
        )


class DeadlineReminderHoursModal(ui.Modal, title="Deadline reminder window"):
    hours_input = ui.TextInput(
        label=f"Hours before due ({MIN_DEADLINE_REMINDER_HOURS}-{MAX_DEADLINE_REMINDER_HOURS})",
        placeholder=f"e.g. {DEFAULT_DEADLINE_REMINDER_HOURS}",
        min_length=1, max_length=2,
    )

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        raw = self.hours_input.value.strip()
        try:
            hours = int(raw)
            if not (MIN_DEADLINE_REMINDER_HOURS <= hours <= MAX_DEADLINE_REMINDER_HOURS):
                raise ValueError
        except ValueError:
            await interaction.response.send_message(
                f'❌ "{raw}" isn\'t a whole number {MIN_DEADLINE_REMINDER_HOURS}-{MAX_DEADLINE_REMINDER_HOURS}.',
                ephemeral=True,
            )
            return

        registered_users.setdefault(self.uid, {})["deadline_reminder_hours"] = hours
        persist_users()
        log.info("User %s set deadline reminder window to %dh (via /settings)", self.uid, hours)
        await interaction.response.edit_message(
            view=build_settings_view(interaction.user, _PAGE_FOR_KIND["drtime"])
        )


class AddCourseModal(ui.Modal, title="Add a course"):
    course_input = ui.TextInput(label="Course code", placeholder="e.g. 2110405", min_length=4, max_length=20)

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        raw = self.course_input.value.strip()
        if not raw.isdigit():
            await interaction.response.send_message(
                "❌ Enter a numeric course code (e.g. `2110405`). Use `/enroll` instead if you'd rather paste an MCV link.",
                ephemeral=True,
            )
            return

        subjects = registered_users.setdefault(self.uid, {}).setdefault("subjects", [])
        if raw not in subjects:
            subjects.append(raw)
            persist_users()
            log.info("User %s enrolled in course %s (via /settings)", self.uid, raw)

        await interaction.response.edit_message(
            view=build_settings_view(interaction.user, _PAGE_FOR_KIND["addcourse"])
        )


class AddAssignmentModal(ui.Modal, title="Add an assignment"):
    """The /settings twin of /homeworkadd.

    Four separate inputs rather than one "when is it due" field: a modal
    can't validate as you type, so splitting date from time keeps the error
    message specific about which half didn't parse. Everything past reading
    the fields — validation, the course-name lookup, the write — is
    homework/custom.py's create_assignment, so both entry points can't drift.
    """
    course_input = ui.TextInput(
        label="Course", placeholder="e.g. 2110405, or a label like Thesis", max_length=MAX_CUSTOM_COURSE,
    )
    desc_input = ui.TextInput(
        label="What's due", placeholder="e.g. Lab 4 writeup", max_length=MAX_CUSTOM_DESC,
    )
    date_input = ui.TextInput(label="Date", placeholder="2026-09-12 · 12/09 · today · tomorrow · fri", max_length=32)
    time_input = ui.TextInput(
        label="Time (optional)", placeholder="23:59 · 5pm · noon — blank for end of day",
        max_length=16, required=False,
    )

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        try:
            rec = await create_assignment(
                self.uid,
                course=self.course_input.value,
                desc=self.desc_input.value,
                due_date=self.date_input.value,
                due_time=self.time_input.value or "",
            )
        except AssignmentError as exc:
            # Its own message, not an edit of the panel: the panel is still
            # on screen behind this, and the user needs to see what to retype.
            await interaction.response.send_message(f"❌ {exc}", ephemeral=True)
            return

        log.info("User %s added a custom assignment for %s (via /settings)", self.uid, rec["course_code"])
        await interaction.response.edit_message(view=build_settings_view(interaction.user, "assignments"))


class ConfirmUnlinkClassDeeDeeModal(ui.Modal, title="Unlink ClassDeeDee"):
    confirm_input = ui.TextInput(label='Type "UNLINK" to confirm', placeholder="UNLINK", min_length=1, max_length=20)

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        if self.confirm_input.value.strip().upper() != "UNLINK":
            await interaction.response.send_message(
                '❌ Didn\'t match — type exactly "UNLINK" to confirm. Nothing was changed.', ephemeral=True
            )
            return

        info = registered_users.get(self.uid)
        if info is not None:
            info.pop("chulasso", None)
            persist_users()
            log.info("User %s unlinked ClassDeeDee (via /settings)", self.uid)

        await interaction.response.edit_message(
            view=build_settings_view(interaction.user, _PAGE_FOR_KIND["unlinkcdd"])
        )


class ConfirmDeleteAccountModal(ui.Modal, title="Delete your account"):
    confirm_input = ui.TextInput(label='Type "DELETE" to confirm', placeholder="DELETE", min_length=1, max_length=20)

    def __init__(self, uid: str):
        super().__init__()
        self.uid = uid

    async def on_submit(self, interaction: discord.Interaction):
        if self.confirm_input.value.strip().upper() != "DELETE":
            await interaction.response.send_message(
                '❌ Didn\'t match — type exactly "DELETE" to confirm. Nothing was deleted.', ephemeral=True
            )
            return

        registered_users.pop(self.uid, None)
        persist_users()
        purge_custom_assignments_for_user(self.uid)
        log.info("User %s deleted their account (via /settings)", self.uid)

        deleted_view = ui.LayoutView(timeout=None)
        deleted_view.add_item(ui.TextDisplay("# Account deleted"))
        deleted_view.add_item(ui.TextDisplay(
            "Your credentials and all settings have been removed. Run `/register` any time to start over."
        ))
        await interaction.response.edit_message(view=deleted_view)


async def handle_settings_interaction(interaction: discord.Interaction) -> None:
    """Route a "cfg:" component click. Registered as a raw listener so it
    keeps working across restarts (see module docstring).
    """
    if interaction.type != discord.InteractionType.component:
        return
    custom_id = (interaction.data or {}).get("custom_id", "")
    if not custom_id.startswith("cfg:"):
        return

    if custom_id.startswith("cfg:nav:"):
        _, _, uid, page = custom_id.split(":", 3)
        if str(interaction.user.id) != uid:
            await interaction.response.send_message("This isn't your settings panel.", ephemeral=True)
            return
        await interaction.response.edit_message(view=build_settings_view(interaction.user, page))
        return

    if custom_id.startswith("cfg:rmcourse:"):
        _, _, uid, code = custom_id.split(":", 3)
        if str(interaction.user.id) != uid:
            await interaction.response.send_message("This isn't your settings panel.", ephemeral=True)
            return
        subjects = registered_users.get(uid, {}).get("subjects", [])
        if code in subjects:
            subjects.remove(code)
            persist_users()
            log.info("User %s unenrolled from course %s (via /settings)", uid, code)
        await interaction.response.edit_message(view=build_manage_courses_view(uid))
        return

    parts = custom_id.split(":", 2)
    if len(parts) != 3:
        await interaction.response.defer()
        return
    _, kind, uid = parts

    if str(interaction.user.id) != uid:
        await interaction.response.send_message("This isn't your settings panel.", ephemeral=True)
        return

    if uid not in registered_users:
        await interaction.response.send_message("❌ You need to `/register` first.", ephemeral=True)
        return

    if kind == "hwtime":
        await interaction.response.send_modal(HomeworkTimeSettingsModal(uid))
        return
    if kind == "drtime":
        await interaction.response.send_modal(DeadlineReminderHoursModal(uid))
        return
    if kind == "addcourse":
        await interaction.response.send_modal(AddCourseModal(uid))
        return
    if kind == "addassignment":
        await interaction.response.send_modal(AddAssignmentModal(uid))
        return
    if kind == "manageassignments":
        # The same view /homeworklist opens, with its own "hwc:" delete
        # buttons — routed by homework/custom.py, not by this module.
        await interaction.response.send_message(view=build_assignment_list_view(uid), ephemeral=True)
        return
    if kind == "managecourses":
        await interaction.response.send_message(view=build_manage_courses_view(uid), ephemeral=True)
        return
    if kind == "unlinkcdd":
        await interaction.response.send_modal(ConfirmUnlinkClassDeeDeeModal(uid))
        return
    if kind == "delaccount":
        await interaction.response.send_modal(ConfirmDeleteAccountModal(uid))
        return

    if kind == "hwtoggle":
        new_state = not registered_users[uid].get("homework_check", False)
        registered_users[uid]["homework_check"] = new_state
        persist_users()
        log.info("User %s %s homework digest (via /settings)", uid, "enabled" if new_state else "disabled")
    elif kind == "drtoggle":
        new_state = not registered_users[uid].get("deadline_reminder_enabled", False)
        registered_users[uid]["deadline_reminder_enabled"] = new_state
        persist_users()
        log.info("User %s %s deadline reminder (via /settings)", uid, "enabled" if new_state else "disabled")
    elif kind == "cddcheckintoggle":
        new_state = not classdeedee_purpose_enabled(registered_users[uid], "checkin")
        registered_users[uid]["classdeedee_checkin_enabled"] = new_state
        persist_users()
        log.info("User %s %s ClassDeeDee check-in (via /settings)", uid, "enabled" if new_state else "disabled")
    elif kind == "cddhwtoggle":
        new_state = not classdeedee_purpose_enabled(registered_users[uid], "homework")
        registered_users[uid]["classdeedee_homework_enabled"] = new_state
        persist_users()
        log.info("User %s %s ClassDeeDee homework (via /settings)", uid, "enabled" if new_state else "disabled")
    elif kind == "checkintoggle":
        new_state = not registered_users[uid].get("checkin_enabled", True)
        registered_users[uid]["checkin_enabled"] = new_state
        persist_users()
        log.info("User %s %s automatic check-in (via /settings)", uid, "enabled" if new_state else "disabled")
    else:
        await interaction.response.defer()
        return

    await interaction.response.edit_message(
        view=build_settings_view(interaction.user, _PAGE_FOR_KIND.get(kind, DEFAULT_PAGE))
    )
