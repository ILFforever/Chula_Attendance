"""Consolidated /settings panel — one Components V2 message covering the
personal controls that would otherwise need their own slash command to
check or change: notification preferences (homework digest, deadline
reminder), automatic check-in + course enrollment, ClassDeeDee (its own
card — see _build_classdeedee_card for why it doesn't fit under either of
the other two), and account management. Server/channel-scoped commands
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

Custom IDs use a "cfg:" prefix and are routed by a raw on_interaction
listener (not View callbacks), so a click keeps working even after a bot
restart — same reasoning as homework/dm.py's "hw:"/"hwctl:" listener.
"""
from __future__ import annotations

import discord
from discord import ui

from attendance_bot.config import log, registered_users, persist_users
from attendance_bot.homework.dm import (
    DEFAULT_HOMEWORK_HOUR,
    DEFAULT_DEADLINE_REMINDER_HOURS,
    MIN_DEADLINE_REMINDER_HOURS,
    MAX_DEADLINE_REMINDER_HOURS,
)
from attendance_bot.classdeedee.attendance import classdeedee_purpose_enabled


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


# Discord's message-component budget is a flat 40 components per message,
# counted recursively across the whole view — a Container, a Section, and
# each TextDisplay/Button/Separator inside one all count individually. With
# 4 cards, splitting every line of text into its own TextDisplay blew past
# that (43 vs. the 40 cap). TextDisplay natively renders multi-line Markdown
# in one component, so every card below joins its lines with "\n" into as
# few TextDisplay components as layout allows, instead of one per line.
def _build_identity_card(user: discord.abc.User, info: dict) -> ui.Container:
    """The info-panel header: avatar, display name, @handle, Discord ID, and
    (when registered) the MyCourseVille username/login method.
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
    return ui.Container(identity, accent_colour=BRAND_ACCENT)


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


def build_settings_view(user: discord.abc.User) -> ui.LayoutView:
    """Rebuilt fresh on every render (initial send, and after every click)
    so it always reflects registered_users' current state. Five Container
    cards — identity, notifications, attendance (incl. courses), classdeedee,
    account — each carrying the same brand-pink accent bar so the panel
    reads as one surface, not a stack of unrelated message blocks.
    """
    uid = str(user.id)
    info = registered_users.get(uid, {})

    view = ui.LayoutView(timeout=None)
    view.add_item(_build_identity_card(user, info))
    view.add_item(_build_notifications_card(uid, info))
    view.add_item(_build_attendance_card(uid, info))
    view.add_item(_build_classdeedee_card(uid, info))
    view.add_item(_build_account_card(uid, info))
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
        await interaction.response.edit_message(view=build_settings_view(interaction.user))


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
        await interaction.response.edit_message(view=build_settings_view(interaction.user))


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

        await interaction.response.edit_message(view=build_settings_view(interaction.user))


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

        await interaction.response.edit_message(view=build_settings_view(interaction.user))


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

    await interaction.response.edit_message(view=build_settings_view(interaction.user))
