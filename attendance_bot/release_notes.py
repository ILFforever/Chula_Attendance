"""Release notes — shown via /release and DM'd to newly registered users.

Single source of truth for both: update RELEASE_MESSAGES here and both paths
pick it up automatically. Each message is kept under Discord's DM-friendly
~500 char range on purpose — this is meant to be read at a glance, not as
full changelog prose.
"""

WELCOME_MESSAGE = (
    "**Welcome to Chula Attendance v3.3!**\n"
    "You're registered — the bot will now auto check you into MyCourseVille and ClassDeeDee "
    "attendance links/QRs the moment they're posted in a watched channel, no scrambling before they expire.\n"
    "By default that's every course. Use `/enroll <course_code>` to limit it to just yours.\n"
    "Full command list: `/help`"
)

WHATS_NEW_MESSAGE = (
    "**What's new — Homework Check & Settings**\n"
    "A daily DM listing outstanding work across MyCourseVille + ClassDeeDee, sorted by urgency, plus an "
    "off-by-default heads-up DM shortly before something's actually due.\n"
    "`/homework on` · `/deadlinereminder on` (default 12h, `/deadlinereminderhours` to change it)\n"
    "`/settings` — one panel for notifications, courses, and account (unlink ClassDeeDee or delete your "
    "account, each confirm-gated). `/classdeedee off` skips ClassDeeDee entirely."
)

WHATS_NEW_MESSAGE_3_3 = (
    "**What's new in v3.3 — Attendance opt-out**\n"
    "Only want the homework digest, not auto check-in? `/autocheckin off` stops the bot from checking you "
    "into MyCourseVille/ClassDeeDee links or QRs — Homework Check keeps working, since it only reads your "
    "outstanding work and never submits anything.\n"
    "Also on the `/settings` panel now, in its own **Attendance** card."
)

RELEASE_MESSAGES = [WELCOME_MESSAGE, WHATS_NEW_MESSAGE, WHATS_NEW_MESSAGE_3_3]
