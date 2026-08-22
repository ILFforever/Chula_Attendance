"""Release notes — shown via /release and DM'd to newly registered users.

Single source of truth for both: update RELEASE_MESSAGES here and both paths
pick it up automatically. Each message is kept under Discord's DM-friendly
~500 char range on purpose — this is meant to be read at a glance, not as
full changelog prose.
"""

WELCOME_MESSAGE = (
    "👋 **Welcome to Chula Attendance v3.0!**\n"
    "You're registered — the bot will now auto check you into MyCourseVille and ClassDeeDee "
    "attendance links/QRs the moment they're posted in a watched channel, no scrambling before they expire.\n"
    "By default that's every course. Use `/enroll <course_code>` to limit it to just yours.\n"
    "Full command list: `/help`"
)

WHATS_NEW_MESSAGE = (
    "🆕 **What's new in v3.0 — Homework Check**\n"
    "Get a daily DM listing outstanding work across both platforms, sorted by urgency, with buttons "
    "to open each item or mark it done (undo anytime, no harm done).\n"
    "`/homework on` · `/homeworktime <hr>` · `/homeworkcheck` to try now\n"
    "Also: `/classdeedee off` lets CU Net accounts skip ClassDeeDee entirely."
)

RELEASE_MESSAGES = [WELCOME_MESSAGE, WHATS_NEW_MESSAGE]
