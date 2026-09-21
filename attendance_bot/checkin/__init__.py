"""Platform-neutral check-in plumbing shared by MyCourseVille and ClassDeeDee.

This package is to attendance what `attendance_bot/homework/` is to the
homework check: each platform keeps its own login and check-in logic, while
everything that isn't platform-specific — deciding who to check in, bounding
how much runs at once, fanning the work out — lives here so the two paths
can't drift apart.

The concurrency bound is deliberately process-wide rather than per-scan: an
MCV link and a ClassDeeDee QR can now be processed at the same time, and
sizing the cap per-scan would let two overlapping scans open twice the
sessions the Fly instance has memory for.
"""
from attendance_bot.checkin.runner import (
    CHECKIN_CONCURRENCY,
    CheckInTarget,
    TargetSet,
    collect_targets,
    is_success,
    run_batch,
    succeeded,
)

__all__ = [
    "CHECKIN_CONCURRENCY",
    "CheckInTarget",
    "TargetSet",
    "collect_targets",
    "is_success",
    "run_batch",
    "succeeded",
]
