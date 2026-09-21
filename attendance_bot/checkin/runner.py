"""Shared target collection and bounded fan-out for both check-in platforms."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from attendance_bot.config import log, registered_users

# Max platform logins in flight at any moment, across every concurrent scan.
# CDD_CHECKIN_CONCURRENCY is the name this was deployed under before the bound
# became shared, so it is still honoured as a fallback.
CHECKIN_CONCURRENCY = max(1, int(
    os.environ.get("CHECKIN_CONCURRENCY")
    or os.environ.get("CDD_CHECKIN_CONCURRENCY")
    or "16"
))

# Process-wide, not per-scan. Each worker holds a slot for the whole of its
# login+check, so N simultaneous scans still never exceed CHECKIN_CONCURRENCY
# concurrent sessions — which is what keeps a double scan inside the Fly
# instance's 256 MB budget (~1.5 MB per concurrent login).
_login_slots = threading.BoundedSemaphore(CHECKIN_CONCURRENCY)


@dataclass
class CheckInTarget:
    """One user to attempt a check-in for, with credentials already resolved."""
    uid: str
    display_name: str
    username: str
    password: str
    login_method: str = "cu_net"


@dataclass
class TargetSet:
    targets: list[CheckInTarget] = field(default_factory=list)
    # (uid, message) rows for users who can't be attempted but must still be
    # reported — e.g. credentials that wouldn't decrypt.
    skipped: list[tuple[str, str]] = field(default_factory=list)
    # Whether any user passed the enrollment filter at all. Distinguishes
    # "nobody is enrolled in this course" from "nobody has a usable login".
    matched_any: bool = False


def collect_targets(
    resolve: Callable[[dict], tuple[str, str, str] | None],
    *,
    course_code: str | None = None,
    filter_subjects: bool = False,
) -> TargetSet:
    """Resolve every opted-in registered user into a CheckInTarget.

    `resolve(info)` returns (username, password, login_method), or None when
    the user has no usable login for this platform; it may raise ValueError if
    a stored password won't decrypt.

    `filter_subjects` applies the user's /enroll list against `course_code`;
    an empty list always means "everything". Only MyCourseVille passes this
    today — see the note in classdeedee/attendance.py's check_in_all.

    registered_users is snapshotted before iterating: with scans now able to
    overlap, a /register or /unregister landing mid-scan would otherwise mutate
    the dict while it is being walked.
    """
    out = TargetSet()
    for uid, info in list(registered_users.items()):
        if not info.get("checkin_enabled", True):
            continue  # opted out with /autocheckin off — Homework Check is unaffected
        if filter_subjects:
            subjects = info.get("subjects") or []
            if subjects and course_code and course_code not in subjects:
                continue
        out.matched_any = True

        display_name = info.get("display_name", info.get("username", uid))
        try:
            creds = resolve(info)
        except ValueError:
            log.error("Failed to decrypt credentials for %s", display_name)
            out.skipped.append(
                (uid, f"❌ **{display_name}** — failed to decrypt password (may need to re-register)")
            )
            continue
        if creds is None:
            continue  # no usable login for this platform — skipped silently

        username, password, login_method = creds
        out.targets.append(CheckInTarget(uid, display_name, username, password, login_method))
    return out


def is_success(message: str) -> bool:
    """Whether a rendered per-user result counts as a successful check-in.

    Both platforms report results as pre-formatted Discord strings, so success
    is a substring test. Defined once here rather than re-spelled at each call
    site, which is what let the leaderboard and the log lines drift apart.
    """
    return "✅" in message


def succeeded(results: list[tuple[str, str]]) -> int:
    return sum(1 for _, message in results if is_success(message))


def run_batch(
    targets: list[CheckInTarget],
    check_one: Callable[[CheckInTarget], str],
    *,
    label: str,
    deadline_seconds: int | None = None,
) -> list[tuple[str, str]]:
    """Run `check_one` for every target concurrently, globally bounded.

    Returns (uid, message) tuples in completion order. `deadline_seconds`, when
    given, only drives a warning log — it is the window the platform's code is
    valid for (ClassDeeDee's rotating nonce), not a timeout.
    """
    if not targets:
        return []

    workers = min(CHECKIN_CONCURRENCY, len(targets))
    log.info("%s: %d user(s) across %d worker(s)", label, len(targets), workers)
    started = time.perf_counter()

    def _one(target: CheckInTarget) -> tuple[str, str]:
        with _login_slots:
            return target.uid, check_one(target)

    results: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=label) as pool:
        for future in as_completed([pool.submit(_one, t) for t in targets]):
            results.append(future.result())

    elapsed = time.perf_counter() - started
    log.info("%s done: %d/%d ok in %.2fs", label, succeeded(results), len(results), elapsed)
    if deadline_seconds and elapsed > deadline_seconds:
        log.warning(
            "%s took %.2fs — past the ~%ds validity window; late users may have been rejected",
            label, elapsed, deadline_seconds,
        )
    return results
