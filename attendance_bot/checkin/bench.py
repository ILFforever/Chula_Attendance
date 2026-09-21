"""Platform-neutral login benchmark behind /deedeebench and /mcvbench.

Logs in every user a real check-in would attempt, in parallel, under the same
bound — this is the stress test for the concurrent-login path, so it has to use
the same target collection and the same cap the real thing does or it measures
nothing useful. Login only: no attendance is recorded.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from attendance_bot.config import log, registered_users
from attendance_bot.checkin.runner import (
    CHECKIN_CONCURRENCY,
    CheckInTarget,
    collect_targets,
)


def reset_peak_rss() -> bool:
    """Reset the kernel's peak-RSS counter (VmHWM) to the current RSS.

    VmHWM is otherwise a lifetime high-water mark, so a bench would report the
    largest spike the process ever had rather than its own — and running both
    platforms back to back would credit the first one's peak to the second.
    Writing 5 to clear_refs resets only that counter; it does not touch page
    tables or memory, unlike the soft-dirty modes (1-4). Linux-only.
    """
    try:
        with open("/proc/self/clear_refs", "w", encoding="ascii") as f:
            f.write("5")
        return True
    except OSError:
        return False


def read_rss_mb() -> tuple[float | None, float | None]:
    """Return (current_rss_mb, peak_rss_mb). Dependency-free on Linux/Fly.

    Reads VmRSS/VmHWM from /proc/self/status (VmHWM is the process's peak RSS,
    so we get the high-water mark without a sampler thread). Falls back to
    psutil, then to (None, None) on platforms without either (e.g. Windows).

    Paired with reset_peak_rss() at the start of a run, the peak reported is
    that run's own rather than the process's lifetime maximum.
    """
    try:
        cur = peak = None
        with open("/proc/self/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    cur = int(line.split()[1]) / 1024  # kB → MB
                elif line.startswith("VmHWM:"):
                    peak = int(line.split()[1]) / 1024
        if cur is not None:
            return cur, peak
    except OSError:
        pass
    try:
        import psutil  # optional
        return psutil.Process().memory_info().rss / 1e6, None
    except Exception:
        return None, None


def run_login_bench(
    resolve: Callable[[dict], tuple[str, str, str] | None],
    attempt_login: Callable[[CheckInTarget], str | None],
    *,
    label: str,
) -> dict:
    """Benchmark logging every eligible user into one platform.

    `resolve` is the platform's collect_targets resolver. `attempt_login`
    performs one login and returns None on success or a short error string —
    each platform catches its own exception types, since they don't share a
    hierarchy.

    Returns a stats dict for the Discord summary, and writes a per-user
    breakdown to the bot log.
    """
    if not registered_users:
        return {"error": "No users registered. Use `/register` first."}

    # Exactly the set a real check-in would attempt, /autocheckin opt-out
    # included — benchmarking users who would never be checked in measures
    # the wrong thing.
    collected = collect_targets(resolve)
    targets = collected.targets

    # Undecryptable credentials are the only real failure at this stage. Users
    # with no login for this platform are counted separately: a check-in skips
    # them silently, so calling them failures makes a healthy run look broken.
    per: list[dict] = [
        {"name": registered_users.get(uid, {}).get("display_name", uid),
         "ok": False, "seconds": 0.0, "error": "decrypt failed"}
        for uid, _ in collected.skipped
    ]

    workers = min(CHECKIN_CONCURRENCY, len(targets)) if targets else 1
    waves = -(-len(targets) // workers) if targets else 0  # ceil division

    # Measure this run's own peak, not whatever the process hit earlier.
    reset_peak_rss()
    rss_before, _ = read_rss_mb()
    started = time.perf_counter()

    def _one(target: CheckInTarget) -> dict:
        t0 = time.perf_counter()
        try:
            error = attempt_login(target)
        except Exception as exc:  # noqa: BLE001 - a benchmark must never crash its caller
            error = f"unexpected ({exc})"[:80]
        return {
            "name": target.display_name,
            "ok": error is None,
            "seconds": time.perf_counter() - t0,
            "error": error,
        }

    if targets:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"{label}_bench") as pool:
            for future in as_completed([pool.submit(_one, t) for t in targets]):
                per.append(future.result())

    wall = time.perf_counter() - started
    rss_after, rss_peak = read_rss_mb()
    ok = sum(1 for r in per if r["ok"])
    login_times = [r["seconds"] for r in per if r["ok"]]

    stats = {
        "platform": label,
        "total": len(per) + len(collected.unavailable),
        "attempted": len(targets),
        "ok": ok,
        "failed": len(per) - ok,
        "no_login": len(collected.unavailable),
        "wall": wall,
        "workers": workers,
        "waves": waves,
        "slowest": max(login_times) if login_times else 0.0,
        "fastest": min(login_times) if login_times else 0.0,
        "rss_before": rss_before,
        "rss_after": rss_after,
        "rss_peak": rss_peak,
        "per": per,
    }

    def _f(v):
        return f"{v:.1f}" if isinstance(v, (int, float)) else "n/a"
    log.info(
        "BENCH %s logins: %d/%d ok in %.2fs | %d worker(s), %d wave(s) | RSS before=%s after=%s peak=%s MB",
        label, ok, len(targets), wall, workers, waves, _f(rss_before), _f(rss_after), _f(rss_peak),
    )
    for r in per:
        log.info("  BENCH %-24s %-4s %5.2fs  %s", r["name"], "OK" if r["ok"] else "FAIL",
                 r["seconds"], r["error"] or "")

    return stats
