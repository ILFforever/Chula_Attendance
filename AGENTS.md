# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## Commands

```bash
pip install -r requirements.txt        # install deps
export DISCORD_TOKEN="your-token"      # required
export ENCRYPTION_KEY="your-key"       # required, for password encryption
python main.py                         # run the bot locally
```

There is no test suite, linter, or formatter configured in this repo — don't invent commands for them.

Deploys are automatic: pushing to `main` triggers `.github/workflows/deploy.yml`, which runs `flyctl deploy --remote-only`. Never run `flyctl deploy` locally.

## Architecture

Discord bot (`discord.py`) that auto-checks-in registered users for two unrelated platforms — **MyCourseVille** (MCV) and **ClassDeeDee** (ChulaSSO) — either from an attendance link/QR posted in a monitored channel, or scanned with a phone via the bundled web scanner. No headless browser: check-in is done with `requests` + `BeautifulSoup` HTTP calls to keep the Fly.io deployment under 256 MB RAM.

**Entry point:** `main.py` → `attendance_bot/client.py` (`AttendanceBot(discord.Client)`). The scanner's aiohttp web server (`attendance_bot/scanner/webserver.py`) is started from `setup_hook()` and shares the bot's event loop, so a QR scan reaches directly into the same check-in helpers (`process_attendance_link`, `handle_web_scan_cdd`) used by the Discord message handler — there is exactly one check-in code path per platform regardless of entry (message vs. scan).

**Two independent platform integrations**, each self-contained under its own package:
- `attendance_bot/mcv/` — MCV login/OAuth flow (`attendance.py`), plus public course-code lookup via OpenGraph metadata scraping and CU Get Reg (`cugetreg.py`). No MCV login needed just to identify a course from a posted link.
- `attendance_bot/classdeedee/` — ChulaSSO CAS ticket login (`login.py`) and QR-based check-in (`attendance.py`). The attendance QR encodes `{sid, nonce}` and the nonce is only valid ~8s, so all logins for one scan must run concurrently to land inside that window.

**Shared check-in plumbing (`attendance_bot/checkin/`)** is to attendance what `attendance_bot/homework/` is to the homework check: each platform keeps its own login/check-in logic, while target collection (`collect_targets` — opt-out, enrollment filter, credential resolution) and the bounded fan-out (`run_batch`) live in one place so the two paths can't drift. Both platforms check in concurrently.

The concurrency cap (`CHECKIN_CONCURRENCY`, default 16) is a process-wide semaphore, not a per-scan pool size: an MCV link and a ClassDeeDee QR can be processed at the same time, and a per-scan bound would let two overlapping scans open twice the sessions the 256 MB Fly instance has room for. `CDD_CHECKIN_CONCURRENCY` is still honoured as a fallback name.

Scans are deduplicated per code rather than serialized globally — `webserver._inflight` rejects a second scan of the *same* code with a 429 while the first is live, but two different codes proceed concurrently. Anything that checks "have I seen this code?" and then records it must use `config.claim_link()`, which does both in one step; doing it in two lets two concurrent scans of one code both claim leaderboard credit.

A user's login method (CU Net vs. MyCourseVille account) determines which platform(s) they're checked into automatically; MCV-account users must separately add a ChulaSSO login via `/deedeeregister` to also be covered on ClassDeeDee.

**Persistence:** flat JSON files (no DB), loaded once into module-level dicts in `attendance_bot/config.py` and explicitly saved back via `persist_*()` after mutation — nothing autosaves.
- `users.json` — `{ discord_user_id: { username, password (encrypted), display_name, subjects: [...] } }`. Passwords are encrypted via `attendance_bot/security/crypto.py`; plaintext entries are auto-migrated to encrypted on startup.
- `config.json` — `monitored_channels`.
- `leaderboard.json` — `counts` (post leaderboard) and `seen_links` (dedup cache, pruned by `SEEN_LINK_TTL` = 48h since attendance codes can't stay valid longer than a day).
- `homework.json` — `suppressed` (items a user marked finished), `deadlines` (cached due times driving the deadline reminder without a fresh login), and `custom` (assignments added with `/homeworkadd`). All three are keyed `uid:platform:course_code:item_key`, so deleting a custom assignment has to purge the other two stores' rows for it (`config.remove_custom_assignment`) — a stale `deadlines` row would still fire a reminder for something that no longer exists.

**Course enrollment / filtering (`subjects` on a user):** MCV attendance links carry MCV's internal course ID, which is unrelated to the public course code students know — so matching against a user's `/enroll`ed course codes is done by scraping the link's OpenGraph metadata for the public code rather than trusting the internal ID. An empty `subjects` list means "checked in for everything"; this is the existing pattern for making a feature opt-in/scoped per user and per course.

**Commands:** all slash commands live in one file, `attendance_bot/commands.py`, registered via a single `setup(bot, tree, attendance, executor, bot_start_time)` called from `client.py` — there's no per-command file convention to follow.

**No scheduled/background jobs exist yet** — everything today is event-driven (Discord message or web scan). A recurring task (e.g. `discord.ext.tasks.loop`) would need to be started from `setup_hook()` in `client.py`, same place the web server is started.

**Config/env vars** are all read once in `attendance_bot/config.py` (see that file for the full list — `DATA_DIR`, `SCAN_SECRET`, `SCAN_BASE_URL`, `WEB_PORT`, etc.). Add new ones there, not inline elsewhere. The one exception is `CHECKIN_CONCURRENCY`, read in `attendance_bot/checkin/runner.py` next to the semaphore it sizes.
