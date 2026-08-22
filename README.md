# Chula Attendance Bot (v3)

A Discord bot for Chula students: it automatically checks you into **MyCourseVille** attendance links and **ClassDeeDee** attendance QR codes, and can DM you a daily summary of outstanding homework across both platforms.

**🌐 [ilfforever.github.io/Chula_Attendance](https://ilfforever.github.io/Chula_Attendance/)** — landing page, feature overview, and setup guide.

## Features

- **Attendance check-in** — auto check-in the moment a link/QR is posted, for MyCourseVille and ClassDeeDee
- **Homework Check** *(new in v3)* — a daily DM listing outstanding work across both platforms, sorted by urgency, with buttons to open or mark items done
- **Leaderboard** — tracks who posts attendance links most often
- **Course enrollment** — optionally scope either feature to just your own courses

---

## Attendance Check-In

1. Register your credentials with `/register`
2. Set a channel to watch with `/monitor`
3. When an attendance link is posted in that channel, the bot logs in and checks in everyone automatically

For **ClassDeeDee**, scan the instructor's attendance QR with the phone scanner from `/scanner` — the bot logs everyone in and checks them in. See [ClassDeeDee (ChulaSSO)](#classdeedee-chulasso) below.

### Course Enrollment

By default, a registered user is checked in for **every** attendance link posted in a monitored channel. If you only want to be checked in for specific courses, use `/enroll <course_code>` with the public course code you already know (e.g. `2110405`, same as CU Get Reg / your registration record). The bot looks up the name on [CU Get Reg](https://cugetreg.com) so you can confirm you typed the right one.

Once you've enrolled in at least one course, you'll only be checked in for attendance links belonging to those courses. Use `/unenroll` to remove one — if your list becomes empty, you go back to being checked in for everything.

This same enrollment list also scopes the Homework Check, so you only need to set it once.

#### How matching actually works

MyCourseVille's attendance links embed MCV's own internal course ID (e.g. `75974`), which is **not** the public course code (e.g. `2110405`) — the two are unrelated numbering schemes. Rather than rely on that internal ID, the bot fetches the posted attendance link's public page metadata (the same OpenGraph data Discord itself uses to generate a link preview — no MCV login required) and reads the public course code out of it. That's what gets compared against what you typed into `/enroll`, so both sides are always in the same, human-recognizable code space.

One edge case: large courses split into multiple sections may show as one course code with several sections in the metadata title — enrolling by course code covers all of them.

### Leaderboard

`/leaderboard` ranks whoever posts attendance links most often. To keep it fair:

- **Duplicate posts don't count.** Each attendance link (matched on the exact URL, including its one-time check-in code) only earns leaderboard credit the *first* time it's posted — reposting the same link still re-runs check-in as normal (in case someone missed it the first time), it just won't earn another point. Since attendance codes are valid for at most a day, the bot only needs to remember recent links, so this dedup cache stays tiny and never grows unbounded.
- **A link only earns a point if it actually worked.** A post only counts toward the leaderboard if at least one real check-in attempt against it came back successful — stale, expired, or fake links get processed (so legitimate attempts still show their real result) but award no leaderboard credit.

### ClassDeeDee (ChulaSSO)

ClassDeeDee authenticates through **ChulaSSO** (`account.it.chula.ac.th`), not MyCourseVille. Its attendance QR — displayed by the instructor and rotating every ~8 seconds — encodes JSON `{"sid": <sessionid>, "n": <nonce>}`. Scanning it with the `/scanner` page checks in every eligible user by posting `{sessionid, nonce}` to ClassDeeDee's `/api/attendants/checkin`.

**Who needs to do what:**

- **CU Net users** — nothing. A CU Net login *is* a ChulaSSO login, so it works on ClassDeeDee automatically.
- **MyCourseVille users** — a platform account can't log into ChulaSSO. Add your ChulaSSO login once with `/deedeeregister <student_id> <password>`; it's verified on the spot and stored alongside your MCV credential. Users who don't add one are simply skipped on ClassDeeDee scans and homework checks.

Use `/deedeecheck` any time to confirm your ClassDeeDee login works (it echoes back your name and student ID). If you're a CU Net user who'd rather not use ClassDeeDee at all, `/classdeedee off` excludes your account from it entirely — both check-in and homework checks — without touching MyCourseVille.

**Timing note:** because the nonce lives only ~8 seconds, all logins for a scan run concurrently across a bounded thread pool (`CDD_CHECKIN_CONCURRENCY`, default 16) so the whole class lands inside the window while keeping RAM modest.

### Login Methods

| Method | For | Works on |
|--------|-----|----------|
| **CU Net** | Chula students/staff with a 10-digit student ID | MyCourseVille + ClassDeeDee |
| **MyCourseVille** | Platform accounts (username or email) | MyCourseVille (add `/deedeeregister` for ClassDeeDee) |

---

## Homework Check

A daily DM listing what you still have outstanding across MyCourseVille and ClassDeeDee — separate from attendance check-in, and off by default.

1. Turn it on with `/homework on` — you'll get a DM once a day (default 8am Bangkok time)
2. Change the hour any time with `/homeworktime <hour>` (0-23, Bangkok time)
3. Want to see it right now instead of waiting? `/homeworkcheck` runs it immediately, whether or not the daily DM is on

### What the DM looks like

Each course with outstanding work gets its own message, most urgent course first, colored red/yellow/green by how soon the earliest item is due. Every item shows:

- **Open in web** — a button straight to the assignment page
- **Mark as finished** — a personal "stop reminding me" toggle. This doesn't tell MyCourseVille or ClassDeeDee anything — it just suppresses future reminders for that one item on your end, independent of whatever the platform's own submission status says.

At the end of the run, three more controls appear:

| Control | What it does |
|---------|---------------|
| 🔔/🔕 Turn reminders on/off | Live toggle — same as `/homework`, no command needed |
| 🕒 Change reminder time | Pops up a quick form — same as `/homeworktime` |
| 📋 View finished items | Lists everything you've marked done, each with a **↩️ Restore** button in case you clicked by mistake |

These buttons keep working even after the bot restarts, or days after the message was sent.

### Data sources

- **MyCourseVille**: one authenticated call to MCV's own "due soon" homepage panel, covering every enrolled course at once.
- **ClassDeeDee**: no equivalent single-call endpoint exists, so the bot fetches your enrolled course list, then queries each course's assignments individually.

Both respect your `/enroll` list the same way attendance check-in does — enrolled in nothing means everything is checked; enrolled in specific courses means only those are.

---

## Commands

### Account

| Command | Description |
|---------|-------------|
| `/register <login_method> <username> <password>` | Save your credentials (ephemeral) |
| `/unregister` | Remove your credentials |
| `/users` | List registered users |
| `/deedeeregister <username> <password>` | **MyCourseVille users only:** add a ClassDeeDee (ChulaSSO) login |
| `/deedeecheck` | Test if your saved credentials can log into ClassDeeDee (ChulaSSO) |
| `/classdeedee <on\|off>` | Include/exclude your account from ClassDeeDee entirely (default: on) |
| `/release` | Show what's new in the latest version |
| `/help` | Show all commands |
| `/status` | Bot uptime and info |

### Attendance Check-In

| Command | Description |
|---------|-------------|
| `/enroll <course_code>` | Enroll in a course so you're only checked in for its links |
| `/unenroll <course_code>` | Remove a course from your enrollment list |
| `/unenrollall` | Remove every course from your enrollment list |
| `/subjects` | List the courses you're enrolled in |
| `/monitor [channel]` | Watch a channel for attendance links |
| `/unmonitor [channel]` | Stop watching a channel |
| `/channels` | List monitored channels |
| `/checkin <url>` | Manually trigger check-in |
| `/scanner` | DM yourself a phone-camera QR scanner (MCV links **and** ClassDeeDee QRs) |
| `/logincheck` | Test if your saved credentials can log in (MyCourseVille) |
| `/leaderboard` | See who's posted the most attendance links |

### Homework Check

| Command | Description |
|---------|-------------|
| `/homework <on\|off>` | Turn the daily homework reminder DM on or off |
| `/homeworktime <hour>` | Set what hour it arrives, 0-23 Bangkok time (default 8am) |
| `/homeworkcheck` | Run it once right now, whether or not the daily DM is on |

---

## Setup

### Requirements

- Python 3.11+
- A Discord bot token

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_TOKEN` | Yes | Discord bot token |
| `ENCRYPTION_KEY` | Yes | Key for encrypting stored passwords |
| `DATA_DIR` | No | Directory for persistent data (default: `.`) |
| `SCAN_SECRET` | No | Shared secret that gates the `/scanner` QR web page; unset disables the scanner |
| `SCAN_BASE_URL` | No | Public base URL of the scanner page (used to build the `/scanner` link) |
| `WEB_PORT` | No | Port the scanner web server listens on (default: `8080`) |
| `CDD_CHECKIN_CONCURRENCY` | No | Max concurrent ClassDeeDee logins per attendance scan (default: `16`) |
| `HOMEWORK_CONCURRENCY` | No | Max concurrent users processed per homework-check tick (default: `4`) |

### Run Locally

```bash
pip install -r requirements.txt
export DISCORD_TOKEN="your-token"
export ENCRYPTION_KEY="your-key"
python main.py
```

### Deploy to Fly.io

```bash
fly launch
fly secrets set DISCORD_TOKEN="your-token" ENCRYPTION_KEY="your-key"
fly deploy
```

Pushes to `main` auto-deploy via GitHub Actions.

## Architecture

The bot uses lightweight HTTP requests (`requests` + `BeautifulSoup`) instead of a headless browser, keeping RAM usage under 256 MB on Fly.io.

**Attendance check-in:**
- **MyCourseVille** check-in logs in via MCV's OAuth/SSO form ([attendance_bot/mcv/attendance.py](attendance_bot/mcv/attendance.py)).
- **ClassDeeDee** check-in logs in via ChulaSSO's CAS ticket flow ([attendance_bot/classdeedee/login.py](attendance_bot/classdeedee/login.py)) and posts attendance ([attendance_bot/classdeedee/attendance.py](attendance_bot/classdeedee/attendance.py)); logins run concurrently but bounded by `CDD_CHECKIN_CONCURRENCY` to stay inside the ~8 s QR nonce window without spiking memory.
- The shared phone QR scanner ([attendance_bot/scanner/webserver.py](attendance_bot/scanner/webserver.py) + [web/scan.html](web/scan.html)) decodes on-device and routes MCV links and ClassDeeDee QRs to the right handler.

**Homework Check** ([attendance_bot/homework/](attendance_bot/homework/)):
- [check.py](attendance_bot/homework/check.py) — logs into both platforms, merges MyCourseVille's "due soon" panel with ClassDeeDee's per-course assignment lists, groups by course and sorts by urgency.
- [dm.py](attendance_bot/homework/dm.py) — builds and sends the DM using Discord's **Components V2** layout system (not classic embeds), which is what lets each item's buttons sit directly next to it rather than bottom-attached to the whole message. Also owns the button click handling and the per-user hourly scheduler.
- A `homework.json` store (separate from `users.json`/`leaderboard.json`) tracks which items a user has clicked "Mark as finished" on, and which day each user's reminder last ran (so a 15-minute scheduler tick doesn't double-send).
