# Chula Attendance Bot (v2)

A Discord bot that automatically checks in registered users when a MyCourseVille attendance link is posted.

**🌐 [ilfforever.github.io/Chula_Attendance](https://ilfforever.github.io/Chula_Attendance/)** — landing page, feature overview, and setup guide.

## How It Works

1. Register your MyCourseVille credentials with `/register`
2. Set a channel to watch with `/monitor`
3. When an attendance link is posted in that channel, the bot logs in and checks in everyone automatically

## Commands

| Command | Description |
|---------|-------------|
| `/register <login_method> <username> <password>` | Save your credentials (ephemeral) |
| `/unregister` | Remove your credentials |
| `/users` | List registered users |
| `/enroll <course_code>` | Enroll in a course so you're only checked in for its links |
| `/unenroll <course_code>` | Remove a course from your enrollment list |
| `/unenrollall` | Remove every course from your enrollment list |
| `/subjects` | List the courses you're enrolled in |
| `/monitor [channel]` | Watch a channel for attendance links |
| `/unmonitor [channel]` | Stop watching a channel |
| `/channels` | List monitored channels |
| `/checkin <url>` | Manually trigger check-in |
| `/logincheck` | Test if your saved credentials can log in |
| `/status` | Bot uptime and info |
| `/leaderboard` | See who's posted the most attendance links |
| `/help` | Show all commands |

## Course Enrollment

By default, a registered user is checked in for **every** attendance link posted in a monitored channel. If you only want to be checked in for specific courses, use `/enroll <course_code>` with the public course code you already know (e.g. `2110405`, same as CU Get Reg / your registration record). The bot looks up the name on [CU Get Reg](https://cugetreg.com) so you can confirm you typed the right one.

Once you've enrolled in at least one course, you'll only be checked in for attendance links belonging to those courses. Use `/unenroll` to remove one — if your list becomes empty, you go back to being checked in for everything.

### How matching actually works

MyCourseVille's attendance links embed MCV's own internal course ID (e.g. `75974`), which is **not** the public course code (e.g. `2110405`) — the two are unrelated numbering schemes. Rather than rely on that internal ID, the bot fetches the posted attendance link's public page metadata (the same OpenGraph data Discord itself uses to generate a link preview — no MCV login required) and reads the public course code out of it. That's what gets compared against what you typed into `/enroll`, so both sides are always in the same, human-recognizable code space.

One edge case: large courses split into multiple sections may show as one course code with several sections in the metadata title — enrolling by course code covers all of them.

## Leaderboard

`/leaderboard` ranks whoever posts attendance links most often. To keep it fair:

- **Duplicate posts don't count.** Each attendance link (matched on the exact URL, including its one-time check-in code) only earns leaderboard credit the *first* time it's posted — reposting the same link still re-runs check-in as normal (in case someone missed it the first time), it just won't earn another point. Since attendance codes are valid for at most a day, the bot only needs to remember recent links, so this dedup cache stays tiny and never grows unbounded.
- **A link only earns a point if it actually worked.** A post only counts toward the leaderboard if at least one real check-in attempt against it came back successful — stale, expired, or fake links get processed (so legitimate attempts still show their real result) but award no leaderboard credit.

## Login Methods

| Method | For |
|--------|-----|
| **CU Net** | Chula students/staff with a 10-digit student ID |
| **MyCourseVille** | Platform accounts (username or email) |

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

### Run Locally

```bash
pip install -r requirements.txt
export DISCORD_TOKEN="your-token"
export ENCRYPTION_KEY="your-key"
python bot.py
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
