# Chula Attendance Bot

A Discord bot that automatically checks in registered users when a MyCourseVille attendance link is posted.

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
| `/monitor [channel]` | Watch a channel for attendance links |
| `/unmonitor [channel]` | Stop watching a channel |
| `/channels` | List monitored channels |
| `/checkin <url>` | Manually trigger check-in |
| `/status` | Bot uptime and info |
| `/help` | Show all commands |

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
