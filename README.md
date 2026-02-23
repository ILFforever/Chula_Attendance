# Chula Attendance Bot

A Discord bot that automatically checks in registered users when a MyCourseVille attendance link is posted.

## How It Works

1. Register your MyCourseVille credentials with `/register`
2. Set a channel to watch with `/monitor`
3. When an attendance link is posted in that channel, the bot logs in and checks in everyone automatically

## Commands

| Command | Description |
|---------|-------------|
| `/register <username> <password>` | Save your credentials (ephemeral) |
| `/unregister` | Remove your credentials |
| `/users` | List registered users |
| `/monitor [channel]` | Watch a channel for attendance links |
| `/unmonitor [channel]` | Stop watching a channel |
| `/channels` | List monitored channels |
| `/checkin <url>` | Manually trigger check-in |
| `/status` | Bot uptime and info |

## Setup

### Requirements

- Python 3.11+
- Chrome/Chromium + ChromeDriver
- A Discord bot token

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_TOKEN` | Yes | Discord bot token |
| `ENCRYPTION_KEY` | Yes | Key for encrypting stored passwords |
| `CHROME_BIN` | No | Path to Chrome binary |
| `CHROMEDRIVER_PATH` | No | Path to ChromeDriver |

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
