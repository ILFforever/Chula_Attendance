# Deployment Guide - Password Security

## Overview

This bot now uses **AES-128-CBC encryption with HMAC** (via `cryptography.Fernet`) to secure user passwords. Passwords are encrypted before storage and decrypted only when needed for login automation.

## Security Model

- **Encryption:** Fernet (symmetric encryption using AES-128-CBC + HMAC-SHA256)
- **Key Storage:** Environment variable `ENCRYPTION_KEY`
- **Password Storage:** Encrypted in `users.json` (base64-encoded tokens)
- **Migration:** Automatic migration of plaintext passwords on first startup with key

## Local Development Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate an encryption key
```bash
python password_crypto.py generate-key
```

Example output:
```
Generating new encryption key:
xK3j9mP2vR8nQ4wL7tY6hJ5fD3gS1zN2bV0cX9aZ=
```

### 3. Set the environment variable

**Windows (PowerShell):**
```powershell
$env:ENCRYPTION_KEY="xK3j9mP2vR8nQ4wL7tY6hJ5fD3gS1zN2bV0cX9aZ="
```

**Windows (Command Prompt):**
```cmd
set ENCRYPTION_KEY=xK3j9mP2vR8nQ4wL7tY6hJ5fD3gS1zN2bV0cX9aZ=
```

**Linux/macOS:**
```bash
export ENCRYPTION_KEY="xK3j9mP2vR8nQ4wL7tY6hJ5fD3gS1zN2bV0cX9aZ="
```

### 4. Run the bot
```bash
python bot.py
```

## fly.io Deployment

### 1. Generate and set the encryption key

Generate a key (you only need to do this once):
```bash
python password_crypto.py generate-key
```

Set it as a fly.io secret:
```bash
flyctl secrets set ENCRYPTION_KEY=xK3j9mP2vR8nQ4wL7tY6hJ5fD3gS1zN2bV0cX9aZ=
```

### 2. Set the Discord token
```bash
flyctl secrets set DISCORD_TOKEN=your_discord_bot_token_here
```

### 3. Deploy
```bash
flyctl deploy
```

## Key Management Best Practices

### DO:
- Generate a **unique key** for each deployment environment
- Store keys securely (fly.io secrets, environment variables, password managers)
- Keep a **backup** of your encryption key in a secure location
- Rotate keys periodically (requires users to re-register)

### DO NOT:
- Commit encryption keys to git repositories
- Share keys in chat, email, or unencrypted channels
- Use the same key across different environments
- Lose the key (encrypted passwords cannot be recovered without it)

## What Happens If You Lose the Key?

- **Passwords cannot be decrypted** - this is by design
- Users will need to **re-register** their credentials
- Old encrypted entries in `users.json` will cause decryption errors
- Solution: Remove `users.json` and have all users re-register

## Migration from Plaintext

When the bot starts with `ENCRYPTION_KEY` set for the first time:
1. It detects plaintext passwords in `users.json`
2. Automatically encrypts all passwords
3. Saves the encrypted version back to `users.json`
4. Logs the number of migrated users

**Note:** This migration is one-way. Once encrypted, passwords cannot be reverted to plaintext without the key.

## Verification

Check that encryption is working:

```bash
# After first run, inspect users.json
cat users.json
```

Encrypted passwords look like:
```json
{
  "123456789": {
    "username": "6401001",
    "password": "gAAAAABl...",
    "display_name": "John Doe",
    "encrypted": true
  }
}
```

Plaintext passwords (before encryption):
```json
{
  "123456789": {
    "username": "6401001",
    "password": "MyPassword123",
    "display_name": "John Doe"
  }
}
```

## Troubleshooting

### Error: "ENCRYPTION_KEY environment variable not set"
- Generate a key: `python password_crypto.py generate-key`
- Set it in your environment or fly.io secrets

### Error: "Failed to decrypt password"
- The `ENCRYPTION_KEY` may have changed
- Users need to re-register their credentials
- Or the password was stored with a different key

### Error: "Invalid ENCRYPTION_KEY length"
- Keys must be exactly 44 characters (base64-encoded 32 bytes)
- Generate a new key with the provided script
