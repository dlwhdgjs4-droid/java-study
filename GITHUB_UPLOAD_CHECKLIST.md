# GitHub Upload Checklist

Use this before uploading study work to GitHub.

## Current Remote

```text
origin = https://github.com/dlwhdgjs4-droid/java-study.git
branch = main
```

## Safety Rule

Never upload sensitive information.

Examples:

- API keys
- passwords
- access tokens
- private keys
- `.env` files
- local Spring config
- credential JSON files

## Before Commit Or Push

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-sensitive.ps1
```

If it fails:

```text
Do not add.
Do not commit.
Do not push.
```

## Daily Automation

Codex automation:

```text
daily-java-study-sensitive-info-check
```

Purpose:

```text
Run secret scan daily and report the result.
```

Important:

```text
The automation does not push automatically.
It only checks for sensitive information.
```

## Upload Order

```text
1. git status
2. run secret check
3. git add
4. run staged secret check
5. git commit
6. git push
```
