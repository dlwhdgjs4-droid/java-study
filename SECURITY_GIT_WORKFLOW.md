# Security Git Workflow

This repository must never push sensitive information.

## Never Commit

- API keys
- passwords
- access tokens
- refresh tokens
- private keys
- `.env` files
- local Spring config such as `application-local.yml`
- credential JSON files

## Safety Layers

This repository uses three safety layers:

```text
1. .gitignore blocks common local secret files
2. scripts/check-sensitive.ps1 scans tracked and untracked files
3. .githooks/pre-commit and .githooks/pre-push block commits/pushes when suspicious content is found
```

## Manual Check

Run this before committing or pushing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-sensitive.ps1
```

Check only staged files:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-sensitive.ps1 -Staged
```

## Daily Rule

Before any daily GitHub upload:

```text
secret check first
commit second
push last
```

If the check fails, do not push.

## Codex Daily Automation

Automation id:

```text
daily-java-study-sensitive-info-check
```

This automation runs the secret check once per day and reports the result.

It does not automatically commit or push. This is intentional: upload should
happen only after the user confirms the study state is ready.
