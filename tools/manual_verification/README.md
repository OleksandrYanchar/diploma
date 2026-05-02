# Manual Verification Runner

End-to-end verification script that exercises all Phase 1-6 scenarios against a live backend stack.

## Prerequisites

- Docker and Docker Compose installed
- Poetry environment set up: `cd backend && poetry install`
- `.env` file at repository root with at minimum `JWT_SECRET_KEY` set

## Quick start

```bash
# 1. Start the test stack (PostgreSQL on 5434, Redis on 6380, backend on 8000)
make start-test-env

# 2. Apply migrations
make migrate-test

# 3. Run verification
make verify
```

## Artifact output

Results are written to `artifacts/manual_verification/<timestamp>/`:
- `summary.md` — pass/fail table for all scenarios
- `scenarios.jsonl` — machine-readable per-scenario detail
- `scenarios.md` — human-readable per-scenario detail
- `docker_logs.txt` — backend container logs captured during the run

## Options

```bash
# Run only smoke tests (register + login)
make verify-smoke

# Skip Docker startup (if stack is already running)
poetry run python tools/manual_verification/run_local_verification.py --skip-migrations

# Start Docker stack automatically before running
poetry run python tools/manual_verification/run_local_verification.py --start-docker
```

## Credentials

The test stack uses fixed credentials (`testuser`/`testpassword`/`testdb`). These are intentional — the database runs on tmpfs and is ephemeral. The `JWT_SECRET_KEY` is always pulled from the host `.env` file.

## Notes

- All sensitive values (tokens, passwords, TOTP secrets) are redacted before being written to artifact files
- Scenarios that depend on earlier scenarios (e.g., step-up transfer requires MFA setup) will be marked `BLOCKED` if the prerequisite scenario failed — this is expected behavior
- The `artifacts/` directory is gitignored; do not commit verification output
