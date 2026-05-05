"""Docker and DB helpers for the local verification runner.

All functions in this module are synchronous (subprocess-based) and do NOT
import any application code — they shell out to docker/psql.

Secret handling: pg_password is passed via the PGPASSWORD env-var inside the
container, not as a CLI argument, to avoid it appearing in ps output on the
host.
"""

import subprocess
from pathlib import Path

# make verify always runs against the test stack (docker-compose.test.yml).
BACKEND_CONTAINER = "diploma-test-backend-1"
POSTGRES_CONTAINER = "diploma-test-postgres-test-1"


# ──────────────────────────────────────────────────────────────────────────────
# Docker log helpers
# ──────────────────────────────────────────────────────────────────────────────


def fetch_container_logs(container: str = BACKEND_CONTAINER, tail: int = 500) -> str:
    """Return the last *tail* lines of a container's stdout+stderr."""
    try:
        res = subprocess.run(
            ["docker", "logs", container, "--tail", str(tail)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.stdout + res.stderr
    except Exception:
        return ""


def extract_demo_token(email: str, kind: str, container: str = BACKEND_CONTAINER) -> str | None:
    """Extract a DEMO MODE token from backend container logs.

    Parses lines of the form:
        [DEMO MODE] <kind> token for <email>: <raw_token>

    ``kind`` should be "Email verification" or "Password reset".
    Returns the raw token string, or None if not found.
    """
    logs = fetch_container_logs(container)
    prefix = f"[DEMO MODE] {kind} token for {email}:"
    for line in reversed(logs.splitlines()):
        if prefix in line:
            return line.rsplit(": ", maxsplit=1)[-1].strip()
    return None


# ──────────────────────────────────────────────────────────────────────────────
# PostgreSQL helpers (via docker exec)
# ──────────────────────────────────────────────────────────────────────────────


def psql_exec(
    sql: str,
    pg_user: str,
    pg_password: str,
    pg_db: str,
    container: str = POSTGRES_CONTAINER,
) -> str:
    """Execute a SQL statement in the postgres container and return output."""
    try:
        res = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                f"PGPASSWORD={pg_password}",
                container,
                "psql",
                "-U",
                pg_user,
                "-d",
                pg_db,
                "-c",
                sql,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return res.stdout + res.stderr
    except Exception as exc:
        return str(exc)


def promote_to_admin(
    email: str,
    pg_user: str,
    pg_password: str,
    pg_db: str,
) -> bool:
    if not isinstance(email, str) or any(c in email for c in ("'", ";", "--")):
        raise ValueError(f"Unsafe email value for admin promotion: {email!r}")
    out = psql_exec(
        f"UPDATE users SET role='admin' WHERE email='{email}';",
        pg_user,
        pg_password,
        pg_db,
    )
    return "UPDATE 1" in out


def promote_to_auditor(
    email: str,
    pg_user: str,
    pg_password: str,
    pg_db: str,
) -> bool:
    if not isinstance(email, str) or any(c in email for c in ("'", ";", "--")):
        raise ValueError(f"Unsafe email value for auditor promotion: {email!r}")
    out = psql_exec(
        f"UPDATE users SET role='auditor' WHERE email='{email}';",
        pg_user,
        pg_password,
        pg_db,
    )
    return "UPDATE 1" in out


def set_account_status(
    account_number: str,
    status: str,  # "ACTIVE" | "INACTIVE" | "FROZEN"
    pg_user: str,
    pg_password: str,
    pg_db: str,
) -> bool:
    if status not in {"ACTIVE", "INACTIVE", "FROZEN"}:
        raise ValueError(f"Invalid status: {status!r}")
    if not isinstance(account_number, str) or any(c in account_number for c in ("'", ";", "--")):
        raise ValueError(f"Unsafe account_number: {account_number!r}")
    out = psql_exec(
        f"UPDATE accounts SET status='{status}' WHERE account_number='{account_number}';",
        pg_user,
        pg_password,
        pg_db,
    )
    return "UPDATE 1" in out


def set_account_balance(
    account_number: str,
    balance: int,
    pg_user: str,
    pg_password: str,
    pg_db: str,
) -> bool:
    if not isinstance(account_number, str) or any(c in account_number for c in ("'", ";", "--")):
        raise ValueError(f"Unsafe account_number: {account_number!r}")
    out = psql_exec(
        f"UPDATE accounts SET balance={balance} WHERE account_number='{account_number}';",
        pg_user,
        pg_password,
        pg_db,
    )
    return "UPDATE 1" in out


# ──────────────────────────────────────────────────────────────────────────────
# Migration and startup helpers
# ──────────────────────────────────────────────────────────────────────────────


def run_migrations(container: str = BACKEND_CONTAINER) -> tuple[bool, str]:
    """Run ``alembic upgrade head`` inside the backend container."""
    try:
        res = subprocess.run(
            ["docker", "exec", container, "alembic", "upgrade", "head"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return res.returncode == 0, res.stdout + res.stderr
    except Exception as exc:
        return False, str(exc)


def start_docker_stack(compose_file: Path, override_file: Path | None = None) -> tuple[bool, str]:
    """Start the Docker stack with ``docker compose up -d``."""
    cmd = ["docker", "compose", "-f", str(compose_file)]
    if override_file and override_file.exists():
        cmd += ["-f", str(override_file)]
    cmd += ["up", "-d", "--build"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return res.returncode == 0, res.stdout + res.stderr
    except Exception as exc:
        return False, str(exc)


def read_env_file(repo_root: Path) -> dict[str, str]:
    """Parse ``<repo_root>/.env`` into a dict."""
    env_file = repo_root / ".env"
    result: dict[str, str] = {}
    if not env_file.exists():
        return result
    for raw_line in env_file.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        result[k.strip()] = v.strip()
    return result
