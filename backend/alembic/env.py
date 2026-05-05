"""Alembic environment configuration.

This module is executed by Alembic when running migration commands (upgrade,
downgrade, revision --autogenerate, etc.).  It connects Alembic to the
application's SQLAlchemy metadata and database URL.

Running migrations
------------------
PostgreSQL has no published port on the host (security checkpoint SC-01).
All Alembic commands must be run **inside the backend container**::

    docker compose exec backend .venv/bin/alembic upgrade head
    docker compose exec backend .venv/bin/alembic downgrade -1
    docker compose exec backend .venv/bin/alembic revision --autogenerate -m "description"

Running ``alembic`` directly on the host will fail with a connection error
because ``localhost:5432`` is not reachable from outside Docker.

Database URL resolution
-----------------------
The URL is resolved in order:
1. ``DATABASE_URL`` environment variable (injected by Docker Compose).
2. ``POSTGRES_USER`` + ``POSTGRES_PASSWORD`` + ``POSTGRES_DB`` component
   variables, read from the process environment or a ``.env`` file.

Async engine pattern: SQLAlchemy 2.0 async engines require running migrations
via ``run_sync`` within an async context.  This env.py uses the recommended
approach from the Alembic + asyncio documentation.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

import app.models  # noqa: F401 — side-effect import registers all ORM models
from alembic import context

# Import Base so that all models' metadata is accessible to Alembic.
# The models/__init__.py import ensures every ORM class has been loaded.
from app.core.database import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _load_dotenv_values() -> None:
    """Load key/value pairs from common .env locations into process env.

    Alembic commands are often run directly from a shell where variables from
    ``backend/.env`` (or repo-root ``.env``) are not exported.  This helper
    reads those files and inserts missing variables into ``os.environ``.

    Security property: values are only read from local .env files; no defaults
    with secrets are introduced in code.
    """
    env_paths = (
        Path(__file__).resolve().parents[1] / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    )

    for env_path in env_paths:
        if not env_path.exists():
            continue

        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)


def get_database_url() -> str:
    """Return the async PostgreSQL DSN for Alembic migrations.

    Tries two sources in order:
    1. ``DATABASE_URL`` environment variable (full DSN — used inside Docker
       where Compose constructs it from component vars and injects it).
    2. Individual ``POSTGRES_*`` component variables — used when running
       Alembic locally without exporting a full DSN.  The .env file supplies
       these automatically when loaded by the shell or by ``dotenv``.

    Returns:
        The async PostgreSQL DSN string with the ``postgresql+asyncpg://`` scheme.

    Raises:
        RuntimeError: If neither a full DSN nor all required component
            variables (POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB) are set.
    """
    _load_dotenv_values()

    url = os.environ.get("DATABASE_URL")
    if url:
        return url

    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    db = os.environ.get("POSTGRES_DB")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")

    if user and password and db:
        return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"

    msg = (
        "Cannot determine the database URL.  Set one of:\n"
        "  - DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db\n"
        "  - POSTGRES_USER + POSTGRES_PASSWORD + POSTGRES_DB "
        "(optionally POSTGRES_HOST and POSTGRES_PORT)"
    )
    raise RuntimeError(msg)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    In offline mode Alembic generates SQL statements without a live database
    connection.  This is useful for generating migration SQL for review.

    The URL is passed directly to the context; no engine is created.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Compare column types to detect type-change migrations.
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations using the provided synchronous connection.

    Called by ``run_migrations_online`` within ``run_sync``.
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode with a live database connection.

    Creates an async engine from the database URL and delegates to
    ``do_run_migrations`` via ``run_sync``, which is the required pattern
    for SQLAlchemy 2.0 async engines with Alembic.
    """
    url = get_database_url()

    # Build a configuration dict for async_engine_from_config.
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # No connection pooling during migrations.
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
