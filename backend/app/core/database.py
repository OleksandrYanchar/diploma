"""Async SQLAlchemy engine and session factory.

Provides the ``AsyncSession`` dependency for FastAPI route handlers and the
``Base`` declarative base that all ORM models inherit from.

Security property enforced: all database queries go through SQLAlchemy's
parameterized query mechanism — raw SQL string interpolation is never used,
preventing SQL injection (SR-20).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base class shared by all ORM models.

    All models in ``app/models/`` must inherit from this class so that
    Alembic's autogenerate can discover their table definitions through the
    shared ``metadata`` object.
    """


# Module-level engine and session factory.  These are initialised once during
# application startup (via the ``init_db`` function called from the FastAPI
# lifespan) and reused for the lifetime of the process.
#
# They are intentionally module-level rather than global mutable state in the
# sense that they are set exactly once and never mutated afterwards.  Tests
# replace these via ``override_get_db`` dependency overrides, not by mutating
# these variables directly.

_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(database_url: str) -> None:
    """Initialise the database engine and session factory.

    Must be called once during application startup (inside the FastAPI
    lifespan context manager) before any request is handled.

    Args:
        database_url: The async PostgreSQL DSN string, e.g.
            ``postgresql+asyncpg://user:pass@host:5432/dbname``.
    """
    global _engine, _async_session_factory  # noqa: PLW0603

    _engine = create_async_engine(
        database_url,
        # Echo SQL statements only in development; never in production.
        echo=False,
        # Pool settings appropriate for a single-process Uvicorn deployment.
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,  # Detect and replace stale connections.
    )

    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,  # Avoids lazy-load errors after commit.
        autocommit=False,
        autoflush=False,
    )


async def close_db() -> None:
    """Dispose of the database engine connection pool.

    Must be called during application shutdown (inside the FastAPI lifespan
    context manager) to release all pooled connections cleanly.
    """
    global _engine  # noqa: PLW0603

    if _engine is not None:
        await _engine.dispose()
        _engine = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session per request.

    Each request receives its own ``AsyncSession``.  The session is committed
    if the handler completes without error, and rolled back if an exception
    is raised, ensuring that partial writes never reach the database.

    Usage in a route::

        from fastapi import Depends
        from sqlalchemy.ext.asyncio import AsyncSession
        from app.core.database import get_db

        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            ...

    Raises:
        RuntimeError: If ``init_db`` has not been called before the first
            request (programming error, not a client error).
    """
    if _async_session_factory is None:
        msg = "Database has not been initialised. Call init_db() during startup."
        raise RuntimeError(msg)

    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
