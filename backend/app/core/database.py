"""Async SQLAlchemy engine and session factory.

Provides the ``AsyncSession`` dependency for FastAPI route handlers and the
``Base`` declarative base that all ORM models inherit from.

Security property enforced: all database queries go through SQLAlchemy's
parameterized query mechanism — raw SQL string interpolation is never used,
preventing SQL injection (SR-20).
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base class shared by all ORM models."""


_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(database_url: str) -> None:
    """Initialise the database engine and session factory.

    Must be called once during application startup before any request is handled.
    """
    global _engine, _async_session_factory  # noqa: PLW0603

    _engine = create_async_engine(
        database_url,
        echo=False,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
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

    Each request receives its own ``AsyncSession``.

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
