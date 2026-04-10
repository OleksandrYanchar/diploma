"""Pytest configuration and shared fixtures for the backend test suite.

Sets up an isolated test environment with:
- In-memory SQLite database via aiosqlite (no PostgreSQL required)
- FakeRedis in-memory store (no Redis server required)
- httpx AsyncClient targeting the FastAPI ASGI application directly

Security note: all secrets used here are test-only values that are never
deployed.  They exist solely to satisfy the Settings validator (minimum 32
characters for jwt_secret_key).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Environment variables must be set BEFORE app.main is imported, because
# create_application() calls get_settings() at module level, which triggers
# pydantic-settings validation.  Setting these here at conftest import time
# ensures they are present when pytest first imports app.main.
# ---------------------------------------------------------------------------
import os

# Provide all required Settings fields that have no defaults.  These values
# are test-only and have no security significance.
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)
os.environ.setdefault("REDIS_URL", "redis://:testpass@localhost:6379/0")
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-secret-key-that-is-at-least-32-chars-long-for-hs256",
)
os.environ.setdefault("ENVIRONMENT", "test")
# Prevent pydantic-settings from reading ALLOWED_ORIGINS from a local .env
# file that may contain a comma-separated value (e.g. http://localhost,http://localhost:3000).
# The comma-separated format is now handled by _CommaListEnvSource, but setting
# this default here avoids any .env file being loaded during tests at all.
os.environ.setdefault("ALLOWED_ORIGINS", "http://testserver")

from collections.abc import AsyncGenerator  # noqa: E402

import fakeredis.aioredis as fakeredis  # noqa: E402
import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.core.redis import get_redis  # noqa: E402
from app.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Settings override
# ---------------------------------------------------------------------------
# These are the values injected whenever a route handler declares
# ``settings: Settings = Depends(get_settings)``.  Constructing Settings
# explicitly (not relying on env_file) guarantees isolation: test runs are
# never affected by a developer's local .env.
# ---------------------------------------------------------------------------
_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
)

# ---------------------------------------------------------------------------
# SQLite engine for tests
# ---------------------------------------------------------------------------
# SQLite with aiosqlite is used instead of PostgreSQL so that the test suite
# runs without any external services.  The in-memory URL ensures each test
# session starts from a completely empty database.
#
# check_same_thread=False is required for SQLite when used with async drivers
# because SQLAlchemy may access the connection from different coroutines.
# ---------------------------------------------------------------------------
_SQLITE_URL = "sqlite+aiosqlite:///:memory:"

_test_engine = create_async_engine(
    _SQLITE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

_TestSessionFactory = async_sessionmaker(
    bind=_test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# Session-scoped table setup
# ---------------------------------------------------------------------------
# Tables are created once per test session (not per test function) because
# creating/dropping schema is expensive and the fixture provides isolation
# through transaction rollback (see db_session below).
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
async def create_tables() -> AsyncGenerator[None, None]:
    """Create all ORM-defined tables in the SQLite test database.

    Runs once for the entire test session before any test executes.
    All tables are dropped after the session ends, leaving no artefacts.

    This fixture does NOT call ``init_db()`` — the application's startup
    function is intentionally bypassed because the dependency override for
    ``get_db`` replaces it entirely.
    """
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await _test_engine.dispose()


# ---------------------------------------------------------------------------
# Per-test database session fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an isolated AsyncSession for a single test.

    Uses a savepoint strategy: the session begins a transaction before the
    test and rolls it back afterwards, ensuring that no data written during
    one test is visible to another.

    Security note: isolation prevents test-order dependencies that could mask
    security bugs (e.g., a leftover locked account affecting subsequent tests).
    """
    async with _TestSessionFactory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# Dependency overrides
# ---------------------------------------------------------------------------
def _override_get_db_factory(session: AsyncSession):  # type: ignore[return]
    """Return a FastAPI dependency override that yields the provided session.

    Args:
        session: The test ``AsyncSession`` to be yielded by the dependency.

    Returns:
        An async generator function compatible with FastAPI's ``Depends()``.
    """

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        """Yield the test database session in place of the real ``get_db``."""
        yield session

    return _override


# ---------------------------------------------------------------------------
# FakeRedis fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.FakeRedis, None]:
    """Yield an in-process FakeRedis instance for a single test.

    The FakeRedis instance is created fresh per test so that Redis state
    (blacklisted tokens, rate-limit counters, session records) does not
    leak between tests.

    This fixture does NOT call ``init_redis()`` — the application's Redis
    startup is bypassed via the ``get_redis`` dependency override registered
    in ``async_client``.
    """
    redis = fakeredis.FakeRedis(decode_responses=True)
    yield redis
    await redis.aclose()


# ---------------------------------------------------------------------------
# HTTP client fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def async_client(
    db_session: AsyncSession,
    fake_redis: fakeredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx AsyncClient wired to the FastAPI ASGI application.

    Dependency overrides are installed before the client is created and
    removed after the test completes, ensuring no override leaks across tests.

    The ``ASGITransport`` routes requests directly through the ASGI interface
    without starting a real TCP server.  This is both faster and more
    deterministic than spawning a server process.

    Args:
        db_session: Isolated test database session (per-test fixture).
        fake_redis: In-memory Redis substitute (per-test fixture).

    Yields:
        A configured ``AsyncClient`` instance ready for use in tests.
    """
    from app.core.config import get_settings
    from app.core.database import get_db

    # Install overrides: replace the real DB session and Redis client with
    # their test counterparts.  get_settings is also overridden to prevent
    # the test from depending on any .env file present on the developer's
    # machine.
    app.dependency_overrides[get_db] = _override_get_db_factory(db_session)
    app.dependency_overrides[get_redis] = lambda: fake_redis
    app.dependency_overrides[get_settings] = lambda: _TEST_SETTINGS

    transport = ASGITransport(app=app)  # type: ignore[arg-type]

    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        yield client

    # Remove all overrides after the test to restore the application to its
    # original state.  This prevents override state from affecting other tests
    # that run in the same process.
    app.dependency_overrides.clear()
