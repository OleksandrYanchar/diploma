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

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)
os.environ.setdefault("REDIS_URL", "redis://:testpass@localhost:6379/0")
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-secret-key-that-is-at-least-32-chars-long-for-hs256",
)
os.environ.setdefault("ENVIRONMENT", "test")
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
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402

# ---------------------------------------------------------------------------
# Settings override
# ---------------------------------------------------------------------------
_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
)

# ---------------------------------------------------------------------------
# SQLite in-memory engine
# ---------------------------------------------------------------------------
_SQLITE_FILE = os.environ.get("TEST_SQLITE_FILE")
_SQLITE_URL = (
    f"sqlite+aiosqlite:///{_SQLITE_FILE}"
    if _SQLITE_FILE
    else "sqlite+aiosqlite:///:memory:"
)

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
@pytest.fixture(scope="session", autouse=True)
async def create_tables() -> AsyncGenerator[None, None]:
    """Create all ORM-defined tables in the SQLite test database.

    Runs once for the entire test session before any test executes.
    All tables are dropped after the session ends, leaving no artefacts.
    """
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    if not _SQLITE_FILE:
        async with _test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    await _test_engine.dispose()


# ---------------------------------------------------------------------------
# Per-test database session fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an isolated AsyncSession for a single test.

    Uses a rollback after each test to ensure that no data written during
    one test is visible to another.

    Security note: isolation prevents test-order dependencies that could mask
    security bugs (e.g. a leftover locked account affecting subsequent tests).
    """
    async with _TestSessionFactory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# FakeRedis fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.FakeRedis, None]:
    """Yield a fresh in-process FakeRedis instance for a single test.

    Created fresh per test so that Redis state (blacklisted tokens,
    rate-limit counters, session records) does not leak between tests.
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

    Args:
        db_session: Isolated test database session (per-test fixture).
        fake_redis: In-memory Redis substitute (per-test fixture).

    Yields:
        A configured AsyncClient instance ready for use in tests.
    """
    from app.core.config import get_settings
    from app.core.database import get_db

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: fake_redis
    app.dependency_overrides[get_settings] = lambda: _TEST_SETTINGS

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://testserver",
    ) as client:
        yield client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Role-specific user fixtures
# ---------------------------------------------------------------------------
# Distinct session IDs per fixture role prevent Redis key collisions when two
# fixtures are active in the same test (e.g. a test that creates both a
# verified_user and an admin_user and checks Redis state for each).
_VERIFIED_SESSION_ID = "00000000-0000-0000-0000-000000000001"
_ADMIN_SESSION_ID = "00000000-0000-0000-0000-000000000002"
_AUDITOR_SESSION_ID = "00000000-0000-0000-0000-000000000003"
_UNVERIFIED_SESSION_ID = "00000000-0000-0000-0000-000000000004"


@pytest.fixture()
async def verified_user(db_session: AsyncSession) -> tuple[User, str]:
    """Create a verified USER-role account and return (user, access_token).

    Security properties demonstrated:
    - is_verified=True — satisfies the require_verified gate (SR-03).
    - role=UserRole.USER — least-privilege default role (SR-11).
    """
    user = User(
        email="testuser_verified@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=_VERIFIED_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    return user, token


@pytest.fixture()
async def admin_user(db_session: AsyncSession) -> tuple[User, str]:
    """Create a verified ADMIN-role account and return (user, access_token).

    Security properties demonstrated:
    - is_verified=True — satisfies the require_verified gate (SR-03).
    - role=UserRole.ADMIN — full-access administrative role (SR-11).
    """
    user = User(
        email="testuser_admin@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=_ADMIN_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    return user, token


@pytest.fixture()
async def auditor_user(db_session: AsyncSession) -> tuple[User, str]:
    """Create a verified AUDITOR-role account and return (user, access_token).

    Security properties demonstrated:
    - is_verified=True — satisfies the require_verified gate (SR-03).
    - role=UserRole.AUDITOR — read-only audit role (SR-11).
    """
    user = User(
        email="testuser_auditor@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.AUDITOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=_AUDITOR_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    return user, token


@pytest.fixture()
async def unverified_user(db_session: AsyncSession) -> tuple[User, str]:
    """Create an unverified USER-role account and return (user, access_token).

    Security properties demonstrated:
    - is_verified=False — must be rejected by require_verified (SR-03).
    - role=UserRole.USER — least-privilege default role (SR-11).
    """
    user = User(
        email="testuser_unverified@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=_UNVERIFIED_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    return user, token
