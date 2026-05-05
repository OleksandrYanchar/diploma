"""Pytest configuration and shared fixtures for the backend test suite."""

# Environment variables must be set before app.main is imported.
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

_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
)

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


@pytest.fixture(scope="session", autouse=True)
async def create_tables() -> AsyncGenerator[None, None]:
    """Create all ORM tables once per session; drop them on teardown."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    if not _SQLITE_FILE:
        async with _test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    await _test_engine.dispose()


@pytest.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an isolated AsyncSession; rolls back after each test."""
    async with _TestSessionFactory() as session:
        yield session
        await session.rollback()


@pytest.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.FakeRedis, None]:
    """Yield a fresh FakeRedis instance per test to prevent state leakage."""
    redis = fakeredis.FakeRedis(decode_responses=True)
    yield redis
    await redis.aclose()


@pytest.fixture()
async def async_client(
    db_session: AsyncSession,
    fake_redis: fakeredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx AsyncClient wired to the FastAPI app with test overrides."""
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


# Distinct session IDs per role prevent Redis key collisions
# in tests using multiple fixtures.
_VERIFIED_SESSION_ID = "00000000-0000-0000-0000-000000000001"
_ADMIN_SESSION_ID = "00000000-0000-0000-0000-000000000002"
_AUDITOR_SESSION_ID = "00000000-0000-0000-0000-000000000003"
_UNVERIFIED_SESSION_ID = "00000000-0000-0000-0000-000000000004"


@pytest.fixture()
async def verified_user(db_session: AsyncSession) -> tuple[User, str]:
    """Create a verified USER-role account and return (user, access_token)."""
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
    """Create a verified ADMIN-role account and return (user, access_token)."""
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
    """Create a verified AUDITOR-role account and return (user, access_token)."""
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
    """Create an unverified USER-role account and return (user, access_token)."""
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
