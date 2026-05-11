"""Tests for the application-layer rate limiting middleware (SR-15).

Each test uses a dedicated ``rate_limit_client`` fixture that:
- Creates a fresh FakeRedis instance (decode_responses=True).
- Assigns it to ``app.state.redis`` so the middleware finds it via
  ``request.app.state.redis`` without going through FastAPI's DI system.
- Provides an httpx AsyncClient over the ASGI transport.
- Cleans up ``app.state.redis`` after the test to avoid cross-test leakage.

Rate limit settings used in tests are overridden via the Settings dependency
so that limits are small (e.g., 3 requests) and windows are short (1 second),
making tests fast and deterministic.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import Mock

import fakeredis.aioredis as fakeredis
import pytest
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError

from app.core.config import Settings
from app.main import app

# ---------------------------------------------------------------------------
# Shared test settings
# ---------------------------------------------------------------------------

_BASE_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
    # Tight limits so tests complete quickly.
    rate_limit_window_seconds=60,
    rate_limit_login_max=3,
    rate_limit_refresh_max=3,
    rate_limit_register_max=3,
    rate_limit_password_reset_max=3,
)

_SHORT_WINDOW_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
    # 1-second window so the reset test can wait for expiry without sleeping long.
    rate_limit_window_seconds=1,
    rate_limit_login_max=3,
    rate_limit_refresh_max=3,
    rate_limit_register_max=3,
    rate_limit_password_reset_max=3,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def rl_fake_redis() -> AsyncGenerator[fakeredis.FakeRedis, None]:
    """Fresh FakeRedis instance per test — prevents state leakage."""
    redis = fakeredis.FakeRedis(decode_responses=True)
    yield redis
    await redis.aclose()


@pytest.fixture()
async def rate_limit_client(
    rl_fake_redis: fakeredis.FakeRedis,
    db_session: Any,
) -> AsyncGenerator[AsyncClient, None]:
    """AsyncClient wired to the app with fake Redis for rate limit middleware.

    The FakeRedis instance is set on ``app.state.redis`` so the middleware
    finds it.  The Settings dependency is overridden to use tight limits.
    The DB dependency is overridden to prevent real DB connections.
    """
    from app.core.config import get_settings
    from app.core.database import get_db
    from app.core.redis import get_redis

    async def _override_get_db() -> AsyncGenerator[Any, None]:
        yield db_session

    # app.state.settings is read by the middleware per request to get the limits.
    app.state.settings = _BASE_SETTINGS
    app.state.redis = rl_fake_redis
    app.dependency_overrides[get_settings] = lambda: _BASE_SETTINGS
    app.dependency_overrides[get_db] = _override_get_db
    # Route handlers also use get_redis via Depends(); override it so that
    # requests that pass the rate limit can reach their endpoint successfully.
    app.dependency_overrides[get_redis] = lambda: rl_fake_redis

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://testserver",
    ) as client:
        yield client

    app.dependency_overrides.clear()
    for attr in ("redis", "settings"):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


@pytest.fixture()
async def rate_limit_client_short_window(
    rl_fake_redis: fakeredis.FakeRedis,
    db_session: Any,
) -> AsyncGenerator[AsyncClient, None]:
    """Same as ``rate_limit_client`` but uses a 1-second sliding window."""
    from app.core.config import get_settings
    from app.core.database import get_db
    from app.core.redis import get_redis

    async def _override_get_db() -> AsyncGenerator[Any, None]:
        yield db_session

    app.state.settings = _SHORT_WINDOW_SETTINGS
    app.state.redis = rl_fake_redis
    app.dependency_overrides[get_settings] = lambda: _SHORT_WINDOW_SETTINGS
    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: rl_fake_redis

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://testserver",
    ) as client:
        yield client

    app.dependency_overrides.clear()
    for attr in ("redis", "settings"):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_LOGIN_PAYLOAD = {"email": "x@example.com", "password": "wrong"}
_RESET_PAYLOAD = {"email": "x@example.com"}
_REFRESH_PAYLOAD = {"refresh_token": "notarealtoken"}
_REGISTER_PAYLOAD = {
    "email": "new@example.com",
    "password": "StrongPass123!",
}


def _ip_headers(ip: str) -> dict[str, str]:
    return {"X-Real-IP": ip}


# ---------------------------------------------------------------------------
# T1 — login rate limit triggers after N+1 requests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rate_limit_triggers(
    rate_limit_client: AsyncClient,
) -> None:
    """After rate_limit_login_max requests the next one returns 429 with Retry-After."""
    limit = _BASE_SETTINGS.rate_limit_login_max
    ip_headers = _ip_headers("1.2.3.4")

    for _ in range(limit):
        resp = await rate_limit_client.post(
            "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
        )
        assert resp.status_code != 429, "Should not be rate-limited yet"

    resp = await rate_limit_client.post(
        "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) >= 1


# ---------------------------------------------------------------------------
# T2 — within-limit requests pass (rate limit does not trigger early)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_within_limit_passes(
    rate_limit_client: AsyncClient,
) -> None:
    """Exactly rate_limit_login_max POST /auth/login requests must not be blocked."""
    limit = _BASE_SETTINGS.rate_limit_login_max
    ip_headers = _ip_headers("2.3.4.5")

    for i in range(limit):
        resp = await rate_limit_client.post(
            "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
        )
        assert resp.status_code != 429, f"Request {i + 1} should not be rate-limited"


# ---------------------------------------------------------------------------
# T3 — refresh endpoint rate limit triggers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_rate_limit_triggers(
    rate_limit_client: AsyncClient,
) -> None:
    """After rate_limit_refresh_max requests, POST /auth/refresh returns 429."""
    limit = _BASE_SETTINGS.rate_limit_refresh_max
    ip_headers = _ip_headers("3.4.5.6")

    for _ in range(limit):
        await rate_limit_client.post(
            "/api/v1/auth/refresh", json=_REFRESH_PAYLOAD, headers=ip_headers
        )

    resp = await rate_limit_client.post(
        "/api/v1/auth/refresh", json=_REFRESH_PAYLOAD, headers=ip_headers
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# T4 — password reset rate limit triggers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_rate_limit_triggers(
    rate_limit_client: AsyncClient,
) -> None:
    """After rate_limit_password_reset_max requests the reset endpoint returns 429."""
    limit = _BASE_SETTINGS.rate_limit_password_reset_max
    ip_headers = _ip_headers("4.5.6.7")

    for _ in range(limit):
        await rate_limit_client.post(
            "/api/v1/auth/password/reset/request",
            json=_RESET_PAYLOAD,
            headers=ip_headers,
        )

    resp = await rate_limit_client.post(
        "/api/v1/auth/password/reset/request",
        json=_RESET_PAYLOAD,
        headers=ip_headers,
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# T5 — register endpoint rate limit triggers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_rate_limit_triggers(
    rate_limit_client: AsyncClient,
) -> None:
    """After rate_limit_register_max requests, POST /auth/register returns 429."""
    limit = _BASE_SETTINGS.rate_limit_register_max
    ip_headers = _ip_headers("5.6.7.8")

    for _ in range(limit):
        await rate_limit_client.post(
            "/api/v1/auth/register", json=_REGISTER_PAYLOAD, headers=ip_headers
        )

    resp = await rate_limit_client.post(
        "/api/v1/auth/register", json=_REGISTER_PAYLOAD, headers=ip_headers
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# T6 — different IPs are isolated from each other
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_different_ips_are_isolated(
    rate_limit_client: AsyncClient,
) -> None:
    """Exhausting the limit for IP-A must not affect requests from IP-B."""
    limit = _BASE_SETTINGS.rate_limit_login_max

    # Exhaust IP-A's limit.
    for _ in range(limit + 1):
        await rate_limit_client.post(
            "/api/v1/auth/login",
            json=_LOGIN_PAYLOAD,
            headers=_ip_headers("10.0.0.1"),
        )

    # Confirm IP-A is now blocked.
    resp_a = await rate_limit_client.post(
        "/api/v1/auth/login",
        json=_LOGIN_PAYLOAD,
        headers=_ip_headers("10.0.0.1"),
    )
    assert resp_a.status_code == 429

    # IP-B must still receive normal (non-429) responses.
    resp_b = await rate_limit_client.post(
        "/api/v1/auth/login",
        json=_LOGIN_PAYLOAD,
        headers=_ip_headers("10.0.0.2"),
    )
    assert resp_b.status_code != 429


# ---------------------------------------------------------------------------
# T7 — unrelated endpoints are unaffected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unrelated_endpoint_unaffected(
    rate_limit_client: AsyncClient,
) -> None:
    """GET /api/v1/health must never return 429 regardless of request volume."""
    for _ in range(20):
        resp = await rate_limit_client.get(
            "/api/v1/health", headers=_ip_headers("9.9.9.9")
        )
        assert resp.status_code != 429


# ---------------------------------------------------------------------------
# T8 — window resets after expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_window_resets_after_expiry(
    rate_limit_client_short_window: AsyncClient,
) -> None:
    """After the 1-second window expires, the rate limit counter resets."""
    limit = _SHORT_WINDOW_SETTINGS.rate_limit_login_max
    ip_headers = _ip_headers("7.8.9.10")

    # Exhaust the limit.
    for _ in range(limit):
        await rate_limit_client_short_window.post(
            "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
        )

    blocked = await rate_limit_client_short_window.post(
        "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
    )
    assert blocked.status_code == 429

    # Wait for the window to expire.
    await asyncio.sleep(1.1)

    # First request in the new window must not be rate-limited.
    after_reset = await rate_limit_client_short_window.post(
        "/api/v1/auth/login", json=_LOGIN_PAYLOAD, headers=ip_headers
    )
    assert after_reset.status_code != 429


# ---------------------------------------------------------------------------
# T9 — Redis unavailable fails open
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_unavailable_fails_open(
    rl_fake_redis: fakeredis.FakeRedis,
    db_session: Any,
) -> None:
    """When Redis raises RedisError the middleware fails open (request is allowed)."""
    from app.core.config import get_settings
    from app.core.database import get_db
    from app.core.redis import get_redis

    async def _override_get_db() -> AsyncGenerator[Any, None]:
        yield db_session

    # Broken Redis: pipeline() is a synchronous method that raises RedisError
    # immediately.  The middleware catches RedisError and fails open.
    # This broken instance is only used by the middleware (app.state.redis).
    # Route-level Depends(get_redis) is overridden with working fakeredis.
    broken_redis = fakeredis.FakeRedis(decode_responses=True)
    broken_redis.pipeline = Mock(side_effect=RedisError("connection refused"))

    app.state.settings = _BASE_SETTINGS
    app.state.redis = broken_redis
    app.dependency_overrides[get_settings] = lambda: _BASE_SETTINGS
    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = lambda: rl_fake_redis

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),  # type: ignore[arg-type]
            base_url="http://testserver",
        ) as client:
            # Send more requests than the limit — none should be blocked because
            # Redis is broken and the middleware must fail open.
            limit = _BASE_SETTINGS.rate_limit_login_max
            for _ in range(limit + 2):
                resp = await client.post(
                    "/api/v1/auth/login",
                    json=_LOGIN_PAYLOAD,
                    headers=_ip_headers("6.7.8.9"),
                )
                assert (
                    resp.status_code != 429
                ), "Middleware must fail open when Redis is unavailable"
    finally:
        app.dependency_overrides.clear()
        for attr in ("redis", "settings"):
            if hasattr(app.state, attr):
                delattr(app.state, attr)
