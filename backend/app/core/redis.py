"""Async Redis client singleton.

Provides a single ``redis.asyncio.Redis`` connection pool shared across all
requests.  The client is initialised during application startup and closed
during shutdown via the FastAPI lifespan.

Redis is used for:
- Session records keyed by session_id (SR-10)
- Access token blacklist after logout (SR-09)
- Step-up token one-time-use flags (SR-14)
- Rate limit sliding-window counters (SR-15)

Security property enforced: the Redis connection requires authentication via
the password embedded in ``REDIS_URL``.  The password is never hardcoded; it
comes from the environment variable (SR-19).
"""

from __future__ import annotations

import redis.asyncio as aioredis
from redis.asyncio import Redis

# Module-level client.  Set once during startup, never mutated afterwards.
_redis_client: Redis | None = None  # type: ignore[type-arg]


def init_redis(redis_url: str) -> None:
    """Initialise the Redis connection pool.

    Must be called once during application startup (inside the FastAPI
    lifespan context manager) before any request is handled.

    Args:
        redis_url: Redis connection URL, e.g.
            ``redis://:password@host:6379/0``.
            The password in the URL provides authentication (SR-19).
    """
    global _redis_client  # noqa: PLW0603

    _redis_client = aioredis.from_url(
        redis_url,
        encoding="utf-8",
        decode_responses=True,
    )


async def close_redis() -> None:
    """Close the Redis connection pool.

    Must be called during application shutdown to release connections cleanly.
    """
    global _redis_client  # noqa: PLW0603

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


def get_redis() -> Redis:  # type: ignore[type-arg]
    """Return the shared Redis client instance.

    This is a synchronous getter (not an async generator) because the Redis
    client itself is connection-pool backed and thread/coroutine safe.  It
    is intended to be used as a FastAPI dependency via ``Depends(get_redis)``.

    Usage in a route::

        from fastapi import Depends
        from redis.asyncio import Redis
        from app.core.redis import get_redis

        @router.get("/example")
        async def example(redis: Redis = Depends(get_redis)):
            await redis.set("key", "value", ex=60)

    Raises:
        RuntimeError: If ``init_redis`` has not been called before the first
            request (programming error, not a client error).
    """
    if _redis_client is None:
        msg = "Redis has not been initialised. Call init_redis() during startup."
        raise RuntimeError(msg)
    return _redis_client
