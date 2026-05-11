"""Application-layer rate limiting middleware.

Implements a per-IP sliding window rate limiter using Redis sorted sets (SR-15).
The middleware intercepts requests to a configured set of paths and enforces a
per-IP request cap within a rolling time window.
"""

import math
import time
import uuid

from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window per-IP rate limiter for a configurable set of endpoints.

    Only the exact (method, path) pairs supplied in ``rules`` are rate-limited.
    All other requests are passed through without any Redis interaction.

    Args:
        app:   The ASGI application to wrap.
        rules: Mapping of ``(HTTP_METHOD_UPPER, path)`` to the ``Settings``
               attribute name that holds ``max_requests`` for that route.
               The window duration is always taken from
               ``settings.rate_limit_window_seconds``.
               Example: ``{("POST", "/api/v1/auth/login"): "rate_limit_login_max"}``.
    """

    def __init__(
        self,
        app: object,
        rules: dict[tuple[str, str], str],
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._rules = rules

    async def dispatch(self, request: Request, call_next: object) -> Response:
        """Apply rate limiting then delegate to the next ASGI handler.

        Returns HTTP 429 with a ``Retry-After`` header when the per-IP limit is
        exceeded.  Fails open on any Redis error so that an unavailable Redis
        never blocks legitimate traffic.
        """
        key_tuple = (request.method.upper(), request.url.path)
        settings_attr = self._rules.get(key_tuple)

        if settings_attr is None:
            # Path not rate-limited — pass through immediately.
            return await call_next(request)  # type: ignore[operator]

        settings = getattr(request.app.state, "settings", None)
        if settings is None:
            from app.core.config import get_settings

            settings = get_settings()

        max_requests: int = getattr(settings, settings_attr)
        window_seconds: int = settings.rate_limit_window_seconds

        redis: Redis | None = None  # type: ignore[type-arg]
        try:
            redis = request.app.state.redis
        except AttributeError:
            return await call_next(request)  # type: ignore[operator]

        ip = request.headers.get("X-Real-IP") or (
            request.client.host if request.client else "unknown"
        )

        # Sanitise path into a short slug safe for use as a Redis key segment.
        path_slug = request.url.path.strip("/").replace("/", "_")
        method = request.method.upper()
        redis_key = f"rl:{method}:{path_slug}:{ip}"

        try:
            return await self._check_and_enforce(
                redis, redis_key, max_requests, window_seconds, request, call_next
            )
        except RedisError:
            return await call_next(request)  # type: ignore[operator]

    async def _check_and_enforce(
        self,
        redis: Redis,  # type: ignore[type-arg]
        redis_key: str,
        max_requests: int,
        window_seconds: int,
        request: Request,
        call_next: object,
    ) -> Response:
        """Run the sliding window check and either block or allow the request.

        Raises:
            RedisError: Propagated to ``dispatch`` which converts it to fail-open.
        """
        now_ms = int(time.time() * 1000)
        window_ms = window_seconds * 1000
        window_start_ms = now_ms - window_ms

        # Prune expired entries and count remaining in one pipeline.
        async with redis.pipeline(transaction=False) as pipe:
            pipe.zremrangebyscore(redis_key, "-inf", window_start_ms)
            pipe.zcard(redis_key)
            results = await pipe.execute()

        current_count: int = results[1]

        if current_count >= max_requests:
            retry_after = await self._calculate_retry_after(
                redis, redis_key, now_ms, window_ms
            )
            return PlainTextResponse(
                content="Rate limit exceeded",
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        # timestamp+uuid to handle same-millisecond arrivals without collisions.
        member = f"{now_ms}:{uuid.uuid4().hex}"
        async with redis.pipeline(transaction=False) as pipe:
            pipe.zadd(redis_key, {member: now_ms})
            pipe.expire(redis_key, window_seconds)
            await pipe.execute()

        return await call_next(request)  # type: ignore[operator]

    async def _calculate_retry_after(
        self,
        redis: Redis,  # type: ignore[type-arg]
        redis_key: str,
        now_ms: int,
        window_ms: int,
    ) -> int:
        """Return the number of seconds until the next request slot opens.

        Fetches the oldest entry in the sorted set.  The slot opens when that
        entry's timestamp exits the sliding window.

        Returns:
            Seconds to wait, minimum 1.
        """
        oldest: list[tuple[str, float]] = await redis.zrange(
            redis_key, 0, 0, withscores=True
        )
        if not oldest:
            return 1
        oldest_ms = int(oldest[0][1])
        seconds = math.ceil((oldest_ms + window_ms - now_ms) / 1000)
        return max(1, seconds)
