"""FastAPI application entry point.

Creates the FastAPI application, registers the lifespan context manager for
startup/shutdown, and includes all routers.

Phase 1 state: only the health router is registered.  All other routers
(auth, users, accounts, transactions, admin) are added in subsequent phases.

Security note: OpenAPI docs (/docs, /redoc) are disabled in production.
In development, they are useful for manually verifying the API surface area
and security dependencies.  The ``debug`` flag in settings controls this.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.router import router as auth_router
from app.core.config import Settings, get_settings
from app.core.database import close_db, init_db
from app.core.redis import close_redis, init_redis
from app.routers.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Startup:
    - Initialise the PostgreSQL connection pool via SQLAlchemy.
    - Initialise the Redis connection pool.

    Shutdown:
    - Gracefully close the Redis connection pool.
    - Dispose of the PostgreSQL connection pool.

    This is the correct place for one-time initialisation of shared resources.
    All shared resources are injected via ``Depends()`` in route handlers, not
    accessed as module-level globals from this function.
    """
    settings: Settings = get_settings()

    # --- Startup ---
    init_db(str(settings.database_url))
    init_redis(str(settings.redis_url))

    yield

    # --- Shutdown ---
    await close_redis()
    await close_db()


def create_application() -> FastAPI:
    """Factory function that creates and configures the FastAPI application.

    Using a factory rather than a module-level ``app`` variable makes it easy
    for tests to create isolated application instances.

    Returns:
        A configured ``FastAPI`` application instance.
    """
    settings: Settings = get_settings()

    # Disable interactive docs in production to reduce the attack surface.
    docs_url: str | None = "/docs" if settings.debug else None
    redoc_url: str | None = "/redoc" if settings.debug else None

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        # Disable the OpenAPI schema endpoint in production as well.
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # CORS middleware.
    # In production, ``allowed_origins`` must be locked to the exact frontend
    # URL.  Wildcard origins are never acceptable for a Zero Trust system.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Step-Up-Token"],
    )

    # --- Routers ---
    # Phase 1: health only.
    # Phase 2: auth (registration, email verification; login/refresh added later).
    application.include_router(health_router, prefix="/api/v1")
    application.include_router(auth_router, prefix="/api/v1")

    return application


# Module-level application instance used by Uvicorn.
app: FastAPI = create_application()
