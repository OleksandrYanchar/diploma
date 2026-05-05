"""FastAPI application entry point.

Creates the FastAPI application, registers the lifespan context manager for
startup/shutdown, and includes all routers.

Security note: OpenAPI docs (/docs, /redoc) are disabled in production.
In development, they are useful for manually verifying the API surface area
and security dependencies.  The ``debug`` flag in settings controls this.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.accounts.router import router as accounts_router
from app.admin.router import router as admin_router
from app.auth.router import router as auth_router
from app.core.config import Settings, get_settings
from app.core.database import close_db, init_db
from app.core.redis import close_redis, init_redis
from app.routers.health import router as health_router
from app.transactions.router import router as transactions_router
from app.users.router import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Initialises the PostgreSQL and Redis connection pools on startup and
    disposes them on shutdown.
    """
    settings: Settings = get_settings()

    # Startup
    init_db(str(settings.database_url))
    init_redis(str(settings.redis_url))

    yield

    # Shutdown
    await close_redis()
    await close_db()


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings: Settings = get_settings()

    docs_url: str | None = "/docs" if settings.debug else None
    redoc_url: str | None = "/redoc" if settings.debug else None

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        # Disables the OpenAPI schema endpoint in production.
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Step-Up-Token"],
    )

    application.include_router(health_router, prefix="/api/v1")
    application.include_router(auth_router, prefix="/api/v1")
    application.include_router(users_router, prefix="/api/v1")
    application.include_router(admin_router, prefix="/api/v1")
    application.include_router(accounts_router, prefix="/api/v1")
    application.include_router(transactions_router, prefix="/api/v1")

    return application


app: FastAPI = create_application()
