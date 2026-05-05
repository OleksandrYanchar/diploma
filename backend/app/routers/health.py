"""Health check router.

Provides a single public endpoint that confirms the application is running.
This endpoint is intentionally unauthenticated — its only purpose is to let
infrastructure (Docker health checks, Nginx upstream probes, monitoring) verify
that the FastAPI process is alive and reachable.
"""

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.schemas.common import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application health check",
    description=(
        "Returns HTTP 200 with application status when the service is running. "
        "This endpoint is public and requires no authentication. "
        "It is intended for infrastructure health probes only."
    ),
)
async def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Return the current health status of the application.

    This is the only public endpoint in Phase 1.  No authentication or
    authorisation dependency is declared because infrastructure probes must
    be able to reach it without credentials.  This is intentional and
    documented here per CLAUDE.md section 7.

    Args:
        settings: Injected application settings used to read the version string.

    Returns:
        HealthResponse with ``status="ok"`` and the application version.
    """
    return HealthResponse(status="ok", version=settings.app_version)
