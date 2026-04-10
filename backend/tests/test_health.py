"""Health endpoint smoke tests.

Verifies that the application is running and the health endpoint responds
correctly.  These tests are the Phase 1 acceptance criteria.

Security note: the health endpoint is intentionally unauthenticated.  No
credentials or sensitive data are expected in the response.  Tests here
verify that the response contains no unexpected fields that could leak
internal state.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_200(async_client: AsyncClient) -> None:
    """GET /api/v1/health returns HTTP 200 with status 'ok' and a version string.

    This is the Phase 1 smoke test: if the application boots, the dependency
    injection wiring is correct, and the health router is reachable, this test
    passes.

    Args:
        async_client: httpx client pointed at the FastAPI ASGI app.
    """
    response = await async_client.get("/api/v1/health")

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_health_response_has_no_extra_fields(async_client: AsyncClient) -> None:
    """GET /api/v1/health response body contains exactly the expected keys.

    Guards against accidental information leakage: if a debug flag, internal
    version detail, or environment name is added to the health response, this
    test will catch it before it reaches a deployed environment.

    Args:
        async_client: httpx client pointed at the FastAPI ASGI app.
    """
    response = await async_client.get("/api/v1/health")

    assert response.json().keys() == {"status", "version"}


@pytest.mark.asyncio
async def test_health_is_unauthenticated(async_client: AsyncClient) -> None:
    """GET /api/v1/health succeeds without an Authorization header.

    The health endpoint is intentionally unauthenticated so that load
    balancers and monitoring probes can reach it.  This test documents and
    enforces that intent: if an auth dependency is accidentally added to the
    health router, this test will fail.

    Args:
        async_client: httpx client pointed at the FastAPI ASGI app.
    """
    response = await async_client.get(
        "/api/v1/health",
        headers={},
    )

    assert response.status_code == 200
