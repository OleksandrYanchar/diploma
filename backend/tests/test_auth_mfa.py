"""Tests for the POST /auth/mfa/setup endpoint (Phase 3 Step 2).

Covers:
- Authenticated user calls setup → 200 with secret and QR code (SR-04, SR-16)
- Secret is non-empty, QR code is valid base64 (SR-04)
- mfa_secret is persisted to DB; mfa_enabled remains False (SR-04)
- MFA_SETUP_INITIATED audit log entry is written (SR-16)
- Unauthenticated call → 403 (HTTPBearer behaviour)
- Setup when MFA already enabled → 400 (SR-04)
- Re-setup overwrites old secret and updates mfa_secret in DB

All tests use the register → verify-email → login helper pattern to produce
a valid access token before exercising the MFA setup endpoint.  Each test is
fully isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per
test).
"""

from __future__ import annotations

import base64
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"
_MFA_SETUP_URL = "/api/v1/auth/mfa/setup"

_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Helper: register, verify email, and login — returns (user_id, access_token)
# ---------------------------------------------------------------------------


async def _register_verify_login(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Register a user, verify their email, and log them in.

    Returns the user UUID (as a string) and the access token so that MFA
    setup tests can both call the endpoint and inspect DB state scoped to
    the specific user.

    Args:
        async_client: Test HTTP client fixture.
        capsys:       pytest stdout capture fixture (captures DEMO MODE token).
        email:        Email address to register.

    Returns:
        A 2-tuple ``(user_id, access_token)``.
    """
    # Register
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id: str = reg_resp.json()["id"]

    # Capture the raw verification token printed to stdout (DEMO MODE).
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    # Verify email
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    # Login
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200
    access_token: str = login_resp.json()["access_token"]

    return user_id, access_token


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_setup_returns_200_with_secret_and_qr(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/setup returns 200 with a non-empty secret and QR code.

    Happy-path confirmation that the endpoint is reachable, correctly wired,
    and returns the expected response shape (SR-04).
    """
    email = "mfa_setup_200@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()

    # Secret must be present and non-empty.
    assert "secret" in data
    assert isinstance(data["secret"], str)
    assert len(data["secret"]) > 0

    # QR code must be present, non-empty, and valid base64.
    assert "qr_code_base64" in data
    assert isinstance(data["qr_code_base64"], str)
    assert len(data["qr_code_base64"]) > 0

    # Validate that qr_code_base64 decodes without error.
    decoded_bytes = base64.b64decode(data["qr_code_base64"])
    assert len(decoded_bytes) > 0

    # issuer must also be present (MFASetupResponse includes it).
    assert "issuer" in data
    assert isinstance(data["issuer"], str)
    assert len(data["issuer"]) > 0


@pytest.mark.asyncio
async def test_mfa_setup_persists_secret_and_does_not_enable_mfa(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """mfa_secret is written to DB; mfa_enabled remains False after setup (SR-04).

    MFA setup only stores the secret.  The user must confirm with a valid
    TOTP code (Phase 4 enable step) before the gate is activated.
    """
    email = "mfa_setup_db@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    returned_secret: str = response.json()["secret"]

    # Reload the user row from the test DB session to inspect persisted state.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()

    assert user is not None
    assert user.mfa_secret is not None, "mfa_secret must be set after setup"
    assert (
        user.mfa_secret == returned_secret
    ), "Stored secret must match the secret returned in the response"
    assert (
        user.mfa_enabled is False
    ), "mfa_enabled must remain False until the enable step is completed"


@pytest.mark.asyncio
async def test_mfa_setup_writes_audit_log(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A MFA_SETUP_INITIATED audit log entry is written on success (SR-16).

    Queries the ``audit_logs`` table scoped by action and user_id to confirm
    the event was recorded for this specific user.
    """
    email = "mfa_setup_audit@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_SETUP_INITIATED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a MFA_SETUP_INITIATED audit log entry"
    assert log_entry.details is not None
    assert log_entry.details.get("email") == email


@pytest.mark.asyncio
async def test_mfa_setup_requires_authentication(
    async_client: AsyncClient,
) -> None:
    """POST /auth/mfa/setup without Authorization header returns 403.

    ``HTTPBearer`` raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  The setup endpoint must not be accessible without a
    valid credential.
    """
    response = await async_client.post(_MFA_SETUP_URL)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_mfa_setup_fails_when_already_enabled(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/setup returns 400 if MFA is already enabled on the account.

    An already-enrolled user must disable MFA before re-running setup (SR-04).
    Directly sets mfa_enabled=True in the DB to simulate an enrolled account.
    """
    email = "mfa_setup_already_enabled@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    # Simulate MFA already being enabled by mutating DB state directly.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    user.mfa_enabled = True
    await db_session.commit()

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    assert "already enabled" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mfa_setup_overwrites_abandoned_secret(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Calling setup twice overwrites the old secret with a new one.

    When a user calls setup but never completes enrollment (mfa_enabled stays
    False), a second setup call should replace the abandoned secret.  Only the
    latest secret must be stored.  The two returned secrets must differ.
    """
    email = "mfa_setup_overwrite@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    # First setup call.
    first_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_resp.status_code == 200
    first_secret: str = first_resp.json()["secret"]

    # Second setup call — must succeed because mfa_enabled is still False.
    second_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert second_resp.status_code == 200
    second_secret: str = second_resp.json()["secret"]

    # The two secrets must be different (generated independently).
    assert first_secret != second_secret, "Each setup call must generate a fresh secret"

    # The DB must store only the latest secret.
    # expire() forces SQLAlchemy to discard its cached state and re-read from DB.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert (
        user.mfa_secret == second_secret
    ), "The stored secret must match the most recent setup response"
    assert user.mfa_enabled is False
