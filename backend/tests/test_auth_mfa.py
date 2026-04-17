"""Tests for MFA endpoints: POST /auth/mfa/setup (Phase 3 Step 2),
POST /auth/mfa/enable (Phase 3 Step 3), the MFA login gate (Phase 3 Step 4),
and POST /auth/mfa/disable (Phase 3 Step 5).

Step 2 coverage:
- Authenticated user calls setup → 200 with secret and QR code (SR-04, SR-16)
- Secret is non-empty, QR code is valid base64 (SR-04)
- mfa_secret is persisted to DB; mfa_enabled remains False (SR-04)
- MFA_SETUP_INITIATED audit log entry is written (SR-16)
- Unauthenticated call → 403 (HTTPBearer behaviour)
- Setup when MFA already enabled → 400 (SR-04)
- Re-setup overwrites old secret and updates mfa_secret in DB

Step 3 coverage:
- Valid TOTP code enables MFA → 200; mfa_enabled True in DB; MFA_ENABLED audit log
  (SR-04, SR-16)
- Invalid TOTP code → 401; mfa_enabled remains False; MFA_FAILED audit log (SR-16)
- Enable without prior setup → 400 (SR-04)
- Enable when already enabled → 400 (SR-04)
- Unauthenticated call → 403 (HTTPBearer behaviour)

Step 5 coverage (POST /auth/mfa/disable):
- Correct password + valid TOTP → 200; mfa_enabled False in DB; mfa_secret None;
  MFA_DISABLED audit
- Wrong password → 401; mfa_enabled still True in DB
- Valid password + wrong TOTP → 401; mfa_enabled still True; MFA_FAILED audit log
- Disable when MFA not enabled → 400
- Unauthenticated call → 403
- After disabling, login no longer requires TOTP (regression guard)

Step 4 coverage (MFA gate at login):
- MFA user, no totp_code → HTTP 200, mfa_required=True, no access_token (T-03)
- MFA user, invalid totp_code → HTTP 401, MFA_FAILED audit log written (T-04)
- MFA user, valid totp_code → HTTP 200, access_token + refresh_token issued,
  MFA_VERIFIED audit log written (SR-04, SR-16)
- Non-MFA user login still works (regression guard)

All tests use the register → verify-email → login helper pattern to produce
a valid access token before exercising the MFA endpoints.  Each test is
fully isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per
test).
"""

from __future__ import annotations

import base64
import uuid

import pyotp
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
_MFA_ENABLE_URL = "/api/v1/auth/mfa/enable"
_MFA_DISABLE_URL = "/api/v1/auth/mfa/disable"

# ---------------------------------------------------------------------------
# URL constants — Step 4
# (Login URL is shared with the block above; listed here for readability.)
# ---------------------------------------------------------------------------
# _LOGIN_URL already defined above.

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


# ---------------------------------------------------------------------------
# Phase 3 Step 3: POST /auth/mfa/enable tests
# ---------------------------------------------------------------------------


async def _setup_mfa_and_get_secret(
    async_client: AsyncClient,
    access_token: str,
) -> str:
    """Call POST /auth/mfa/setup and return the TOTP secret.

    Args:
        async_client: Test HTTP client fixture.
        access_token: Valid Bearer token for the authenticated user.

    Returns:
        The Base32-encoded TOTP secret string from the setup response.
    """
    setup_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert setup_resp.status_code == 200
    return setup_resp.json()["secret"]


@pytest.mark.asyncio
async def test_mfa_enable_valid_code_returns_200_and_activates_mfa(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/enable with valid TOTP → 200; mfa_enabled True; MFA_ENABLED audit.

    Confirms the full happy path for SR-04 enrollment (SR-04, SR-16):
    1. Setup is called to obtain the secret.
    2. A valid TOTP code is generated from that secret using pyotp.
    3. POST /auth/mfa/enable accepts the code and activates the MFA gate.
    4. The DB row reflects mfa_enabled = True.
    5. An MFA_ENABLED audit log entry is recorded (SR-16).
    """
    email = "mfa_enable_valid@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    secret = await _setup_mfa_and_get_secret(async_client, access_token)

    # Generate a valid TOTP code from the secret returned by setup.
    valid_code = pyotp.TOTP(secret).now()

    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": valid_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json().get("detail") == "MFA enabled successfully"

    # The DB row must reflect the activated gate.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must be True after successful enable"

    # An MFA_ENABLED audit log entry must exist for this user.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_ENABLED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected an MFA_ENABLED audit log entry"


@pytest.mark.asyncio
async def test_mfa_enable_invalid_code_returns_401_and_writes_mfa_failed_audit(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid TOTP code → 401; mfa_enabled stays False; MFA_FAILED audit written.

    Verifies that a wrong code is rejected securely (SR-04) and that the
    failure is recorded before the exception is raised (SR-16).
    """
    email = "mfa_enable_invalid@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    await _setup_mfa_and_get_secret(async_client, access_token)

    # Submit a code that is guaranteed to be wrong.
    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "000000"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # mfa_enabled must remain False — the gate must not activate on failure.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is False, "mfa_enabled must remain False after invalid code"

    # An MFA_FAILED audit log entry must have been committed before the 401.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_FAILED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected an MFA_FAILED audit log entry"


@pytest.mark.asyncio
async def test_mfa_enable_without_prior_setup_returns_400(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/enable without calling setup first returns 400.

    A fresh user has mfa_secret = None.  Enabling before setup has no secret
    to verify against and must be rejected (SR-04).
    """
    email = "mfa_enable_no_setup@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)

    # Attempt enable without calling setup first.
    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "123456"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    assert "not initiated" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mfa_enable_when_already_enabled_returns_400(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/enable after MFA is already active returns 400.

    After a successful enable, calling enable again (even with a valid code)
    must be rejected — the gate is already active and re-activation is not
    permitted without a disable step (SR-04).
    """
    email = "mfa_enable_already_on@example.com"
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    secret = await _setup_mfa_and_get_secret(async_client, access_token)

    # First enable — must succeed.
    first_code = pyotp.TOTP(secret).now()
    first_resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": first_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_resp.status_code == 200

    # Confirm mfa_enabled is True in DB before the second attempt.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True

    # Second enable — must be rejected because MFA is already active.
    second_code = pyotp.TOTP(secret).now()
    second_resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": second_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert second_resp.status_code == 400
    assert "already enabled" in second_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mfa_enable_missing_totp_code_returns_422(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/enable with an empty body returns 422.

    The ``MFAEnableRequest`` schema requires a ``totp_code`` field. Omitting it
    must trigger Pydantic validation failure (422) before service logic runs.
    """
    email = "mfa_enable_no_code@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)
    await _setup_mfa_and_get_secret(async_client, access_token)

    resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_enable_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """POST /auth/mfa/enable without Authorization header returns 403.

    ``HTTPBearer`` raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  The enable endpoint must not be accessible without a
    valid credential.
    """
    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "123456"},
    )

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Phase 3 Step 4: MFA gate at POST /auth/login
# ---------------------------------------------------------------------------


async def _register_verify_login_and_enable_mfa(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Register, verify email, log in, set up MFA, and enable it.

    Performs the full enrollment flow so that the user's account has
    ``mfa_enabled=True`` by the time this helper returns.

    Args:
        async_client: Test HTTP client fixture.
        capsys:       pytest stdout capture fixture.
        email:        Unique email address for this test.

    Returns:
        A 2-tuple ``(user_id, totp_secret)`` where ``user_id`` is the UUID
        string and ``totp_secret`` is the Base32-encoded TOTP secret stored on
        the account (needed to generate valid codes in the calling test).
    """
    user_id, access_token = await _register_verify_login(async_client, capsys, email)

    # Initiate MFA setup — returns secret and QR code.
    setup_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert setup_resp.status_code == 200
    secret: str = setup_resp.json()["secret"]

    # Enable MFA by submitting a valid TOTP code.
    valid_code = pyotp.TOTP(secret).now()
    enable_resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": valid_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable_resp.status_code == 200

    return user_id, secret


@pytest.mark.asyncio
async def test_mfa_login_no_totp_code_returns_mfa_required(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-03: Login with MFA enabled and no totp_code returns HTTP 200 + mfa_required.

    After the password is verified, the service detects a missing TOTP code
    and returns the (None, None) sentinel.  The router converts this to an
    MFARequiredResponse (HTTP 200) without issuing any tokens (SR-04).

    Asserts:
    - HTTP 200
    - Response body has mfa_required=True
    - Response body does NOT contain access_token or refresh_token
    """
    email = "mfa_login_no_code@example.com"
    _user_id, _secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
        # totp_code deliberately omitted
    )

    assert response.status_code == 200

    data = response.json()
    assert data.get("mfa_required") is True, "Expected mfa_required=True"
    assert "access_token" not in data, "access_token must not be issued without TOTP"
    assert "refresh_token" not in data, "refresh_token must not be issued without TOTP"


@pytest.mark.asyncio
async def test_mfa_login_invalid_totp_code_returns_401_and_writes_mfa_failed_audit(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-04: Login with MFA enabled and an invalid TOTP code returns HTTP 401.

    The service must reject the wrong code, commit a MFA_FAILED audit log
    entry BEFORE raising, and return 401 with an appropriate detail message
    (SR-04, SR-16).

    Asserts:
    - HTTP 401
    - Response detail contains "invalid"
    - MFA_FAILED AuditLog row exists for the user in the database
    """
    email = "mfa_login_bad_code@example.com"
    user_id, _secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD, "totp_code": "000000"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # An MFA_FAILED audit entry must have been committed before the 401 (SR-16).
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_FAILED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = result.scalar_one_or_none()
    assert (
        log_entry is not None
    ), "Expected an MFA_FAILED audit log entry after bad TOTP"
    assert log_entry.details is not None
    assert log_entry.details.get("reason") == "invalid_totp_code"


@pytest.mark.asyncio
async def test_mfa_login_valid_totp_code_returns_tokens_and_writes_mfa_verified_audit(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Login with MFA enabled and a valid TOTP code issues tokens + MFA_VERIFIED audit.

    A correct TOTP code must complete authentication, producing a full
    TokenResponse (access_token, refresh_token, token_type, expires_in) and
    an MFA_VERIFIED audit log entry committed atomically with the session
    creation (SR-04, SR-06, SR-07, SR-10, SR-16).

    Asserts:
    - HTTP 200
    - Response contains access_token, refresh_token, token_type, expires_in
    - MFA_VERIFIED AuditLog row exists for the user in the database
    """
    email = "mfa_login_good_code@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    valid_code = pyotp.TOTP(secret).now()
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD, "totp_code": valid_code},
    )

    assert response.status_code == 200

    data = response.json()
    assert (
        "access_token" in data
    ), "access_token must be present on successful MFA login"
    assert (
        "refresh_token" in data
    ), "refresh_token must be present on successful MFA login"
    assert data.get("token_type") == "bearer"
    assert isinstance(data.get("expires_in"), int) and data["expires_in"] > 0

    # An MFA_VERIFIED audit entry must exist for this user (SR-16).
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_VERIFIED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = result.scalar_one_or_none()
    assert log_entry is not None, "Expected an MFA_VERIFIED audit log entry"


@pytest.mark.asyncio
async def test_login_without_mfa_still_works_after_step4(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression guard: non-MFA login continues to work after Step 4 changes.

    A verified user with mfa_enabled=False must receive a full TokenResponse
    (HTTP 200, access_token, refresh_token) when no totp_code is supplied.
    This ensures the Step 4 MFA gate did not break the existing code path
    for users who have not enrolled in MFA (SR-06, SR-07).

    Asserts:
    - HTTP 200
    - Response contains access_token and refresh_token
    - token_type is "bearer"
    """
    email = "no_mfa_regression@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)

    # _register_verify_login already performs a successful login and returns the
    # access_token.  We assert here that the login step inside that helper did
    # in fact succeed with full tokens (not an mfa_required sentinel).
    assert isinstance(access_token, str) and len(access_token) > 0

    # Perform a second explicit login to confirm the endpoint is still correct.
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data, "Non-MFA login must return access_token"
    assert "refresh_token" in data, "Non-MFA login must return refresh_token"
    assert data.get("token_type") == "bearer"


# ---------------------------------------------------------------------------
# Phase 3 Step 5: POST /auth/mfa/disable tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_disable_correct_password_and_valid_totp_returns_200(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Correct password + valid TOTP → 200; mfa_enabled False; mfa_secret None;
    MFA_DISABLED audit.

    Full happy-path test for SR-04 deactivation:
    1. Full enrollment flow produces an account with mfa_enabled=True.
    2. POST /auth/mfa/disable with correct password and a fresh TOTP code succeeds.
    3. The DB row has mfa_enabled=False and mfa_secret=None.
    4. An MFA_DISABLED audit log entry is committed (SR-16).
    """
    email = "mfa_disable_ok@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    # Re-login to obtain a fresh access token after MFA was enabled.
    valid_login_code = pyotp.TOTP(secret).now()
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={
            "email": email,
            "password": _STRONG_PASSWORD,
            "totp_code": valid_login_code,
        },
    )
    assert login_resp.status_code == 200
    access_token: str = login_resp.json()["access_token"]

    valid_disable_code = pyotp.TOTP(secret).now()
    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": valid_disable_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json().get("detail") == "MFA disabled successfully"

    # DB: mfa_enabled must be False and mfa_secret must be cleared.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is False, "mfa_enabled must be False after disable"
    assert user.mfa_secret is None, "mfa_secret must be cleared after disable"

    # Audit: an MFA_DISABLED log entry must exist for this user.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_DISABLED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected an MFA_DISABLED audit log entry"


@pytest.mark.asyncio
async def test_mfa_disable_wrong_password_returns_401(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Wrong password → 401; mfa_enabled remains True in DB.

    An incorrect password must be rejected immediately (SR-04).  The MFA gate
    must remain active — a failed password check must not alter user state.
    """
    email = "mfa_disable_bad_pw@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    # Re-login with valid TOTP to get a fresh token.
    valid_login_code = pyotp.TOTP(secret).now()
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={
            "email": email,
            "password": _STRONG_PASSWORD,
            "totp_code": valid_login_code,
        },
    )
    assert login_resp.status_code == 200
    access_token: str = login_resp.json()["access_token"]

    valid_code = pyotp.TOTP(secret).now()
    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": "WrongPassword99!", "totp_code": valid_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401

    # mfa_enabled must remain True — the gate must not deactivate on wrong password.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must remain True after wrong password"

    # An MFA_FAILED audit entry must have been committed before the 401 (SR-16).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_FAILED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected MFA_FAILED audit log after wrong password"
    assert log_entry.details is not None
    assert log_entry.details.get("reason") == "invalid_password"


@pytest.mark.asyncio
async def test_mfa_disable_bad_totp_returns_401_and_writes_mfa_failed_audit(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Valid password + wrong TOTP → 401; mfa_enabled still True; MFA_FAILED audit.

    An invalid TOTP code must be rejected and a MFA_FAILED audit log entry
    must be committed BEFORE the 401 is returned (SR-04, SR-16).  The gate
    must remain active.
    """
    email = "mfa_disable_bad_totp@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    # Re-login with valid TOTP to get a fresh token.
    valid_login_code = pyotp.TOTP(secret).now()
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={
            "email": email,
            "password": _STRONG_PASSWORD,
            "totp_code": valid_login_code,
        },
    )
    assert login_resp.status_code == 200
    access_token: str = login_resp.json()["access_token"]

    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "000000"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # mfa_enabled must remain True.
    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must remain True after invalid TOTP"

    # An MFA_FAILED audit entry must have been committed before the 401 (SR-16).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "MFA_FAILED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected MFA_FAILED audit log after invalid TOTP"
    assert log_entry.details is not None
    assert log_entry.details.get("reason") == "invalid_totp_code"


@pytest.mark.asyncio
async def test_mfa_disable_when_mfa_not_enabled_returns_400(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/disable on an account with mfa_enabled=False returns 400.

    A fresh verified user has never enrolled in MFA.  Calling disable on such
    an account must be rejected with HTTP 400 (SR-04).
    """
    email = "mfa_disable_not_enabled@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "123456"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    assert "not enabled" in response.json()["detail"].lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"password": "StrongPass1!"},
        {"totp_code": "123456"},
        {},
    ],
    ids=["missing-totp", "missing-password", "empty-body"],
)
async def test_mfa_disable_missing_fields_returns_422(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    body: dict,
) -> None:
    """POST /auth/mfa/disable with missing required fields returns 422.

    The ``MFADisableRequest`` schema requires both ``password`` and
    ``totp_code`` fields. Omitting either must trigger Pydantic validation
    failure before any service logic runs.
    """
    email = f"mfa_dis_422_{id(body)}@example.com"
    _user_id, access_token = await _register_verify_login(async_client, capsys, email)

    resp = await async_client.post(
        _MFA_DISABLE_URL,
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_disable_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """POST /auth/mfa/disable without Authorization header returns 403.

    ``HTTPBearer`` raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  The disable endpoint must not be accessible without a
    valid credential.
    """
    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "123456"},
    )

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Fix 1 — require_verified on MFA routes
# ---------------------------------------------------------------------------
# Helper: register and login WITHOUT verifying email.
# The login service issues tokens regardless of verification status;
# require_verified enforced at endpoint level, not at login.


async def _register_and_login_unverified(
    async_client: AsyncClient,
    email: str,
) -> str:
    """Register a user without verifying their email, then log in.

    Returns the access token so unverified callers can attempt MFA endpoints.

    Args:
        async_client: Test HTTP client fixture.
        email:        Email address to register.

    Returns:
        The access token string for the unverified user.
    """
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201

    # Log in WITHOUT calling /auth/verify-email.
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


@pytest.mark.asyncio
async def test_unverified_user_cannot_setup_mfa(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/setup returns 403 for an unverified user (SR-03).

    ``require_verified`` must block access to the setup endpoint before
    any service logic runs.  An unverified user with a valid Bearer token
    must receive HTTP 403.
    """
    email = "unverified_setup@example.com"
    access_token = await _register_and_login_unverified(async_client, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unverified_user_cannot_enable_mfa(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/enable returns 403 for an unverified user (SR-03).

    ``require_verified`` must block access to the enable endpoint before
    any service logic runs.  An unverified user with a valid Bearer token
    must receive HTTP 403.
    """
    email = "unverified_enable@example.com"
    access_token = await _register_and_login_unverified(async_client, email)

    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "123456"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unverified_user_cannot_disable_mfa(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/disable returns 403 for an unverified user (SR-03).

    ``require_verified`` must block access to the disable endpoint before
    any service logic runs.  An unverified user with a valid Bearer token
    must receive HTTP 403.
    """
    email = "unverified_disable@example.com"
    access_token = await _register_and_login_unverified(async_client, email)

    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "123456"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_mfa_disable_login_no_longer_requires_totp_after_disable(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression guard: after disabling MFA, login succeeds with password only.

    Once MFA is disabled, the account must behave like a non-MFA account.  A
    login with email and password but no totp_code must return a full
    TokenResponse (HTTP 200, access_token, refresh_token) rather than the
    MFARequiredResponse sentinel (SR-04, SR-06, SR-07).
    """
    email = "mfa_disable_regression@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

    # Re-login with TOTP to obtain a fresh token, then disable MFA.
    valid_login_code = pyotp.TOTP(secret).now()
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={
            "email": email,
            "password": _STRONG_PASSWORD,
            "totp_code": valid_login_code,
        },
    )
    assert login_resp.status_code == 200
    access_token: str = login_resp.json()["access_token"]

    valid_disable_code = pyotp.TOTP(secret).now()
    disable_resp = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": valid_disable_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert disable_resp.status_code == 200

    # Login with password only — must now succeed without a TOTP code.
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
        # totp_code deliberately omitted
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data, "access_token must be issued after MFA is disabled"
    assert "refresh_token" in data, "refresh_token must be issued after MFA is disabled"
    assert data.get("token_type") == "bearer"
    assert "mfa_required" not in data, "mfa_required must not appear in TokenResponse"
