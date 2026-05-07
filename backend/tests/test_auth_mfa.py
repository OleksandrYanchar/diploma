"""Tests for MFA endpoints: POST /auth/mfa/setup (Phase 3 Step 2),
POST /auth/mfa/enable (Phase 3 Step 3), the MFA login gate (Phase 3 Step 4),
and POST /auth/mfa/disable (Phase 3 Step 5).

All tests use the register → verify-email → login helper pattern to produce
a valid access token before exercising the MFA endpoints.  Each test is
fully isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per
test).
"""

import base64
import uuid

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User
from tests.helpers import REGISTER_URL, STRONG_PASSWORD, register_verify_login

_REGISTER_URL = REGISTER_URL
_LOGIN_URL = "/api/v1/auth/login"
_MFA_SETUP_URL = "/api/v1/auth/mfa/setup"
_MFA_ENABLE_URL = "/api/v1/auth/mfa/enable"
_MFA_DISABLE_URL = "/api/v1/auth/mfa/disable"

_STRONG_PASSWORD = STRONG_PASSWORD


@pytest.mark.asyncio
async def test_mfa_setup_returns_200_with_secret_and_qr(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/setup returns 200 with a non-empty secret and QR code (SR-04)."""
    email = "mfa_setup_200@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()

    assert "secret" in data
    assert isinstance(data["secret"], str)
    assert len(data["secret"]) > 0

    assert "qr_code_base64" in data
    assert isinstance(data["qr_code_base64"], str)
    assert len(data["qr_code_base64"]) > 0

    decoded_bytes = base64.b64decode(data["qr_code_base64"])
    assert len(decoded_bytes) > 0

    assert "issuer" in data
    assert isinstance(data["issuer"], str)
    assert len(data["issuer"]) > 0


@pytest.mark.asyncio
async def test_mfa_setup_persists_secret_and_does_not_enable_mfa(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """mfa_secret is written to DB; mfa_enabled remains False
    until the enable step (SR-04)."""
    email = "mfa_setup_db@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    response = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    returned_secret: str = response.json()["secret"]

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
    """A MFA_SETUP_INITIATED audit log entry is written on success (SR-16)."""
    email = "mfa_setup_audit@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """POST /auth/mfa/setup without Authorization header returns 403 (HTTPBearer)."""
    response = await async_client.post(_MFA_SETUP_URL)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_mfa_setup_fails_when_already_enabled(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/mfa/setup returns 400 if MFA is already enabled (SR-04)."""
    email = "mfa_setup_already_enabled@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """Calling setup twice overwrites the abandoned secret;
    only the latest is stored."""
    email = "mfa_setup_overwrite@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    first_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_resp.status_code == 200
    first_secret: str = first_resp.json()["secret"]

    second_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert second_resp.status_code == 200
    second_secret: str = second_resp.json()["secret"]

    assert first_secret != second_secret, "Each setup call must generate a fresh secret"

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert (
        user.mfa_secret == second_secret
    ), "The stored secret must match the most recent setup response"
    assert user.mfa_enabled is False


async def _setup_mfa_and_get_secret(
    async_client: AsyncClient,
    access_token: str,
) -> str:
    """Call POST /auth/mfa/setup and return the TOTP secret."""
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
    """Valid TOTP → 200; mfa_enabled True in DB;
    MFA_ENABLED audit log written (SR-04, SR-16)."""
    email = "mfa_enable_valid@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    secret = await _setup_mfa_and_get_secret(async_client, access_token)

    valid_code = pyotp.TOTP(secret).now()

    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": valid_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json().get("detail") == "MFA enabled successfully"

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must be True after successful enable"

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
    """Invalid TOTP → 401; mfa_enabled stays False;
    MFA_FAILED audit committed before raise (SR-04, SR-16)."""
    email = "mfa_enable_invalid@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    await _setup_mfa_and_get_secret(async_client, access_token)

    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "000000"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is False, "mfa_enabled must remain False after invalid code"

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
    """POST /auth/mfa/enable without prior setup returns 400
    — no secret to verify (SR-04)."""
    email = "mfa_enable_no_setup@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """POST /auth/mfa/enable when already active returns 400;
    re-activation requires a disable step (SR-04)."""
    email = "mfa_enable_already_on@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    secret = await _setup_mfa_and_get_secret(async_client, access_token)

    first_code = pyotp.TOTP(secret).now()
    first_resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": first_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_resp.status_code == 200

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True

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
    """POST /auth/mfa/enable with empty body returns 422 (Pydantic validation)."""
    email = "mfa_enable_no_code@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)
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
    """POST /auth/mfa/enable without Authorization header returns 403 (HTTPBearer)."""
    response = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": "123456"},
    )

    assert response.status_code == 403


async def _register_verify_login_and_enable_mfa(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Full enrollment helper: register → verify → login → setup MFA → enable MFA.

    Returns ``(user_id, totp_secret)`` with mfa_enabled=True on the account.
    """
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    setup_resp = await async_client.post(
        _MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert setup_resp.status_code == 200
    secret: str = setup_resp.json()["secret"]

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
    """T-03: MFA user + no totp_code → HTTP 200, mfa_required=True,
    no tokens issued (SR-04)."""
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
    """T-04: MFA user + invalid TOTP → 401;
    MFA_FAILED audit committed before raise (SR-04, SR-16)."""
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
    """Valid TOTP at login issues full TokenResponse
    + MFA_VERIFIED audit (SR-04, SR-06, SR-16)."""
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
    """Regression guard: non-MFA login still returns full TokenResponse
    after MFA gate added."""
    email = "no_mfa_regression@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    # register_verify_login already performs a successful login and returns the
    # access_token.  We assert here that the login step inside that helper did
    # in fact succeed with full tokens (not an mfa_required sentinel).
    assert isinstance(access_token, str) and len(access_token) > 0

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data, "Non-MFA login must return access_token"
    assert "refresh_token" in data, "Non-MFA login must return refresh_token"
    assert data.get("token_type") == "bearer"


@pytest.mark.asyncio
async def test_mfa_disable_correct_password_and_valid_totp_returns_200(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Correct password + valid TOTP → 200; mfa_enabled False;
    mfa_secret None; MFA_DISABLED audit (SR-04, SR-16)."""
    email = "mfa_disable_ok@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

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

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is False, "mfa_enabled must be False after disable"
    assert user.mfa_secret is None, "mfa_secret must be cleared after disable"

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
    """Wrong password → 401; mfa_enabled remains True;
    MFA_FAILED audit written (SR-04)."""
    email = "mfa_disable_bad_pw@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

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

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must remain True after wrong password"

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
    """Valid password + wrong TOTP → 401; mfa_enabled still True;
    MFA_FAILED audit committed before raise (SR-04, SR-16)."""
    email = "mfa_disable_bad_totp@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

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

    result = await db_session.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user: User | None = result.scalar_one_or_none()
    assert user is not None
    assert user.mfa_enabled is True, "mfa_enabled must remain True after invalid TOTP"

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
    """POST /auth/mfa/disable on a non-enrolled account returns 400 (SR-04)."""
    email = "mfa_disable_not_enabled@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """POST /auth/mfa/disable with missing required fields
    returns 422 (Pydantic validation)."""
    email = f"mfa_dis_422_{id(body)}@example.com"
    _user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """POST /auth/mfa/disable without Authorization header returns 403 (HTTPBearer)."""
    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "123456"},
    )

    assert response.status_code == 403


async def _register_and_login_unverified(
    async_client: AsyncClient,
    email: str,
) -> str:
    """Register without verifying email, log in, and return the access token."""
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201

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
    """POST /auth/mfa/setup returns 403 for an unverified user
    — require_verified gate (SR-03)."""
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
    """POST /auth/mfa/enable returns 403 for an unverified user
    — require_verified gate (SR-03)."""
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
    """POST /auth/mfa/disable returns 403 for an unverified user
    — require_verified gate (SR-03)."""
    email = "unverified_disable@example.com"
    access_token = await _register_and_login_unverified(async_client, email)

    response = await async_client.post(
        _MFA_DISABLE_URL,
        json={"password": _STRONG_PASSWORD, "totp_code": "123456"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_disable_mfa_wrong_password_triggers_lockout(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Repeated wrong-password calls to disable_mfa trigger account lockout (M-3/SR-05)."""
    from tests.conftest import _TEST_SETTINGS

    email = f"dmfa_lockout_{uuid.uuid4().hex[:8]}@example.com"
    user_id, access_token, _ = await register_verify_login(async_client, capsys, email)

    # Enable MFA first so disable_mfa checks can run (past the mfa_enabled guard).
    setup_resp = await async_client.post(
        _MFA_SETUP_URL, headers={"Authorization": f"Bearer {access_token}"}
    )
    assert setup_resp.status_code == 200
    totp_secret = setup_resp.json()["secret"]
    totp_code = pyotp.TOTP(totp_secret).now()
    enable_resp = await async_client.post(
        _MFA_ENABLE_URL,
        json={"totp_code": totp_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable_resp.status_code == 200

    max_attempts = _TEST_SETTINGS.max_failed_login_attempts
    for _ in range(max_attempts):
        resp = await async_client.post(
            _MFA_DISABLE_URL,
            json={"password": "WrongPassword99!", "totp_code": "000000"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 401

    result = await db_session.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    locked_user = result.scalar_one()
    assert locked_user.locked_until is not None, (
        "Account must be locked after repeated wrong-password submissions to disable_mfa (M-3)"
    )


@pytest.mark.asyncio
async def test_mfa_disable_login_no_longer_requires_totp_after_disable(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression guard: after disabling MFA, login succeeds
    with password only (SR-04)."""
    email = "mfa_disable_regression@example.com"
    user_id, secret = await _register_verify_login_and_enable_mfa(
        async_client, capsys, email
    )

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
