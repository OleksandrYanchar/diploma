"""Tests for the POST /auth/login endpoint.

Covers:
- Successful login returning tokens (SR-06, SR-07)
- Invalid credentials (wrong password, nonexistent email) returning 401 (SR-02)
- Login succeeding for unverified users (SR-03 gates resource access, not login)
- Account lockout after max_failed_login_attempts failures (SR-05)
- Audit log written on both success and failure (SR-16)

All tests are isolated via the ``async_client`` fixture, which provides a
fresh in-memory SQLite database and FakeRedis instance per test.  No test
depends on state produced by another test.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.audit_log import AuditLog
from app.models.user import User

_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"

_STRONG_PASSWORD = "StrongPass1!"


async def _register_and_verify(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> None:
    """Register a user and complete email verification."""
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 201

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200


@pytest.mark.asyncio
async def test_login_returns_tokens_for_valid_credentials(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Successful login with correct credentials returns 200 with access token in the
    body and refresh token in the HttpOnly ``zt_rt`` cookie (SR-06, SR-07).

    The refresh token must NOT appear in the JSON body — it is delivered only
    via ``Set-Cookie`` so that JavaScript cannot read it.
    """
    email = "login_valid@example.com"
    await _register_and_verify(async_client, capsys, email)

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    # SR-07: refresh token must be in the HttpOnly cookie, not the JSON body.
    assert (
        "refresh_token" not in data
    ), "refresh_token must not appear in the JSON body (SR-07)"
    assert data["token_type"] == "bearer"
    assert isinstance(data["expires_in"], int)
    assert data["expires_in"] > 0
    # Verify the HttpOnly cookie is present.
    assert (
        response.cookies.get("zt_rt") is not None
    ), "zt_rt cookie must be set after successful login (SR-07)"
    # Assert cookie security attributes via the raw Set-Cookie header (SR-07).
    set_cookie_header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie_header, "zt_rt cookie must be HttpOnly (SR-07)"
    assert (
        "Path=/api/v1/auth" in set_cookie_header
    ), "zt_rt cookie must be scoped to /api/v1/auth (SR-07)"
    assert (
        "samesite=lax" in set_cookie_header.lower()
    ), "zt_rt cookie must have SameSite=lax (SR-07)"


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Login with a wrong password returns 401 regardless of whether the email exists.

    This tests SR-02: the service must reject invalid credentials without
    leaking which part of the credential pair was wrong.
    """
    email = "login_wrongpw@example.com"
    await _register_and_verify(async_client, capsys, email)

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": "WrongPassword9!"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_email_returns_401(
    async_client: AsyncClient,
) -> None:
    """Login with an email that was never registered returns 401.

    The same error is returned as for a wrong password, preventing email
    enumeration (anti-timing dummy hash is applied in the service).
    """
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": "ghost@example.com", "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_unverified_user_can_still_login(
    async_client: AsyncClient,
) -> None:
    """Login succeeds for a registered but unverified user.

    SR-03 gates access to protected endpoints, not the login endpoint itself.
    The verification requirement is enforced by the require_verified dependency
    (Phase 4), not here.  Login must succeed so the user can obtain a token
    and then be redirected to complete verification.

    The refresh token is delivered via the ``zt_rt`` HttpOnly cookie (SR-07),
    not in the JSON body.
    """
    email = "login_unverified@example.com"
    register_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert register_resp.status_code == 201

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    # SR-07: refresh token is in the HttpOnly cookie, not the JSON body.
    assert "refresh_token" not in data
    assert response.cookies.get("zt_rt") is not None


@pytest.mark.asyncio
async def test_login_account_lockout_after_max_failures(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After max_failed_login_attempts wrong-password attempts the account is locked.

    The default threshold is 5.  All 5 failed attempts must return 401.
    The subsequent attempt with the CORRECT password must return 403 (locked),
    enforcing SR-05 (account lockout).
    """
    email = "login_lockout@example.com"
    await _register_and_verify(async_client, capsys, email)

    for attempt in range(5):
        resp = await async_client.post(
            _LOGIN_URL,
            json={"email": email, "password": "WrongPassword9!"},
        )
        assert (
            resp.status_code == 401
        ), f"Expected 401 on attempt {attempt + 1}, got {resp.status_code}"

    locked_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert locked_resp.status_code == 403


@pytest.mark.asyncio
async def test_login_audit_log_written_on_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A LOGIN_SUCCESS audit log entry is written after a successful login.

    Queries the database directly via the db_session fixture to verify that
    an AuditLog row with action="LOGIN_SUCCESS" exists for the specific user
    registered in this test (SR-16).  The query is scoped by user_id obtained
    from the registration response to avoid collisions with rows written by
    other tests sharing the same SQLite in-memory engine.
    """
    email = "login_audit_ok@example.com"

    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_SUCCESS",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a LOGIN_SUCCESS audit log entry"
    assert log_entry.user_id is not None


@pytest.mark.asyncio
async def test_login_audit_log_written_on_failure(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A LOGIN_FAILED audit log entry is written after a failed login attempt.

    Queries the database directly to verify that an AuditLog row with
    action="LOGIN_FAILED" exists after a wrong-password attempt (SR-16).  The
    query is scoped by user_id to avoid false matches from other tests.
    """
    email = "login_audit_fail@example.com"

    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    fail_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": "WrongPassword9!"},
    )
    assert fail_resp.status_code == 401

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a LOGIN_FAILED audit log entry"
    assert log_entry.details == {"reason": "invalid_password"}


@pytest.mark.asyncio
async def test_login_failed_audit_log_unknown_email(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A LOGIN_FAILED audit log with user_id=None is written
    for unregistered email (SR-16)."""
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": "never_registered@example.com", "password": _STRONG_PASSWORD},
    )
    assert response.status_code == 401

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.user_id.is_(None),
        )
    )
    all_entries = result.scalars().all()
    log_entry = next(
        (
            e
            for e in all_entries
            if e.details and e.details.get("reason") == "user_not_found"
        ),
        None,
    )

    assert (
        log_entry is not None
    ), "Expected a LOGIN_FAILED audit log entry for unknown email"
    assert log_entry.user_id is None
    assert log_entry.details.get("reason") == "user_not_found"


@pytest.mark.asyncio
async def test_login_mfa_gate_returns_mfa_required(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When mfa_enabled=True the login endpoint returns HTTP 200 with mfa_required=True.

    Directly sets user.mfa_enabled=True in the DB without calling a Phase 3
    MFA setup endpoint.  Verifies that the response body has the
    MFARequiredResponse shape (mfa_required=True) and NOT a TokenResponse shape
    (no access_token or refresh_token fields).  Ensures the fix for raising
    HTTPException(status_code=200) is in place (SR-04 gate behaviour).
    """
    email = "mfa_gate_shape@example.com"
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    user_result = await db_session.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = user_result.scalar_one()
    user.mfa_enabled = True
    await db_session.commit()

    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200

    data = response.json()
    assert (
        data.get("mfa_required") is True
    ), "Expected mfa_required=True in response body"
    assert (
        "access_token" not in data
    ), "access_token must NOT be present on MFA gate response"
    assert (
        "refresh_token" not in data
    ), "refresh_token must NOT be present on MFA gate response"


@pytest.mark.asyncio
async def test_login_mfa_gate_writes_audit_log(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An audit log with action="LOGIN_MFA_REQUIRED" is written on the MFA gate path.

    Verifies SR-16: every security-relevant event, including the MFA gate,
    produces an audit log entry.  The entry must be scoped to the correct
    user_id so that it can be correlated in forensic analysis (ADR-18).
    """
    email = "mfa_gate_audit@example.com"
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    user_result = await db_session.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = user_result.scalar_one()
    user.mfa_enabled = True
    await db_session.commit()

    mfa_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert mfa_resp.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_MFA_REQUIRED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a LOGIN_MFA_REQUIRED audit log entry"
    assert log_entry.user_id == uuid.UUID(user_id)


@pytest.mark.asyncio
async def test_login_deactivated_user_returns_403(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Login with a deactivated account returns 403 (SR-05)."""
    email = "login_deactivated@example.com"
    await _register_and_verify(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.is_active = False
    await db_session.commit()

    resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_login_prelocked_user_returns_403(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Login with a pre-locked account returns 403 (SR-05)."""
    email = "login_prelocked@example.com"
    await _register_and_verify(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.locked_until = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    await db_session.commit()

    resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_login_creates_redis_session(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    fake_redis: object,
) -> None:
    """Successful login creates a Redis session key (SR-10)."""
    email = "login_redis@example.com"
    await _register_and_verify(async_client, capsys, email)

    resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 200

    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        resp.json()["access_token"],
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    session_id = decoded["session_id"]

    session_val = await fake_redis.get(f"session:{session_id}")  # type: ignore[union-attr]
    assert session_val is not None, "Redis session must exist after login"


@pytest.mark.asyncio
async def test_login_resets_failed_count_on_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Successful login resets the failed_login_count to 0 (SR-05)."""
    email = "login_reset_count@example.com"
    await _register_and_verify(async_client, capsys, email)

    for _ in range(3):
        await async_client.post(
            _LOGIN_URL,
            json={"email": email, "password": "WrongPassword9!"},
        )

    resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 200

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    assert user.failed_login_count == 0, "Counter must reset after successful login"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"password": "StrongPass1!"},
        {"email": "miss_pw@example.com"},
        {},
    ],
    ids=["missing-email", "missing-password", "empty-body"],
)
async def test_login_missing_fields_returns_422(
    async_client: AsyncClient,
    body: dict,
) -> None:
    """Missing required fields in login request return 422."""
    resp = await async_client.post(_LOGIN_URL, json=body)
    assert resp.status_code == 422


_USERS_ME_URL = "/api/v1/users/me"


@pytest.mark.asyncio
async def test_concurrent_logins_produce_independent_sessions(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two successive logins yield two independent sessions (SR-10).

    Each login creates its own Redis session and access token.  Both tokens
    must work because the service does NOT revoke prior sessions on login.
    After logging out with one token, the other must still be valid.

    The refresh token for each login is stored in the ``zt_rt`` HttpOnly
    cookie (SR-07).  The httpx client automatically updates its cookie jar
    on each ``Set-Cookie`` response, so after the second login the cookie
    jar holds the second session's refresh token.  To log out the first
    session independently we explicitly pass its refresh token via the
    cookie parameter.
    """
    email = f"concurrent_{uuid.uuid4().hex[:8]}@example.com"
    await _register_and_verify(async_client, capsys, email)

    login_1 = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_1.status_code == 200
    token_1 = login_1.json()["access_token"]
    # Capture the refresh token from the cookie before the second login
    # overwrites it in the client's cookie jar.
    refresh_cookie_1 = login_1.cookies.get("zt_rt")
    assert refresh_cookie_1 is not None

    login_2 = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_2.status_code == 200
    token_2 = login_2.json()["access_token"]

    assert token_1 != token_2

    me_1 = await async_client.get(
        _USERS_ME_URL,
        headers={"Authorization": f"Bearer {token_1}"},
    )
    me_2 = await async_client.get(
        _USERS_ME_URL,
        headers={"Authorization": f"Bearer {token_2}"},
    )
    assert me_1.status_code == 200
    assert me_2.status_code == 200

    # Log out session 1 by explicitly passing its refresh token cookie.
    logout = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token_1}"},
        cookies={"zt_rt": refresh_cookie_1},
    )
    assert logout.status_code == 200

    me_after = await async_client.get(
        _USERS_ME_URL,
        headers={"Authorization": f"Bearer {token_2}"},
    )
    assert me_after.status_code == 200
