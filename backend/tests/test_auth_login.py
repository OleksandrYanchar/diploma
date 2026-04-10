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

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------

_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"

_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


async def _register_and_verify(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> None:
    """Register a user and complete email verification.

    Registers the given email with the shared strong password, then captures
    the raw verification token from stdout (DEMO MODE print) and calls the
    verify-email endpoint.  After this helper returns, the user is active and
    verified, ready for login tests.

    Args:
        async_client: The test HTTP client fixture.
        capsys:       pytest's stdout/stderr capture fixture.
        email:        The email address to register.
    """
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 201

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_returns_tokens_for_valid_credentials(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Successful login with correct credentials returns 200 and all token fields.

    Asserts that the response body contains access_token, refresh_token,
    token_type="bearer", and a positive expires_in value (SR-06, SR-07).
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
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert isinstance(data["expires_in"], int)
    assert data["expires_in"] > 0


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
    """
    email = "login_unverified@example.com"
    register_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert register_resp.status_code == 201

    # Deliberately do NOT verify the email — login should still succeed.
    response = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


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

    # Exhaust the allowed failure count (default: 5).
    for attempt in range(5):
        resp = await async_client.post(
            _LOGIN_URL,
            json={"email": email, "password": "WrongPassword9!"},
        )
        assert (
            resp.status_code == 401
        ), f"Expected 401 on attempt {attempt + 1}, got {resp.status_code}"

    # The account should now be locked.  Even correct credentials must be rejected.
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

    # Register directly so we capture the user id from the response body.
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # Complete email verification.
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200

    import uuid as _uuid

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_SUCCESS",
            AuditLog.user_id == _uuid.UUID(user_id),
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

    # Register directly to capture user id.
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # Complete email verification.
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    fail_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": "WrongPassword9!"},
    )
    assert fail_resp.status_code == 401

    import uuid as _uuid

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.user_id == _uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a LOGIN_FAILED audit log entry"
    assert log_entry.details == {"reason": "invalid_password"}
