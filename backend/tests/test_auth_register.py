"""Tests for user registration and email verification endpoints.

All tests are isolated via the ``async_client`` fixture, which provides a
fresh in-memory SQLite database and FakeRedis instance per test.  No test
depends on state produced by another test.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"

_VALID_EMAIL = "alice@example.com"
_STRONG_PASSWORD = "StrongPass1!"


@pytest.mark.asyncio
async def test_register_valid_user_returns_201(async_client: AsyncClient) -> None:
    """Valid registration returns 201;
    sensitive fields must be absent (SR-02, SR-04)."""
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": _VALID_EMAIL, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 201

    data = response.json()
    assert "id" in data
    assert data["email"] == _VALID_EMAIL
    assert data["is_verified"] is False

    assert "hashed_password" not in data
    assert "mfa_secret" not in data


@pytest.mark.asyncio
async def test_register_weak_password_returns_422(async_client: AsyncClient) -> None:
    """Weak password returns 422 (SR-01 policy enforced before any DB interaction)."""
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": "bob@example.com", "password": "short"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_409(async_client: AsyncClient) -> None:
    """Duplicate email returns 409 on the second attempt."""
    payload = {"email": "duplicate@example.com", "password": _STRONG_PASSWORD}

    first = await async_client.post(_REGISTER_URL, json=payload)
    assert first.status_code == 201

    second = await async_client.post(_REGISTER_URL, json=payload)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_register_invalid_email_returns_422(async_client: AsyncClient) -> None:
    """Invalid email format returns 422 (Pydantic EmailStr validation)."""
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": "not-an-email", "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "password",
    [
        "nouppercase1!aa",
        "NOLOWERCASE1!AA",
        "NoDigitHere!abc",
        "NoSpecialChar1a",
    ],
    ids=["no-uppercase", "no-lowercase", "no-digit", "no-special"],
)
async def test_register_password_policy_violation_returns_422(
    async_client: AsyncClient,
    password: str,
) -> None:
    """Each SR-01 sub-rule is enforced: uppercase, lowercase, digit, special."""
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": f"policy_{password[:8]}@example.com", "password": password},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"password": "StrongPass1!"},
        {"email": "missing_pw@example.com"},
        {},
    ],
    ids=["missing-email", "missing-password", "empty-body"],
)
async def test_register_missing_fields_returns_422(
    async_client: AsyncClient,
    body: dict,
) -> None:
    """Missing required fields return 422."""
    resp = await async_client.post(_REGISTER_URL, json=body)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_creates_audit_log_entry(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Registration writes a REGISTER audit log entry (SR-16)."""
    email = "register_audit@example.com"
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "REGISTER",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()
    assert log_entry is not None, "Expected a REGISTER audit log entry"


@pytest.mark.asyncio
async def test_register_response_excludes_email_verification_token(
    async_client: AsyncClient,
) -> None:
    """Registration response must not leak the email_verification_token_hash."""
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": "no_leak@example.com", "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "email_verification_token_hash" not in body
    assert "hashed_password" not in body
    assert "mfa_secret" not in body
    assert "failed_login_count" not in body


@pytest.mark.asyncio
async def test_verify_email_valid_token_returns_200(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Valid verification token returns 200 with a message (SR-03)."""
    email = "verify_valid@example.com"
    await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    response = await async_client.get(_VERIFY_URL, params={"token": raw_token})

    assert response.status_code == 200
    assert "message" in response.json()


@pytest.mark.asyncio
async def test_verify_email_invalid_token_returns_400(
    async_client: AsyncClient,
) -> None:
    """Bogus verification token returns 400 (SR-03)."""
    response = await async_client.get(_VERIFY_URL, params={"token": "bogus"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_verify_email_already_used_returns_400(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reusing a consumed verification token returns 400
    (single-use property, SR-03)."""
    email = "verify_reuse@example.com"
    await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    first = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert first.status_code == 200

    second = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert second.status_code == 400


@pytest.mark.asyncio
async def test_verify_email_creates_audit_log_entry(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Email verification writes an EMAIL_VERIFIED audit log entry (SR-16)."""
    email = "verify_audit@example.com"
    reg = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg.status_code == 201
    user_id = reg.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert resp.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "EMAIL_VERIFIED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()
    assert log_entry is not None, "Expected an EMAIL_VERIFIED audit log entry"
