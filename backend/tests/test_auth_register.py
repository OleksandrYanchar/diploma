"""Tests for user registration and email verification endpoints.

Covers:
- POST /api/v1/auth/register   (SR-01, SR-02, SR-03, SR-16)
- GET  /api/v1/auth/verify-email (SR-03)

All tests are isolated via the ``async_client`` fixture, which provides a
fresh in-memory SQLite database and FakeRedis instance per test.  No test
depends on state produced by another test.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"

_VALID_EMAIL = "alice@example.com"
_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_valid_user_returns_201(async_client: AsyncClient) -> None:
    """Registering with a valid email and strong password returns HTTP 201.

    Asserts that:
    - The response status is 201 Created.
    - The response body contains ``id``, ``email``, and ``is_verified=False``.
    - Sensitive fields (``hashed_password``, ``mfa_secret``) are NOT present in
      the response, enforcing SR-02 and SR-04 serialisation boundaries.
    """
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": _VALID_EMAIL, "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 201

    data = response.json()
    assert "id" in data
    assert data["email"] == _VALID_EMAIL
    assert data["is_verified"] is False

    # Sensitive fields must never appear in the response (SR-02, SR-04).
    assert "hashed_password" not in data
    assert "mfa_secret" not in data


@pytest.mark.asyncio
async def test_register_weak_password_returns_422(async_client: AsyncClient) -> None:
    """Registering with a password that fails the SR-01 strength policy returns 422.

    The password "short" is only 5 characters and lacks uppercase, digit, and
    special character — it violates every sub-rule of the policy.  The service
    must reject it before any DB interaction occurs.
    """
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": "bob@example.com", "password": "short"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_409(async_client: AsyncClient) -> None:
    """Attempting to register the same email twice returns 409 on the second attempt.

    The first registration succeeds with 201.  The second registration with the
    same email must be rejected with HTTP 409 Conflict, preventing account
    enumeration through diverging error codes (SR-03).
    """
    payload = {"email": "duplicate@example.com", "password": _STRONG_PASSWORD}

    first = await async_client.post(_REGISTER_URL, json=payload)
    assert first.status_code == 201

    second = await async_client.post(_REGISTER_URL, json=payload)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_register_invalid_email_returns_422(async_client: AsyncClient) -> None:
    """Registering with a syntactically invalid email address returns 422.

    Pydantic's ``EmailStr`` field rejects malformed addresses at the schema
    boundary, before the service layer is reached.  This enforces SR-20 (input
    validation).
    """
    response = await async_client.post(
        _REGISTER_URL,
        json={"email": "not-an-email", "password": _STRONG_PASSWORD},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Email verification tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_email_valid_token_returns_200(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Consuming a valid verification token returns 200 with a success message.

    The raw token is captured from stdout (the DEMO MODE print in the service).
    The print format is:
        [DEMO MODE] Email verification token for {email}: {raw_token}

    The token is the substring after the last ": " on the output line.

    Asserts that:
    - The verification response is 200.
    - The response body contains a ``message`` key.
    - (Implicitly) the token is single-use: the token hash is cleared on success,
      which is verified by the next test.
    """
    email = "verify_valid@example.com"
    await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    # Capture and parse the raw verification token printed by the service.
    captured = capsys.readouterr()
    # The print line ends with ": {raw_token}"; split on the last ": " to extract it.
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    response = await async_client.get(_VERIFY_URL, params={"token": raw_token})

    assert response.status_code == 200
    assert "message" in response.json()


@pytest.mark.asyncio
async def test_verify_email_invalid_token_returns_400(
    async_client: AsyncClient,
) -> None:
    """Submitting a bogus verification token returns HTTP 400.

    An unrecognised token produces no matching row in the database (the SHA-256
    hash of "bogus" will not match any stored hash), so the service must raise
    HTTPException 400 without leaking whether the token format is wrong or
    simply not found.
    """
    response = await async_client.get(_VERIFY_URL, params={"token": "bogus"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_verify_email_already_used_returns_400(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reusing an already-consumed verification token returns HTTP 400.

    After the first successful verification the token hash is cleared from the
    database (``email_verification_token_hash = None``).  A second attempt with
    the same raw token must therefore fail with 400, enforcing the single-use
    property required by SR-03.
    """
    email = "verify_reuse@example.com"
    await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    # First verification: must succeed.
    first = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert first.status_code == 200

    # Second verification with the same token: must fail.
    second = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert second.status_code == 400
