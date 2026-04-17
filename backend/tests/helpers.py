"""Shared test helpers for the backend integration test suite.

Centralises the register → verify → login flow and ORM user creation so that
individual test modules do not duplicate the same boilerplate.  Each helper
asserts on the intermediate steps so that a failure in the setup phase is
immediately visible in the test output.
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from tests.conftest import _TEST_SETTINGS

REGISTER_URL = "/api/v1/auth/register"
VERIFY_URL = "/api/v1/auth/verify-email"
LOGIN_URL = "/api/v1/auth/login"
MFA_SETUP_URL = "/api/v1/auth/mfa/setup"
MFA_ENABLE_URL = "/api/v1/auth/mfa/enable"

STRONG_PASSWORD = "StrongPass1!"

_HELPER_SESSION_ID = "00000000-0000-0000-0000-100000000001"


async def register_verify_login(
    client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
    password: str = STRONG_PASSWORD,
) -> tuple[str, str, str]:
    """Register a user, verify email, and login.

    Returns ``(user_id, access_token, refresh_token)``.
    """
    reg = await client.post(REGISTER_URL, json={"email": email, "password": password})
    assert reg.status_code == 201
    user_id: str = reg.json()["id"]

    raw_token = capsys.readouterr().out.strip().rsplit(": ", maxsplit=1)[-1]

    verify = await client.get(VERIFY_URL, params={"token": raw_token})
    assert verify.status_code == 200

    login = await client.post(LOGIN_URL, json={"email": email, "password": password})
    assert login.status_code == 200
    data = login.json()
    return user_id, data["access_token"], data["refresh_token"]


async def enable_mfa(client: AsyncClient, access_token: str) -> str:
    """Run MFA setup + enable.  Returns the TOTP secret."""
    setup = await client.post(
        MFA_SETUP_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert setup.status_code == 200
    secret: str = setup.json()["secret"]

    code = pyotp.TOTP(secret).now()
    enable = await client.post(
        MFA_ENABLE_URL,
        json={"totp_code": code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable.status_code == 200
    return secret


async def make_orm_user(
    db: AsyncSession,
    redis: object,
    email: str,
    role: UserRole = UserRole.USER,
    *,
    is_verified: bool = True,
    password: str = "TestPassword123!",
    session_id: str = _HELPER_SESSION_ID,
) -> tuple[User, str]:
    """Create a user via ORM, seed a Redis session, return (user, access_token)."""
    user = User(
        email=email,
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
        is_verified=is_verified,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=session_id,
        settings=_TEST_SETTINGS,
    )
    await redis.set(f"session:{session_id}", str(user.id))  # type: ignore[union-attr]
    return user, token
