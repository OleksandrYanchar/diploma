"""Negative-path and denial API tests.

Covers authentication failures, authorization denials, and validation
rejections across all Phase 1–4 endpoints in a single focused module.

Each test targets a specific denial or failure scenario.  Tests that
exercise the MFA or login flows use the HTTP register → verify → login
helper so the full service layer runs.  Tests for RBAC and password-change
denials create users via ORM and seed FakeRedis directly, which is faster
and avoids coupling to the registration flow.

All tests are isolated via the ``async_client`` fixture (fresh in-memory
SQLite + FakeRedis per test).
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from tests.conftest import _TEST_SETTINGS

_REGISTER = "/api/v1/auth/register"
_VERIFY = "/api/v1/auth/verify-email"
_LOGIN = "/api/v1/auth/login"
_LOGOUT = "/api/v1/auth/logout"
_ME = "/api/v1/users/me"
_ADMIN_PING = "/api/v1/admin/ping"
_MFA_SETUP = "/api/v1/auth/mfa/setup"
_MFA_ENABLE = "/api/v1/auth/mfa/enable"
_MFA_DISABLE = "/api/v1/auth/mfa/disable"
_PW_CHANGE = "/api/v1/auth/password/change"

_STRONG_PWD = "StrongPass1!"

_ORM_SESSION_ID = "00000000-0000-0000-0000-200000000001"
_ORM_PASSWORD = "TestPassword123!"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _register_verify_login(
    client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Register, verify email, login.  Returns (access_token, refresh_token)."""
    reg = await client.post(_REGISTER, json={"email": email, "password": _STRONG_PWD})
    assert reg.status_code == 201

    raw_token = capsys.readouterr().out.strip().rsplit(": ", maxsplit=1)[-1]
    assert (await client.get(_VERIFY, params={"token": raw_token})).status_code == 200

    login = await client.post(_LOGIN, json={"email": email, "password": _STRONG_PWD})
    assert login.status_code == 200
    d = login.json()
    return d["access_token"], d["refresh_token"]


async def _enable_mfa(client: AsyncClient, access_token: str) -> str:
    """Run MFA setup + enable.  Returns the TOTP secret."""
    setup = await client.post(
        _MFA_SETUP, headers={"Authorization": f"Bearer {access_token}"}
    )
    assert setup.status_code == 200
    secret: str = setup.json()["secret"]

    code = pyotp.TOTP(secret).now()
    enable = await client.post(
        _MFA_ENABLE,
        json={"totp_code": code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable.status_code == 200
    return secret


async def _make_orm_user(
    db: AsyncSession,
    redis: object,
    email: str,
    role: UserRole,
    *,
    is_verified: bool = True,
) -> tuple[User, str]:
    """Create a user via ORM, seed a Redis session, return (user, access_token)."""
    user = User(
        email=email,
        hashed_password=hash_password(_ORM_PASSWORD),
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
        session_id=_ORM_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    await redis.set(f"session:{_ORM_SESSION_ID}", str(user.id))  # type: ignore[union-attr]
    return user, token


# ---------------------------------------------------------------------------
# Login failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_nonexistent_email_returns_401(
    async_client: AsyncClient,
) -> None:
    """Login with an unregistered email → 401."""
    r = await async_client.post(
        _LOGIN, json={"email": "nobody@example.com", "password": _STRONG_PWD}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Login with wrong password → 401."""
    email = "denial_wrong_pw@example.com"
    await _register_verify_login(async_client, capsys, email)

    r = await async_client.post(
        _LOGIN, json={"email": email, "password": "WrongPassword9!"}
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# MFA login failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_login_without_totp_returns_mfa_required(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MFA user, totp_code omitted → HTTP 200 + mfa_required, no tokens issued."""
    email = "denial_mfa_no_code@example.com"
    access, _ = await _register_verify_login(async_client, capsys, email)
    await _enable_mfa(async_client, access)

    r = await async_client.post(_LOGIN, json={"email": email, "password": _STRONG_PWD})
    assert r.status_code == 200
    assert r.json()["mfa_required"] is True
    assert "access_token" not in r.json()


@pytest.mark.asyncio
async def test_mfa_login_invalid_totp_returns_401(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MFA user, wrong TOTP → 401."""
    email = "denial_mfa_bad_code@example.com"
    access, _ = await _register_verify_login(async_client, capsys, email)
    await _enable_mfa(async_client, access)

    r = await async_client.post(
        _LOGIN,
        json={"email": email, "password": _STRONG_PWD, "totp_code": "000000"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Unauthenticated access
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_users_me_returns_403(
    async_client: AsyncClient,
) -> None:
    """GET /users/me without Authorization header → 403 (HTTPBearer)."""
    r = await async_client.get(_ME)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_logout_returns_403(
    async_client: AsyncClient,
) -> None:
    """POST /auth/logout without Authorization header → 403 (HTTPBearer)."""
    r = await async_client.post(_LOGOUT, json={"refresh_token": "x"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# RBAC denials on /admin/ping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_denied_admin_ping(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Verified USER role → 403 on /admin/ping (require_role ADMIN)."""
    _, token = await _make_orm_user(
        db_session, fake_redis, "denial_user_admin@example.com", UserRole.USER
    )
    r = await async_client.get(
        _ADMIN_PING, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_auditor_denied_admin_ping(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Verified AUDITOR role → 403 on /admin/ping."""
    _, token = await _make_orm_user(
        db_session, fake_redis, "denial_auditor_admin@example.com", UserRole.AUDITOR
    )
    r = await async_client.get(
        _ADMIN_PING, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_unverified_admin_denied_admin_ping(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Unverified ADMIN → 403 on /admin/ping (require_verified blocks first)."""
    _, token = await _make_orm_user(
        db_session,
        fake_redis,
        "denial_unv_admin@example.com",
        UserRole.ADMIN,
        is_verified=False,
    )
    r = await async_client.get(
        _ADMIN_PING, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Password change failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_change_wrong_current_returns_401(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Wrong current password → 401."""
    _, token = await _make_orm_user(
        db_session, fake_redis, "denial_pw_wrong@example.com", UserRole.USER
    )
    r = await async_client.post(
        _PW_CHANGE,
        json={"current_password": "WrongPassword99!", "new_password": "N3wStr0ng!Pass"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_change_weak_new_returns_422(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """New password passes schema (12+ chars) but fails SR-01 policy → 422."""
    _, token = await _make_orm_user(
        db_session, fake_redis, "denial_pw_weak@example.com", UserRole.USER
    )
    r = await async_client.post(
        _PW_CHANGE,
        json={
            "current_password": _ORM_PASSWORD,
            "new_password": "weakpassword12",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# MFA enable / disable failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_enable_without_setup_returns_400(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Enable MFA without prior setup (no mfa_secret on account) → 400."""
    email = "denial_mfa_no_setup@example.com"
    access, _ = await _register_verify_login(async_client, capsys, email)

    r = await async_client.post(
        _MFA_ENABLE,
        json={"totp_code": "123456"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_mfa_disable_wrong_password_returns_401(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MFA disable with incorrect password → 401."""
    email = "denial_mfa_dis_pw@example.com"
    access, _ = await _register_verify_login(async_client, capsys, email)
    secret = await _enable_mfa(async_client, access)

    mfa_login = await async_client.post(
        _LOGIN,
        json={
            "email": email,
            "password": _STRONG_PWD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert mfa_login.status_code == 200
    access = mfa_login.json()["access_token"]

    r = await async_client.post(
        _MFA_DISABLE,
        json={"password": "WrongPassword99!", "totp_code": pyotp.TOTP(secret).now()},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_mfa_disable_wrong_totp_returns_401(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MFA disable with wrong TOTP code → 401."""
    email = "denial_mfa_dis_totp@example.com"
    access, _ = await _register_verify_login(async_client, capsys, email)
    secret = await _enable_mfa(async_client, access)

    mfa_login = await async_client.post(
        _LOGIN,
        json={
            "email": email,
            "password": _STRONG_PWD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert mfa_login.status_code == 200
    access = mfa_login.json()["access_token"]

    r = await async_client.post(
        _MFA_DISABLE,
        json={"password": _STRONG_PWD, "totp_code": "000000"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 401
