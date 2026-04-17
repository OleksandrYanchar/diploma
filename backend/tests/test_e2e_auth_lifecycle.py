"""End-to-end happy-path test for the complete authentication lifecycle.

Walks through every Phase 1–4 auth flow in a single test:
register → verify email → login → GET /users/me → refresh → MFA setup →
MFA enable → logout → MFA login → password change → MFA disable →
plain login → logout → blacklisted-token rejection.

This test exercises the real HTTP endpoints via async_client (ASGI
transport with in-memory SQLite + FakeRedis).  It does NOT create ORM
objects directly — every state change flows through the API surface so that
the full dependency chain (schemas, service, security, audit logging) is
exercised end-to-end.
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient

_REGISTER = "/api/v1/auth/register"
_VERIFY = "/api/v1/auth/verify-email"
_LOGIN = "/api/v1/auth/login"
_REFRESH = "/api/v1/auth/refresh"
_LOGOUT = "/api/v1/auth/logout"
_ME = "/api/v1/users/me"
_MFA_SETUP = "/api/v1/auth/mfa/setup"
_MFA_ENABLE = "/api/v1/auth/mfa/enable"
_MFA_DISABLE = "/api/v1/auth/mfa/disable"
_PW_CHANGE = "/api/v1/auth/password/change"

_PWD = "StrongPass1!"
_NEW_PWD = "N3wStr0ng!Pass"


@pytest.mark.asyncio
async def test_full_auth_lifecycle(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Complete happy-path lifecycle exercising every Phase 1–4 auth endpoint."""
    email = "e2e_lifecycle@example.com"
    auth = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731

    # ---- 1. Register ----
    reg = await async_client.post(_REGISTER, json={"email": email, "password": _PWD})
    assert reg.status_code == 201
    assert reg.json()["email"] == email
    assert reg.json()["is_verified"] is False

    # ---- 2. Verify email ----
    raw_token = capsys.readouterr().out.strip().rsplit(": ", maxsplit=1)[-1]
    verify = await async_client.get(_VERIFY, params={"token": raw_token})
    assert verify.status_code == 200

    # ---- 3. Login (no MFA) ----
    login = await async_client.post(_LOGIN, json={"email": email, "password": _PWD})
    assert login.status_code == 200
    d = login.json()
    access, refresh = d["access_token"], d["refresh_token"]
    assert d["token_type"] == "bearer"
    assert d["expires_in"] > 0

    # ---- 4. GET /users/me ----
    me = await async_client.get(_ME, headers=auth(access))
    assert me.status_code == 200
    assert me.json()["email"] == email
    assert me.json()["is_verified"] is True

    # ---- 5. Refresh tokens ----
    ref = await async_client.post(_REFRESH, json={"refresh_token": refresh})
    assert ref.status_code == 200
    access, refresh = ref.json()["access_token"], ref.json()["refresh_token"]

    # ---- 6. MFA setup ----
    setup = await async_client.post(_MFA_SETUP, headers=auth(access))
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert len(setup.json()["qr_code_base64"]) > 0

    # ---- 7. MFA enable ----
    enable = await async_client.post(
        _MFA_ENABLE,
        json={"totp_code": pyotp.TOTP(secret).now()},
        headers=auth(access),
    )
    assert enable.status_code == 200

    # ---- 8. Logout (old session) ----
    out1 = await async_client.post(
        _LOGOUT, json={"refresh_token": refresh}, headers=auth(access)
    )
    assert out1.status_code == 200

    # ---- 9. Login with MFA (password + TOTP) ----
    mfa_login = await async_client.post(
        _LOGIN,
        json={
            "email": email,
            "password": _PWD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert mfa_login.status_code == 200
    access, refresh = (
        mfa_login.json()["access_token"],
        mfa_login.json()["refresh_token"],
    )

    # ---- 10. Password change ----
    pw = await async_client.post(
        _PW_CHANGE,
        json={"current_password": _PWD, "new_password": _NEW_PWD},
        headers=auth(access),
    )
    assert pw.status_code == 200

    # ---- 11. MFA disable (uses new password) ----
    disable = await async_client.post(
        _MFA_DISABLE,
        json={"password": _NEW_PWD, "totp_code": pyotp.TOTP(secret).now()},
        headers=auth(access),
    )
    assert disable.status_code == 200

    # ---- 12. Login without TOTP (MFA off, new password) ----
    plain = await async_client.post(_LOGIN, json={"email": email, "password": _NEW_PWD})
    assert plain.status_code == 200
    assert "mfa_required" not in plain.json()
    access, refresh = plain.json()["access_token"], plain.json()["refresh_token"]

    # ---- 13. Final logout ----
    out2 = await async_client.post(
        _LOGOUT, json={"refresh_token": refresh}, headers=auth(access)
    )
    assert out2.status_code == 200

    # ---- 14. Blacklisted token rejected (SR-09) ----
    rejected = await async_client.get(_ME, headers=auth(access))
    assert rejected.status_code == 401
