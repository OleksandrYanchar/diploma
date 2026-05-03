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

Run with ``-s`` to see the step-by-step request trace::

    poetry run pytest tests/test_e2e_auth_lifecycle.py -v -s
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient, Response

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

_TOTAL_STEPS = 14


def _log(step: int, method: str, path: str, resp: Response) -> None:
    """Print a single-line request trace visible when pytest runs with ``-s``."""
    status = resp.status_code
    tag = "OK" if status < 400 else "DENIED"
    print(f"  [{step:>2}/{_TOTAL_STEPS}] {method:<5} {path:<35} -> {status} {tag}")


@pytest.mark.asyncio
async def test_full_auth_lifecycle(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Complete happy-path lifecycle exercising every Phase 1–4 auth endpoint."""
    email = "e2e_lifecycle@example.com"
    auth = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731

    print("\n--- E2E Auth Lifecycle ---")

    # 1. Register
    reg = await async_client.post(_REGISTER, json={"email": email, "password": _PWD})
    assert reg.status_code == 201
    assert reg.json()["email"] == email
    assert reg.json()["is_verified"] is False
    # Capture the DEMO-mode token before any _log() pollutes the buffer.
    raw_token = capsys.readouterr().out.strip().rsplit(": ", maxsplit=1)[-1]
    _log(1, "POST", _REGISTER, reg)

    # 2. Verify email
    verify = await async_client.get(_VERIFY, params={"token": raw_token})
    _log(2, "GET", _VERIFY, verify)
    assert verify.status_code == 200

    # 3. Login (no MFA)
    login = await async_client.post(_LOGIN, json={"email": email, "password": _PWD})
    _log(3, "POST", _LOGIN, login)
    assert login.status_code == 200
    d = login.json()
    access, refresh = d["access_token"], d["refresh_token"]
    assert d["token_type"] == "bearer"
    assert d["expires_in"] > 0

    # 4. GET /users/me
    me = await async_client.get(_ME, headers=auth(access))
    _log(4, "GET", _ME, me)
    assert me.status_code == 200
    assert me.json()["email"] == email
    assert me.json()["is_verified"] is True

    # 5. Refresh tokens
    ref = await async_client.post(_REFRESH, json={"refresh_token": refresh})
    _log(5, "POST", _REFRESH, ref)
    assert ref.status_code == 200
    access, refresh = ref.json()["access_token"], ref.json()["refresh_token"]

    # 6. MFA setup
    setup = await async_client.post(_MFA_SETUP, headers=auth(access))
    _log(6, "POST", _MFA_SETUP, setup)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert len(setup.json()["qr_code_base64"]) > 0

    # 7. MFA enable
    enable = await async_client.post(
        _MFA_ENABLE,
        json={"totp_code": pyotp.TOTP(secret).now()},
        headers=auth(access),
    )
    _log(7, "POST", _MFA_ENABLE, enable)
    assert enable.status_code == 200

    # 8. Logout (old session)
    out1 = await async_client.post(
        _LOGOUT, json={"refresh_token": refresh}, headers=auth(access)
    )
    _log(8, "POST", _LOGOUT, out1)
    assert out1.status_code == 200

    # 9. Login with MFA (password + TOTP)
    mfa_login = await async_client.post(
        _LOGIN,
        json={
            "email": email,
            "password": _PWD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    _log(9, "POST", _LOGIN + " (MFA)", mfa_login)
    assert mfa_login.status_code == 200
    access, refresh = (
        mfa_login.json()["access_token"],
        mfa_login.json()["refresh_token"],
    )

    # 10. Password change
    pw = await async_client.post(
        _PW_CHANGE,
        json={"current_password": _PWD, "new_password": _NEW_PWD},
        headers=auth(access),
    )
    _log(10, "POST", _PW_CHANGE, pw)
    assert pw.status_code == 200

    # 11. MFA disable (uses new password)
    disable = await async_client.post(
        _MFA_DISABLE,
        json={"password": _NEW_PWD, "totp_code": pyotp.TOTP(secret).now()},
        headers=auth(access),
    )
    _log(11, "POST", _MFA_DISABLE, disable)
    assert disable.status_code == 200

    # 12. Login without TOTP (MFA off, new password)
    plain = await async_client.post(_LOGIN, json={"email": email, "password": _NEW_PWD})
    _log(12, "POST", _LOGIN + " (no MFA)", plain)
    assert plain.status_code == 200
    assert "mfa_required" not in plain.json()
    access, refresh = plain.json()["access_token"], plain.json()["refresh_token"]

    # 13. Final logout
    out2 = await async_client.post(
        _LOGOUT, json={"refresh_token": refresh}, headers=auth(access)
    )
    _log(13, "POST", _LOGOUT, out2)
    assert out2.status_code == 200

    # ---- 14. Blacklisted token rejected (SR-09) ----
    rejected = await async_client.get(_ME, headers=auth(access))
    _log(14, "GET", _ME + " (blacklisted)", rejected)
    assert rejected.status_code == 401

    print("--- All 14 steps passed ---\n")
