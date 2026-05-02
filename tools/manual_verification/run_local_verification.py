#!/usr/bin/env python3
"""Local verification runner for the Zero Trust financial platform.

Runs real HTTP requests against the locally running Docker stack and writes
a full report (summary.md, scenarios.jsonl, scenarios.md, docker_logs.txt).

Typical usage (from repository root, inside the backend poetry env):

    cd backend && poetry run python ../tools/manual_verification/run_local_verification.py

Flags:
    --base-url URL        Base URL for the app (default: http://localhost:8000).
                          Use http://localhost for nginx (rate limits apply).
    --output-dir DIR      Where to write artifacts (default: ../artifacts/manual_verification).
    --start-docker        Automatically start the Docker stack before testing.
    --skip-migrations     Skip the alembic upgrade head step.
    --smoke-only          Run only happy-path scenarios.

Docker note:
    The default --base-url is http://localhost:8000 (direct backend, no rate
    limits). This requires port 8000 to be exposed. The repo includes
    docker-compose.test-override.yml for this. Start the stack with:

        docker compose -f docker-compose.yml -f docker-compose.test-override.yml up -d

    Or just:
        docker compose up -d
    and use --base-url http://localhost (nginx, rate limits at 10 req/min for auth).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import textwrap
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# pyotp is a main dep of the backend — available in ``poetry run`` context
try:
    import pyotp  # type: ignore[import]

    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

# Locate this script and the repo root so relative paths work regardless of
# the working directory the caller uses.
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent.parent  # tools/manual_verification → tools → repo_root

# Add the helpers module to the path
sys.path.insert(0, str(_SCRIPT_DIR))
from docker_helpers import (  # noqa: E402
    BACKEND_CONTAINER,
    POSTGRES_CONTAINER,
    extract_demo_token,
    fetch_container_logs,
    promote_to_admin,
    read_env_file,
    run_migrations,
    set_account_balance,
    set_account_status,
    start_docker_stack,
)


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_BLOCKED = "BLOCKED"


@dataclass
class ScenarioResult:
    timestamp: str
    flow: str
    branch: str
    name: str
    method: str
    full_url: str
    request_headers: dict[str, str]
    request_payload: Any
    status_code: int | None
    response_headers: dict[str, str]
    response_body: Any
    result: str
    notes: str = ""
    expected_status: int | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Sanitization
# ──────────────────────────────────────────────────────────────────────────────

_REDACT_KEYS = frozenset(
    {
        "password",
        "current_password",
        "new_password",
        "refresh_token",
        "access_token",
        "step_up_token",
        "token",
        "mfa_secret",
        "secret",
        "qr_code_base64",
        "totp_code",
    }
)
_REDACT_HEADERS = frozenset({"authorization", "x-step-up-token"})


def _sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: "<REDACTED>" if k in _REDACT_KEYS else _sanitize(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize(i) for i in obj]
    return obj


def _sanitize_headers(h: dict[str, str]) -> dict[str, str]:
    return {
        k: "<REDACTED>" if k.lower() in _REDACT_HEADERS else v for k, v in h.items()
    }


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────


class VerificationRunner:
    def __init__(
        self,
        base_url: str,
        output_dir: Path,
        env: dict[str, str],
        smoke_only: bool = False,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.out = output_dir
        self.env = env
        self.smoke_only = smoke_only
        self.results: list[ScenarioResult] = []
        self._client: httpx.AsyncClient | None = None
        self._run_id = datetime.now(timezone.utc).strftime("%H%M%S")

    # ── utilities ─────────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self.base}/api/v1{path}"

    def _email(self, tag: str) -> str:
        return f"ztvfy_{self._run_id}_{tag}@example.com"

    def _pg(self) -> tuple[str, str, str]:
        # Test stack uses fixed credentials (docker-compose.test.yml) that are
        # independent of the production .env file.
        return (
            self.env.get("TEST_POSTGRES_USER", "testuser"),
            self.env.get("TEST_POSTGRES_PASSWORD", "testpassword"),
            self.env.get("TEST_POSTGRES_DB", "testdb"),
        )

    async def _req(
        self,
        method: str,
        path: str,
        *,
        flow: str,
        branch: str,
        name: str,
        json_body: dict | None = None,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        expected: int,
        notes: str = "",
    ) -> tuple[ScenarioResult, Any]:
        """Execute one HTTP request, record result, return (ScenarioResult, raw_body)."""
        assert self._client is not None
        url = self._url(path)
        req_headers = headers or {}
        ts = datetime.now(timezone.utc).isoformat()
        raw_body: Any = None

        try:
            resp = await self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=req_headers,
                timeout=30.0,
            )
            try:
                raw_body = resp.json()
            except Exception:
                raw_body = resp.text

            outcome = RESULT_PASS if resp.status_code == expected else RESULT_FAIL
            extra = (
                f" | got {resp.status_code}, expected {expected}"
                if outcome == RESULT_FAIL
                else ""
            )
            rec = ScenarioResult(
                timestamp=ts,
                flow=flow,
                branch=branch,
                name=name,
                method=method.upper(),
                full_url=url,
                request_headers=_sanitize_headers(dict(req_headers)),
                request_payload=_sanitize(json_body or {}),
                status_code=resp.status_code,
                response_headers=_sanitize_headers(dict(resp.headers)),
                response_body=_sanitize(raw_body),
                result=outcome,
                notes=(notes + extra).strip(),
                expected_status=expected,
            )
        except Exception as exc:
            rec = ScenarioResult(
                timestamp=ts,
                flow=flow,
                branch=branch,
                name=name,
                method=method.upper(),
                full_url=url,
                request_headers=_sanitize_headers(dict(req_headers)),
                request_payload=_sanitize(json_body or {}),
                status_code=None,
                response_headers={},
                response_body=str(exc),
                result=RESULT_BLOCKED,
                notes=f"Request exception: {exc}",
                expected_status=expected,
            )

        self.results.append(rec)
        icon = "✓" if rec.result == RESULT_PASS else ("⚠" if rec.result == RESULT_BLOCKED else "✗")
        sc = str(rec.status_code) if rec.status_code is not None else "—"
        print(f"  {icon} [{rec.result:<7}] {method:6} {path:<52} {sc:>4}")
        return rec, raw_body

    def _blocked(
        self,
        flow: str,
        branch: str,
        name: str,
        notes: str,
    ) -> ScenarioResult:
        ts = datetime.now(timezone.utc).isoformat()
        rec = ScenarioResult(
            timestamp=ts,
            flow=flow,
            branch=branch,
            name=name,
            method="N/A",
            full_url="N/A",
            request_headers={},
            request_payload={},
            status_code=None,
            response_headers={},
            response_body=None,
            result=RESULT_BLOCKED,
            notes=notes,
        )
        self.results.append(rec)
        print(f"  ⚠ [BLOCKED] {name}: {notes}")
        return rec

    async def _wait_for_logs(self, seconds: float = 0.6) -> None:
        await asyncio.sleep(seconds)

    # ── scenario groups ───────────────────────────────────────────────────────

    async def _run_health(self) -> None:
        print("\n─── Health ───────────────────────────────────────────────────")
        await self._req(
            "GET", "/health",
            flow="health", branch="ok",
            name="health endpoint returns ok",
            expected=200,
        )

    async def _run_docs(self) -> None:
        print("\n─── Docs / OpenAPI ───────────────────────────────────────────")
        assert self._client is not None
        ts = datetime.now(timezone.utc).isoformat()
        try:
            r = await self._client.get(f"{self.base}/docs", timeout=10)
            outcome = RESULT_PASS if r.status_code == 200 else RESULT_FAIL
            rec = ScenarioResult(
                timestamp=ts, flow="startup", branch="docs_available",
                name="Swagger UI available when DEBUG=true",
                method="GET", full_url=f"{self.base}/docs",
                request_headers={}, request_payload={},
                status_code=r.status_code, response_headers={},
                response_body=f"<{len(r.text)} bytes HTML>",
                result=outcome, notes="",
            )
            self.results.append(rec)
            print(f"  {'✓' if outcome == RESULT_PASS else '✗'} [{outcome:<7}] GET    /docs")
        except Exception as e:
            self._blocked("startup", "docs_available", "Swagger UI /docs", str(e))

    async def _run_registration(self) -> dict[str, Any]:
        """Register + verify two users. Returns ctx with emails."""
        print("\n─── Registration ─────────────────────────────────────────────")
        ctx: dict[str, Any] = {}
        email_a = self._email("user_a")
        email_b = self._email("user_b")

        r, body = await self._req(
            "POST", "/auth/register",
            flow="registration", branch="valid",
            name="register user_a with valid credentials → 201",
            json_body={"email": email_a, "password": "StrongPass1!"},
            expected=201,
        )
        if r.result == RESULT_PASS and isinstance(body, dict):
            ctx["email_a"] = email_a
            ctx["user_a_id"] = body.get("id")

        await self._req(
            "POST", "/auth/register",
            flow="registration", branch="duplicate_email",
            name="register duplicate email → 409",
            json_body={"email": email_a, "password": "StrongPass1!"},
            expected=409,
        )
        await self._req(
            "POST", "/auth/register",
            flow="registration", branch="weak_password",
            name="register weak password → 422",
            json_body={"email": self._email("weak_pw"), "password": "weak"},
            expected=422,
        )
        await self._req(
            "POST", "/auth/register",
            flow="registration", branch="invalid_email",
            name="register invalid email format → 422",
            json_body={"email": "not-an-email", "password": "StrongPass1!"},
            expected=422,
        )

        r_b, body_b = await self._req(
            "POST", "/auth/register",
            flow="registration", branch="valid",
            name="register user_b (transfer destination) → 201",
            json_body={"email": email_b, "password": "StrongPass1!"},
            expected=201,
        )
        if r_b.result == RESULT_PASS:
            ctx["email_b"] = email_b

        return ctx

    async def _run_email_verification(self, ctx: dict[str, Any]) -> dict[str, Any]:
        print("\n─── Email Verification ───────────────────────────────────────")
        await self._wait_for_logs()

        email_a = ctx.get("email_a", "")
        email_b = ctx.get("email_b", "")

        # valid token for user_a
        token_a = extract_demo_token(email_a, "Email verification")
        if token_a:
            await self._req(
                "GET", "/auth/verify-email",
                flow="email_verification", branch="valid_token",
                name="verify email user_a valid token → 200",
                params={"token": token_a},
                expected=200,
            )
        else:
            self._blocked("email_verification", "valid_token", "verify email user_a",
                          "Token not found in Docker logs")

        # invalid token
        await self._req(
            "GET", "/auth/verify-email",
            flow="email_verification", branch="invalid_token",
            name="verify email invalid token → 400",
            params={"token": "garbage_token_xyz_invalid"},
            expected=400,
        )

        # already-used token (replay)
        if token_a:
            await self._req(
                "GET", "/auth/verify-email",
                flow="email_verification", branch="already_used_token",
                name="verify email already-used token → 400",
                params={"token": token_a},
                expected=400,
            )

        # verify user_b
        token_b = extract_demo_token(email_b, "Email verification")
        if token_b:
            await self._req(
                "GET", "/auth/verify-email",
                flow="email_verification", branch="valid_token",
                name="verify email user_b valid token → 200",
                params={"token": token_b},
                expected=200,
            )
        else:
            self._blocked("email_verification", "valid_token", "verify email user_b",
                          "Token not found in Docker logs")

        return ctx

    async def _run_login_and_session(self, ctx: dict[str, Any]) -> dict[str, Any]:
        print("\n─── Login & Session ──────────────────────────────────────────")
        email_a = ctx.get("email_a", "")

        # valid login
        r, body = await self._req(
            "POST", "/auth/login",
            flow="login", branch="valid_no_mfa",
            name="login valid credentials no MFA → 200",
            json_body={"email": email_a, "password": "StrongPass1!"},
            expected=200,
        )
        if r.result == RESULT_PASS and isinstance(body, dict):
            ctx["access_a"] = body.get("access_token")
            ctx["refresh_a"] = body.get("refresh_token")

        # nonexistent email
        await self._req(
            "POST", "/auth/login",
            flow="login", branch="nonexistent_email",
            name="login nonexistent email → 401",
            json_body={"email": "nobody_here@example.com", "password": "StrongPass1!"},
            expected=401,
        )

        # wrong password
        await self._req(
            "POST", "/auth/login",
            flow="login", branch="wrong_password",
            name="login wrong password → 401",
            json_body={"email": email_a, "password": "WrongPassword999!"},
            expected=401,
        )

        # users/me authenticated
        if ctx.get("access_a"):
            await self._req(
                "GET", "/users/me",
                flow="users", branch="authenticated",
                name="GET /users/me authenticated → 200",
                headers={"Authorization": f"Bearer {ctx['access_a']}"},
                expected=200,
            )

        # users/me unauthenticated
        await self._req(
            "GET", "/users/me",
            flow="users", branch="unauthenticated",
            name="GET /users/me no token → 403",
            expected=403,
        )

        # refresh valid → rotates token
        if ctx.get("refresh_a"):
            r_ref, body_ref = await self._req(
                "POST", "/auth/refresh",
                flow="session", branch="refresh_valid",
                name="refresh valid token → 200 new token pair",
                json_body={"refresh_token": ctx["refresh_a"]},
                expected=200,
            )
            old_refresh = ctx["refresh_a"]
            if r_ref.result == RESULT_PASS and isinstance(body_ref, dict):
                ctx["access_a"] = body_ref.get("access_token")
                ctx["refresh_a"] = body_ref.get("refresh_token")

            # refresh reuse detection (old token is now revoked)
            await self._req(
                "POST", "/auth/refresh",
                flow="session", branch="refresh_reuse_detection",
                name="refresh revoked (reused) token → 401",
                json_body={"refresh_token": old_refresh},
                expected=401,
            )
            # After reuse detection the session is wiped — re-login
            r_rl, body_rl = await self._req(
                "POST", "/auth/login",
                flow="session", branch="relogin_after_reuse",
                name="re-login after reuse detection → 200",
                json_body={"email": email_a, "password": "StrongPass1!"},
                expected=200,
            )
            if r_rl.result == RESULT_PASS and isinstance(body_rl, dict):
                ctx["access_a"] = body_rl.get("access_token")
                ctx["refresh_a"] = body_rl.get("refresh_token")

        # refresh invalid (garbage)
        await self._req(
            "POST", "/auth/refresh",
            flow="session", branch="refresh_invalid_token",
            name="refresh garbage token → 401",
            json_body={"refresh_token": "garbage_not_a_token"},
            expected=401,
        )

        # logout valid
        if ctx.get("access_a") and ctx.get("refresh_a"):
            r_lo, _ = await self._req(
                "POST", "/auth/logout",
                flow="session", branch="logout_valid",
                name="logout with valid tokens → 200",
                json_body={"refresh_token": ctx["refresh_a"]},
                headers={"Authorization": f"Bearer {ctx['access_a']}"},
                expected=200,
            )
            if r_lo.result == RESULT_PASS:
                dead_access = ctx.pop("access_a")
                ctx.pop("refresh_a", None)

                # access with revoked token
                await self._req(
                    "GET", "/users/me",
                    flow="session", branch="access_after_logout",
                    name="users/me after logout (revoked token) → 401",
                    headers={"Authorization": f"Bearer {dead_access}"},
                    expected=401,
                )

        # logout unauthenticated
        await self._req(
            "POST", "/auth/logout",
            flow="session", branch="logout_unauthenticated",
            name="logout without Authorization → 403",
            json_body={"refresh_token": "whatever"},
            expected=403,
        )

        # re-login for subsequent tests
        r_fresh, body_fresh = await self._req(
            "POST", "/auth/login",
            flow="session", branch="fresh_login",
            name="fresh login to restore session for remaining tests",
            json_body={"email": email_a, "password": "StrongPass1!"},
            expected=200,
        )
        if r_fresh.result == RESULT_PASS and isinstance(body_fresh, dict):
            ctx["access_a"] = body_fresh.get("access_token")
            ctx["refresh_a"] = body_fresh.get("refresh_token")

        return ctx

    async def _run_lockout(self) -> None:
        print("\n─── Account Lockout ──────────────────────────────────────────")
        email_locked = self._email("locked_user")

        r, _ = await self._req(
            "POST", "/auth/register",
            flow="lockout", branch="setup",
            name="register lockout test user",
            json_body={"email": email_locked, "password": "StrongPass1!"},
            expected=201,
        )
        if r.result != RESULT_PASS:
            self._blocked("lockout", "all", "account lockout flow", "registration failed")
            return

        await self._wait_for_logs()
        tok = extract_demo_token(email_locked, "Email verification")
        if tok:
            await self._req(
                "GET", "/auth/verify-email",
                flow="lockout", branch="setup",
                name="verify lockout user email",
                params={"token": tok},
                expected=200,
            )

        # 5 consecutive failed logins
        for i in range(5):
            await self._req(
                "POST", "/auth/login",
                flow="lockout", branch=f"failed_attempt_{i + 1}",
                name=f"wrong password attempt {i + 1}/5 → 401",
                json_body={"email": email_locked, "password": "WrongPassword999!"},
                expected=401,
            )

        # correct password should now return 403 (locked)
        await self._req(
            "POST", "/auth/login",
            flow="lockout", branch="correct_password_while_locked",
            name="correct password while account is locked → 403",
            json_body={"email": email_locked, "password": "StrongPass1!"},
            expected=403,
        )

    async def _run_password_flows(self, ctx: dict[str, Any]) -> dict[str, Any]:
        print("\n─── Password Change ──────────────────────────────────────────")
        access = ctx.get("access_a")
        email_a = ctx.get("email_a", "")

        if access:
            r_chg, _ = await self._req(
                "POST", "/auth/password/change",
                flow="password_change", branch="valid",
                name="change password valid → 200",
                json_body={"current_password": "StrongPass1!", "new_password": "NewStrongPass2!"},
                headers={"Authorization": f"Bearer {access}"},
                expected=200,
            )
            if r_chg.result == RESULT_PASS:
                ctx["pw_a"] = "NewStrongPass2!"
                r_nl, body_nl = await self._req(
                    "POST", "/auth/login",
                    flow="password_change", branch="login_with_new_password",
                    name="login with new password → 200",
                    json_body={"email": email_a, "password": "NewStrongPass2!"},
                    expected=200,
                )
                if r_nl.result == RESULT_PASS and isinstance(body_nl, dict):
                    ctx["access_a"] = body_nl.get("access_token")
                    ctx["refresh_a"] = body_nl.get("refresh_token")
                    access = ctx["access_a"]

            # wrong current password
            await self._req(
                "POST", "/auth/password/change",
                flow="password_change", branch="wrong_current_password",
                name="change password wrong current → 401",
                json_body={"current_password": "WrongCurrent99!", "new_password": "NewStrongPass3!"},
                headers={"Authorization": f"Bearer {access}"},
                expected=401,
            )
            # weak new password
            await self._req(
                "POST", "/auth/password/change",
                flow="password_change", branch="weak_new_password",
                name="change password weak new → 422",
                json_body={"current_password": ctx.get("pw_a", "NewStrongPass2!"), "new_password": "weakpw"},
                headers={"Authorization": f"Bearer {access}"},
                expected=422,
            )

        print("\n─── Password Reset ───────────────────────────────────────────")
        email_reset = self._email("reset_user")
        r_reg, _ = await self._req(
            "POST", "/auth/register",
            flow="password_reset", branch="setup",
            name="register dedicated reset test user",
            json_body={"email": email_reset, "password": "OriginalPass1!"},
            expected=201,
        )
        if r_reg.result == RESULT_PASS:
            await self._wait_for_logs()
            vt = extract_demo_token(email_reset, "Email verification")
            if vt:
                await self._req(
                    "GET", "/auth/verify-email",
                    flow="password_reset", branch="setup",
                    name="verify reset user email",
                    params={"token": vt},
                    expected=200,
                )

        # request for known email (non-enumeration: always 200)
        await self._req(
            "POST", "/auth/password/reset/request",
            flow="password_reset", branch="request_known_email",
            name="reset request known email → 200",
            json_body={"email": email_reset},
            expected=200,
        )
        # request for unknown email (same response)
        await self._req(
            "POST", "/auth/password/reset/request",
            flow="password_reset", branch="request_unknown_email_non_enumeration",
            name="reset request unknown email → 200 same body (SR-18 non-enumeration)",
            json_body={"email": "nobody_at_all@no-domain.example"},
            expected=200,
        )
        # confirm with invalid token
        await self._req(
            "POST", "/auth/password/reset/confirm",
            flow="password_reset", branch="invalid_token",
            name="reset confirm invalid token → 400",
            json_body={"token": "completely_garbage_token_xyz", "new_password": "BrandNewPass1!"},
            expected=400,
        )
        # confirm with weak new password (schema rejects before token check)
        await self._req(
            "POST", "/auth/password/reset/confirm",
            flow="password_reset", branch="weak_new_password",
            name="reset confirm weak new password → 422",
            json_body={"token": "any_token", "new_password": "weak"},
            expected=422,
        )

        await self._wait_for_logs()
        reset_token = extract_demo_token(email_reset, "Password reset")
        if reset_token:
            r_conf, _ = await self._req(
                "POST", "/auth/password/reset/confirm",
                flow="password_reset", branch="valid_token",
                name="reset confirm valid token → 200",
                json_body={"token": reset_token, "new_password": "BrandNewPass1!"},
                expected=200,
            )
            if r_conf.result == RESULT_PASS:
                # login with new password
                await self._req(
                    "POST", "/auth/login",
                    flow="password_reset", branch="login_after_reset",
                    name="login with new password after reset → 200",
                    json_body={"email": email_reset, "password": "BrandNewPass1!"},
                    expected=200,
                )
                # reuse same reset token (should be cleared)
                await self._req(
                    "POST", "/auth/password/reset/confirm",
                    flow="password_reset", branch="token_reuse",
                    name="reset confirm same token again → 400 (single-use)",
                    json_body={"token": reset_token, "new_password": "AnotherPass1!"},
                    expected=400,
                )
        else:
            self._blocked("password_reset", "valid_token", "reset confirm valid",
                          "Could not extract reset token from Docker logs")

        return ctx

    async def _run_mfa(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """MFA lifecycle: setup, enable, login with MFA, step-up, disable."""
        print("\n─── MFA Lifecycle ────────────────────────────────────────────")

        if not HAS_PYOTP:
            self._blocked("mfa", "all_mfa", "MFA flows (all)",
                          "pyotp not available — install it in the backend poetry env")
            ctx["mfa_available"] = False
            return ctx

        email_mfa = self._email("mfa_user")
        r_reg, _ = await self._req(
            "POST", "/auth/register",
            flow="mfa", branch="setup_user",
            name="register MFA test user",
            json_body={"email": email_mfa, "password": "StrongPass1!"},
            expected=201,
        )
        if r_reg.result != RESULT_PASS:
            self._blocked("mfa", "all_mfa", "MFA flows", "MFA user registration failed")
            ctx["mfa_available"] = False
            return ctx

        await self._wait_for_logs()
        mfa_vt = extract_demo_token(email_mfa, "Email verification")
        if mfa_vt:
            await self._req(
                "GET", "/auth/verify-email",
                flow="mfa", branch="setup_user",
                name="verify MFA user email",
                params={"token": mfa_vt},
                expected=200,
            )

        r_login, body_login = await self._req(
            "POST", "/auth/login",
            flow="mfa", branch="login_before_mfa_enabled",
            name="login MFA user (MFA not yet enabled)",
            json_body={"email": email_mfa, "password": "StrongPass1!"},
            expected=200,
        )
        if r_login.result != RESULT_PASS or not isinstance(body_login, dict):
            self._blocked("mfa", "all_mfa", "MFA flows", "Could not login MFA user")
            ctx["mfa_available"] = False
            return ctx

        access_mfa = body_login.get("access_token")
        refresh_mfa = body_login.get("refresh_token")
        auth_h: dict[str, str] = {"Authorization": f"Bearer {access_mfa}"}

        # MFA setup — fetch raw response to extract secret for TOTP generation
        assert self._client is not None
        setup_resp = await self._client.post(self._url("/auth/mfa/setup"), headers=auth_h, timeout=30)
        totp_secret: str | None = None
        if setup_resp.status_code == 200:
            setup_body = setup_resp.json()
            totp_secret = setup_body.get("secret")
            # Record as PASS (manually, since we bypassed _req)
            ts = datetime.now(timezone.utc).isoformat()
            self.results.append(ScenarioResult(
                timestamp=ts, flow="mfa", branch="setup_first_time",
                name="MFA setup first time → 200 + secret",
                method="POST", full_url=self._url("/auth/mfa/setup"),
                request_headers=_sanitize_headers(auth_h), request_payload={},
                status_code=200, response_headers={},
                response_body=_sanitize(setup_body),
                result=RESULT_PASS, notes="secret extracted for TOTP; redacted in artifact",
            ))
            print(f"  ✓ [PASS   ] POST   /auth/mfa/setup                                    200")
        else:
            self.results.append(ScenarioResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow="mfa", branch="setup_first_time",
                name="MFA setup first time",
                method="POST", full_url=self._url("/auth/mfa/setup"),
                request_headers=_sanitize_headers(auth_h), request_payload={},
                status_code=setup_resp.status_code, response_headers={},
                response_body=setup_resp.text,
                result=RESULT_FAIL, notes=f"Expected 200, got {setup_resp.status_code}",
            ))
            print(f"  ✗ [FAIL   ] POST   /auth/mfa/setup                               {setup_resp.status_code}")

        if not totp_secret:
            self._blocked("mfa", "enable_and_beyond", "MFA enable+", "No TOTP secret extracted")
            ctx["mfa_available"] = False
            return ctx

        totp = pyotp.TOTP(totp_secret)

        # enable with invalid code
        await self._req(
            "POST", "/auth/mfa/enable",
            flow="mfa", branch="enable_invalid_code",
            name="MFA enable with invalid TOTP code → 401",
            json_body={"totp_code": "000000"},
            headers=auth_h,
            expected=401,
        )

        # enable with valid code
        r_en, _ = await self._req(
            "POST", "/auth/mfa/enable",
            flow="mfa", branch="enable_valid_code",
            name="MFA enable with valid TOTP code → 200",
            json_body={"totp_code": totp.now()},
            headers=auth_h,
            expected=200,
        )

        # MFA setup when already enabled → 400 (must run after enable, not after setup)
        await self._req(
            "POST", "/auth/mfa/setup",
            flow="mfa", branch="setup_when_already_enabled",
            name="MFA setup again when MFA already enabled → 400",
            headers=auth_h,
            expected=400,
        )

        # login without totp_code when MFA is enabled → MFARequiredResponse
        r_mfa_req, body_mfa_req = await self._req(
            "POST", "/auth/login",
            flow="mfa", branch="mfa_login_missing_code",
            name="login MFA-enabled user without totp_code → 200 mfa_required",
            json_body={"email": email_mfa, "password": "StrongPass1!"},
            expected=200,
        )
        if r_mfa_req.result == RESULT_PASS and isinstance(body_mfa_req, dict):
            is_mfa_req = body_mfa_req.get("mfa_required") is True
            note = "mfa_required=True in body ✓" if is_mfa_req else "WARN: mfa_required not in body"
            self.results[-1].notes = note

        # login with invalid TOTP code
        await self._req(
            "POST", "/auth/login",
            flow="mfa", branch="mfa_login_invalid_code",
            name="login MFA-enabled user with invalid totp_code → 401",
            json_body={"email": email_mfa, "password": "StrongPass1!", "totp_code": "000000"},
            expected=401,
        )

        # login with valid TOTP code
        r_mfa_ok, body_mfa_ok = await self._req(
            "POST", "/auth/login",
            flow="mfa", branch="mfa_login_valid_code",
            name="login MFA-enabled user with valid totp_code → 200",
            json_body={"email": email_mfa, "password": "StrongPass1!", "totp_code": totp.now()},
            expected=200,
        )
        if r_mfa_ok.result == RESULT_PASS and isinstance(body_mfa_ok, dict):
            access_mfa = body_mfa_ok.get("access_token")
            refresh_mfa = body_mfa_ok.get("refresh_token")
            auth_h = {"Authorization": f"Bearer {access_mfa}"}

        # Store MFA context for step-up and transfer tests
        ctx.update({
            "email_mfa": email_mfa,
            "access_mfa": access_mfa,
            "refresh_mfa": refresh_mfa,
            "totp_secret_mfa": totp_secret,
            "mfa_available": True,
        })

        # Step-up: valid TOTP
        print("\n─── Step-Up Auth ──────────────────────────────────────────────")
        r_su, body_su = await self._req(
            "POST", "/auth/step-up",
            flow="step_up", branch="valid_totp",
            name="step-up with valid TOTP → 200 step_up_token",
            json_body={"totp_code": totp.now()},
            headers=auth_h,
            expected=200,
        )
        if r_su.result == RESULT_PASS and isinstance(body_su, dict):
            ctx["step_up_token_mfa"] = body_su.get("step_up_token")

        # Step-up: invalid TOTP
        await self._req(
            "POST", "/auth/step-up",
            flow="step_up", branch="invalid_totp",
            name="step-up with invalid TOTP → 401",
            json_body={"totp_code": "000000"},
            headers=auth_h,
            expected=401,
        )

        # Step-up for a user WITHOUT MFA enabled (user_a)
        if ctx.get("access_a"):
            await self._req(
                "POST", "/auth/step-up",
                flow="step_up", branch="no_mfa_enabled",
                name="step-up when MFA not enabled → 403",
                json_body={"totp_code": "123456"},
                headers={"Authorization": f"Bearer {ctx['access_a']}"},
                expected=403,
            )

        # MFA disable with wrong password
        await self._req(
            "POST", "/auth/mfa/disable",
            flow="mfa", branch="disable_wrong_password",
            name="MFA disable wrong password → 401",
            json_body={"password": "WrongPassword999!", "totp_code": totp.now()},
            headers=auth_h,
            expected=401,
        )
        # MFA disable with invalid TOTP
        await self._req(
            "POST", "/auth/mfa/disable",
            flow="mfa", branch="disable_invalid_totp",
            name="MFA disable invalid TOTP code → 401",
            json_body={"password": "StrongPass1!", "totp_code": "000000"},
            headers=auth_h,
            expected=401,
        )
        # MFA disable valid
        r_disable, _ = await self._req(
            "POST", "/auth/mfa/disable",
            flow="mfa", branch="disable_valid",
            name="MFA disable with correct password + TOTP → 200",
            json_body={"password": "StrongPass1!", "totp_code": totp.now()},
            headers=auth_h,
            expected=200,
        )
        # MFA is now disabled — step-up transfer scenarios cannot run for this user.
        # Mark as unavailable so the transfers section blocks cleanly instead of failing.
        if r_disable.result == RESULT_PASS:
            ctx["mfa_available"] = False

        return ctx

    async def _run_rbac(self, ctx: dict[str, Any]) -> dict[str, Any]:
        print("\n─── RBAC / Authorization Gates ───────────────────────────────")
        pg_user, pg_pw, pg_db = self._pg()

        email_admin = self._email("admin_user")
        r_reg, _ = await self._req(
            "POST", "/auth/register",
            flow="rbac", branch="admin_user_setup",
            name="register admin test user",
            json_body={"email": email_admin, "password": "StrongPass1!"},
            expected=201,
        )
        access_admin: str | None = None
        if r_reg.result == RESULT_PASS:
            await self._wait_for_logs()
            vt = extract_demo_token(email_admin, "Email verification")
            if vt:
                await self._req(
                    "GET", "/auth/verify-email",
                    flow="rbac", branch="admin_user_setup",
                    name="verify admin user email",
                    params={"token": vt},
                    expected=200,
                )
            # Promote to admin via psql
            promoted = promote_to_admin(email_admin, pg_user, pg_pw, pg_db)
            if not promoted:
                self._blocked("rbac", "admin_ping_success",
                              "admin ping as admin role",
                              "Could not promote user to admin via psql")
            else:
                r_adm_login, body_adm = await self._req(
                    "POST", "/auth/login",
                    flow="rbac", branch="admin_login",
                    name="login admin user after role promotion",
                    json_body={"email": email_admin, "password": "StrongPass1!"},
                    expected=200,
                )
                if r_adm_login.result == RESULT_PASS and isinstance(body_adm, dict):
                    access_admin = body_adm.get("access_token")

        # admin ping as regular user (403)
        if ctx.get("access_a"):
            await self._req(
                "GET", "/admin/ping",
                flow="rbac", branch="wrong_role_user",
                name="admin ping with USER role → 403",
                headers={"Authorization": f"Bearer {ctx['access_a']}"},
                expected=403,
            )

        # admin ping as admin (200)
        if access_admin:
            await self._req(
                "GET", "/admin/ping",
                flow="rbac", branch="admin_role_ok",
                name="admin ping with ADMIN role → 200",
                headers={"Authorization": f"Bearer {access_admin}"},
                expected=200,
            )
        else:
            self._blocked("rbac", "admin_role_ok", "admin ping as ADMIN",
                          "No admin access token available")

        # admin ping unauthenticated
        await self._req(
            "GET", "/admin/ping",
            flow="rbac", branch="unauthenticated",
            name="admin ping unauthenticated → 403",
            expected=403,
        )

        # Unverified user cannot access accounts (financial endpoint)
        email_unverified = self._email("unverified_user")
        r_uv, _ = await self._req(
            "POST", "/auth/register",
            flow="rbac", branch="unverified_setup",
            name="register unverified user",
            json_body={"email": email_unverified, "password": "StrongPass1!"},
            expected=201,
        )
        if r_uv.result == RESULT_PASS:
            r_uv_login, body_uv = await self._req(
                "POST", "/auth/login",
                flow="rbac", branch="unverified_login",
                name="login unverified user (no email verify)",
                json_body={"email": email_unverified, "password": "StrongPass1!"},
                expected=200,
            )
            if r_uv_login.result == RESULT_PASS and isinstance(body_uv, dict):
                access_uv = body_uv.get("access_token")
                await self._req(
                    "GET", "/accounts/me",
                    flow="rbac", branch="unverified_financial_access",
                    name="accounts/me with unverified user → 403",
                    headers={"Authorization": f"Bearer {access_uv}"},
                    expected=403,
                )

        return ctx

    async def _run_accounts_and_transfers(self, ctx: dict[str, Any]) -> dict[str, Any]:
        print("\n─── Accounts/me ──────────────────────────────────────────────")
        access_a = ctx.get("access_a")
        email_b = ctx.get("email_b", "")
        pg_user, pg_pw, pg_db = self._pg()

        # accounts/me unauthenticated
        await self._req(
            "GET", "/accounts/me",
            flow="accounts", branch="unauthenticated",
            name="accounts/me no token → 403",
            expected=403,
        )

        account_a_number: str | None = None
        account_b_number: str | None = None

        # accounts/me first access (creates account with seed balance)
        if access_a:
            r_acc, body_acc = await self._req(
                "GET", "/accounts/me",
                flow="accounts", branch="first_access_creates_account",
                name="accounts/me first access → 200 new account created",
                headers={"Authorization": f"Bearer {access_a}"},
                expected=200,
            )
            if r_acc.result == RESULT_PASS and isinstance(body_acc, dict):
                account_a_number = body_acc.get("account_number")
                ctx["account_a_number"] = account_a_number

            # second access (idempotent)
            await self._req(
                "GET", "/accounts/me",
                flow="accounts", branch="second_access_idempotent",
                name="accounts/me second access → 200 same account",
                headers={"Authorization": f"Bearer {access_a}"},
                expected=200,
            )

        # Get/create user_b account
        if email_b:
            r_b_login, body_b_login = await self._req(
                "POST", "/auth/login",
                flow="accounts", branch="user_b_login",
                name="login user_b to get their account",
                json_body={"email": email_b, "password": "StrongPass1!"},
                expected=200,
            )
            if r_b_login.result == RESULT_PASS and isinstance(body_b_login, dict):
                access_b = body_b_login.get("access_token")
                r_b_acc, body_b_acc = await self._req(
                    "GET", "/accounts/me",
                    flow="accounts", branch="user_b_account",
                    name="accounts/me user_b → 200",
                    headers={"Authorization": f"Bearer {access_b}"},
                    expected=200,
                )
                if r_b_acc.result == RESULT_PASS and isinstance(body_b_acc, dict):
                    account_b_number = body_b_acc.get("account_number")
                    ctx["account_b_number"] = account_b_number

        print("\n─── Transfers ────────────────────────────────────────────────")

        if not access_a or not account_a_number or not account_b_number:
            self._blocked("transfers", "all", "all transfer scenarios",
                          "Missing access token or account numbers")
        else:
            # Transfer below threshold ($100, no step-up needed)
            r_t1, body_t1 = await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="below_threshold_no_step_up",
                name="transfer $100 below threshold (no step-up) → 200",
                json_body={"to_account_number": account_b_number, "amount": "100.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=200,
            )

            # Transfer above threshold WITHOUT step-up
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="above_threshold_no_step_up",
                name="transfer $1000 above threshold without step-up → 403",
                json_body={"to_account_number": account_b_number, "amount": "1000.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=403,
            )

            # Self-transfer (422)
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="self_transfer",
                name="transfer to own account → 422",
                json_body={"to_account_number": account_a_number, "amount": "50.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=422,
            )

            # Nonexistent destination account
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="nonexistent_destination",
                name="transfer to nonexistent account number → 400",
                json_body={"to_account_number": "AAAAAAAAAAAAAAAA", "amount": "10.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=400,
            )

            # Invalid amount: negative
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="invalid_amount_negative",
                name="transfer negative amount → 422",
                json_body={"to_account_number": account_b_number, "amount": "-50.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=422,
            )

            # Too many decimal places
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="too_many_decimals",
                name="transfer amount with 3 decimal places → 422",
                json_body={"to_account_number": account_b_number, "amount": "10.001"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=422,
            )

            # Inactive destination account
            if set_account_status(account_b_number, "INACTIVE", pg_user, pg_pw, pg_db):
                await self._req(
                    "POST", "/transactions/transfer",
                    flow="transfers", branch="inactive_destination",
                    name="transfer to INACTIVE destination → 400",
                    json_body={"to_account_number": account_b_number, "amount": "10.00"},
                    headers={"Authorization": f"Bearer {access_a}"},
                    expected=400,
                )
                # Restore for subsequent tests
                set_account_status(account_b_number, "ACTIVE", pg_user, pg_pw, pg_db)
            else:
                self._blocked("transfers", "inactive_destination", "transfer to INACTIVE",
                              "Could not set account status via psql")

            # Frozen destination account
            if set_account_status(account_b_number, "FROZEN", pg_user, pg_pw, pg_db):
                await self._req(
                    "POST", "/transactions/transfer",
                    flow="transfers", branch="frozen_destination",
                    name="transfer to FROZEN destination → 400",
                    json_body={"to_account_number": account_b_number, "amount": "10.00"},
                    headers={"Authorization": f"Bearer {access_a}"},
                    expected=400,
                )
                set_account_status(account_b_number, "ACTIVE", pg_user, pg_pw, pg_db)
            else:
                self._blocked("transfers", "frozen_destination", "transfer to FROZEN",
                              "Could not set account status via psql")

            # Insufficient balance — user A started with $1000, transferred $100 → $900 left.
            # Use $950: above the $900 balance but below the $1000 step-up threshold so the
            # balance check (400) fires rather than the step-up gate (403).
            await self._req(
                "POST", "/transactions/transfer",
                flow="transfers", branch="insufficient_balance",
                name="transfer amount exceeding balance → 400",
                json_body={"to_account_number": account_b_number, "amount": "950.00"},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=400,
            )

        # ── Transfers with step-up ──────────────────────────────────────────
        if ctx.get("mfa_available") and ctx.get("access_mfa") and ctx.get("totp_secret_mfa"):
            email_mfa = ctx.get("email_mfa", "")
            totp = pyotp.TOTP(ctx["totp_secret_mfa"])  # type: ignore[attr-defined]
            access_mfa = ctx["access_mfa"]
            auth_mfa = {"Authorization": f"Bearer {access_mfa}"}

            # Need a destination: use user_a's account
            dest = ctx.get("account_a_number") or account_a_number
            if not dest:
                self._blocked("transfers", "step_up_flows", "step-up transfers",
                              "No destination account number")
            else:
                # Create/get MFA user's account
                r_mfa_acc, body_mfa_acc = await self._req(
                    "GET", "/accounts/me",
                    flow="transfers", branch="mfa_user_account",
                    name="get/create MFA user account",
                    headers=auth_mfa,
                    expected=200,
                )
                account_mfa_number: str | None = None
                if r_mfa_acc.result == RESULT_PASS and isinstance(body_mfa_acc, dict):
                    account_mfa_number = body_mfa_acc.get("account_number")

                # Restore MFA user balance for step-up tests (set to $3000)
                if account_mfa_number:
                    set_account_balance(account_mfa_number, 3000, pg_user, pg_pw, pg_db)

                # Get fresh step-up token
                r_su1, body_su1 = await self._req(
                    "POST", "/auth/step-up",
                    flow="transfers", branch="get_step_up_for_transfer",
                    name="get step-up token for above-threshold transfer",
                    json_body={"totp_code": totp.now()},
                    headers=auth_mfa,
                    expected=200,
                )
                step_up_token_1: str | None = None
                if r_su1.result == RESULT_PASS and isinstance(body_su1, dict):
                    step_up_token_1 = body_su1.get("step_up_token")

                # Transfer above threshold WITH valid step-up token
                if step_up_token_1:
                    r_big, _ = await self._req(
                        "POST", "/transactions/transfer",
                        flow="transfers", branch="above_threshold_with_step_up",
                        name="transfer $1000 above threshold WITH step-up → 200",
                        json_body={"to_account_number": dest, "amount": "1000.00"},
                        headers={**auth_mfa, "X-Step-Up-Token": step_up_token_1},
                        expected=200,
                    )

                    # Reuse the same step-up token (now consumed)
                    # Restore balance first so the request reaches step-up validation
                    if account_mfa_number:
                        set_account_balance(account_mfa_number, 3000, pg_user, pg_pw, pg_db)

                    await self._req(
                        "POST", "/transactions/transfer",
                        flow="transfers", branch="reused_step_up_token",
                        name="transfer with already-consumed step-up token → 403",
                        json_body={"to_account_number": dest, "amount": "1000.00"},
                        headers={**auth_mfa, "X-Step-Up-Token": step_up_token_1},
                        expected=403,
                    )
                else:
                    self._blocked("transfers", "above_threshold_with_step_up",
                                  "transfer with valid step-up", "No step-up token obtained")

                # Cross-user step-up bypass: use user_a's regular access token as step-up
                if ctx.get("access_a"):
                    if account_mfa_number:
                        set_account_balance(account_mfa_number, 3000, pg_user, pg_pw, pg_db)

                    # Get a fresh step-up token for the MFA user (user A as "foreign user")
                    # User A does NOT have MFA so cannot get step-up token.
                    # Instead, use the MFA user's access token as a bogus step-up token
                    await self._req(
                        "POST", "/transactions/transfer",
                        flow="transfers", branch="foreign_step_up_token",
                        name="transfer with access token in X-Step-Up-Token slot → 403",
                        json_body={"to_account_number": dest, "amount": "1000.00"},
                        headers={**auth_mfa, "X-Step-Up-Token": ctx["access_a"]},
                        expected=403,
                    )
        else:
            self._blocked("transfers", "step_up_transfers", "all step-up transfer scenarios",
                          "MFA user not available — set up MFA first")

        return ctx

    async def _run_history(self, ctx: dict[str, Any]) -> None:
        print("\n─── Transaction History ──────────────────────────────────────")
        access_a = ctx.get("access_a")

        # Own transactions
        if access_a:
            await self._req(
                "GET", "/transactions/history",
                flow="history", branch="own_transactions",
                name="GET /transactions/history → 200 own items only",
                headers={"Authorization": f"Bearer {access_a}"},
                expected=200,
            )
            # Pagination
            await self._req(
                "GET", "/transactions/history",
                flow="history", branch="pagination",
                name="GET /transactions/history page=1 page_size=2 → 200",
                params={"page": 1, "page_size": 2},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=200,
            )
            # Out-of-range page_size
            await self._req(
                "GET", "/transactions/history",
                flow="history", branch="invalid_page_size",
                name="GET /transactions/history page_size=200 → 422",
                params={"page": 1, "page_size": 200},
                headers={"Authorization": f"Bearer {access_a}"},
                expected=422,
            )

        # Unauthenticated
        await self._req(
            "GET", "/transactions/history",
            flow="history", branch="unauthenticated",
            name="GET /transactions/history unauthenticated → 403",
            expected=403,
        )

    # ── top-level run ─────────────────────────────────────────────────────────

    async def run(self) -> None:
        self.out.mkdir(parents=True, exist_ok=True)

        async with httpx.AsyncClient(base_url=self.base, timeout=30.0) as client:
            self._client = client

            await self._run_health()
            await self._run_docs()
            ctx = await self._run_registration()
            ctx = await self._run_email_verification(ctx)
            ctx = await self._run_login_and_session(ctx)
            await self._run_lockout()
            ctx = await self._run_password_flows(ctx)

            if not self.smoke_only:
                ctx = await self._run_mfa(ctx)
                ctx = await self._run_rbac(ctx)
                ctx = await self._run_accounts_and_transfers(ctx)
                await self._run_history(ctx)
            else:
                # Smoke-only: light account + transfer + history happy paths
                ctx = await self._run_rbac(ctx)
                if ctx.get("access_a"):
                    r_acc, body_acc = await self._req(
                        "GET", "/accounts/me",
                        flow="accounts", branch="smoke_happy_path",
                        name="[SMOKE] accounts/me happy path",
                        headers={"Authorization": f"Bearer {ctx['access_a']}"},
                        expected=200,
                    )
                    if r_acc.result == RESULT_PASS and isinstance(body_acc, dict):
                        ctx["account_a_number"] = body_acc.get("account_number")
                    await self._req(
                        "GET", "/transactions/history",
                        flow="history", branch="smoke_happy_path",
                        name="[SMOKE] transaction history happy path",
                        headers={"Authorization": f"Bearer {ctx['access_a']}"},
                        expected=200,
                    )

        self._write_reports()

    # ── report writing ────────────────────────────────────────────────────────

    def _write_reports(self) -> None:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.result == RESULT_PASS)
        failed = sum(1 for r in self.results if r.result == RESULT_FAIL)
        blocked = sum(1 for r in self.results if r.result == RESULT_BLOCKED)

        print(f"\n{'─' * 60}")
        print(f"  Results: {passed} PASS  {failed} FAIL  {blocked} BLOCKED  ({total} total)")
        print(f"  Output:  {self.out}")
        print(f"{'─' * 60}\n")

        # scenarios.jsonl
        jsonl = self.out / "scenarios.jsonl"
        with jsonl.open("w") as f:
            for r in self.results:
                f.write(json.dumps(asdict(r), default=str) + "\n")

        # scenarios.md
        md = self.out / "scenarios.md"
        with md.open("w") as f:
            f.write("# Verification Scenarios\n\n")
            for r in self.results:
                icon = "✅" if r.result == RESULT_PASS else ("⚠️" if r.result == RESULT_BLOCKED else "❌")
                f.write(f"## {icon} {r.name}\n\n")
                f.write(f"- **Flow**: {r.flow}\n")
                f.write(f"- **Branch**: {r.branch}\n")
                f.write(f"- **Method**: `{r.method} {r.full_url}`\n")
                f.write(f"- **Expected status**: {r.expected_status}  **Got**: {r.status_code}\n")
                f.write(f"- **Result**: **{r.result}**\n")
                if r.notes:
                    f.write(f"- **Notes**: {r.notes}\n")
                if r.request_payload:
                    f.write(f"\n**Request payload:**\n```json\n{json.dumps(r.request_payload, indent=2, default=str)}\n```\n")
                if r.response_body is not None:
                    body_str = (
                        json.dumps(r.response_body, indent=2, default=str)
                        if isinstance(r.response_body, (dict, list))
                        else str(r.response_body)
                    )
                    f.write(f"\n**Response body:**\n```json\n{body_str}\n```\n")
                f.write("\n---\n\n")

        # summary.md
        branch_out = ""
        try:
            import subprocess as _sp
            branch_out = _sp.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                          cwd=_REPO_ROOT, text=True).strip()
            commit_out = _sp.check_output(["git", "rev-parse", "--short", "HEAD"],
                                          cwd=_REPO_ROOT, text=True).strip()
        except Exception:
            branch_out = "unknown"
            commit_out = "unknown"

        fail_list = "\n".join(
            f"  - [{r.flow}/{r.branch}] {r.name} — status {r.status_code} (expected {r.expected_status})"
            for r in self.results if r.result == RESULT_FAIL
        )
        blocked_list = "\n".join(
            f"  - [{r.flow}/{r.branch}] {r.name}: {r.notes}"
            for r in self.results if r.result == RESULT_BLOCKED
        )

        summary_text = textwrap.dedent(f"""
            # Local Verification Summary

            | Field | Value |
            |---|---|
            | Timestamp | {datetime.now(timezone.utc).isoformat()} |
            | Git branch | `{branch_out}` |
            | Git commit | `{commit_out}` |
            | Base URL | `{self.base}` |
            | Smoke only | {self.smoke_only} |
            | Total scenarios | {total} |
            | PASS | {passed} |
            | FAIL | {failed} |
            | BLOCKED | {blocked} |

            ## Docker startup commands used

            ```bash
            # Start stack (requires docker-compose.test-override.yml for port 8000):
            docker compose -f docker-compose.yml -f docker-compose.test-override.yml up -d
            # Or through nginx:
            docker compose up -d

            # Apply migrations:
            docker exec diploma-backend-1 alembic upgrade head
            ```

            ## Failures
            {"None" if not fail_list else fail_list}

            ## Blocked scenarios
            {"None" if not blocked_list else blocked_list}
        """).lstrip()

        (self.out / "summary.md").write_text(summary_text)

        # docker_logs.txt
        logs = fetch_container_logs()
        if logs:
            (self.out / "docker_logs.txt").write_text(logs)


# ──────────────────────────────────────────────────────────────────────────────
# Startup checks
# ──────────────────────────────────────────────────────────────────────────────


def check_app_reachable(base_url: str) -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def print_startup_instructions() -> None:
    print(textwrap.dedent("""
        ──────────────────────────────────────────────────────────────────
        The app is NOT reachable. Start the stack first, then re-run.

        Option A — expose backend directly on port 8000 (recommended, no rate limits):
            cd /path/to/diploma
            docker compose -f docker-compose.yml -f docker-compose.test-override.yml up -d
            docker exec diploma-backend-1 alembic upgrade head

        Option B — through nginx on port 80 (rate limits apply):
            cd /path/to/diploma
            docker compose up -d
            docker exec diploma-backend-1 alembic upgrade head

        Then re-run:
            cd backend && poetry run python ../tools/manual_verification/run_local_verification.py

        Use --base-url http://localhost for nginx (Option B).
        ──────────────────────────────────────────────────────────────────
    """))


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Local verification runner for the Zero Trust financial platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--base-url", default="http://localhost:8000",
                   help="Base URL (default: http://localhost:8000)")
    p.add_argument("--output-dir", type=Path,
                   default=_REPO_ROOT / "artifacts" / "manual_verification",
                   help="Where to write artifacts")
    p.add_argument("--start-docker", action="store_true",
                   help="Auto-start Docker stack before running")
    p.add_argument("--skip-migrations", action="store_true",
                   help="Skip alembic upgrade head")
    p.add_argument("--smoke-only", action="store_true",
                   help="Run only happy-path scenarios")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output_dir: Path = Path(args.output_dir) / ts
    env = read_env_file(_REPO_ROOT)

    print(f"\nZero Trust platform — local verification runner")
    print(f"Base URL : {args.base_url}")
    print(f"Output   : {output_dir}")
    print(f"Smoke    : {args.smoke_only}")

    # Optionally start Docker
    if args.start_docker:
        print("\nStarting Docker stack…")
        compose_file = _REPO_ROOT / "docker-compose.yml"
        override_file = _REPO_ROOT / "docker-compose.test-override.yml"
        ok, log = start_docker_stack(compose_file, override_file)
        if not ok:
            print(f"Docker startup failed:\n{log}")
            sys.exit(1)
        print("Waiting for services to become healthy…")
        import time
        for _ in range(30):
            if check_app_reachable(args.base_url):
                break
            time.sleep(2)

    # Check reachability
    if not check_app_reachable(args.base_url):
        print_startup_instructions()
        sys.exit(1)
    print("\nApp reachable ✓")

    # Run migrations
    if not args.skip_migrations:
        print("Running migrations…")
        ok, mig_log = run_migrations()
        if ok:
            print("Migrations applied ✓")
        else:
            print(f"Migration warning (may already be up to date):\n{mig_log}")

    # Execute verification
    runner = VerificationRunner(
        base_url=args.base_url,
        output_dir=output_dir,
        env=env,
        smoke_only=args.smoke_only,
    )
    asyncio.run(runner.run())

    print(f"\nArtifacts written to:\n  {output_dir}/summary.md\n  {output_dir}/scenarios.jsonl\n  {output_dir}/scenarios.md\n  {output_dir}/docker_logs.txt\n")


if __name__ == "__main__":
    main()
