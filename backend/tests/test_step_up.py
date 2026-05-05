"""Integration tests for POST /auth/step-up."""

import uuid

import pyotp
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User
from tests.helpers import make_orm_user

STEP_UP_URL = "/api/v1/auth/step-up"

_MFA_SECRET = pyotp.random_base32()


async def _make_mfa_user(
    db: AsyncSession,
    redis: object,
    email: str,
    mfa_secret: str = _MFA_SECRET,
) -> tuple[User, str]:
    """Create a verified user with MFA enabled and seed the Redis session.

    The user is built via ORM to avoid the full register/verify/login/setup/enable
    HTTP round-trip.  ``mfa_enabled=True`` and ``mfa_secret`` are set directly so
    that the step-up endpoint sees a fully enrolled MFA account.

    Args:
        db:         Test database session.
        redis:      FakeRedis instance used to seed the session record.
        email:      Unique email address for the new user.
        mfa_secret: Base32 TOTP secret to store on the user (default: module constant).

    Returns:
        A ``(User, access_token)`` tuple ready for use in tests.
    """
    user, token = await make_orm_user(db, redis, email=email)
    # Activate MFA directly on the ORM object — no HTTP round-trip needed.
    user.mfa_secret = mfa_secret
    user.mfa_enabled = True
    await db.commit()
    await db.refresh(user)
    return user, token


async def test_step_up_requires_authentication(async_client: AsyncClient) -> None:
    """Request without a bearer token is rejected with 401 or 403.

    Security property (SR-13): the step-up endpoint must never be accessible
    without a valid, active session — unauthenticated callers cannot prove
    they are entitled to a step-up token.
    """
    response = await async_client.post(STEP_UP_URL, json={"totp_code": "123456"})
    assert response.status_code in (401, 403)


async def test_step_up_requires_verification(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Unverified user is rejected with 403.

    Security property (SR-03): unverified accounts must not reach the
    step-up flow.  Email verification is a prerequisite for any sensitive
    operation gated by ``require_verified``.
    """
    _, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"unverified_{uuid.uuid4()}@example.com",
        is_verified=False,
    )
    response = await async_client.post(
        STEP_UP_URL,
        json={"totp_code": "123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


async def test_step_up_requires_mfa_enabled(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Verified user without MFA enabled is rejected with 403.

    Security property (SR-13): step-up authentication requires an enrolled
    second factor.  Without MFA the server has nothing to verify, so the
    request is rejected before any Redis or DB writes occur.
    """
    _, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"nomfa_{uuid.uuid4()}@example.com",
    )
    response = await async_client.post(
        STEP_UP_URL,
        json={"totp_code": "123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


async def test_step_up_invalid_totp(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Wrong TOTP code returns 401 and commits a STEP_UP_FAILED audit log.

    Security property (SR-16): every failed step-up attempt must produce a
    persisted audit record so that brute-force attempts are visible in the
    audit trail.
    """
    secret = pyotp.random_base32()
    _, token = await _make_mfa_user(
        db_session,
        fake_redis,
        email=f"stepup_fail_{uuid.uuid4()}@example.com",
        mfa_secret=secret,
    )

    response = await async_client.post(
        STEP_UP_URL,
        json={"totp_code": "000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401

    # Verify the STEP_UP_FAILED audit row was committed.
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "STEP_UP_FAILED")
    )
    audit = result.scalars().first()
    assert audit is not None, "STEP_UP_FAILED audit log must be written on invalid TOTP"


async def test_step_up_valid_totp(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Correct TOTP code returns 200 with a step_up_token; Redis key has TTL > 0.

    Security properties:
    - SR-13: a valid step-up JWT is issued after successful TOTP re-verification.
    - SR-14: the JTI is stored in Redis under ``step_up:{jti}`` with a positive
      TTL, enabling single-use consumption by ``require_step_up`` (Phase 6).
    """
    secret = pyotp.random_base32()
    _, token = await _make_mfa_user(
        db_session,
        fake_redis,
        email=f"stepup_ok_{uuid.uuid4()}@example.com",
        mfa_secret=secret,
    )

    code = pyotp.TOTP(secret).now()
    response = await async_client.post(
        STEP_UP_URL,
        json={"totp_code": code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    data = response.json()
    assert "step_up_token" in data, "Response must contain step_up_token field"
    assert isinstance(data["step_up_token"], str)
    assert len(data["step_up_token"]) > 0
    assert "expires_in" in data

    # Decode the step-up JWT to extract the JTI.
    import jwt as pyjwt

    from tests.conftest import _TEST_SETTINGS

    payload = pyjwt.decode(
        data["step_up_token"],
        _TEST_SETTINGS.jwt_secret_key,
        algorithms=[_TEST_SETTINGS.jwt_algorithm],
    )
    jti: str = payload["jti"]

    # Verify the Redis marker was written with a positive TTL (SR-14).
    ttl = await fake_redis.ttl(f"step_up:{jti}")  # type: ignore[union-attr]
    assert ttl > 0, f"Redis key step_up:{jti} must exist with TTL > 0; got {ttl}"


async def test_step_up_audit_log_on_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Successful step-up call writes a STEP_UP_VERIFIED audit log entry.

    Security property (SR-16): sensitive authentication events must always
    produce an audit record so that the security trail is complete.
    """
    secret = pyotp.random_base32()
    user, token = await _make_mfa_user(
        db_session,
        fake_redis,
        email=f"stepup_audit_{uuid.uuid4()}@example.com",
        mfa_secret=secret,
    )

    code = pyotp.TOTP(secret).now()
    response = await async_client.post(
        STEP_UP_URL,
        json={"totp_code": code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    # Verify the STEP_UP_VERIFIED audit row was committed.
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "STEP_UP_VERIFIED",
            AuditLog.user_id == user.id,
        )
    )
    audit = result.scalars().first()
    assert audit is not None, "STEP_UP_VERIFIED audit log must be written on success"
    assert "jti" in audit.details, "Audit details must contain the step-up JTI"
