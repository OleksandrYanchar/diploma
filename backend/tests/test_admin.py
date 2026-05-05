"""Integration tests for the Phase 7 admin read-only endpoints.

Covers GET /admin/users, GET /admin/audit-logs, GET /admin/security-events.

Security requirements verified:
- SR-11: Role-based access — ADMIN-only and ADMIN/AUDITOR endpoints enforced.
- SR-03: Unverified callers are rejected before role checks.
- SR-02/SR-04: Sensitive user fields absent from GET /admin/users responses.
- SR-16/SR-17: Audit log and security event records retrievable by
  authorised callers.

Test isolation note:
  The SQLite in-memory database does not roll back committed data between
  tests.  To prevent UNIQUE constraint failures every test creates users
  with UUID-generated emails via ``_make_inline_user`` rather than reusing
  the shared conftest fixtures.
"""

import uuid

import fakeredis.aioredis as fakeredis
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent, Severity
from app.models.user import User, UserRole
from tests.conftest import _TEST_SETTINGS

_USERS_URL = "/api/v1/admin/users"
_AUDIT_LOGS_URL = "/api/v1/admin/audit-logs"
_SECURITY_EVENTS_URL = "/api/v1/admin/security-events"

_SENSITIVE_USER_FIELDS = {
    "hashed_password",
    "mfa_secret",
    "email_verification_token_hash",
    "password_reset_token_hash",
    "password_reset_sent_at",
    "email_verification_sent_at",
}


async def _make_inline_user(
    db_session: AsyncSession,
    fake_redis: fakeredis.FakeRedis,
    role: UserRole,
    is_verified: bool = True,
) -> tuple[User, str]:
    """Create a user with a UUID-unique email, seed Redis, return (user, token).

    Each call produces a distinct email so the shared in-memory SQLite never
    hits a UNIQUE constraint, regardless of test execution order.
    """
    session_id = str(uuid.uuid4())
    user = User(
        email=f"admin_test_{uuid.uuid4().hex}@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=role,
        is_active=True,
        is_verified=is_verified,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=session_id,
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"session:{session_id}", str(user.id))
    return user, token


@pytest.mark.asyncio
async def test_admin_list_users_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No Authorization header on GET /admin/users returns 403 (HTTPBearer)."""
    response = await async_client.get(_USERS_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_users_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/users returns 403 for a USER-role caller (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


@pytest.mark.asyncio
async def test_admin_list_users_auditor_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/users returns 403 for an AUDITOR-role caller.

    The user-list endpoint is ADMIN-only; auditors must not enumerate
    users or their security state (SR-11).
    """
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.AUDITOR)

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


@pytest.mark.asyncio
async def test_admin_list_users_admin_returns_200_with_list(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/users returns 200 and a list for ADMIN callers (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) >= 1


@pytest.mark.asyncio
async def test_admin_list_users_contains_security_metadata(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/users response includes failed_login_count and locked_until."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    caller_entry = next(
        (u for u in response.json() if u["id"] == str(user.id)),
        None,
    )
    assert caller_entry is not None
    assert "failed_login_count" in caller_entry
    assert "locked_until" in caller_entry


@pytest.mark.asyncio
async def test_admin_list_users_sensitive_fields_absent(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Sensitive user fields must not appear in GET /admin/users responses.

    Verifies that SR-02 (hashed_password), SR-04 (mfa_secret), and token
    hash fields are excluded from the ``UserAdminView`` serialisation.
    """
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    for user_obj in response.json():
        exposed = set(user_obj.keys()) & _SENSITIVE_USER_FIELDS
        assert exposed == set(), f"Sensitive fields exposed: {exposed}"


@pytest.mark.asyncio
async def test_admin_list_users_unverified_admin_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Unverified ADMIN is rejected by require_verified before role check (SR-03)."""
    user, token = await _make_inline_user(
        db_session, fake_redis, UserRole.ADMIN, is_verified=False
    )

    response = await async_client.get(
        _USERS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_audit_logs_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No Authorization header on GET /admin/audit-logs returns 403."""
    response = await async_client.get(_AUDIT_LOGS_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_audit_logs_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/audit-logs returns 403 for a USER-role caller (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.get(
        _AUDIT_LOGS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


@pytest.mark.asyncio
async def test_admin_list_audit_logs_auditor_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/audit-logs returns 200 for AUDITOR callers (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.AUDITOR)

    response = await async_client.get(
        _AUDIT_LOGS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_admin_list_audit_logs_admin_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/audit-logs returns 200 for ADMIN callers (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.get(
        _AUDIT_LOGS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_admin_list_audit_logs_returns_seeded_records(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/audit-logs returns actual AuditLog rows seeded in the DB (SR-16)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    log = AuditLog(
        id=uuid.uuid4(),
        user_id=user.id,
        action="TEST_ACTION_SEEDED",
        ip_address="127.0.0.1",
    )
    db_session.add(log)
    await db_session.commit()

    response = await async_client.get(
        _AUDIT_LOGS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    actions = [entry["action"] for entry in response.json()]
    assert "TEST_ACTION_SEEDED" in actions


@pytest.mark.asyncio
async def test_admin_list_audit_logs_response_fields(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """AuditLogResponse shape includes all required fields (SR-16)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    log = AuditLog(
        id=uuid.uuid4(),
        user_id=user.id,
        action="FIELD_SHAPE_CHECK",
        ip_address="10.0.0.1",
        details={"key": "value"},
    )
    db_session.add(log)
    await db_session.commit()

    response = await async_client.get(
        _AUDIT_LOGS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    entry = next(
        (e for e in response.json() if e["action"] == "FIELD_SHAPE_CHECK"),
        None,
    )
    assert entry is not None
    expected_fields = (
        "id",
        "user_id",
        "action",
        "ip_address",
        "user_agent",
        "details",
        "created_at",
    )
    for field in expected_fields:
        assert field in entry, f"Expected field '{field}' missing"


@pytest.mark.asyncio
async def test_admin_list_security_events_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No Authorization header on GET /admin/security-events returns 403."""
    response = await async_client.get(_SECURITY_EVENTS_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_security_events_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/security-events returns 403 for a USER-role caller (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.get(
        _SECURITY_EVENTS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


@pytest.mark.asyncio
async def test_admin_list_security_events_auditor_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/security-events returns 200 for AUDITOR callers (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.AUDITOR)

    response = await async_client.get(
        _SECURITY_EVENTS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_admin_list_security_events_admin_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/security-events returns 200 for ADMIN callers (SR-11)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.get(
        _SECURITY_EVENTS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_admin_list_security_events_returns_seeded_records(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/security-events returns seeded SecurityEvent rows (SR-17)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    event = SecurityEvent(
        id=uuid.uuid4(),
        user_id=user.id,
        event_type="TOKEN_REUSE",
        severity=Severity.CRITICAL,
        ip_address="192.168.1.1",
    )
    db_session.add(event)
    await db_session.commit()

    response = await async_client.get(
        _SECURITY_EVENTS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    event_types = [e["event_type"] for e in response.json()]
    assert "TOKEN_REUSE" in event_types


@pytest.mark.asyncio
async def test_admin_list_security_events_response_fields(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """SecurityEventResponse shape includes all required fields (SR-17)."""
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    event = SecurityEvent(
        id=uuid.uuid4(),
        user_id=user.id,
        event_type="ACCOUNT_LOCKED",
        severity=Severity.HIGH,
    )
    db_session.add(event)
    await db_session.commit()

    response = await async_client.get(
        _SECURITY_EVENTS_URL,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    entry = next(
        (e for e in response.json() if e["event_type"] == "ACCOUNT_LOCKED"),
        None,
    )
    assert entry is not None
    expected_fields = (
        "id",
        "user_id",
        "event_type",
        "severity",
        "ip_address",
        "details",
        "created_at",
    )
    for field in expected_fields:
        assert field in entry, f"Expected field '{field}' missing"


@pytest.mark.asyncio
async def test_auditor_can_read_events_but_not_list_users(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Auditor access boundary: events/logs accessible, users endpoint rejected.

    A single AUDITOR token is used for both requests to confirm that the
    role boundaries are enforced independently per endpoint (SR-11).
    """
    user, token = await _make_inline_user(db_session, fake_redis, UserRole.AUDITOR)
    auth = {"Authorization": f"Bearer {token}"}

    events_response = await async_client.get(_SECURITY_EVENTS_URL, headers=auth)
    users_response = await async_client.get(_USERS_URL, headers=auth)

    assert events_response.status_code == 200
    assert users_response.status_code == 403
