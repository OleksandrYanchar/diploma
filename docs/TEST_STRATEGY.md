# Test Strategy

---

## 1. Testing Goals in the Context of a Bachelor Thesis in Cybersecurity

The primary goal of testing in this project is not general code quality assurance — it is **proving that implemented security controls actually work**.

For a cybersecurity thesis, a security mechanism that is implemented but not verified is academically insufficient. Each security control must be accompanied by at least one test that demonstrates its effect: that the control blocks what it should block, allows what it should allow, and produces the expected security artefacts (audit log entries, security events, error responses).

Specific testing goals:

1. **Prove that authentication controls are enforced.** Registration with weak credentials fails. Login with wrong credentials fails. Login with stolen session fails after logout.

2. **Prove that MFA cannot be bypassed.** Login with valid password but no MFA code (when MFA is enabled) does not yield tokens.

3. **Prove that token lifecycle controls are correct.** Refresh token rotation works. Reused revoked tokens are rejected. Revoked access tokens are rejected. Token reuse triggers a security event.

4. **Prove that authorization is correctly enforced.** RBAC prevents users from accessing elevated endpoints. Ownership checks prevent horizontal access to other users' resources.

5. **Prove that step-up authentication gates sensitive operations.** Large transfers without a step-up token are rejected. Reusing a step-up token is rejected.

6. **Prove that rate limiting and lockout mechanisms respond to abuse.** Brute force scenarios trigger lockout. Excessive requests trigger rate limiting.

7. **Prove that audit logs and security events are created.** Key actions produce the expected log entries, enabling non-repudiation claims in the thesis.

These tests serve a dual purpose: they validate the implementation during development and they provide evidence for the academic defense that the security subsystem behaves as designed.

---

## 2. Testing Levels

### 2.1 Unit Tests

**Scope:** Individual functions in isolation. No database, no Redis, no HTTP.

**What to test:**
- Password hashing and verification (`hash_password`, `verify_password`)
- Password strength validation (`is_password_strong`)
- JWT creation and decoding (`create_access_token`, `create_step_up_token`, `decode_token`)
- Token hash generation (`hash_token`, `generate_refresh_token`)
- Token expiry logic (expired token raises `JWTError`)
- Token type validation (step-up token rejected when access token expected)
- Account lockout state logic (`user.is_locked()`)
- Refresh token validity logic (`token.is_valid()`, `token.is_expired()`)
- Input schema validation (Pydantic schemas reject malformed input)

**Tools:** `pytest`, standard `unittest.mock` where needed.

**Characteristics:**
- Fast (milliseconds per test)
- No external dependencies
- Can be run without Docker
- Deterministic

---

### 2.2 Integration Tests

**Scope:** Full request-response cycle through the FastAPI application with real application logic, mocked infrastructure (in-memory SQLite database, fake Redis).

**What to test:**
- Complete authentication flows (register → verify email → login → refresh → logout)
- Complete MFA flows (setup → enable → login with TOTP → step-up)
- Token lifecycle (rotation, revocation, reuse detection)
- Authorization enforcement (RBAC, ownership, session validity)
- Financial operations with security controls (transfer with and without step-up)
- Rate limiting behavior
- Audit log and security event creation
- Password reset flow
- Error response formats and status codes

**Tools:** `pytest`, `pytest-asyncio`, `httpx.AsyncClient` with `ASGITransport`, `fakeredis.FakeAsyncRedis`, `aiosqlite` + SQLite in-memory database.

**Characteristics:**
- Tests the real application code end-to-end through HTTP
- Infrastructure (DB, Redis) is mocked with in-memory equivalents
- Each test function gets a fresh, empty database and Redis instance (via fixtures)
- Can be run without Docker
- The primary test layer for security verification

---

### 2.3 End-to-End Tests

**Scope:** Full stack running in Docker Compose (Nginx + FastAPI + PostgreSQL + Redis), tested via HTTP from outside the containers.

**What to test:**
- Nginx rate limiting zones are applied (auth endpoints limited to 10 req/min)
- Security headers are present in all responses
- The full user journey: register → verify → login → MFA setup → transfer → logout
- Inter-service connectivity (backend can reach PostgreSQL and Redis)

**Tools:** `pytest` + `httpx` pointed at `http://localhost`, or manual verification with `curl`.

**When to run:** After Phase 7 (all backend services complete), as a final verification before frontend integration.

**Characteristics:**
- Requires running Docker Compose stack
- Slower than integration tests
- Tests real Nginx config, real PostgreSQL, real Redis
- Confirms that environment configuration (env vars, network isolation) is correct

---

## 3. Security-Focused Test Categories

The following categories group tests by security domain. Each category maps to one or more security requirements from `SECURITY_REQUIREMENTS.md`.

### Category A — Authentication Controls
Tests that verify login security, credential validation, and account lockout.

- Correct credentials → tokens issued
- Wrong password → 401, failed attempt logged
- Nonexistent email → 401, no user information leaked
- Account locked after N failures → 403 on subsequent attempts (including correct password)
- Locked account unlocked by admin → login resumes
- Deactivated account → 403 even with valid token

### Category B — MFA Enforcement
Tests that verify TOTP behavior at login and during step-up.

- MFA enabled + no TOTP code at login → mfa_required=true, no tokens issued
- MFA enabled + invalid TOTP code → 401
- MFA enabled + valid TOTP code → tokens issued
- MFA setup returns secret and QR code
- MFA cannot be enabled without first completing setup
- MFA disable requires password confirmation

### Category C — Token Lifecycle
Tests that verify the JWT and refresh token security properties.

- Access token with invalid signature → 401
- Access token with tampered payload → 401
- Expired access token → 401
- Access token with wrong type claim ("step_up" used as "access") → 401
- Blacklisted access token (after logout) → 401
- Refresh token rotation: old token rejected after use
- Refresh token reuse: revoked token triggers session revocation
- Refresh token after password reset: all tokens revoked
- Step-up token: valid → 200; expired → 403; reused → 403; mismatched user → 403

### Category D — Session Management
Tests that verify session validity controls.

- Request with valid token but deleted session in Redis → 401
- Logout deletes session: subsequent request with same access token → 401
- Password reset deletes all sessions: all refresh tokens revoked
- New login creates new session: old session remains independent until expiry

### Category E — Authorization: RBAC
Tests that verify role enforcement.

- Regular user accessing admin endpoint → 403
- Auditor accessing audit logs → 200
- Auditor attempting to deactivate a user → 403
- Admin accessing all admin endpoints → 200
- Unauthenticated request to any protected endpoint → 401

### Category F — Authorization: Ownership
Tests that verify resource scoping.

- Authenticated user can access their own account → 200
- Authenticated user cannot access another user's account → 403 or 404
- Authenticated user's transaction history contains only their own transactions
- Transfer from another user's account → rejected (ownership enforced at account lookup)

### Category G — Step-up Authentication
Tests that verify the step-up mechanism for sensitive operations.

- Transfer below threshold without step-up token → 200 (no step-up required)
- Transfer at or above threshold without step-up token → 403 + X-Step-Up-Required: true
- Transfer at or above threshold with expired step-up token → 403
- Transfer at or above threshold with valid step-up token → 200
- Transfer at or above threshold with reused step-up token → 403
- Step-up token belonging to different user → 403

### Category H — Rate Limiting and Abuse Prevention
Tests that verify rate limiting and lockout behavior.

- N+1 requests per minute from same IP → 429 with Retry-After header
- Brute force: 5 failed logins on same account → account locked
- Brute force: IP-level lockout after excessive attempts across multiple accounts

### Category I — Audit Logging
Tests that verify audit log creation.

- After successful login: AuditLog entry with action=LOGIN_SUCCESS
- After failed login: AuditLog entry with action=LOGIN_FAILED
- After logout: AuditLog entry with action=LOGOUT
- After transfer: AuditLog entry with action=TRANSFER_COMPLETED
- After MFA setup initiated: AuditLog entry with action=MFA_SETUP_INITIATED
- After MFA enable: AuditLog entry with action=MFA_ENABLED
- After MFA disable: AuditLog entry with action=MFA_DISABLED
- After MFA TOTP verification at login: AuditLog entry with action=MFA_VERIFIED
- After MFA TOTP verification failure: AuditLog entry with action=MFA_FAILED
- After login halted for missing TOTP code: AuditLog entry with action=LOGIN_MFA_REQUIRED
- After account lockout: AuditLog entry with action=ACCOUNT_LOCKED
- After step-up verification: AuditLog entry with action=STEP_UP_VERIFIED

### Category J — Security Events
Tests that verify security event creation.

- After account lockout: SecurityEvent with event_type=ACCOUNT_LOCKED, severity=HIGH
- After refresh token reuse: SecurityEvent with event_type=TOKEN_REUSE, severity=CRITICAL
- After transfer attempted without step-up: SecurityEvent with event_type=STEP_UP_BYPASS_ATTEMPT

### Category K — Input Validation
Tests that verify rejection of malformed or malicious input.

- Registration with password below minimum length → 422
- Registration with password missing required character classes → 422
- Transfer with negative amount → 422
- Transfer with amount exceeding maximum → 422
- Transfer with non-numeric amount → 422
- Requests with unexpected field types → 422

### Category L — Password Reset Security
Tests that verify the credential recovery flow.

- Reset request for nonexistent email → 200 (no enumeration)
- Reset request for existing email → 200, token stored hashed
- Reset with invalid token → 400
- Reset with expired token → 400
- Reset with valid token → 200, password changed
- After successful reset, existing refresh tokens rejected → 401

---

## 4. Mapping from Security Requirements to Test Scenarios

| SR | Requirement (short) | Test Category | Key Test Scenarios |
|----|--------------------|--------------|--------------------|
| SR-01 | Password strength enforcement | K | Weak password → 422; strong password → 201 |
| SR-02 | Argon2 hashing | A, code review | Verify_password works; plaintext never stored |
| SR-03 | Email verification | D, F | Unverified user → 403 on protected endpoints |
| SR-04 | MFA (TOTP) | B | No code → mfa_required; invalid code → 401; valid code → tokens |
| SR-05 | Account lockout | A, H | 5 failed logins → account locked; correct password after lock → 403 |
| SR-06 | Short-lived access tokens | C | Expired token → 401; token contains exp claim at 15 min |
| SR-07 | Refresh token rotation | C | Old token rejected after refresh |
| SR-08 | Token reuse detection | C, J | Revoked token reuse → session revoked; CRITICAL event created |
| SR-09 | Access token blacklisting | C, D | Post-logout access token → 401 |
| SR-10 | Session validity per request | D | Deleted session → 401 even with valid token |
| SR-11 | RBAC | E | User → admin endpoint 403; admin → 200; auditor → correct scope |
| SR-12 | Resource ownership | F | User A cannot access User B's account or transactions |
| SR-13 | Step-up authentication | G | Large transfer without step-up → 403; with step-up → 200 |
| SR-14 | Step-up one-time use | G | Second use of same step-up token → 403 |
| SR-15 | Rate limiting | H | > limit req/min → 429 |
| SR-16 | Audit logging | I | Key actions produce correct AuditLog entries |
| SR-17 | Security event detection | J | Lockout, token reuse, step-up bypass create SecurityEvent records |
| SR-18 | Password reset security | L | Non-enumerable; expired token rejected; sessions revoked after reset |
| SR-19 | Security headers | E2E | Response headers include all required values |
| SR-20 | Input validation | K | Invalid amounts, weak passwords → 422 |

---

## 5. MVP-Critical Security Tests

These tests **must pass** before the thesis can be defended. They directly verify the core Zero Trust claims of the project.

| # | Test Name | Category | SR | Why It Is Critical |
|---|-----------|---------|----|--------------------|
| T-01 | Login with wrong password returns 401 | A | SR-02 | Proves credentials are actually verified |
| T-02 | Account locked after 5 failed logins | A | SR-05 | Proves brute force protection works |
| T-03 | Login without MFA code (MFA enabled) returns mfa_required | B | SR-04 | Proves MFA cannot be bypassed |
| T-04 | Login with invalid TOTP code returns 401 | B | SR-04 | Proves TOTP validation is enforced |
| T-05 | Refresh token rotation: old token rejected | C | SR-07 | Proves rotation is enforced |
| T-06 | Revoked refresh token reuse triggers session revocation | C | SR-08 | Proves reuse detection works |
| T-07 | Post-logout access token rejected | C | SR-09 | Proves blacklisting works |
| T-08 | Request with valid token but no Redis session returns 401 | D | SR-10 | Proves session-level revocation works |
| T-09 | User-role account accessing /admin/* returns 403 | E | SR-11 | Proves RBAC is enforced |
| T-10 | Unauthenticated request to protected endpoint returns 401 | E | SR-11 | Proves auth is required |
| T-11 | User cannot access another user's account | F | SR-12 | Proves ownership is enforced |
| T-12 | Large transfer without step-up token returns 403 | G | SR-13 | Proves step-up gate exists |
| T-13 | Large transfer with valid step-up token returns 200 | G | SR-13 | Proves step-up mechanism works |
| T-14 | Step-up token cannot be reused | G | SR-14 | Proves one-time use is enforced |
| T-15 | Rate limit exceeded returns 429 | H | SR-15 | Proves rate limiting is active |
| T-16 | Login success creates AuditLog entry | I | SR-16 | Proves audit logging works |
| T-17 | Password reset for nonexistent email returns 200 | L | SR-18 | Proves no email enumeration |
| T-18 | Password reset revokes all active sessions | L | SR-18 | Proves credential recovery revokes access |
| T-19 | Weak password at registration returns 422 | K | SR-01 | Proves password policy is enforced |
| T-20 | Token reuse creates CRITICAL SecurityEvent | J | SR-17 | Proves detection and recording of attacks |

---

## 5a. T-ID → Test Function Mapping (Phases 1–5)

The table below maps each MVP-critical test identifier to the concrete pytest
function that implements it, or notes that the test is deferred to a later
phase.  Only T-IDs whose implementing phase is complete are mapped; the rest
are listed as "Phase N — not yet implemented".

| T-ID | Test Function | File | Status |
|------|--------------|------|--------|
| T-01 | `test_login_wrong_password_returns_401` | `test_auth_login.py` | Implemented |
| T-02 | `test_login_account_lockout_after_max_failures` | `test_auth_login.py` | Implemented |
| T-03 | `test_mfa_login_no_totp_code_returns_mfa_required` | `test_auth_mfa.py` | Implemented |
| T-04 | `test_mfa_login_invalid_totp_code_returns_401_and_writes_mfa_failed_audit` | `test_auth_mfa.py` | Implemented |
| T-05 | `test_refresh_old_token_rejected_after_rotation` | `test_auth_refresh.py` | Implemented |
| T-06 | `test_refresh_reuse_detection_revokes_session` | `test_auth_refresh.py` | Implemented |
| T-07 | `test_logout_blacklists_access_token` | `test_auth_logout.py` | Implemented |
| T-08 | `test_protected_endpoint_rejects_missing_redis_session` | `test_get_current_user.py` | Implemented |
| T-09 | `test_admin_ping_user_role_returns_403` | `test_rbac.py` | Implemented |
| T-10 | `test_admin_ping_unauthenticated_returns_403` | `test_rbac.py` | Implemented |
| T-11 | `test_get_account_scoped_to_authenticated_user` | `test_accounts.py` | Implemented |
| T-12 | `test_transfer_above_threshold_missing_step_up` | `test_transfers.py` | Implemented |
| T-13 | `test_transfer_above_threshold_with_valid_step_up` | `test_transfers.py` | Implemented |
| T-14 | `test_transfer_above_threshold_consumed_step_up` | `test_transfers.py` | Implemented |
| T-15 | — | — | Phase 7 — not yet implemented |
| T-16 | `test_login_audit_log_written_on_success` | `test_auth_login.py` | Implemented |
| T-17 | — | — | Phase 6 — not yet implemented |
| T-18 | — | — | Phase 6 — not yet implemented |
| T-19 | `test_register_weak_password_returns_422` | `test_auth_register.py` | Implemented |
| T-20 | — | — | Phase 6 — not yet implemented |

**16 of 20** MVP-critical tests are implemented as of the end of Phase 5.
The remaining four (T-15, T-17, T-18, T-20) are scheduled for Phase 6
(password reset + security events) and Phase 7 (rate limiting).

---

## 6. Post-MVP / Optional Tests

These tests verify features that are deferred to post-MVP or that go beyond the minimum thesis requirements.

| Test | Covers | Condition to include |
|------|--------|----------------------|
| Concurrent session limit enforced | Post-MVP feature | If concurrent session limits are implemented |
| Per-user rate limiting (not just per-IP) | Post-MVP feature | If per-user rate limiting is added |
| TOTP backup codes work and are single-use | Post-MVP feature | If backup codes are implemented |
| RS256 signature verification | Post-MVP enhancement | If RS256 is adopted |
| Strict device fingerprint mismatch rejection | Post-MVP hardening | If strict device binding is implemented |
| TOTP replay within 30-second window rejected | Optional hardening | If TOTP code tracking in Redis is added |
| Admin deactivation immediately invalidates session | Enhancement | If proactive session revocation on deactivation is added |
| CSP header blocks inline scripts | E2E header check | As part of security headers E2E suite |
| HSTS header present | E2E header check | When TLS is configured |

---

## 7. Phase-by-Phase Verification Approach

Each implementation phase from `IMPLEMENTATION_PLAN.md` has a corresponding set of tests that must pass before moving to the next phase. This creates a progressive verification model where each phase is tested before building on top of it.

---

### Phase 1 — Project Foundation

**Verification method:** Manual + smoke test.

| Check | Method |
|-------|--------|
| `GET /health` returns 200 | `pytest` smoke test or `curl` |
| Alembic migration runs without error | `alembic upgrade head` in container |
| No service exposed except via Nginx | `docker ps` + attempt direct connection to backend port |
| Security headers present on Nginx responses | `curl -I http://localhost/health` |
| No `.env` file committed | `git status` check |

---

### Phase 2 — Core Authentication

**Verification method:** Integration tests in `tests/test_auth.py` and `tests/test_tokens.py`.

| Test | SR |
|------|----|
| T-19: Weak password → 422 | SR-01 |
| Registration with valid password → 201 | SR-01 |
| Duplicate email → 409 | — |
| T-01: Wrong password → 401 | SR-02 |
| Login success → access + refresh tokens | SR-06 |
| T-05: Old refresh token rejected after rotation | SR-07 |
| T-07: Post-logout access token rejected | SR-09 |
| T-08: Request with no Redis session → 401 | SR-10 |
| T-16: Login success creates AuditLog | SR-16 |

---

### Phase 3 — MFA (TOTP)

**Verification method:** Integration tests in `tests/test_auth.py` (MFA section).

| Test | SR |
|------|----|
| T-03: Login without TOTP code when MFA enabled → mfa_required | SR-04 |
| T-04: Login with invalid TOTP → 401 | SR-04 |
| Login with valid TOTP → tokens | SR-04 |
| MFA setup returns secret and QR code | SR-04 |
| MFA enable with valid TOTP code activates MFA | SR-04 |

---

### Phase 4 — Authorization

**Verification method:** Integration tests in `tests/test_rbac.py` and `tests/test_ownership.py`.

| Test | SR |
|------|----|
| T-10: Unauthenticated request → 401 | SR-11 |
| T-09: User role → /admin/* → 403 | SR-11 |
| Admin role → /admin/* → 200 | SR-11 |
| T-11: User cannot access another user's account | SR-12 |
| Unverified user → /accounts/me → 403 | SR-03 |

---

### Phase 5 — Financial Logic + Step-up Authentication

**Verification method:** Integration tests in `tests/test_step_up_auth.py`.

| Test | SR |
|------|----|
| T-12: Large transfer without step-up → 403 + X-Step-Up-Required | SR-13 |
| T-13: Large transfer with valid step-up → 200 | SR-13 |
| T-14: Step-up token reuse → 403 | SR-14 |
| Step-up token from different user → 403 | SR-13 |
| Transfer with negative amount → 422 | SR-20 |
| Transfer with insufficient balance → 400 | — |
| Transfer below threshold succeeds without step-up | SR-13 |

---

### Phase 6 — Password Reset + Security Events

**Verification method:** Integration tests in `tests/test_auth.py` (password reset section) and `tests/test_security_events.py`.

| Test | SR |
|------|----|
| T-17: Reset request for nonexistent email → 200 | SR-18 |
| Reset with expired token → 400 | SR-18 |
| Reset with invalid token → 400 | SR-18 |
| T-18: After reset, existing refresh tokens rejected → 401 | SR-18 |
| T-20: Token reuse creates CRITICAL SecurityEvent | SR-17 |
| Account lockout creates HIGH SecurityEvent | SR-17 |

---

### Phase 7 — Admin API + Rate Limiting

**Verification method:** Integration tests in `tests/test_rbac.py` (admin section) and `tests/test_rate_limiting.py`.

| Test | SR |
|------|----|
| T-15: > rate limit requests/min → 429 | SR-15 |
| T-02: 5 failed logins → account locked | SR-05 |
| Admin can list users | SR-11 |
| Auditor can read audit logs but not modify users | SR-11 |
| Regular user cannot read audit logs → 403 | SR-11 |

---

### Phase 8 — Full Integration Test Suite

**Verification method:** All tests in `tests/` pass. End-to-end verification against running Docker stack.

| Check | Method |
|-------|--------|
| All 20 MVP-critical tests pass | `pytest tests/ -v` |
| Security headers present in live stack responses | `curl -I http://localhost` |
| Nginx rate limiting applied (auth endpoint) | Send 11+ requests to /auth/login; 11th → 429 |
| Full user journey (browser or curl) | Manual or scripted E2E |

---

## 8. Tools and Testing Stack

| Tool | Role | Notes |
|------|------|-------|
| `pytest` | Test runner | Standard Python testing framework |
| `pytest-asyncio` | Async test support | Required for `async def` test functions with FastAPI |
| `httpx.AsyncClient` + `ASGITransport` | HTTP test client | Sends real HTTP requests to the FastAPI app in-process |
| `fakeredis.FakeAsyncRedis` | Redis mock | In-memory async Redis; used via `app.dependency_overrides` |
| `aiosqlite` + SQLite (`:memory:`) | DB mock | In-memory SQLite for tests; each test gets a fresh schema via `create_all` / `drop_all` |
| `pyotp` | TOTP generation in tests | Used to generate valid TOTP codes in test scenarios |
| `pytest` fixtures | Test state management | `verified_user`, `admin_user`, `client`, `test_db`, `test_redis` created per test function |
| `pytest.mark.asyncio` | Marks async tests | Applied to all integration test functions |

### Fixture email addresses

The named role fixtures (`verified_user`, `admin_user`, `auditor_user`, `unverified_user`) each use a fixed email address. This works fine when a test uses one of these fixtures on its own. If a test needs an additional user of the same kind within the same scenario — for example, to verify that one user cannot access another user's data — create that extra user inline with a unique email (e.g. `f"user_{uuid4()}@example.com"`) rather than requesting the same fixture twice in the same test.

### Test file structure

```
backend/tests/
├── conftest.py              # Shared fixtures: test_db, test_redis, client, verified_user, admin_user
├── test_auth.py             # Category A, B, L: authentication, MFA, password reset
├── test_tokens.py           # Category C, D: token lifecycle, session management
├── test_rbac.py             # Category E: role-based access control
├── test_ownership.py        # Category F: resource ownership enforcement
├── test_rate_limiting.py    # Category H: rate limiting, account lockout
├── test_step_up_auth.py     # Category G: step-up authentication for transfers
├── test_audit_log.py        # Category I: audit log creation verification
├── test_security_events.py  # Category J: security event creation verification
└── test_input_validation.py # Category K: input validation and schema enforcement
```

### Running tests

```bash
# Run all tests (inside backend container or with venv active)
pytest tests/ -v

# Run a specific category
pytest tests/test_step_up_auth.py -v

# Run only MVP-critical tests (tagged)
pytest tests/ -m "mvp_critical" -v

# Run with coverage report
pytest tests/ --cov=app --cov-report=term-missing
```

### Test isolation guarantees

- Each test function receives a fresh in-memory SQLite database (tables created, populated with fixtures, dropped after test).
- Each test function receives a fresh `FakeAsyncRedis` instance with no pre-existing keys.
- `app.dependency_overrides` replaces `get_db` and `get_redis` for the duration of each test.
- Tests are fully independent and can run in any order.
- Tests do not require Docker, a running PostgreSQL instance, or a running Redis instance.
