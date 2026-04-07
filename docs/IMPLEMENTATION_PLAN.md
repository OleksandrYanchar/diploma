# Implementation Plan

This document defines the implementation sequence in eight phases. Each phase has clear goals, deliverables, dependencies, security checkpoints, and test goals. Phases are ordered so that each builds on the previous and security is validated progressively.

---

## Phase 1 — Project Foundation

**Goal:** Establish a working, runnable project skeleton with all infrastructure services connected. No business logic, no security mechanisms yet — just a verified base to build on.

**Deliverables:**
- Docker Compose configuration (backend, frontend, PostgreSQL, Redis, Nginx)
- Nginx reverse proxy configuration with auth rate limit zones and security headers
- FastAPI application skeleton (`main.py`, router inclusion, health endpoint)
- Configuration management (`core/config.py` via pydantic-settings, `.env.example`)
- Database connection (`core/database.py` — async SQLAlchemy engine + session factory)
- Redis connection (`core/redis.py` — async client singleton)
- Alembic migration setup (`alembic.ini`, `alembic/env.py`)
- All SQLAlchemy models defined: User, Account, Transaction, RefreshToken, AuditLog, SecurityEvent
- Initial Alembic migration (creates all tables)
- Pydantic schemas for all modules

**Dependencies:** None.

**Security checkpoints:**
- No service is exposed except via Nginx (internal Docker network only)
- Security headers present on all Nginx responses (verified manually)
- No sensitive values hardcoded; all from environment variables
- `.env` file in `.gitignore`

**Test goals:**
- `GET /health` returns 200 (smoke test)
- Database migrations run without errors

---

## Phase 2 — Core Authentication

**Goal:** Implement registration, login, logout, and the full JWT + refresh token lifecycle. This phase delivers the foundation of all subsequent security mechanisms.

**Deliverables:**
- `auth/service.py`: `register_user`, `login`, `logout` functions
- `core/security.py`: Argon2 hashing, JWT creation/decoding, refresh token generation (raw + hash), password strength validation
- `auth/router.py`: `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
- Email verification token generation and validation (demo: console logging)
- `GET /auth/verify-email` endpoint
- `dependencies/auth.py`: `get_current_user` dependency (token validation + blacklist check + session check + user state check)
- Session creation in Redis on login
- Audit logging for: REGISTER, LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, EMAIL_VERIFIED

**Dependencies:** Phase 1 (database, Redis, Alembic, models).

**Security checkpoints:**
- Passwords stored as Argon2 hash — never plaintext (SR-02)
- JWT contains only user ID, role, session ID — no PII (SR-06)
- Access token TTL is 15 minutes (SR-06)
- Refresh token stored as SHA-256 hash in DB (SR-07)
- Logout blacklists access token and revokes refresh token (SR-09)
- Session created in Redis on login; verified on every request (SR-10)

**Test goals:**
- Registration with weak password → 422 (SR-01)
- Registration with valid password → 201 (SR-01)
- Registration with duplicate email → 409 (SR-03)
- Login with wrong password → 401 (SR-02)
- Login with correct credentials → 200 + tokens (SR-06)
- Using access token after logout → 401 (SR-09)
- Using revoked refresh token → 401 (SR-07)

---

## Phase 3 — MFA (TOTP)

**Goal:** Implement the full TOTP MFA lifecycle: enrollment, activation, login enforcement, and disable.

**Deliverables:**
- `auth/service.py`: `setup_mfa`, `enable_mfa`, `disable_mfa` functions
- `POST /auth/mfa/setup` — returns TOTP secret + QR code (base64 PNG)
- `POST /auth/mfa/enable` — confirms enrollment by validating first TOTP code
- `POST /auth/mfa/disable` — disables MFA after password confirmation
- Login flow updated: if `mfa_enabled=true`, TOTP code required before tokens are issued
- Audit logging for: MFA_ENABLED, MFA_DISABLED, MFA_VERIFIED, MFA_FAILED

**Dependencies:** Phase 2 (login flow must exist before MFA can be layered in).

**Security checkpoints:**
- TOTP secret never returned after initial setup response (SR-04)
- MFA is enforced at login when enabled — no bypass (SR-04)
- Invalid TOTP code returns 401, not a token (SR-04)
- TOTP verification uses `valid_window=1` (±30 seconds) to account for clock drift (SR-04)

**Test goals:**
- Login without TOTP code when MFA enabled → returns mfa_required=true (SR-04)
- Login with invalid TOTP code → 401 (SR-04)
- Login with valid TOTP code → 200 + tokens (SR-04)
- MFA setup returns secret and QR code (SR-04)
- MFA enable with valid code → MFA is active (SR-04)

---

## Phase 4 — Authorization

**Goal:** Implement RBAC, resource ownership checks, and the verified-user requirement. All endpoints should be protected by the appropriate combination of these controls.

**Deliverables:**
- `dependencies/auth.py`: `require_role(*roles)` dependency factory
- `dependencies/auth.py`: `require_verified()` dependency
- All existing endpoints updated to use appropriate dependency combinations
- Account endpoint: scoped to current user (no account ID in URL)
- Password change endpoint: `POST /auth/password/change`
- Basic user profile endpoint: `GET /users/me`

**Dependencies:** Phase 2 (get_current_user dependency must exist).

**Security checkpoints:**
- No endpoint accessible without `get_current_user` dependency unless explicitly PUBLIC (SR-10, SR-11)
- Admin and auditor endpoints only accessible with correct role (SR-11)
- Account and transaction queries always filtered by `user_id = current_user.id` (SR-12)
- Unverified users cannot access account or transaction endpoints (SR-03)

**Test goals:**
- User-role account accessing admin endpoint → 403 (SR-11)
- Admin-role account accessing admin endpoint → 200 (SR-11)
- Unauthenticated request to protected endpoint → 401 (SR-11)
- Authenticated user cannot access another user's account → 403/404 (SR-12)
- Unverified user accessing /accounts/me → 403 (SR-03)

---

## Phase 5 — Financial Logic + Step-up Authentication

**Goal:** Implement the minimal financial business logic (account, transfer) and the step-up authentication mechanism for sensitive operations. This phase delivers the most academically distinctive security feature.

**Deliverables:**
- `accounts/router.py`: `GET /accounts/me`
- `accounts/service.py`: account retrieval scoped to current user
- Account creation seeded for verified users (on registration or first login)
- `transactions/router.py`: `POST /transactions/transfer`, `GET /transactions/history`
- `transactions/service.py`: transfer logic with balance check, ACID DB transaction
- `auth/service.py`: `verify_step_up` function
- `POST /auth/step-up` endpoint: issues step-up JWT after TOTP re-verification
- Transfer endpoint: checks amount vs threshold; requires step-up token for large transfers
- Step-up token one-time-use flag stored in Redis
- Audit logging for: ACCOUNT_VIEWED, TRANSACTIONS_VIEWED, TRANSFER_INITIATED, TRANSFER_COMPLETED, TRANSFER_REJECTED, STEP_UP_VERIFIED, STEP_UP_FAILED
- Security events for: STEP_UP_BYPASS_ATTEMPT

**Dependencies:** Phases 2–4 (authentication and authorization must be in place before financial endpoints are built).

**Security checkpoints:**
- Transfer below threshold proceeds without step-up token (SR-13)
- Transfer at or above threshold without step-up token → 403 + X-Step-Up-Required: true header (SR-13)
- Transfer at or above threshold with valid step-up token → succeeds (SR-13)
- Step-up token is single-use: second use → 403 (SR-14)
- Step-up token expires after 5 minutes (SR-13)
- Transfer is an ACID DB transaction: balance deducted and credited atomically
- Negative or zero transfer amount → 422 (SR-20)

**Test goals:**
- Transfer >= threshold without step-up → 403 with X-Step-Up-Required header (SR-13)
- Transfer >= threshold with valid step-up token → 200 (SR-13)
- Reuse of same step-up token → 403 (SR-14)
- Transfer with insufficient balance → 400
- Transfer with invalid amount → 422 (SR-20)

---

## Phase 6 — Password Reset + Security Events

**Goal:** Complete the authentication lifecycle with password reset, and implement security event creation for all detectable anomalies.

**Deliverables:**
- `POST /auth/password/reset/request` — generates and stores hashed token; logs to console in demo mode
- `POST /auth/password/reset/confirm` — validates token, resets password, revokes all sessions
- `auth/service.py`: `request_password_reset`, `confirm_password_reset` functions
- Security event creation integrated throughout: brute force (on account lockout trigger), token reuse, rate limit exceeded, step-up bypass attempt
- `SecurityEvent` model in DB populated for all defined event types
- Audit logging for: PASSWORD_RESET_REQUESTED, PASSWORD_RESET_COMPLETED, ACCOUNT_LOCKED

**Dependencies:** Phases 2–5 (requires working auth, session management, and token management).

**Security checkpoints:**
- Password reset token stored as SHA-256 hash; raw token never persisted (SR-18)
- Reset token expires in 30 minutes (SR-18)
- Reset endpoint returns 200 regardless of whether email exists (SR-18)
- All active sessions revoked after successful password reset (SR-18)
- Security events are written for: lockout, brute force, token reuse, step-up bypass (SR-17)

**Test goals:**
- Password reset request with nonexistent email → 200 (no enumeration) (SR-18)
- Password reset with expired token → 400 (SR-18)
- Password reset with invalid token → 400 (SR-18)
- After successful password reset, existing refresh tokens rejected → 401 (SR-18)
- After 5 failed logins, security event of type ACCOUNT_LOCKED exists in DB (SR-17)

---

## Phase 7 — Admin API + Rate Limiting

**Goal:** Complete the admin API for security monitoring and implement the rate limiting middleware.

**Deliverables:**
- `admin/router.py`: all admin endpoints (list users, activate, deactivate, unlock, change role)
- `admin/router.py`: audit log query endpoint with filters
- `admin/router.py`: security events query endpoint with filters
- `core/middleware.py`: sliding window rate limit middleware using Redis sorted sets
- `core/middleware.py`: security headers middleware
- Rate limit middleware integrated into FastAPI app startup

**Dependencies:** Phase 6 (audit logs and security events must be populated).

**Security checkpoints:**
- All admin endpoints require admin role — auditor role cannot modify user state (SR-11)
- Audit log and security event endpoints accessible to auditor and admin (SR-11)
- Rate limit middleware returns 429 with Retry-After header when limit exceeded (SR-15)
- Rate limit uses sliding window (not fixed window) to prevent burst exploitation at window boundaries (SR-15)

**Test goals:**
- Sending more than rate limit requests per minute → 429 (SR-15)
- Admin user can list users, view audit logs, view security events (SR-11)
- Auditor user can view audit logs and security events but cannot deactivate users (SR-11)
- Regular user cannot access any /admin/* endpoint → 403 (SR-11)

---

## Phase 8 — Frontend Demo + Integration Testing

**Goal:** Implement a minimal React frontend that demonstrates the full security flow end-to-end in a browser. Run the full integration test suite and fix any gaps.

**Deliverables:**
- React SPA with TypeScript
- Pages: Register, Login, MFA Setup, MFA Verify, Dashboard (account + transactions), Step-up modal
- Axios HTTP client with interceptors: attaches access token to requests; handles 401 by attempting token refresh; redirects to login on refresh failure
- Auth state management: access token in memory (not localStorage); refresh token in HttpOnly cookie is ideal, or in memory for demo
- Full integration test suite: `tests/test_auth.py`, `tests/test_tokens.py`, `tests/test_rbac.py`, `tests/test_ownership.py`, `tests/test_rate_limiting.py`, `tests/test_step_up_auth.py`
- All tests passing

**Dependencies:** Phases 1–7 (all backend features must be complete).

**Security checkpoints:**
- Access token not stored in localStorage (susceptible to XSS) — kept in memory
- Refresh token handled securely (HttpOnly cookie preferred; memory acceptable for demo)
- Frontend does not store MFA secret after enrollment
- CSP header from Nginx does not need `unsafe-inline` for scripts

**Test goals (complete suite):**

| Test | Scenario | Expected |
|------|---------|---------|
| Failed login handling | Wrong password → 401; after 5 failures → 403 locked | SR-01, SR-05 |
| MFA flow | Login with MFA enabled, no code → mfa_required; valid code → tokens; invalid code → 401 | SR-04 |
| Refresh token rotation | Old token rejected after refresh | SR-07 |
| Revoked token rejection | Logout → access token rejected | SR-09 |
| RBAC enforcement | User → admin endpoint 403; admin → 200 | SR-11 |
| Ownership checks | User A cannot see User B's account | SR-12 |
| Rate limiting | > limit requests/min → 429 | SR-15 |
| Step-up for large transfer | No step-up → 403; valid step-up → 200; reuse → 403 | SR-13, SR-14 |

---

## Phase Summary

| Phase | Core Focus | MVP Tier |
|-------|-----------|---------|
| 1 | Foundation (infra, models, config) | Core MVP |
| 2 | Authentication (register, login, tokens) | Core MVP |
| 3 | MFA (TOTP enrollment, login enforcement) | Core MVP |
| 4 | Authorization (RBAC, ownership, verification) | Core MVP |
| 5 | Financial logic + step-up authentication | Security-Enhanced MVP |
| 6 | Password reset + security events | Core MVP + Security-Enhanced MVP |
| 7 | Admin API + rate limiting | Security-Enhanced MVP |
| 8 | Frontend demo + full test suite | Security-Enhanced MVP |
