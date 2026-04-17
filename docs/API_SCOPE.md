# API Scope

This document lists all planned API endpoints. No request/response schemas are defined here — this is the surface area specification only.

**Visibility markers:**
- `PUBLIC` — No authentication required
- `AUTHENTICATED` — Requires valid JWT access token + active session
- `VERIFIED` — Requires AUTHENTICATED + email verified
- `ROLE:auditor` — Requires AUTHENTICATED + auditor or admin role
- `ROLE:admin` — Requires AUTHENTICATED + admin role
- `STEP-UP` — Requires VERIFIED + valid step-up token in `X-Step-Up-Token` header (for transfers above threshold)

All routes are prefixed with `/api/v1`.

---

## Authentication — `/auth`

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `POST` | `/auth/register` | PUBLIC | Register a new user account. Returns success message. |
| `GET` | `/auth/verify-email` | PUBLIC | Verify email using token from query param. |
| `POST` | `/auth/login` | PUBLIC | Login with email + password (+ TOTP code if MFA enabled). Returns access + refresh tokens, or mfa_required flag. |
| `POST` | `/auth/refresh` | PUBLIC | Exchange a valid refresh token for a new access token and new refresh token. |
| `POST` | `/auth/logout` | AUTHENTICATED | Blacklist access token, revoke refresh token, delete session. |
| `POST` | `/auth/mfa/setup` | AUTHENTICATED | Initiate MFA enrollment. Returns TOTP secret and QR code. Does not enable MFA yet. |
| `POST` | `/auth/mfa/enable` | AUTHENTICATED | Confirm MFA enrollment by submitting a valid TOTP code. Activates MFA for the account. |
| `POST` | `/auth/mfa/disable` | AUTHENTICATED | Disable MFA on the account. Requires current password confirmation. |
| `POST` | `/auth/step-up` | AUTHENTICATED | Submit a fresh TOTP code to receive a short-lived step-up token (5 min, one-time use). |
| `POST` | `/auth/password/change` | AUTHENTICATED | Change password. Requires current password and new password. |
| `POST` | `/auth/password/reset/request` | PUBLIC | Request a password reset link. Always returns 200 (prevents email enumeration). |
| `POST` | `/auth/password/reset/confirm` | PUBLIC | Confirm password reset using token. Revokes all active sessions on success. |

---

## Users — `/users`

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `GET` | `/users/me` | AUTHENTICATED | Get current user's profile (id, email, name, role, mfa_enabled, verified, last_login). |

---

## Accounts — `/accounts`

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `GET` | `/accounts/me` | VERIFIED | Get current user's account details (account number, balance, currency, status). Access is scoped to the authenticated user's own account — no account ID parameter. |

---

## Transactions — `/transactions`

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `POST` | `/transactions/transfer` | VERIFIED / STEP-UP | Initiate a transfer to another account by account number. Requires step-up token if amount >= threshold. |
| `GET` | `/transactions/history` | VERIFIED | Get current user's transaction history (incoming and outgoing). Limited to own transactions — no user ID parameter. |

---

## Admin — `/admin`

All admin endpoints require authentication. Role requirements are noted per endpoint.

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `GET` | `/admin/users` | ROLE:admin | List all users with security metadata (locked status, failed login count, MFA enabled, last login). |
| `GET` | `/admin/users/{user_id}` | ROLE:admin | Get a specific user's details including security metadata. |
| `PATCH` | `/admin/users/{user_id}/deactivate` | ROLE:admin | Deactivate a user account. Active sessions remain valid until token expiry (session delete is optional enhancement). |
| `PATCH` | `/admin/users/{user_id}/activate` | ROLE:admin | Reactivate a deactivated user account. |
| `PATCH` | `/admin/users/{user_id}/unlock` | ROLE:admin | Unlock a locked account before the lockout duration expires. |
| `PATCH` | `/admin/users/{user_id}/role` | ROLE:admin | Change a user's role (user → auditor, user → admin, etc.). Audit logged. |
| `GET` | `/admin/audit-logs` | ROLE:auditor | Query audit logs. Supports filtering by user_id, action type, date range, status. |
| `GET` | `/admin/security-events` | ROLE:auditor | Query security events. Supports filtering by event type, severity, user_id, date range. |
| `GET` | `/admin/ping` | ROLE:admin + VERIFIED | Phase 4 RBAC test anchor. Intentionally minimal placeholder — returns `{"status": "ok"}`. Will be superseded by real admin endpoints in Phase 7. |

---

## Health — `/health`

| Method | Path | Visibility | Description |
|--------|------|-----------|-------------|
| `GET` | `/health` | PUBLIC | Returns `{"status": "ok"}`. Used by Docker health checks and monitoring. |

---

## Security Controls Summary by Endpoint Category

| Category | Auth Required | Email Verified | RBAC | Ownership Check | Step-up |
|----------|-------------|---------------|------|----------------|---------|
| Public auth endpoints | No | No | No | No | No |
| `/users/me` | Yes | No | No | Implicit (self) | No |
| `/accounts/me` | Yes | Yes | No | Implicit (self) | No |
| `/transactions/transfer` (small) | Yes | Yes | No | Implicit (self) | No |
| `/transactions/transfer` (large) | Yes | Yes | No | Implicit (self) | Yes |
| `/transactions/history` | Yes | Yes | No | Implicit (self) | No |
| `/admin/*` | Yes | Yes | admin | No | No |
| `/admin/audit-logs` | Yes | Yes | auditor/admin | No | No |
| `/admin/security-events` | Yes | Yes | auditor/admin | No | No |

---

## Notes on Design Decisions

**No resource ID parameters for user data:** The `/accounts/me` and `/transactions/history` endpoints deliberately do not accept a user ID or account ID parameter from the client. The server resolves the resource from the authenticated user's identity. This eliminates a class of horizontal privilege escalation attacks (IDOR — Insecure Direct Object Reference) at the design level.

**Step-up is conditionally required:** The `/transactions/transfer` endpoint checks the transfer amount server-side. If the amount is below the threshold, the step-up token is ignored even if present. If the amount meets or exceeds the threshold, the step-up token is mandatory. The threshold is configured via environment variable.

**Admin deactivation vs session revocation:** When an admin deactivates a user, the user's `is_active` flag is set to false. On the next request, the `get_current_user` dependency checks `is_active` and returns 403. Existing access tokens are rejected at the next request within their TTL. An optional enhancement is to proactively delete the session in Redis on deactivation to provide immediate revocation.
