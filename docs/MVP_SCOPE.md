# MVP Scope

This document defines which features are mandatory for thesis defense, which are part of an enhanced security MVP, and which are optional post-MVP extensions. This three-tier split ensures that the core academic contribution is protected from scope creep while allowing room for depth where time permits.

---

## Tier 1: Core MVP

**Must be fully implemented and tested for thesis defense.**

These are the minimum features that make the project academically valid as a Zero Trust security subsystem demonstration.

### Authentication

| Feature | Description |
|---------|-------------|
| User registration | Email + password registration with password strength enforcement (Argon2 hashing) |
| Email verification | Verification token sent on registration; account limited until verified |
| Login | Credential validation, failed attempt tracking, account lockout after N failures |
| MFA (TOTP) | TOTP enrollment via QR code, verification required at login when enabled |
| Logout | Access token blacklisted in Redis, session invalidated, refresh token revoked |
| Password change | Authenticated user changes own password |

### Token Management

| Feature | Description |
|---------|-------------|
| JWT access tokens | HS256, 15-minute lifetime, contains user ID, role, session ID |
| Refresh tokens | Opaque, hashed in DB + session tracked in Redis, 7-day lifetime |
| Token rotation | New refresh token issued on every refresh, old one revoked |
| Reuse detection | Reused revoked refresh token triggers full session revocation and security event |
| Token blacklisting | Revoked access tokens stored in Redis for remaining TTL |

### Authorization

| Feature | Description |
|---------|-------------|
| RBAC | Three roles: user, auditor, admin — enforced on every endpoint |
| Resource ownership | Users can only access their own accounts and transactions |
| Session validity check | Every request verifies active session in Redis, not just token signature |
| User state check | Locked or deactivated accounts are rejected even with valid tokens |

### Password Reset

| Feature | Description |
|---------|-------------|
| Reset request | Generates a secure token, stores hash in DB, logs token in demo mode |
| Reset confirmation | Validates token, sets new password, revokes all active sessions and tokens |
| Email enumeration protection | Reset endpoint always returns success regardless of whether email exists |

### Audit Logging

| Feature | Description |
|---------|-------------|
| Auth events | All login attempts (success/failure), logout, MFA events, lockouts |
| Token events | Refresh, revocation, reuse detection |
| Data access events | Account view, transaction history view |
| Transfer events | Transfer initiated, completed, rejected |
| Admin events | User deactivated/activated, role changes |

### Financial Context (minimal)

| Feature | Description |
|---------|-------------|
| User account | Single account per user with balance and currency |
| Transaction history | View own transactions |
| Transfer | Transfer funds to another account by account number |

### Security Infrastructure

| Feature | Description |
|---------|-------------|
| Rate limiting | Sliding window per IP (Redis), enforced at Nginx level for auth endpoints |
| Account lockout | Lock after N failed logins with timed recovery |
| Security headers | X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, CSP (Nginx) |

---

## Tier 2: Security-Enhanced MVP

**Should be implemented for a complete Zero Trust demonstration. Required for full academic credit — these are what make the project a genuine Zero Trust system rather than a basic auth implementation.**

### Step-up Authentication

| Feature | Description |
|---------|-------------|
| Step-up token issuance | POST /auth/step-up: verifies TOTP, issues short-lived (5 min) step-up JWT |
| Step-up enforcement | Transfers >= configured threshold require a valid step-up token in request header |
| One-time use | Step-up token marked as used in Redis after first use; cannot be reused |
| Bypass detection | Attempt to send large transfer without step-up token logged as security event |

### Security Event Detection

| Feature | Description |
|---------|-------------|
| Brute force detection | Repeated failed logins generate a security event |
| Token reuse event | Detected refresh token reuse logged as CRITICAL security event |
| Step-up bypass attempt | Transfer without step-up token above threshold logged as security event |
| Account locked event | Lockout recorded as HIGH severity security event |

### Admin API

| Feature | Description |
|---------|-------------|
| List users | Admin can list all users with security metadata |
| Activate/deactivate user | Admin can disable accounts |
| Audit log query | Admin and auditor roles can query filtered audit logs |
| Security events query | Admin and auditor can query security events |

### MFA Lifecycle

| Feature | Description |
|---------|-------------|
| MFA setup flow | User initiates setup: receives secret + QR code |
| MFA enable confirmation | User confirms setup by submitting a valid TOTP code |
| MFA disable | Authenticated user can disable MFA (requires password confirmation) |

---

## Tier 3: Post-MVP (Optional Extensions)

**Not required for thesis defense. Can be implemented as time allows or described as future work.**

| Feature | Reason for deferral |
|---------|-------------------|
| Concurrent session limits | Adds complexity to session management; not a Zero Trust prerequisite |
| Rate limiting per authenticated user | IP-level rate limiting covers the thesis scope; per-user adds implementation overhead |
| Anomaly detection (unusual IP, time-based) | Valuable but requires baseline data; better suited as future work |
| Admin frontend UI | Admin API endpoints are sufficient for demonstration; UI is cosmetic |
| Email delivery (real SMTP) | Demo mode (console logging) is sufficient for thesis purposes |
| RS256 JWT signing (asymmetric keys) | HS256 is cryptographically valid; RS256 adds key management complexity without changing security properties for this context |
| Refresh token device binding (strict) | Device fingerprint is recorded; strict rejection based on fingerprint mismatch is a production hardening step |
| TOTP backup codes | Useful for real-world recovery; not needed for thesis demonstration |
| Account activity notifications | Nice to have; not a Zero Trust mechanism |
| Pagination on admin endpoints | Implementation detail, not security-critical |

---

## Summary Table

| Category | Core MVP | Security-Enhanced MVP | Post-MVP |
|----------|----------|-----------------------|----------|
| Registration + login | ✓ | | |
| Password strength + Argon2 | ✓ | | |
| Email verification | ✓ | | |
| MFA (TOTP) — basic | ✓ | | |
| MFA lifecycle (setup/enable/disable) | | ✓ | |
| JWT access tokens | ✓ | | |
| Refresh token rotation | ✓ | | |
| Token reuse detection | ✓ | | |
| Token blacklisting | ✓ | | |
| RBAC | ✓ | | |
| Resource ownership | ✓ | | |
| Session validity check | ✓ | | |
| Password reset | ✓ | | |
| Audit logging | ✓ | | |
| Step-up authentication | | ✓ | |
| Security event detection | | ✓ | |
| Admin API | | ✓ | |
| Rate limiting (IP level) | ✓ | | |
| Account lockout | ✓ | | |
| Security headers | ✓ | | |
| Concurrent session limits | | | ✓ |
| Per-user rate limiting | | | ✓ |
| Anomaly detection | | | ✓ |
| Real email delivery | | | ✓ |
| RS256 JWT | | | ✓ |
| Frontend demo UI | | ✓ (minimal) | |
| Admin frontend UI | | | ✓ |
