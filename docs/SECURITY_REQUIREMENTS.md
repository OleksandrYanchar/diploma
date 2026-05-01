# Security Requirements

Each requirement is numbered for traceability. Requirements are referenced from the Threat Model and Implementation Plan.

**Priority levels:**
- **P1 — Critical:** Must be implemented for MVP. Core Zero Trust controls. No thesis without these.
- **P2 — High:** Required for complete Zero Trust demonstration. Part of security-enhanced MVP.
- **P3 — Medium:** Strengthens the system; should be included but can be deferred if time is limited.

**Verification approach** indicates how the requirement will be confirmed to be met.

---

## SR-01 — Password Strength Enforcement

| Field | Value |
|-------|-------|
| **Description** | Passwords must meet a minimum strength policy: at least 12 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character. |
| **Rationale** | Weak passwords are the most common entry point for credential attacks. Enforcing strength at registration and password change reduces the risk of successful brute force and dictionary attacks. |
| **Zero Trust principle** | Verify identity explicitly — weak credentials undermine the authentication guarantee. |
| **Priority** | P1 |
| **Verification** | Unit test: registration with a weak password returns HTTP 422. Unit test: registration with a conforming password succeeds. |

---

## SR-02 — Argon2 Password Hashing

| Field | Value |
|-------|-------|
| **Description** | All passwords must be hashed using the Argon2id algorithm before storage. Plaintext passwords must never be logged or persisted. |
| **Rationale** | Argon2id is a memory-hard hashing function that is resistant to GPU-based brute force and side-channel attacks. It is the winner of the Password Hashing Competition and recommended by OWASP. |
| **Zero Trust principle** | Assume breach — even if the database is compromised, password hashes must be computationally infeasible to reverse. |
| **Priority** | P1 |
| **Verification** | Code review: no plaintext passwords stored. Unit test: verify_password correctly accepts valid and rejects invalid passwords. |

---

## SR-03 — Email Verification

| Field | Value |
|-------|-------|
| **Description** | Users must verify their email address before accessing protected endpoints. A secure random token is generated at registration and delivered out-of-band (email or console in demo mode). |
| **Rationale** | Prevents account registration with fake or stolen email addresses and ensures a communication channel exists for credential recovery. |
| **Zero Trust principle** | Verify identity explicitly — account ownership of the claimed email must be confirmed. |
| **Priority** | P1 |
| **Verification** | Integration test: unverified user attempting to access /accounts/me receives 403. Integration test: verified user can access the endpoint. |

---

## SR-04 — Multi-Factor Authentication (TOTP)

| Field | Value |
|-------|-------|
| **Description** | Users can enroll a TOTP authenticator. Once MFA is enabled, a valid TOTP code is required at every login in addition to the password. |
| **Rationale** | A second factor means that compromised passwords alone are not sufficient for account takeover. TOTP provides a strong second factor with no dependency on external services. |
| **Zero Trust principle** | Verify identity explicitly — single-factor authentication is insufficient for a Zero Trust system. |
| **Priority** | P1 |
| **Verification** | Integration test: login without TOTP code when MFA is enabled returns mfa_required=true. Integration test: login with invalid TOTP code returns 401. Integration test: login with valid TOTP code succeeds. |

---

## SR-05 — Account Lockout

| Field | Value |
|-------|-------|
| **Description** | After N consecutive failed login attempts for the same account, the account is locked for a configurable duration. Failed attempt count resets on successful login. |
| **Rationale** | Prevents online brute force attacks against individual accounts. The lockout duration limits the attack window. |
| **Zero Trust principle** | Assume breach — continuous validation includes detecting and responding to authentication abuse. |
| **Priority** | P1 |
| **Verification** | Integration test: after 5 failed logins, the next attempt (with correct credentials) returns 403 with "locked" message. |

---

## SR-06 — Short-lived Access Tokens

| Field | Value |
|-------|-------|
| **Description** | JWT access tokens must have a maximum lifetime of 15 minutes. The expiration claim is validated on every request. |
| **Rationale** | Limits the window of token misuse if a token is intercepted or stolen. A 15-minute TTL means a stolen token becomes useless quickly without further exploitation. |
| **Zero Trust principle** | Never trust, always verify — token validity must be time-bounded. |
| **Priority** | P1 |
| **Verification** | Unit test: token created with 15-minute expiry contains correct exp claim. Unit test: decoding an expired token raises a JWTError. |

---

## SR-07 — Refresh Token Rotation

| Field | Value |
|-------|-------|
| **Description** | Every successful use of a refresh token must issue a new refresh token and immediately revoke the old one. The old token must not be accepted again. |
| **Rationale** | Token rotation ensures that stolen refresh tokens have a limited window of usefulness. If an attacker obtains an old refresh token, it will already be revoked. |
| **Zero Trust principle** | Never trust, always verify — even long-lived credentials must be continuously validated and rotated. |
| **Priority** | P1 |
| **Verification** | Integration test: after a refresh, the old refresh token is rejected with 401. Integration test: new tokens are returned on each refresh. |

---

## SR-08 — Refresh Token Reuse Detection

| Field | Value |
|-------|-------|
| **Description** | If a refresh token that has already been revoked is presented again, the system must immediately invalidate the entire session (all tokens for that session) and record a CRITICAL security event. |
| **Rationale** | Token reuse is a strong signal that a token has been stolen and both the legitimate user and the attacker are using it. Invalidating the entire session protects the user even if the attacker acts first. |
| **Zero Trust principle** | Assume breach — a reused revoked token is treated as an active attack, not a transient error. |
| **Priority** | P1 |
| **Verification** | Integration test: using a revoked refresh token triggers session invalidation. Subsequent request with access token from that session returns 401. Security event with type TOKEN_REUSE is recorded. |

---

## SR-09 — Access Token Blacklisting on Logout

| Field | Value |
|-------|-------|
| **Description** | On logout, the current access token must be stored in a Redis blacklist with a TTL equal to the token's remaining lifetime. Blacklisted tokens must be rejected on every request. |
| **Rationale** | Without blacklisting, a logout would be ineffective — the access token would remain valid until its natural expiry. This is especially important given the 15-minute TTL window. |
| **Zero Trust principle** | Never trust, always verify — a revoked credential must not be honoured regardless of its cryptographic validity. |
| **Priority** | P1 |
| **Verification** | Integration test: after logout, the same access token is rejected with 401. |

---

## SR-10 — Session Validity Check on Every Request

| Field | Value |
|-------|-------|
| **Description** | Every authenticated request must verify that the session ID embedded in the access token corresponds to an active session record in Redis. A cryptographically valid token is not sufficient without a live session. |
| **Rationale** | This is the core Zero Trust mechanism that enables immediate session revocation. When a user's password is reset or an admin deactivates an account, existing tokens are rendered invalid immediately. |
| **Zero Trust principle** | Never trust, always verify — every request is a new verification event. |
| **Priority** | P1 |
| **Verification** | Integration test: after session deletion in Redis (simulating forced logout), a request with a still-valid access token returns 401. |

---

## SR-11 — Role-Based Access Control (RBAC)

| Field | Value |
|-------|-------|
| **Description** | All endpoints must enforce the minimum required role. The role is embedded in the access token and validated server-side on every request. Three roles exist: user, auditor, admin. |
| **Rationale** | Least privilege — each role has only the permissions needed for its function. Users cannot access admin or auditor endpoints. |
| **Zero Trust principle** | Use least-privilege access — no user has more access than their role requires. |
| **Priority** | P1 |
| **Verification** | Integration test: a user-role account cannot access /admin/* endpoints (403). Integration test: an admin-role account can access /admin/* endpoints. Integration test: unauthenticated request to protected endpoint returns 401/403. |

---

## SR-12 — Resource Ownership Enforcement

| Field | Value |
|-------|-------|
| **Description** | Users may only read or modify resources that belong to them. Access to another user's account or transactions must be denied even if the user is authenticated and holds a valid role. |
| **Rationale** | RBAC alone does not prevent horizontal privilege escalation (a user accessing another user's data within the same role). Ownership checks are required as an additional layer. |
| **Zero Trust principle** | Use least-privilege access — identity alone is not sufficient; resource ownership must be verified. |
| **Priority** | P1 |
| **Verification** | Integration test: authenticated user attempting to access a resource belonging to a different user receives 403 or 404. |

---

## SR-13 — Step-up Authentication for Sensitive Operations

| Field | Value |
|-------|-------|
| **Description** | Transfers at or above a configured threshold amount must require a valid step-up token in the `X-Step-Up-Token` request header. The step-up token is issued by the /auth/step-up endpoint after fresh TOTP verification and is valid for 5 minutes and one use only. |
| **Rationale** | A valid session token proves identity at login time but not at the time of the sensitive operation. Step-up authentication re-verifies the user's second factor immediately before the high-risk operation, limiting the blast radius of a stolen session token. |
| **Zero Trust principle** | Verify explicitly — high-risk operations require additional, just-in-time verification. |
| **Priority** | P2 |
| **Verification** | Integration test: transfer >= threshold without step-up token returns 403 with X-Step-Up-Required header. Integration test: transfer >= threshold with valid step-up token succeeds. Integration test: reuse of the same step-up token for a second transfer returns 403. |

---

## SR-14 — Step-up Token One-time Use

| Field | Value |
|-------|-------|
| **Description** | A step-up token must be marked as used in Redis immediately upon first use. Any subsequent attempt to use the same step-up token must be rejected. |
| **Rationale** | Prevents replay attacks where an attacker who captures a step-up token reuses it for additional unauthorized operations within the 5-minute window. |
| **Zero Trust principle** | Assume breach — a captured step-up token must not enable repeated access. |
| **Priority** | P2 |
| **Verification** | Integration test: same step-up token used twice for two separate transfer requests; second request returns 403. |

---

## SR-15 — IP-level Rate Limiting

| Field | Value |
|-------|-------|
| **Description** | A sliding window rate limit must be enforced per IP address at both the Nginx layer (auth endpoints) and application layer (all endpoints). Exceeding the limit returns HTTP 429 with a Retry-After header. |
| **Rationale** | Limits the speed of automated attacks (credential stuffing, brute force) from a single IP address. |
| **Zero Trust principle** | Assume breach — an attacker is assumed to attempt automated attacks. |
| **Priority** | P1 |
| **Verification** | Integration test: sending more than the configured limit of requests per minute from the same IP returns 429. |

---

## SR-16 — Comprehensive Audit Logging

| Field | Value |
|-------|-------|
| **Description** | All security-relevant actions must be recorded in an append-only audit log including: all authentication events, token lifecycle events, data access events, transfer events, and admin actions. Each log entry must capture user ID, action, status (success/failure), IP address, user agent, timestamp, and structured details. The IP address is extracted from the ``X-Real-IP`` header forwarded by the Nginx reverse proxy; the user agent is taken from the ``User-Agent`` header. Both values are extracted at the router layer and passed as plain string parameters to the service layer — no ``Request`` object crosses the router/service boundary. |
| **Rationale** | Non-repudiation requires an authoritative record of who did what, when, and from where. Audit logs are essential for incident response and regulatory compliance. |
| **Zero Trust principle** | Assume breach — every action is recorded so that breaches can be reconstructed and attributed. |
| **Priority** | P1 |
| **Verification** | Integration tests: after login, a log entry with LOGIN_SUCCESS is present. After failed login, LOGIN_FAILED is present. After transfer, TRANSFER_COMPLETED is present. |

---

## SR-17 — Security Event Detection

| Field | Value |
|-------|-------|
| **Description** | The system must detect and record specific security events: brute force attempts, account lockout, refresh token reuse, step-up bypass attempts, and rate limit violations. Each event has a severity level (LOW, MEDIUM, HIGH, CRITICAL). |
| **Rationale** | Detection is a required component of Zero Trust. Knowing that an attack is occurring allows for investigation, response, and future prevention. |
| **Zero Trust principle** | Assume breach — if something bad is happening, the system must know about it. |
| **Priority** | P2 |
| **Verification** | Integration test: after brute force scenario, a BRUTE_FORCE security event exists in the database. After token reuse, a TOKEN_REUSE CRITICAL event exists. |

---

## SR-18 — Password Reset Security

| Field | Value |
|-------|-------|
| **Description** | Password reset must use a secure random token (at least 32 bytes), stored as a SHA-256 hash. The token must expire in 30 minutes. On successful reset, all active sessions and refresh tokens must be revoked. The reset endpoint must return success regardless of whether the email address exists (prevents enumeration). |
| **Rationale** | Insecure password reset is a common account takeover vector. Token expiry limits the window. Session revocation ensures that an attacker who initiated a reset cannot maintain access through an existing session. Enumeration prevention prevents reconnaissance. |
| **Zero Trust principle** | Verify identity explicitly — credential recovery must be as rigorous as initial authentication. |
| **Priority** | P1 |
| **Verification** | Integration test: reset with expired token returns 400. Integration test: after successful reset, existing refresh tokens are rejected. Integration test: reset request for nonexistent email returns 200 (no enumeration). |

---

## SR-19 — Security Headers

| Field | Value |
|-------|-------|
| **Description** | All HTTP responses must include: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, and a restrictive `Content-Security-Policy`. |
| **Rationale** | These headers protect against clickjacking, MIME sniffing, reflected XSS, and information leakage to third parties. They are a baseline defence for any web application. |
| **Zero Trust principle** | Defence in depth — browser-side controls supplement server-side security. |
| **Priority** | P1 |
| **Verification** | Integration test: any API response includes the required headers with correct values. |

---

## SR-20 — Input Validation

| Field | Value |
|-------|-------|
| **Description** | All request data must be validated through Pydantic schemas before reaching business logic. No raw SQL string interpolation. Transfer amounts must be positive and within defined limits. |
| **Rationale** | Input validation is the primary defence against injection attacks and malformed data. |
| **Zero Trust principle** | Verify explicitly — untrusted input is always sanitized and validated before processing. |
| **Priority** | P1 |
| **Verification** | Unit tests: invalid request bodies return 422. Transfer with negative amount returns 422. Transfer with amount exceeding maximum returns 422. |

---

## Requirements Summary

| ID | Category | Description (short) | Priority |
|----|---------|---------------------|---------|
| SR-01 | Authentication | Password strength enforcement | P1 |
| SR-02 | Authentication | Argon2 password hashing | P1 |
| SR-03 | Authentication | Email verification | P1 |
| SR-04 | Authentication | MFA (TOTP) | P1 |
| SR-05 | Authentication | Account lockout | P1 |
| SR-06 | Token Management | Short-lived access tokens (15 min) | P1 |
| SR-07 | Token Management | Refresh token rotation | P1 |
| SR-08 | Token Management | Refresh token reuse detection | P1 |
| SR-09 | Token Management | Access token blacklisting on logout | P1 |
| SR-10 | Session Management | Session validity check per request | P1 |
| SR-11 | Authorization | Role-based access control | P1 |
| SR-12 | Authorization | Resource ownership enforcement | P1 |
| SR-13 | Authorization | Step-up authentication | P2 |
| SR-14 | Authorization | Step-up token one-time use | P2 |
| SR-15 | API Protection | IP-level rate limiting | P1 |
| SR-16 | Audit | Comprehensive audit logging | P1 |
| SR-17 | Monitoring | Security event detection | P2 |
| SR-18 | Authentication | Password reset security | P1 |
| SR-19 | API Protection | Security headers | P1 |
| SR-20 | API Protection | Input validation | P1 |
