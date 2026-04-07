# Threat Model

**Methodology:** STRIDE  
**Scope:** FinPlatform security subsystem — authentication, authorization, token management, session management, financial transfers  
**Last updated:** 2026-04-08

---

## Attacker Assumptions

The threat model assumes the following attacker profiles and capabilities:

| Attacker Profile | Capabilities | Goal |
|-----------------|-------------|------|
| **External attacker (opportunistic)** | Internet access, automated tooling (credential stuffing, brute force scanners), common exploit scripts | Gain unauthorized account access; steal tokens; extract financial data |
| **External attacker (targeted)** | All of the above plus knowledge of the target platform, ability to intercept traffic on insecure networks, ability to obtain leaked credential databases | Compromise a specific user account; execute unauthorized transfers |
| **Authenticated malicious user** | Valid account on the platform; access to their own tokens | Access other users' data (horizontal privilege escalation); perform operations beyond their own role |
| **Token thief** | Has obtained a valid access or refresh token (e.g., via XSS, man-in-the-middle on HTTP, or leaked logs) | Use stolen token to authenticate as victim; perform actions without knowing the password |
| **Insider / admin impersonator** | May have partial access to infrastructure; may attempt privilege escalation | Access sensitive data, disable security controls, tamper with audit logs |

**Out of scope attackers:**
- Attackers with direct database access (covered by infrastructure hardening, not application security)
- Attackers who have compromised the server OS
- Nation-state level cryptographic attacks on HS256

---

## Assets and Trust Boundaries

See ARCHITECTURE.md for full asset table and trust boundary descriptions.

**Summary of most critical assets:**
1. User passwords (hashed, but hash theft is still a risk)
2. MFA secrets (TOTP shared secrets)
3. Refresh tokens (long-lived; must be hashed and rotated)
4. Active sessions (must be revocable)
5. Financial balances and transaction records

---

## Abuse Cases

Abuse cases describe concrete attack scenarios that inform the threat model. They are mapped to threats and mitigations below.

| ID | Abuse Case | Actor |
|----|-----------|-------|
| AC-01 | Attacker runs automated credential stuffing using a list of leaked email/password pairs | External attacker |
| AC-02 | Attacker performs brute force against a known account's password | External attacker |
| AC-03 | Attacker intercepts a refresh token and attempts to use it after the victim already refreshed | Token thief |
| AC-04 | Attacker captures an access token (e.g., from logs or browser storage) and uses it after the victim logs out | Token thief |
| AC-05 | Authenticated user modifies a request to reference another user's account ID | Malicious user |
| AC-06 | Authenticated user calls the admin endpoint after guessing the URL | Malicious user |
| AC-07 | Attacker initiates a large transfer on a compromised session, bypassing step-up by replaying a captured step-up token | Token thief |
| AC-08 | Attacker requests password reset for a victim's email to discover whether that email is registered | External attacker |
| AC-09 | Attacker sends an enormous number of requests to exhaust server resources or trigger cascading failures | External attacker |
| AC-10 | Attacker uses a forged or tampered JWT to claim a different user identity or elevated role | External attacker |
| AC-11 | Attacker initiates password reset to invalidate a victim's account access, then controls the recovery | External attacker |
| AC-12 | Attacker reuses a step-up token to authorize multiple transfers without re-verifying MFA | Token thief |

---

## STRIDE Threat Matrix

### Spoofing

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| S-01 | Identity spoofing via credential theft | Authentication | Credential stuffing using leaked databases (AC-01) | Account lockout (SR-05); rate limiting (SR-15); MFA required for enrolled users (SR-04) | SR-04, SR-05, SR-15 |
| S-02 | Identity spoofing via password brute force | Login endpoint | Automated password guessing (AC-02) | Account lockout after N failures (SR-05); IP-level rate limiting (SR-15); Nginx auth rate zone | SR-05, SR-15 |
| S-03 | Session spoofing via stolen access token | Any authenticated endpoint | Token captured from insecure storage or intercepted (AC-04) | Short-lived tokens (SR-06); token blacklisting on logout (SR-09); session validity check (SR-10) | SR-06, SR-09, SR-10 |
| S-04 | Session spoofing via stolen refresh token | /auth/refresh | Refresh token captured, used to obtain new access token (AC-03) | Refresh token rotation (SR-07); reuse detection triggers session revocation (SR-08) | SR-07, SR-08 |
| S-05 | JWT forgery (attacker creates own token) | Any authenticated endpoint | Attacker crafts a JWT with arbitrary claims (AC-10) | HS256 signature verification on every request; strong secret key (SR-06) | SR-06 |
| S-06 | JWT claim tampering (role elevation in token) | Admin endpoints | Attacker modifies role claim in JWT payload (AC-10) | JWT signature verification detects any modification; role validated server-side (SR-11) | SR-11 |

---

### Tampering

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| T-01 | Balance manipulation | Transfer endpoint | Attacker modifies transfer amount in transit (MITM) | HTTPS in production; Pydantic input validation rejects malformed requests (SR-20) | SR-20 |
| T-02 | Transfer to unauthorized account | Transfer endpoint | Authenticated user modifies destination account number (AC-05) | Account lookup is by account_number in DB; destination must be ACTIVE; no ownership bypass | SR-12, SR-20 |
| T-03 | Audit log tampering | Audit log DB | Attacker modifies or deletes audit log entries | Audit logs are INSERT-only in application logic; no DELETE or UPDATE operations permitted via API | SR-16 |
| T-04 | Token hash collision attack | Refresh token lookup | Attacker finds SHA-256 collision to use a different token | SHA-256 is collision-resistant for this purpose; not a practical attack | SR-07 |
| T-05 | Request body injection | All endpoints | Attacker injects malicious data in JSON fields | Pydantic strict type validation; parameterized SQL queries only (SR-20) | SR-20 |

---

### Repudiation

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| R-01 | User denies performing a transfer | Transaction records | User claims they did not initiate a transfer | Audit log records transfer initiation with user ID, IP, timestamp, session ID; JWT sub claim ties action to identity (SR-16) | SR-16 |
| R-02 | User denies login from a specific IP | Audit log | User denies accessing account from a location | Audit log captures IP address and user agent for every login event (SR-16) | SR-16 |
| R-03 | Admin denies performing account changes | Audit log | Admin denies deactivating a user | Admin actions recorded with actor's user ID, action, timestamp (SR-16) | SR-16 |

---

### Information Disclosure

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| I-01 | Password hash theft | PostgreSQL | Attacker reads the users table | Argon2id hashing; memory-hard and salted — reverse is computationally infeasible (SR-02) | SR-02 |
| I-02 | Access token interception | HTTP traffic | Attacker captures token from HTTP (non-TLS) | HTTPS enforced in production (HSTS header); short token TTL limits window (SR-06, SR-19) | SR-06, SR-19 |
| I-03 | Email enumeration via registration | /auth/register | Attacker discovers which emails are registered | Registration returns consistent error messages; no distinct "email exists" vs "invalid" responses | SR-18 |
| I-04 | Email enumeration via password reset | /auth/password/reset/request | Attacker probes which emails are registered (AC-08) | Password reset endpoint always returns success (SR-18) | SR-18 |
| I-05 | Cross-user data access | /accounts, /transactions | Authenticated user references another user's resource ID (AC-05, AC-06) | Resource ownership checks: all queries are scoped to current_user.id (SR-12) | SR-12 |
| I-06 | Sensitive data in JWT payload | JWT tokens | Attacker decodes JWT (base64) to read embedded claims | JWTs contain only: user ID, role, session ID. No PII, balances, or secrets embedded | SR-06 |
| I-07 | MFA secret exposure | Database / API | Attacker reads mfa_secret from database or API response | MFA secret is never returned in API responses after enrollment; stored in DB only | SR-04 |

---

### Denial of Service

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| D-01 | Login endpoint flooding | /auth/login | Attacker sends thousands of login requests per second (AC-09) | Nginx auth rate zone (10 req/min with burst); application-level IP rate limiter (SR-15) | SR-15 |
| D-02 | General API flooding | All endpoints | Attacker sends excessive API requests (AC-09) | Nginx general rate zone (60 req/min); application sliding window rate limiter (SR-15) | SR-15 |
| D-03 | Account lockout abuse (DoS against a user) | /auth/login | Attacker intentionally triggers lockout on a victim account using known username | Lockout duration is time-limited (not permanent); attacker must know the email; IP rate limiting limits speed of lockout | SR-05, SR-15 |
| D-04 | Redis resource exhaustion | Redis | Attacker generates enormous numbers of unique IPs to fill rate limit keys | Key TTL ensures automatic cleanup; rate limit counters expire after window | SR-15 |

---

### Elevation of Privilege

| # | Threat | Component | Attack Vector | Mitigation | SR Reference |
|---|--------|-----------|---------------|-----------|-------------|
| E-01 | Role escalation via JWT tampering | Admin endpoints | Attacker modifies role claim in JWT body (AC-10) | JWT signature verification; any tampering invalidates signature (SR-11) | SR-11 |
| E-02 | Horizontal privilege escalation | Account/transaction endpoints | Authenticated user accesses another user's resources by changing IDs (AC-05) | All resource queries scoped to current_user.id; ownership verified before returning data (SR-12) | SR-12 |
| E-03 | Step-up bypass for large transfer | /transactions/transfer | Attacker submits large transfer without step-up token (AC-07) | Step-up token required in X-Step-Up-Token header; absence returns 403 + security event (SR-13, SR-17) | SR-13, SR-17 |
| E-04 | Step-up token replay | /transactions/transfer | Attacker reuses a captured step-up token for additional transfers (AC-07, AC-12) | One-time use enforced via Redis flag; second use returns 403 (SR-14) | SR-14 |
| E-05 | Admin endpoint access by regular user | /admin/* | Regular user guesses admin endpoint URL (AC-06) | RBAC enforced via FastAPI dependency on every admin endpoint; user role returns 403 (SR-11) | SR-11 |
| E-06 | Session persistence after password change/reset | All authenticated endpoints | Attacker maintains session after victim changes password | Password reset revokes all active sessions and refresh tokens (SR-18); password change should prompt re-login | SR-18 |

---

## Threat-to-Security-Requirement Mapping

| SR | Threats Mitigated |
|----|------------------|
| SR-01 | S-01, S-02 |
| SR-02 | I-01 |
| SR-03 | S-01 |
| SR-04 | S-01, S-02 |
| SR-05 | S-01, S-02, D-03 |
| SR-06 | S-03, S-05, S-06, I-02, I-06 |
| SR-07 | S-04 |
| SR-08 | S-04 |
| SR-09 | S-03 |
| SR-10 | S-03, S-04, E-06 |
| SR-11 | S-06, E-01, E-05 |
| SR-12 | I-05, E-02 |
| SR-13 | E-03 |
| SR-14 | E-04 |
| SR-15 | S-01, S-02, D-01, D-02, D-03 |
| SR-16 | R-01, R-02, R-03 |
| SR-17 | S-01, E-03, S-04 |
| SR-18 | I-03, I-04, E-06 |
| SR-19 | I-02, T-01 |
| SR-20 | T-01, T-02, T-05 |

---

## Residual Risks

These risks are acknowledged but not fully mitigated within the project scope:

| Risk | Reason not fully mitigated | Recommended future mitigation |
|------|---------------------------|-------------------------------|
| TLS / HTTPS not enforced in development | Self-signed certs or Let's Encrypt require DNS setup outside thesis scope | Enforce HSTS; use Let's Encrypt in production |
| MFA secret stored unencrypted in DB | Application-level DB encryption adds significant complexity | Encrypt mfa_secret column at rest (e.g., using pgcrypto or application-level encryption) |
| TOTP replay within the 30-second window | TOTP codes are valid for 1 window (30s). An attacker who captures a code has 30s to use it | Track used TOTP codes in Redis for the current window (optional hardening) |
| No concurrent session limit | Post-MVP. A user can have many active sessions. | Implement per-user session count limit in Redis |
| Demo email delivery (console logging) | Reset tokens logged to console; not suitable for production | Integrate real SMTP (SendGrid, SES) or self-hosted mailserver |
| No anomaly detection for unusual login patterns | Time-based and geography-based anomaly detection require historical baselines | Future work: machine learning or rule-based anomaly scoring |
