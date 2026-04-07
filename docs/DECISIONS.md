# Architectural Decision Records

Each significant design decision is documented here using a lightweight ADR format. These records are intended to support thesis writing by demonstrating that design choices were deliberate, considered alternatives, and are grounded in security and academic requirements.

---

## ADR-01 — Monolith over Microservices

**Status:** Accepted

**Context:**  
The system needs to implement multiple security mechanisms (authentication, authorization, token management, audit logging, rate limiting, session management). These could be split into separate services (auth service, user service, transfer service, audit service), which is how production financial platforms are often structured. However, this is a bachelor thesis project, and the academic value is in the security mechanisms themselves, not in the deployment topology.

**Options considered:**

| Option | Pros | Cons |
|--------|------|------|
| Monolith (single FastAPI app with modules) | Low operational complexity; all security code visible in one place; easy to test, demo, and review | Does not demonstrate distributed system security patterns |
| Microservices | Demonstrates inter-service authentication (mTLS, service tokens) | Significantly increases infrastructure complexity; academic value does not justify overhead |

**Decision:** Monolith with clean internal module separation (`auth/`, `users/`, `accounts/`, `transactions/`, `admin/`).

**Rationale:** The thesis contribution is the security subsystem design and implementation, not the deployment architecture. Microservices would add complexity (Docker networking, inter-service auth, distributed tracing) that distracts from the security focus. The module structure inside the monolith provides a clear separation of concerns that is easy to evaluate.

**Consequences:** All security code is in one repository and easy to audit. If the project were extended to microservices, the auth module would become a standalone auth service with minimal changes.

---

## ADR-02 — FastAPI as the Backend Framework

**Status:** Accepted

**Context:**  
The backend framework shapes how authentication, authorization, and validation are implemented. It also affects how testable the security layer is.

**Options considered:**

| Option | Reason not selected |
|--------|---------------------|
| Django + DRF | Synchronous by default; ORM not async-native; adds abstractions not needed for this scope |
| Flask | Requires assembling many extensions; inconsistent async support; less ergonomic for dependency injection |
| FastAPI | Async-native; dependency injection system ideal for composable security checks; built-in OpenAPI; Pydantic validation |

**Decision:** FastAPI.

**Rationale:** FastAPI's `Depends()` system is central to the Zero Trust implementation. Each request passes through a chain of composable dependencies: `get_current_user → require_role → require_verified → require_step_up`. This makes the security verification layers explicit, testable, and easy to understand for thesis reviewers. The async support enables efficient handling of the multiple Redis and DB checks required per request.

**Consequences:** The security verification chain is implemented as FastAPI dependencies, making it auditable and easy to test in isolation.

---

## ADR-03 — TOTP over SMS/Email OTP for MFA

**Status:** Accepted

**Context:**  
Multi-factor authentication requires a second factor beyond a password. Several second-factor mechanisms exist. The choice affects security strength, implementation complexity, and dependency on external services.

**Options considered:**

| Option | Security | Implementation | External dependency |
|--------|---------|----------------|---------------------|
| TOTP (Time-based OTP, RFC 6238) | High — not vulnerable to SIM-swap or email compromise | Low — pyotp library, no external service | None |
| SMS OTP | Medium — vulnerable to SIM-swapping, SS7 attacks | Medium — requires SMS gateway (Twilio, etc.) | Yes — SMS provider |
| Email OTP | Medium — inherits email account security | Low — requires email delivery | Yes — SMTP server |
| FIDO2 / WebAuthn | Very high — phishing-resistant, hardware-bound | High — requires browser API integration, credential management | Browser |
| Push notifications | Medium-High — requires authenticator app server | High — requires third-party push infrastructure | Yes |

**Decision:** TOTP.

**Rationale:** TOTP provides a strong second factor without any dependency on external services, making it self-contained for a demo/academic environment. It is standardized (RFC 6238), widely understood, and supported by NIST SP 800-63B as an acceptable authenticator. FIDO2 would be the stronger choice for production but significantly increases frontend complexity for limited academic benefit. NIST has deprecated SMS OTP for high-assurance authentication, making it inappropriate for a security-focused thesis.

**Consequences:** Users need a TOTP authenticator app (Google Authenticator, Authy, etc.). TOTP is also used for step-up authentication, keeping the verification mechanism consistent across login and sensitive operations.

---

## ADR-04 — JWT (HS256) Access Tokens + Opaque Refresh Tokens

**Status:** Accepted

**Context:**  
The system needs to authenticate users on every API request without a full database lookup on each call. Several token strategies exist.

**Options considered:**

| Strategy | Pros | Cons |
|---------|------|------|
| JWT HS256 (symmetric) + opaque refresh | Self-contained; no DB lookup for access token validation; simple key management | Secret key must be kept secure; token cannot be invalidated without blacklisting |
| JWT RS256 (asymmetric) + opaque refresh | Public key distribution; suitable for microservices | Key management overhead; no practical benefit in a monolith |
| Opaque tokens only (server-side sessions) | Full revocation control; no JWT complexity | DB/Redis lookup required on every request |
| Session cookies only | Simple; browser handles storage | CSRF protection required; less suitable for REST API + SPA pattern |

**Decision:** JWT HS256 for access tokens + opaque tokens (SHA-256 hashed) for refresh tokens.

**Rationale:** JWT access tokens allow stateless verification of identity and role without a database roundtrip. The 15-minute TTL limits the exposure window. Opaque refresh tokens are stored hashed in the database and tracked in Redis, allowing full revocation control for the long-lived credential. The combination gives the best of both: low latency for access token checks, full revocation capability via the session and refresh token mechanisms. RS256 would be the correct choice for a distributed system but adds no practical security benefit in a monolith.

**Consequences:** Access tokens require blacklisting on revocation (stored in Redis for remaining TTL). This is an intentional Zero Trust design: every valid-looking token is still checked against the blacklist and session store.

---

## ADR-05 — Session Validity Stored in Redis

**Status:** Accepted

**Context:**  
JWT access tokens are cryptographically self-validating. This means a token remains technically valid until its expiry even after logout. To implement true session revocation (Zero Trust requirement), a server-side session record is needed.

**Options considered:**

| Option | Revocation speed | Latency impact |
|--------|----------------|----------------|
| Redis session key per session_id | Immediate (delete key → all requests fail) | ~1ms per request (Redis in-memory) |
| Database session table | Immediate | ~5–20ms per request (DB query) |
| No server-side session (pure JWT) | Delayed (wait for token expiry) | None |

**Decision:** Redis session key per session_id.

**Rationale:** Zero Trust requires that sessions can be revoked immediately — not at token expiry. Redis provides sub-millisecond lookups suitable for a check that runs on every authenticated request. The session key is a simple string key with a TTL matching the refresh token lifetime. Deleting the key immediately invalidates all tokens for that session, even if the access token is still cryptographically valid. This is the key mechanism that distinguishes a Zero Trust implementation from a naive JWT implementation.

**Consequences:** Every authenticated request makes one additional Redis call. This is acceptable given Redis's in-memory speed. If Redis is unavailable, all authenticated requests fail — this is an intentional fail-secure design.

---

## ADR-06 — Refresh Token Rotation with Reuse Detection

**Status:** Accepted

**Context:**  
Refresh tokens are long-lived (7 days) and can be used to maintain persistent authentication. If a refresh token is stolen, the attacker can use it to keep generating access tokens indefinitely.

**Options considered:**

| Strategy | Theft detection | Complexity |
|---------|----------------|------------|
| Single refresh token (no rotation) | No — stolen token valid for full TTL | Low |
| Rotation (new token on each use, old revoked) | Partial — stolen token invalid after victim refreshes | Medium |
| Rotation + reuse detection (revoked token reuse triggers session revocation) | Yes — reuse is detected and session is killed | Medium-High |

**Decision:** Rotation with reuse detection.

**Rationale:** Rotation alone limits the attack window to the interval between the victim's refresh calls, but does not detect or respond to theft. Reuse detection adds a critical property: if a revoked token is presented again, this indicates that either the legitimate user or an attacker is using a leaked token. The safe response is to invalidate the entire session, forcing both parties to re-authenticate. This is the approach recommended by RFC 6749 and security practitioners for high-assurance systems. The CRITICAL severity security event provides visibility into the incident.

**Consequences:** Each refresh operation involves a DB read (verify old token), a DB write (revoke old, insert new), and a Redis write (update session TTL). This is acceptable for a low-frequency operation.

---

## ADR-07 — Step-up Authentication for Sensitive Transfers

**Status:** Accepted

**Context:**  
A valid session proves that the user authenticated at some point in the past — possibly hours or days ago. For high-value operations (large transfers), this is not sufficient. An attacker who has hijacked a session should not be able to immediately execute a large transfer.

**Options considered:**

| Option | Security | UX impact |
|--------|---------|-----------|
| No step-up — session token is sufficient | Low | None |
| Require password re-entry | Medium | Disruptive |
| Require TOTP re-verification (step-up) | High — proves user has physical access to authenticator at time of operation | Acceptable — user opens authenticator app |
| Threshold-based step-up (only for large amounts) | High — applies friction where it matters most | Minimal — most transfers unaffected |

**Decision:** Threshold-based TOTP step-up authentication. Transfers at or above a configurable threshold require a valid step-up token issued by `/auth/step-up` after TOTP re-verification. Step-up tokens are one-time use and 5-minute TTL.

**Rationale:** Step-up authentication is a core Zero Trust principle: high-risk operations require additional, just-in-time verification beyond session state. TOTP re-verification proves the user has physical access to their authenticator at the time of the operation. The threshold configuration avoids degrading UX for small, low-risk transfers while ensuring that large transfers are always explicitly re-authorized. One-time use prevents token replay attacks.

**Consequences:** Transfers above threshold require an extra API call to `/auth/step-up` and an additional header in the transfer request. The frontend must implement a step-up modal. This is the most complex security feature in the system and the most academically interesting.

---

## ADR-08 — PostgreSQL as the Primary Database

**Status:** Accepted

**Context:**  
The system stores users, accounts, transactions, refresh tokens, audit logs, and security events. Data integrity is critical, especially for financial operations.

**Decision:** PostgreSQL 15.

**Rationale:** ACID compliance is mandatory for financial operations (transfer must debit and credit atomically). PostgreSQL provides native JSONB support for flexible audit log `details` fields without schema migrations for every new event type. It is the most widely used open-source relational database with strong Python (SQLAlchemy, asyncpg) support. SQLite is used in tests only for speed.

**Consequences:** PostgreSQL requires a running container but is well-supported in Docker Compose. Alembic manages schema migrations.

---

## ADR-09 — RBAC + Contextual Checks (not RBAC alone)

**Status:** Accepted

**Context:**  
Role-Based Access Control (RBAC) alone is insufficient for a Zero Trust system. RBAC answers the question "does this role have permission for this action?" but does not answer "does this user own this resource?" or "is this session still active?"

**Decision:** Layered access control: RBAC + resource ownership + session validity + email verification + (for sensitive operations) step-up token.

**Rationale:** Zero Trust requires that access decisions incorporate all available context. A user with the `user` role might have permission to view accounts in general, but must only see their own account specifically. A valid access token for a role is necessary but not sufficient — the session must be active, the user must not be locked, and for sensitive operations, a fresh MFA verification must have occurred. This layered approach reflects NIST SP 800-207 Zero Trust guidance.

**Consequences:** Every endpoint requires careful specification of which dependency combination to use. The dependency chain is: `get_current_user` (token + blacklist + session + user state) → `require_role` (RBAC) → `require_verified` (email verified) → resource ownership (in service layer query) → `require_step_up` (if applicable).

---

## ADR-10 — React (Minimal) for the Frontend

**Status:** Accepted

**Context:**  
The frontend must exist to demonstrate the security flows in a browser context. However, the frontend is not an academic contribution — the security subsystem is.

**Decision:** Minimal React SPA with TypeScript. Only the pages required to demonstrate the security flows: login, MFA setup, MFA verify, dashboard, step-up modal.

**Rationale:** React is the most widely recognized frontend framework, making the demo accessible to thesis reviewers. TypeScript prevents trivial integration errors. The scope is deliberately minimal to avoid frontend development consuming time that should be spent on backend security. The frontend exists to make the backend observable, not to be evaluated itself.

**Consequences:** No advanced frontend patterns, state management libraries, or UI component frameworks beyond what is needed to demonstrate the security flows. Admin frontend is post-MVP; the admin API is sufficient for the thesis.

---

## ADR-11 — Argon2id for Password Hashing

**Status:** Accepted

**Context:**  
Passwords must be stored in a way that is computationally infeasible to reverse, even with large-scale GPU or ASIC attacks.

**Options considered:**

| Algorithm | Resistance to GPU/ASIC | Recommended by |
|-----------|----------------------|----------------|
| MD5 / SHA-1 | None | Deprecated |
| bcrypt | Good (memory-intensive) | OWASP, widely used |
| scrypt | Good (memory + CPU intensive) | OWASP |
| Argon2id | Excellent (memory-hard, GPU-resistant, side-channel resistant) | OWASP, Password Hashing Competition winner |
| PBKDF2 | Moderate | FIPS-compliant environments |

**Decision:** Argon2id via `passlib[argon2]` + `argon2-cffi`.

**Rationale:** Argon2id is the current OWASP recommendation and the winner of the Password Hashing Competition. It is memory-hard (limits parallel GPU attacks), CPU-intensive (limits ASIC attacks), and provides side-channel resistance. For a security thesis, using the best available algorithm is the correct choice and is academically defensible.

**Consequences:** Argon2 hashing is slower than MD5/SHA (intentionally), which is acceptable for a login operation. The `passlib` library handles parameter selection and salt generation automatically.

---

## ADR-12 — Audit Log as Append-only Application Record

**Status:** Accepted

**Context:**  
Audit logs must support non-repudiation: they must record that an event occurred and cannot be modified retroactively by the application. The question is how to enforce this.

**Options considered:**

| Approach | Tamper resistance | Complexity |
|---------|-----------------|------------|
| Database table with full CRUD via API | None — anyone with API access can delete | Low |
| INSERT-only in application logic (no UPDATE/DELETE endpoints) | Application-level: prevents accidental deletion; does not prevent DB-level tampering | Low |
| Append-only DB table enforced via PostgreSQL policy or trigger | DB-level: prevents modification via SQL as well | Medium |
| External immutable log store (WORM storage, log shipping) | High | High |

**Decision:** INSERT-only in application logic. The API provides no DELETE or UPDATE endpoint for audit logs. The admin API provides read-only access only.

**Rationale:** For the thesis scope, enforcing append-only behavior at the application level is sufficient to demonstrate the principle and is academically valid. Production systems would additionally use database-level append-only policies and ship logs to an immutable external store. This is documented as a residual risk and recommended as a production enhancement.

**Consequences:** Audit logs grow indefinitely (no cleanup mechanism). For a demo system, this is acceptable. A production system would implement log archiving with integrity verification.

---

## ADR-13 — Backend Toolchain: Poetry + Ruff + pytest

**Status:** Accepted

**Context:**  
The backend needs a dependency manager, a linting/style tool, and a test runner. Multiple combinations are common in the Python ecosystem (pip + requirements.txt, pip-tools, Poetry, PDM; flake8 + isort + Black + pylint; Ruff). Choosing overlapping or redundant tools adds friction without value.

**Options considered:**

| Concern | Option A | Option B (chosen) |
|---------|---------|-------------------|
| Dependency management | `pip` + `requirements.txt` | **Poetry** |
| Linting | `flake8` + `pylint` | **Ruff** |
| Import ordering | `isort` (separate tool) | **Ruff** (`I` rule set) |
| Formatting | `Black` (separate tool) | **Ruff** (`ruff format`) |
| Testing | `pytest` | **pytest** |

**Decision:** Poetry for dependency management; Ruff as the single linting, import ordering, and style tool; pytest as the test runner.

**Rationale:**

- **Poetry** provides reproducible installs via `poetry.lock`, integrated virtual environment management, and a single `pyproject.toml` as the source of truth for all project metadata and dependencies. `pip` + `requirements.txt` requires manual version pinning and separate tooling to achieve equivalent reproducibility.

- **Ruff** replaces flake8, isort, pylint, and Black in a single fast tool. It is significantly faster than running multiple tools in sequence, covers the same rule sets, and avoids the need to keep multiple tool configurations in sync. For a project where linting should be a low-friction habit rather than a slow pipeline step, a single tool is strongly preferable. The `S` (Bandit) rule set in Ruff is directly relevant to security — it flags common insecure patterns at lint time.

- **pytest** is the standard Python testing framework. No alternative was seriously considered.

**Consequences:** The toolchain is minimal: three tools, all configured in `pyproject.toml`. No Black, no isort, no flake8. If Ruff's formatter is not used, `ruff format` is still available as a convenience. Adding Black or isort at a later stage would conflict with Ruff and is not permitted by the project standards.

---

## ADR-14 — Frontend Toolchain: npm + ESLint + Prettier + TypeScript Strict

**Status:** Accepted

**Context:**  
The frontend is minimal and not the academic focus. The toolchain should be standard enough to be immediately familiar, low-friction to set up, and enforce the TypeScript type safety needed for the security-relevant frontend code (token handling, API client, auth state).

**Options considered:**

| Concern | Alternatives | Chosen |
|---------|-------------|--------|
| Package manager | Yarn, pnpm | **npm** |
| Linting | Biome, oxlint | **ESLint + @typescript-eslint** |
| Formatting | Biome | **Prettier** |
| TypeScript config | Standard / loose | **Strict mode** |

**Decision:** npm + ESLint + Prettier + TypeScript strict mode.

**Rationale:**

- **npm** is bundled with Node.js, requires no additional installation, and is universally understood. Yarn and pnpm offer marginal performance improvements that are irrelevant for a frontend of this scope.

- **ESLint + Prettier** is the most widely adopted combination for TypeScript React projects. The split is intentional: ESLint enforces code correctness and type-aware rules; Prettier enforces formatting without overlap. This is a well-understood separation that avoids configuration conflicts.

- **TypeScript strict mode** (`"strict": true`) is required because the most security-relevant frontend code — token storage, API request interceptors, auth state — must be fully type-checked. Loose TypeScript would allow `any` types in exactly the places where type safety matters most.

- **Alternatives like Biome** were considered but rejected. Biome is a capable combined tool, but ESLint + Prettier is more mature, has broader plugin support (especially for `@typescript-eslint`), and is more likely to be familiar to thesis reviewers.

**Consequences:** Two separate frontend config files (`eslint.config.js`, `.prettierrc`) must be maintained and kept non-conflicting. This is a standard, well-documented setup. The `eslint-config-prettier` package disables ESLint formatting rules that would conflict with Prettier.
