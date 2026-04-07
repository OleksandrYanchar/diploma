# Technology Stack

This document describes all chosen technologies, the security-relevant properties of each, the versions used, and the alternatives that were considered and rejected with reasoning.

---

## Stack Overview

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend framework | FastAPI | 0.111.x |
| Language | Python | 3.12 |
| ASGI server | Uvicorn | 0.29.x |
| Database ORM | SQLAlchemy (async) | 2.0.x |
| Database migrations | Alembic | 1.13.x |
| Primary database | PostgreSQL | 15 |
| Session / cache store | Redis | 7 |
| Password hashing | Argon2 (via passlib) | argon2-cffi 23.x |
| JWT | python-jose | 3.3.x |
| MFA | pyotp | 2.9.x |
| QR code generation | qrcode + Pillow | 7.4.x / 10.x |
| Data validation | Pydantic v2 | 2.7.x |
| Settings management | pydantic-settings | 2.2.x |
| Frontend framework | React | 18.x |
| Frontend language | TypeScript | 5.x |
| HTTP client (frontend) | Axios | 1.6.x |
| Reverse proxy | Nginx | 1.25 |
| Containerization | Docker + Docker Compose | latest stable |
| Dependency management | Poetry | 1.8.x |
| Linting + style | Ruff | 0.4.x |
| Testing | pytest + pytest-asyncio | 8.x / 0.23.x |
| Test HTTP client | HTTPX | 0.27.x |
| Test Redis | fakeredis | 2.23.x |
| Test database | SQLite (aiosqlite) | 0.20.x |
| Frontend package manager | npm | 10.x (bundled with Node 20) |
| Frontend linting | ESLint + @typescript-eslint | 8.x / 7.x |
| Frontend formatting | Prettier | 3.x |

---

## Backend Framework: FastAPI

### Why FastAPI

- **Native async support** — Full async/await support allows non-blocking I/O for database and Redis operations, which is important for a platform where multiple security checks run per request.
- **Dependency injection** — FastAPI's `Depends()` system is used to implement Zero Trust verification as composable, reusable dependencies (token validation, session check, RBAC, ownership check). This makes the security layer explicit and testable.
- **Automatic OpenAPI documentation** — Useful for documenting the security surface area of the API during development. Can be disabled in production.
- **Pydantic integration** — Request and response validation is handled by Pydantic v2, which enforces input sanitization at the framework level.
- **Pythonic and readable** — Reduces cognitive overhead when reviewing security logic; the auth flow is easy to trace.

### Alternatives considered

| Alternative | Reason not selected |
|------------|---------------------|
| **Django + DRF** | Django is a full-stack framework with many built-in abstractions that are not needed here. Its ORM and request handling are synchronous by default, which requires extra configuration for async. The thesis focus is on security mechanisms, not framework features. DRF adds boilerplate without equivalent benefit for this use case. |
| **Flask** | Flask requires assembling many third-party extensions (Flask-JWT-Extended, Flask-Limiter, Flask-SQLAlchemy) with inconsistent async support. FastAPI provides a more coherent async-native base. |
| **Litestar** | A modern async framework similar to FastAPI. Technically sound but has a smaller ecosystem and community. FastAPI is more established and easier to evaluate for academic reviewers. |

---

## MFA Approach: TOTP (Time-based One-Time Password)

### Why TOTP

- **RFC 6238 standard** — TOTP is a well-documented, widely implemented standard, making it academically defensible and easy to justify.
- **No server-side secret transmission** — After initial QR code enrollment, the server never sends the TOTP secret again. The shared secret is stored server-side (encrypted at rest in production) and in the authenticator app only.
- **No dependency on external services** — TOTP works offline and requires no SMS gateway or email delivery for the second factor. This eliminates a class of SIM-swapping and email interception attacks and simplifies the demo setup.
- **Widely supported** — Works with Google Authenticator, Authy, Microsoft Authenticator, and any RFC 6238-compatible app.
- **Suitable for step-up** — TOTP is used both at login and as the step-up verification mechanism, keeping the security model consistent.

### Alternatives considered

| Alternative | Reason not selected |
|------------|---------------------|
| **SMS OTP** | SMS is vulnerable to SIM-swapping attacks and SS7 protocol weaknesses. NIST SP 800-63B has deprecated SMS OTP for high-assurance authentication. Not appropriate for a Zero Trust security thesis. |
| **Email OTP** | Shares the attack surface of the user's email account. If the email account is compromised, the second factor is also compromised. Lower assurance than TOTP. |
| **FIDO2 / WebAuthn** | Hardware security keys or platform authenticators (Face ID, Windows Hello) provide the strongest second factor available. However, WebAuthn requires browser integration, credential management, and a more complex enrollment flow. The thesis focus is on demonstrating Zero Trust principles, not on frontend UX depth. TOTP was selected for its simplicity of demonstration while remaining cryptographically strong. WebAuthn is noted as a production-grade enhancement. |
| **Push notifications (Duo-style)** | Requires a third-party service or significant custom infrastructure. Out of scope for an academic project. |

---

## Token Strategy: JWT (Access) + Opaque Refresh Tokens

### Why this combination

**Access tokens (JWT):**
- Self-contained: the server can validate a token without a database lookup on every request, enabling stateless verification of identity and role.
- Short-lived (15 minutes): limits the window of exposure if a token is stolen.
- Contain only what is needed: user ID, role, session ID. No sensitive data embedded in the token.
- Signed with HS256 using a strong server-side secret.

**Refresh tokens (opaque, stored hashed):**
- Long-lived (7 days) but never sent in API requests — only used at the refresh endpoint.
- Stored in the database as a SHA-256 hash; the raw token is never persisted.
- Bound to a session ID, device fingerprint, and IP address for contextual validation.
- Rotation on every use: a new refresh token is issued and the old one is immediately revoked, preventing silent token theft.
- Reuse detection: if a revoked token is presented again, the entire session is invalidated and a CRITICAL security event is recorded.

**Session tracking (Redis):**
- A session record in Redis is the authoritative source of session validity.
- Deleting the session key immediately invalidates all tokens for that session, regardless of token TTL.
- This is the key Zero Trust mechanism: token validity alone is not sufficient; session must also be active.

### Alternatives considered

| Alternative | Reason not selected |
|------------|---------------------|
| **RS256 (asymmetric JWT signing)** | RS256 allows token verification without access to the signing key, which is valuable in microservice architectures where services verify tokens independently. In a monolith, this benefit does not apply. HS256 with a strong secret is cryptographically equivalent for this architecture. RS256 is noted as the correct choice for a distributed production system. |
| **Opaque access tokens** | Would require a database or Redis lookup on every request to resolve the token. Higher latency, more infrastructure dependency. JWT allows in-memory verification with only a Redis blacklist check for revoked tokens. |
| **Session cookies only** | Cookie-based sessions are a valid approach but are less suitable for a REST API consumed by a frontend SPA. CSRF protection becomes necessary. JWT with Authorization header avoids this class of issues. |
| **Short-lived access tokens without refresh** | Acceptable but forces re-login every 15 minutes. Unusable UX. The refresh token mechanism maintains session continuity while keeping the access token window short. |

---

## Primary Database: PostgreSQL

### Why PostgreSQL

- **ACID compliance** — Critical for financial operations (transfers, balance updates). Transactions ensure consistency even under failure.
- **JSONB support** — Audit log `details` field and security event `details` field use JSONB for flexible structured data without schema changes.
- **Mature ecosystem** — Well-supported by SQLAlchemy, Alembic, and asyncpg for async access.
- **Row-level locking** — Available for balance updates to prevent race conditions in concurrent transfers.

### Alternatives considered

| Alternative | Reason not selected |
|------------|---------------------|
| **MySQL / MariaDB** | Comparable features, but PostgreSQL has stronger JSONB support and is generally preferred in Python ecosystems. No functional reason to choose MySQL here. |
| **SQLite** | Used in testing only. Not suitable for production due to lack of true concurrency and limited data types. |
| **MongoDB** | Document databases are not well-suited for relational financial data (accounts, transactions, ownership). ACID guarantees require extra coordination. Not appropriate for this domain. |

---

## Session / Cache Store: Redis

### Why Redis

- **In-memory speed** — Session validity checks happen on every authenticated request. An in-memory store is essential to avoid database load on every check.
- **TTL support** — Refresh token entries, session keys, blacklisted access tokens, rate limit counters, and step-up token usage flags all expire automatically using Redis TTL. No cleanup jobs needed.
- **Atomic operations** — Lua scripts and pipeline commands allow atomic sliding-window rate limit counters without race conditions.
- **Pub/sub capability** — Available for future security event streaming (post-MVP).

### Alternatives considered

| Alternative | Reason not selected |
|------------|---------------------|
| **Database-only sessions** | Every request would require a DB query to validate session state. Unacceptable latency for a security check that runs on every authenticated endpoint. |
| **Memcached** | No TTL-per-key granularity for sorted sets (needed for sliding window rate limiting). No persistence option. Redis is strictly more capable here. |
| **In-process memory (application state)** | Would not work across multiple worker processes (Uvicorn with multiple workers). Not viable for a production-like setup. |

---

## Frontend: React + TypeScript

### Why React (minimal)

The frontend is intentionally minimal and is **not** an academic contribution. React was selected because:
- It is the most widely known frontend framework, making the demo accessible to thesis reviewers.
- TypeScript provides type safety when calling the backend API, reducing integration errors.
- The security flows (MFA setup, step-up modal, token refresh logic) are straightforward to implement in React without framework-specific complexity.

React is not the subject of academic evaluation. The frontend exists to make the backend security flows observable in a browser.

### Frontend is not the focus

If frontend implementation adds significant overhead without adding security value, it will be reduced to a minimal API client demo. Backend security mechanisms are the primary deliverable.

---

## Backend Toolchain

### Dependency and package management: Poetry

Poetry is used as the single tool for managing Python dependencies, virtual environments, and package metadata. All dependencies (including dev/test dependencies) are declared in `pyproject.toml` and locked in `poetry.lock`.

- `poetry install` reproduces the exact environment.
- `poetry add <pkg>` adds a runtime dependency.
- `poetry add --group dev <pkg>` adds a development or test dependency.
- The `poetry.lock` file must be committed to the repository.

**Alternative considered:** `pip` + `requirements.txt`. Rejected because it requires manual version pinning and separate tooling (`pip-tools`) to get reproducible installs. Poetry provides dependency resolution, environment management, and lock file generation in a single tool.

### Linting and style: Ruff

Ruff is the sole linting and style enforcement tool for Python. It covers:

- **Style and error rules** — PEP 8 compliance, unused imports, undefined names (replaces flake8).
- **Import ordering** — Enforces consistent import grouping and ordering (replaces isort, enabled via the `I` rule set).
- **Security-relevant rules** — The `S` (Bandit) rule set flags common security anti-patterns (e.g., hardcoded passwords, use of `assert` in security logic, unsafe `subprocess` usage).
- **General code quality** — The `B` (flake8-bugbear) rule set catches likely bugs and poor practices.

Ruff is configured in `pyproject.toml` under `[tool.ruff]`. Black is **not used** — Ruff's formatter (`ruff format`) handles formatting if needed, avoiding the need for a separate tool.

Enabled rule sets: `E`, `F`, `I`, `N`, `S`, `B`.

Run before committing:
```
ruff check backend/
ruff format --check backend/
```

### Testing: pytest

See the Testing Stack section below and `TEST_STRATEGY.md` for full details.

---

## Frontend Toolchain

### Package manager: npm

npm (bundled with Node.js 20) is used as the frontend package manager. No additional package manager (Yarn, pnpm) is needed. `package-lock.json` must be committed.

### Linting: ESLint

ESLint with `@typescript-eslint` enforces code quality and type-aware linting rules. TypeScript strict mode is enabled in `tsconfig.json` (`"strict": true`). ESLint configuration is committed in `eslint.config.js` (flat config format).

### Formatting: Prettier

Prettier handles all frontend code formatting (TypeScript, TSX, JSON, CSS). Prettier and ESLint are configured to not conflict — ESLint handles code quality rules, Prettier handles formatting only. Configuration in `.prettierrc`.

Run before committing frontend changes:
```
npm run lint
npm run format:check
```

---

## Containerization: Docker + Docker Compose

### Why Docker Compose

- Reproducible development environment for all services (backend, frontend, PostgreSQL, Redis, Nginx).
- Services communicate over an isolated internal network; only Nginx is exposed on port 80.
- Simplifies thesis demonstration: `docker compose up` starts the full system.

---

## Testing Stack

| Tool | Purpose |
|------|---------|
| **pytest** | Test runner. Standard Python testing framework. |
| **pytest-asyncio** | Async test support for FastAPI async endpoints. |
| **HTTPX** | Async HTTP client for integration tests against the FastAPI app. |
| **fakeredis** | In-memory Redis mock for tests. Eliminates Redis dependency in the test suite. |
| **aiosqlite + SQLite** | In-memory database for tests. Each test function gets a fresh schema. |

Tests run against the real application code with mocked infrastructure (Redis, DB). This tests the security logic directly without requiring running containers.
