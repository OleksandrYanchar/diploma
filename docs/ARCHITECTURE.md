# Architecture

---

## System Overview

```
                         ┌─────────────────────────────────────────┐
                         │             PUBLIC INTERNET              │
                         └───────────────────┬─────────────────────┘
                                             │ HTTP :80
                         ┌───────────────────▼─────────────────────┐
                         │                 NGINX                   │
                         │  - TLS termination (production)         │
                         │  - Rate limiting (auth endpoints)       │
                         │  - Security headers                     │
                         │  - Reverse proxy                        │
                         └──────────┬───────────────┬──────────────┘
                                    │               │
                         /api/*     │               │  /*
                         ┌──────────▼──────┐  ┌────▼──────────────┐
                         │   FastAPI       │  │  React SPA        │
                         │   Backend       │  │  (static files)   │
                         │                 │  └───────────────────┘
                         │  ┌───────────┐  │
                         │  │ Auth      │  │
                         │  │ Users     │  │
                         │  │ Accounts  │  │
                         │  │ Transfers │  │
                         │  │ Admin     │  │
                         │  │ Security  │  │
                         │  └───────────┘  │
                         └────┬───────┬────┘
                              │       │
              ┌───────────────▼──┐  ┌─▼────────────────┐
              │   PostgreSQL     │  │      Redis        │
              │                  │  │                   │
              │  - Users         │  │  - Sessions       │
              │  - Accounts      │  │  - Token          │
              │  - Transactions  │  │    blacklist      │
              │  - Refresh       │  │  - Rate limit     │
              │    tokens        │  │    counters       │
              │  - Audit logs    │  │  - Step-up token  │
              │  - Security      │  │    usage flags    │
              │    events        │  └───────────────────┘
              └──────────────────┘
```

All backend services communicate over an isolated Docker internal network. Only Nginx is exposed externally.

---

## Trust Boundaries

### Boundary 1: Public Internet → Nginx

**What crosses it:** All HTTP requests from browsers and API clients.

**Controls at this boundary:**
- Rate limiting per IP on auth endpoints (`limit_req` zones in Nginx)
- Security headers injected on all responses (CSP, X-Frame-Options, HSTS in production)
- No trust is assumed for any incoming request

**What is NOT trusted:** Any header that could be injected by a client (e.g., `X-Forwarded-For` is read but treated as untrusted input from this boundary).

---

### Boundary 2: Nginx → FastAPI Backend

**What crosses it:** Proxied HTTP requests with added `X-Real-IP` and `X-Forwarded-For` headers set by Nginx.

**Controls at this boundary:**
- JWT verification on every authenticated request
- Token blacklist check in Redis
- Session validity check in Redis
- User state check in PostgreSQL (active, not locked)
- RBAC enforcement via FastAPI dependency injection

**Trust level:** Nginx is trusted infrastructure. The backend trusts `X-Real-IP` as the client IP because Nginx is the only entry point.

---

### Boundary 3: FastAPI Backend → PostgreSQL / Redis

**What crosses it:** SQL queries via SQLAlchemy (parameterized), Redis commands via redis-py.

**Controls at this boundary:**
- All queries are parameterized (no raw SQL string interpolation)
- Redis connection is password-authenticated
- PostgreSQL connection is password-authenticated
- Both services are on the internal Docker network only; no public exposure

**Trust level:** Both are trusted infrastructure components within the internal network.

---

## Main Assets

| Asset | Sensitivity | Storage | Protection |
|-------|------------|---------|-----------|
| User passwords | Critical | PostgreSQL (Argon2 hash only) | Never stored in plaintext; memory-hard hashing |
| MFA secrets (TOTP) | Critical | PostgreSQL | Should be encrypted at rest in production |
| Refresh tokens | High | PostgreSQL (SHA-256 hash only) + Redis session | Raw token never persisted; rotation on every use |
| Access tokens | High | Client-side only | Short TTL (15 min); blacklist on revocation |
| Step-up tokens | High | Client-side only; usage flag in Redis | One-time use; 5-min TTL |
| Password reset tokens | High | PostgreSQL (SHA-256 hash); TTL 30 min | Raw token delivered out-of-band; expires quickly |
| Financial balances | High | PostgreSQL | ACID transactions; ownership enforced |
| Transaction records | High | PostgreSQL | Ownership enforced; immutable once completed |
| Audit logs | Medium | PostgreSQL | Append-only; accessible by admin/auditor only |
| Security events | Medium | PostgreSQL | Accessible by admin/auditor only |
| PII (email, name) | Medium | PostgreSQL | Access controlled by RBAC + ownership |

---

## Backend Module Structure

```
app/
├── core/
│   ├── config.py          # Environment-based settings (pydantic-settings)
│   ├── database.py        # Async SQLAlchemy engine and session factory
│   ├── redis.py           # Redis client singleton
│   ├── security.py        # Hashing, JWT creation/decoding, token generation
│   └── middleware.py      # Rate limit middleware, security headers middleware
│
├── models/                # SQLAlchemy ORM models
│   ├── user.py            # User, UserRole enum
│   ├── account.py         # Account, AccountStatus enum
│   ├── transaction.py     # Transaction, TransactionStatus enum
│   ├── token.py           # RefreshToken
│   ├── audit_log.py       # AuditLog, AuditAction enum, AuditStatus enum
│   └── security_event.py  # SecurityEvent, EventType enum, Severity enum
│
├── schemas/               # Pydantic v2 request/response schemas
│   ├── auth.py
│   ├── user.py
│   ├── account.py
│   ├── transaction.py
│   ├── audit_log.py
│   └── security_event.py
│
├── dependencies/
│   └── auth.py            # get_current_user, require_role, require_verified,
│                          # require_step_up — Zero Trust verification chain
│
├── auth/
│   ├── router.py          # /auth/* endpoints
│   └── service.py         # Business logic: login, register, MFA, tokens, password reset
│
├── users/
│   ├── router.py          # /users/* endpoints (profile)
│   └── service.py
│
├── accounts/
│   ├── router.py          # /accounts/* endpoints
│   └── service.py
│
├── transactions/
│   ├── router.py          # /transactions/* endpoints
│   └── service.py         # Transfer logic + step-up check
│
├── admin/
│   ├── router.py          # /admin/* endpoints
│   └── service.py         # User management, audit log/security event queries
│
└── main.py                # FastAPI app setup, middleware registration, router inclusion
```

---

## Zero Trust Verification Layers

Every authenticated request passes through these verification layers in order:

```
Incoming request
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Token Presence                                │
│  Is an Authorization: Bearer <token> header present?   │
│  → No: 401 Unauthorized                                 │
└───────────────────────────┬─────────────────────────────┘
                            │ Yes
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2: Token Signature + Claims                      │
│  Is the JWT signature valid? Is it not expired?         │
│  Does it have the expected type ("access")?             │
│  → Invalid: 401 Unauthorized                            │
└───────────────────────────┬─────────────────────────────┘
                            │ Valid
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Token Blacklist (Redis)                       │
│  Has this token been explicitly revoked (logout)?       │
│  → Blacklisted: 401 Unauthorized                        │
└───────────────────────────┬─────────────────────────────┘
                            │ Not blacklisted
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Session Validity (Redis)                      │
│  Does the session_id from the token have an active      │
│  session record in Redis?                               │
│  → No session: 401 Unauthorized (session expired/       │
│    invalidated by logout or password reset)             │
└───────────────────────────┬─────────────────────────────┘
                            │ Active session
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 5: User State (PostgreSQL)                       │
│  Does the user exist? Is is_active = true?              │
│  Is locked_until in the past (not currently locked)?    │
│  → Deactivated or locked: 403 Forbidden                 │
└───────────────────────────┬─────────────────────────────┘
                            │ User is valid
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 6: Role (RBAC)                                   │
│  Does the user's role permit access to this endpoint?   │
│  → Wrong role: 403 Forbidden                            │
└───────────────────────────┬─────────────────────────────┘
                            │ Role permitted
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 7: Resource Ownership                            │
│  Does the requested resource belong to this user?       │
│  (e.g., is this account.user_id == current_user.id?)    │
│  → Not owner: 403 Forbidden or 404 Not Found            │
└───────────────────────────┬─────────────────────────────┘
                            │ Owner confirmed
                            ▼
                    Request processed
```

For sensitive operations (transfers above threshold), an additional layer applies:

```
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 8: Step-up Token (sensitive operations only)     │
│  Is a valid X-Step-Up-Token header present?             │
│  Is the step-up token not expired (5 min)?              │
│  Is the step-up token's sub claim = current user?       │
│  Has this step-up token already been used (Redis)?      │
│  → Missing/invalid/used: 403 Forbidden                  │
│    + X-Step-Up-Required: true header                    │
└───────────────────────────┬─────────────────────────────┘
                            │ Step-up valid and unused
                            ▼
                   Step-up token marked used in Redis
                            │
                            ▼
                    Transfer processed
```

---

## Key Data Flows

### Standard Login Flow (with MFA)

```
Client                     Nginx              FastAPI              PostgreSQL    Redis
  │                          │                   │                     │           │
  │  POST /api/v1/auth/login │                   │                     │           │
  │─────────────────────────►│                   │                     │           │
  │                          │ rate-limit check  │                     │           │
  │                          │──────────────────►│                     │           │
  │                          │                   │  SELECT user        │           │
  │                          │                   │  WHERE email=...    │           │
  │                          │                   │────────────────────►│           │
  │                          │                   │◄────────────────────│           │
  │                          │                   │  verify Argon2      │           │
  │                          │                   │  check locked       │           │
  │                          │                   │  verify TOTP        │           │
  │                          │                   │  create session     │           │
  │                          │                   │  SET session:{id}   │           │
  │                          │                   │───────────────────────────────► │
  │                          │                   │  INSERT refresh_token│          │
  │                          │                   │────────────────────►│           │
  │                          │                   │  INSERT audit_log   │           │
  │                          │                   │────────────────────►│           │
  │◄─────────────────────────│◄──────────────────│                     │           │
  │  {access_token,          │                   │                     │           │
  │   refresh_token}         │                   │                     │           │
```

### Token Refresh Flow

```
Client                     FastAPI              PostgreSQL    Redis
  │                           │                     │           │
  │  POST /auth/refresh        │                     │           │
  │  {refresh_token: raw}     │                     │           │
  │──────────────────────────►│                     │           │
  │                           │  SELECT WHERE       │           │
  │                           │  token_hash=SHA256  │           │
  │                           │────────────────────►│           │
  │                           │  check is_revoked   │           │
  │                           │  check expires_at   │           │
  │                           │  revoke old token   │           │
  │                           │  INSERT new token   │           │
  │                           │────────────────────►│           │
  │                           │  new access token   │           │
  │◄──────────────────────────│                     │           │
  │  {access_token (new),     │                     │           │
  │   refresh_token (new)}    │                     │           │
  │                           │                     │           │
  │  [if token was already    │                     │           │
  │   revoked (reuse):]       │                     │           │
  │                           │  DELETE session:{id}│           │
  │                           │──────────────────────────────── │
  │                           │  log CRITICAL event │           │
  │◄──────────────────────────│                     │           │
  │  401 Unauthorized         │                     │           │
```

### Sensitive Transfer Flow (Step-up Authentication)

```
Client                     FastAPI              PostgreSQL    Redis
  │                           │                     │           │
  │  POST /auth/step-up        │                     │           │
  │  {totp_code: "123456"}    │                     │           │
  │──────────────────────────►│                     │           │
  │                           │  verify TOTP        │           │
  │                           │  create step_up JWT │           │
  │                           │  log STEP_UP_VERIFIED           │
  │                           │────────────────────►│           │
  │◄──────────────────────────│                     │           │
  │  {step_up_token}          │                     │           │
  │                           │                     │           │
  │  POST /transactions/transfer                    │           │
  │  Authorization: Bearer <access_token>           │           │
  │  X-Step-Up-Token: <step_up_token>               │           │
  │──────────────────────────►│                     │           │
  │                           │  [Layers 1–7        │           │
  │                           │   verification]     │           │
  │                           │  decode step_up JWT │           │
  │                           │  verify sub matches │           │
  │                           │  GET stepup:used:.. │           │
  │                           │──────────────────────────────── │
  │                           │  (not used)         │           │
  │                           │  SET stepup:used:.. │           │
  │                           │──────────────────────────────── │
  │                           │  execute transfer   │           │
  │                           │  (DB transaction)   │           │
  │                           │────────────────────►│           │
  │                           │  log TRANSFER_COMPLETED         │
  │◄──────────────────────────│                     │           │
  │  {transaction}            │                     │           │
  │                           │                     │           │
  │  [if step-up missing or   │                     │           │
  │   amount >= threshold:]   │                     │           │
  │◄──────────────────────────│                     │           │
  │  403 Forbidden            │                     │           │
  │  X-Step-Up-Required: true │                     │           │
```
