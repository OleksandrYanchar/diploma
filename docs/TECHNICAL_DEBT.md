# Technical Debt

This file tracks known limitations, deferred improvements, and security
hardening items in the Zero Trust financial platform backend.

The document distinguishes three states:

1. **Implemented controls** — described elsewhere (`SECURITY_REQUIREMENTS.md`,
   `ARCHITECTURE.md`); not repeated here.
2. **Missing controls that must be fixed** — listed under **Must-fix** sections.
   These are blockers; they are not "deferred" and must not be treated as such.
3. **Consciously deferred improvements** — listed under **Post-MVP** and
   **Documentation / consistency**. These are acceptable to ship in the MVP
   provided they are documented honestly here.

Items use stable IDs (`TD-NN`). Each item links back to the audit finding(s)
that produced it (`AUDIT-NN`) so traceability is preserved if either document
is later restructured.

The IDs are stable; do not renumber when adding new items. Append at the
end of the relevant section.

Every TD entry uses the same schema:

- Title (`## TD-XX — …`)
- Metadata block: Related audit finding, Severity, Type, Status
- `### Current state`
- `### Risk`
- `### Recommended mitigation`
- `### MVP decision`
- `### Why deferred` — present only when **MVP decision** is `Deferred — Post-MVP`

---

# Section A — Fixed in pre-Phase 8 audit (`fix/pre-defense-security-gaps`, PR #10)

These items were originally must-fix blockers before the Phase 7 merge. All
three were resolved in a dedicated pre-Phase 8 audit pass (`fix/pre-defense-security-gaps`,
merged as PR #10). Status fields below reflect the current fixed state.

---

## TD-02 — Last-active-admin guard is NOT implemented

**Related audit finding:** AUDIT-03, AUDIT-19
**Severity:** High
**Type:** Security gap / Documentation accuracy
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/admin/service.py::deactivate_user` and
`backend/app/admin/service.py::change_user_role` enforce only a self-guard
(actor cannot modify their own account). They do **not** count remaining
active admins before allowing the action. There is no `last_admin_protected`
check in code. Searching the repository for that string returns no hits.

A previous version of this document described the guard as if it existed.
That description was incorrect and has been removed. This entry replaces it.

### Risk

In a system with a single active admin, that admin is locked out by a
brute-force lockout, or in a system with two admins where admin A demotes
admin B, the platform can end up with no reachable administrator. Recovery
then requires direct database access — which the deployment topology may not
permit and which itself bypasses the audit trail.

### Recommended mitigation

In both `deactivate_user` and `change_user_role`, after the existing
self-guard and before mutation, when `target.role == UserRole.ADMIN`:

```text
count = SELECT count(*) FROM users
        WHERE role = 'admin' AND is_active = true AND id != target.id
if count == 0: raise 403 "Cannot remove the last active admin"
                 + audit log failure with reason="last_admin_protected"
```

### MVP decision

Must fix before Phase 7 merge. The fix is small (two service-layer guards,
two audit log branches, two new tests). Deferring it is incompatible with the
thesis claim of a coherent admin governance model.

---

## TD-03 — Admin mutating endpoints capture incomplete audit context

**Related audit finding:** AUDIT-05
**Severity:** High
**Type:** Security gap / Architecture
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/admin/router.py` — all four mutating handlers (`unlock_user`,
`activate_user`, `deactivate_user`, `change_user_role`) compute the audit IP
as:

```python
ip = request.client.host if request.client else None
```

They do not honour the `X-Real-IP` header (set by Nginx) and do not capture
the `User-Agent` header at all. Every other IP-aware handler in the codebase
uses the pattern `request.headers.get("X-Real-IP") or request.client.host`
**and** captures `User-Agent`.

### Risk

Admin mutating endpoints are the highest-risk operations in the system.
Their audit trail is currently the **weakest** in the system. Behind the
production reverse proxy, the recorded IP is Nginx's address, not the
acting admin's. There is no User-Agent fingerprint at all. Forensic
attribution after a rogue-admin incident is degraded.

### Recommended mitigation

Replicate the auth/router pattern in all four admin mutating handlers:

```python
ip_address = request.headers.get("X-Real-IP") or (
    request.client.host if request.client else None
)
user_agent = request.headers.get("User-Agent")
```

Pass both to the service functions and include `user_agent` in
`AuditLog.user_agent`. Update the corresponding tests to assert that
`user_agent` is recorded on success and on each failure branch.

The proxy-trust hardening (TD-08) is a separate, larger item and is **not**
a prerequisite for this fix. The asymmetry between admin and non-admin
endpoints must be eliminated even before the proxy trust model is tightened.

### MVP decision

Must fix before Phase 7 merge.

---

## TD-04 — Missing AUDITOR-rejection tests for activate / deactivate / role

**Related audit finding:** AUDIT-21 (subset)
**Severity:** Medium
**Type:** Test coverage
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/tests/test_admin_mutate.py` covers AUDITOR rejection for `unlock`
only (`test_unlock_auditor_role_returns_403`). It does **not** test that
AUDITOR is rejected on `activate`, `deactivate`, or `role`. The endpoints
do reject AUDITOR via `require_role(UserRole.ADMIN)`, but the tests do not
prove it.

### Risk

A future refactor that accidentally widens `require_role` (for example, a
copy-paste from the read-only routes which allow `UserRole.ADMIN,
UserRole.AUDITOR`) would silently grant AUDITOR write access without any
test failing. SR-11 enforcement is a thesis-critical claim and must have
explicit per-endpoint regression tests.

### Recommended mitigation

Add three tests mirroring `test_unlock_auditor_role_returns_403`:

- `test_activate_auditor_role_returns_403`
- `test_deactivate_auditor_role_returns_403`
- `test_role_change_auditor_role_returns_403`

### MVP decision

Must fix before Phase 7 merge.

---

# Section B — Should-fix before final thesis demo

These items are real security gaps, not just hardening. They do not block
the Phase 7 merge in isolation, but they must be resolved before the thesis
defence demo. Each is small enough to be a self-contained change.

---

## TD-05 — Concurrent transfers can produce a negative balance

**Related audit finding:** AUDIT-01
**Severity:** Critical (financial-integrity defect)
**Type:** Security gap / Concurrency
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/transactions/service.py::execute_transfer` reads source and
destination accounts with plain `select(Account).where(...)`. There is no
`with_for_update()`, no optimistic version column, and no advisory lock.
The balance check at line 294 and the balance mutation at lines 311–312
form a classic read-modify-write race. `db.begin_nested()` only creates a
SAVEPOINT for partial rollback; it does not serialize concurrent reads.

### Risk

Two concurrent transfers of 80 from an account with balance 100 both pass
the `balance >= amount` check and both commit, leaving the account at -60.
For a financial subsystem this is a correctness defect, not just a
performance issue.

### Recommended mitigation

Add `.with_for_update()` to both account selects in `execute_transfer`.
Wrap the read-check-write sequence in a single `async with db.begin():`
so the row locks are held until commit. Add a regression test that runs
two parallel transfers from the same account via `asyncio.gather` and
asserts the post-condition `balance >= 0` and `successful_count <= 1`.

### MVP decision

Should fix before final thesis demo. The thesis is on Zero Trust security
for a financial platform; a financial-integrity defect cannot be left in the
demonstrable state.

---

## TD-06 — TOTP replay window allows multiple step-up tokens from one captured code

**Related audit finding:** AUDIT-02
**Severity:** High
**Type:** Security gap
**Status:** Open — should fix before final demo

### Current state

`backend/app/core/totp.py::verify_totp_code` uses `valid_window=1` (~90 s
acceptance window). The function's own docstring acknowledges the residual
replay risk and says the mitigation "is deferred to the MFA service layer,
which has access to the Redis store." That deferred mitigation has not
been implemented in `auth/service.py::verify_step_up`,
`auth/service.py::login`, `auth/service.py::enable_mfa`, or
`auth/service.py::disable_mfa`.

The step-up JWT JTI is single-use (`getdel` in Redis), but the same TOTP
code can be presented to `POST /auth/step-up` multiple times within ~90 s
to mint **multiple distinct** step-up tokens.

### Risk

An attacker who captures one valid TOTP code (clipboard sniffer, browser
extension, shoulder-surfing) can authorize multiple high-value transfers
within ~90 s. The single-use property of each step-up JWT does not
constrain an attacker who can mint several of them from one TOTP code.

### Recommended mitigation

In each TOTP-consuming function, after `verify_totp_code` returns true,
record the tuple `(user_id, current_window_timestamp, code)` in Redis with
TTL = 90 s (e.g. `last_totp:{user_id}:{window}`). Reject any subsequent
verification of the same tuple.

### MVP decision

Should fix before final thesis demo.

---

## TD-07 — Refresh-token reuse detection does not revoke sibling DB tokens

**Related audit finding:** AUDIT-04
**Severity:** High
**Type:** Security gap
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/auth/service.py::refresh_tokens` (lines 450–474) handles a
revoked-token replay by:

1. fetching all `RefreshToken` rows for the user,
2. deleting their Redis session keys,
3. writing a `SecurityEvent`,
4. raising 401.

It does **not** mark the sibling refresh tokens as `revoked=True`. If the
attacker holds another, separately issued non-revoked refresh token for
the same user, that token remains valid in the DB and can be used to mint
a new session.

### Risk

A token-theft scenario where multiple refresh tokens have been
exfiltrated (e.g. several login sessions on different devices were all
compromised) is detected for one token only. The other stolen tokens
remain operational.

### Recommended mitigation

In the reuse-detection branch, also issue
`UPDATE refresh_tokens SET revoked = true WHERE user_id = :user_id`.
Add a regression test: create two refresh tokens; replay one; assert the
other also returns 401.

### MVP decision

Should fix before final thesis demo.

---

## TD-08 — `X-Real-IP` header is trusted without verifying the source proxy

**Related audit finding:** AUDIT-06
**Severity:** High
**Type:** Security gap / Architecture
**Status:** Open — should fix before final demo

### Current state

Every IP-capturing handler reads `request.headers.get("X-Real-IP")` with
no check that the immediate peer is actually a trusted reverse proxy.
The repository ships `docker-compose.test.yml` which exposes the backend
on port 8000 directly, with no Nginx in front. In that mode any client
can set `X-Real-IP: 1.2.3.4` to forge the audited source IP.

### Risk

Forensic attribution becomes meaningless on the test stack. Any future
per-IP rate limiter (Phase 8) is trivially bypassed by header rotation.
Per-account lockout still triggers but per-IP analytics are unreliable.

### Recommended mitigation

Either:

- configure Uvicorn with `--forwarded-allow-ips` and use Starlette's
  `ProxyHeadersMiddleware` to derive the client IP from `X-Forwarded-For`
  only when the immediate peer is in the trusted list; or
- only honour `X-Real-IP` when `request.client.host` is in a configured
  `TRUSTED_PROXIES` list loaded from settings.

Document the trust boundary in `ARCHITECTURE.md`.

### MVP decision

Should fix before final thesis demo.

---

## TD-09 — TOTP secret stored as plaintext in `users.mfa_secret`

**Related audit finding:** AUDIT-07
**Severity:** High
**Type:** Security gap (encryption at rest)
**Status:** Open — should fix before final demo

### Current state

`backend/app/models/user.py` line 92–97 stores the Base32 TOTP secret as
`String(64)` — plaintext at rest. `backend/app/core/totp.py` docstring
explicitly states the secret "must be stored encrypted (or
hashed-encrypted) at rest". The control is documented but not implemented.

The secret is correctly excluded from API responses (Pydantic `UserResponse`
and `UserAdminView` omit it), so the gap is at the storage layer only.

### Risk

A DB backup leak hands every MFA-enabled account's seed to the attacker.
Combined with offline cracking of any weak Argon2id password hashes, the
attacker can fully impersonate any user — including admins.

### Recommended mitigation

Encrypt `mfa_secret` at rest using a server-held data key (`Fernet` or
AES-GCM) loaded from a new env variable `MFA_SECRET_ENCRYPTION_KEY`.
The key must be separate from `JWT_SECRET_KEY`. Decrypt only inside
`verify_totp_code` call sites. Migration must re-encrypt existing values.

### MVP decision

Should fix before final thesis demo. The thesis is on Zero Trust;
"trust no storage" is part of the thesis statement.

---

## TD-10 — Application-layer rate limiting is absent

**Related audit finding:** AUDIT-10
**Severity:** Medium
**Type:** Security gap / Phase 8 work
**Status:** Fixed — Phase 8 (sliding-window middleware, configurable via `RATE_LIMIT_*` env vars)

### Current state

There is no application-layer rate limiter. `IMPLEMENTATION_PLAN.md`
originally listed it as Phase 7 work; the recent split moves it to Phase 8.
`docker-compose.test.yml` exposes the backend on port 8000 with no Nginx
in front, so in that deployment there is **zero** rate limiting on
`/auth/login`, `/auth/register`, `/auth/password/reset/request`,
`/auth/refresh`, or any admin endpoint.

### Risk

Brute-force enumeration of email addresses via login response timing and
registration 409 responses. Per-account lockout protects login but does
not protect password-reset request, which has no lockout at all. T-15
in `TEST_STRATEGY.md` is currently unimplementable.

### Recommended mitigation

Sliding-window rate limiter middleware in `app/core/middleware.py` using
Redis sorted sets. Separate windows per IP for auth endpoints (tighter)
and a looser global window for everything else. Return `429` with
`Retry-After` header. Emit a `RATE_LIMIT_EXCEEDED` SecurityEvent
(see TD-18). Add `tests/test_rate_limiting.py` covering T-15.

### MVP decision

Should fix before final thesis demo. Already planned as Phase 8.

---

## TD-11 — `disable_mfa` and `change_password` do not increment lockout counter on wrong password

**Related audit finding:** AUDIT-11
**Severity:** Medium
**Type:** Abuse scenario
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/auth/service.py::disable_mfa` (lines 615–629) and
`backend/app/auth/service.py::change_password` (line 679) both verify the
password but do **not** increment `failed_login_count` or contribute to
account lockout on failure.

### Risk

An attacker holding an active access token (e.g., XSS, stolen session,
the 15-minute window after a session compromise) can mount an
**unrestricted** password brute-force against the user via repeated
`/auth/mfa/disable` or `/auth/password/change` calls. Once the password
is guessed, MFA can be disabled and the account fully captured.

### Recommended mitigation

In both functions, on `verify_password` returning false, mirror the
`login` failure path: increment `failed_login_count`; if threshold
reached, set `locked_until` and emit `ACCOUNT_LOCKED` audit log +
SecurityEvent.

### MVP decision

Should fix before final thesis demo.

---

## TD-12 — `TOKEN_REUSE` writes a SecurityEvent but no AuditLog entry

**Related audit finding:** AUDIT-09
**Severity:** Medium
**Type:** Security gap (audit completeness)
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/auth/service.py::refresh_tokens` (lines 459–469) writes only
a `SecurityEvent` for `TOKEN_REUSE`. Every other security incident
(STEP_UP_BYPASS_ATTEMPT, ACCOUNT_LOCKED) writes **both** an `AuditLog`
and a `SecurityEvent`.

### Risk

A forensic timeline query against `audit_logs` for a given user misses
the reuse-detection event. Cross-table correlation is required.

### Recommended mitigation

Add an `AuditLog(action="TOKEN_REUSE_DETECTED", user_id=..., details={...})`
write alongside the existing SecurityEvent in the reuse-detection branch.
Mirror the STEP_UP_BYPASS_ATTEMPT pattern.

### MVP decision

Should fix before final thesis demo.

---

## TD-13 — `confirm_password_reset` failure paths produce no audit log

**Related audit finding:** AUDIT-22
**Severity:** Low / Medium
**Type:** Security gap (audit completeness)
**Status:** Fixed — `fix/pre-defense-security-gaps` (PR #10)

### Current state

`backend/app/auth/service.py::confirm_password_reset` (lines 787–814) has
three failure branches: invalid token, missing `password_reset_sent_at`,
expired token. None writes an audit log entry. An attacker probing
reset tokens leaves no trace in the audit stream.

### Risk

Token-probing attacks are invisible to the auditor view. Combined with
TD-10 (no rate limiting) the gap is exploitable.

### Recommended mitigation

Write `AuditLog(action="PASSWORD_RESET_FAILED", user_id=None,
details={"reason": ...})` on each failure branch. Consider escalating
to a SecurityEvent after N failures from the same IP (depends on TD-10).

### MVP decision

Should fix before final thesis demo.

---

# Section C — Post-MVP technical debt

These items are deferred consciously. They are recorded here so future
maintainers (and thesis examiners) see them; they are not required for
the MVP scope or the thesis demo.

---

## TD-01 — Multi-admin approval for high-risk admin actions

**Related audit finding:** AUDIT-03 (residual risk paragraph)
**Severity:** Medium
**Type:** Security hardening / governance
**Status:** Deferred — Post-MVP

### Current state

The Phase 7 admin API allows any single ADMIN to deactivate or demote
another ADMIN, subject only to the existing self-guard (cannot modify
own account). When the last-active-admin guard from TD-02 is implemented,
that will prevent total loss of admin access — **but it will not prevent
abuse of power** by a malicious or compromised admin while at least one
other active admin remains.

This TD-01 entry intentionally describes the residual risk **independent
of TD-02**: even with the last-active-admin guard in place, the system
has no governance layer for inter-admin operations.

### Risk

A single bad actor with ADMIN credentials can:

- demote every other ADMIN until they are the last admin standing
  (each individual demotion is permitted as long as one other admin
  remains);
- in two-admin systems, demote the other admin in one step, becoming the
  sole admin;
- once sole admin, use that position to tamper with user data, change
  configuration, or mask audit trails before detection.

### Recommended mitigation

Two-person approval workflow for high-risk inter-admin actions:

- a new `admin_pending_actions` model storing action type, target,
  initiator, requested-at timestamp, approval status;
- `POST /admin/actions/{id}/approve` and `POST /admin/actions/{id}/reject`,
  ADMIN-only, both rejecting self-approval (initiator cannot approve
  their own request);
- separate `AuditLog` entries for request creation, approval, rejection,
  and final execution;
- optional expiry: pending requests expire after a configurable TTL
  (e.g. 24 h);
- documented break-glass procedure (privileged ops role with direct DB
  access) for emergencies where no second approver is available.

### MVP decision

Deferred — Post-MVP.

### Why deferred

The MVP scope focuses on Zero Trust access control, session security,
MFA, audit logging, and RBAC enforcement. A two-person approval workflow
introduces a stateful pending-action lifecycle, approver identity
verification, and expiry handling that exceed the thesis scope. Should be
revisited before any real-world deployment.

---

## TD-14 — `confirm_password_reset` uses `redis.scan_iter` (O(N) over all sessions)

**Related audit finding:** AUDIT-08
**Severity:** Medium
**Type:** Performance / Security gap
**Status:** Deferred — Post-MVP

### Current state

`backend/app/auth/service.py::confirm_password_reset` (lines 825–831)
iterates **every** `session:*` key in Redis to find the ones matching
the user. Performance scales O(total_sessions) per password reset.

### Risk

At MVP scale (tens to low-hundreds of users) this is unobservable. At
production scale or under deliberate amplification it stalls Redis on
every reset. Combined with the absence of application-layer rate
limiting on the unauthenticated reset confirmation endpoint, it is also
a denial-of-service vector.

### Recommended mitigation

Maintain a `user:{user_id}:sessions` Redis set, updated on session
create/delete. Look up sessions for the user in O(1).

### MVP decision

Deferred — Post-MVP.

### Why deferred

Optimization. The current implementation is correct; only the cost is
suboptimal.

---

## TD-15 — `change_password` does not revoke other sessions / refresh tokens

**Related audit finding:** AUDIT-12
**Severity:** Medium
**Type:** Security gap / governance trade-off
**Status:** Deferred — Post-MVP (covered by ADR-21)

### Current state

After password change all existing access tokens (up to 15 min) and
refresh tokens (up to `refresh_token_expire_days`, default 7 days)
remain valid. `confirm_password_reset` does revoke them; `change_password`
does not. This asymmetry is an explicit decision recorded in ADR-21.

### Risk

A user who changes their password to lock out a suspected attacker
remains exposed for up to seven days via existing refresh tokens.

### Recommended mitigation

Either revoke all sessions on password change (mirror
`confirm_password_reset`), or add an explicit `?revoke_others=true`
query parameter and document the trade-off in the API contract.

### MVP decision

Deferred — Post-MVP.

### Why deferred

Trade-off documented in ADR-21. Should be re-examined when the user-
facing UX is built (Phase 9), since the right behaviour depends on
the user's intent (deliberate change vs. compromise response).

---

## TD-16 — `refresh_tokens` does not check `is_verified`

**Related audit finding:** AUDIT-13
**Severity:** Low
**Type:** Security gap (consistency)
**Status:** Deferred — Post-MVP

### Current state

`backend/app/auth/service.py::refresh_tokens` (line 486) checks only
`is_active`. An unverified user (registered, never verified email) can
keep extending their session indefinitely via `/auth/refresh`. They
still cannot reach verified-only endpoints.

### Risk

Mass spam-registrations with disposable emails create a horde of
long-lived unverified sessions that consume Redis and DB resources
indefinitely.

### Recommended mitigation

Add `or not user.is_verified` to the rejection branch.

### MVP decision

Deferred — Post-MVP.

### Why deferred

Low impact at MVP scale. No data exfiltration is possible because
verified-only endpoints reject. Affects resource consumption only.

---

## TD-17 — `auth/service.py` exceeds the project's ~200-line guideline

**Related audit finding:** AUDIT-14
**Severity:** Medium
**Type:** Technical debt / Architecture
**Status:** Deferred — Post-MVP

### Current state

`backend/app/auth/service.py` is 1056 lines; `auth/router.py` is 757
lines. CLAUDE.md states: "If a service file is growing beyond ~200
lines, consider whether it has accumulated concerns that belong
elsewhere." The auth service combines eleven distinct concerns:
register, verify-email, login, refresh, logout, MFA setup/enable/
disable, password change, password reset request/confirm, step-up.

### Risk

Indirect: any review or refactor of one concern forces touching a
1000-line file. Increases merge-conflict surface; slows future audits.

### Recommended mitigation

Split into per-concern modules:
`auth/registration.py`, `auth/login.py`, `auth/refresh.py`,
`auth/logout.py`, `auth/mfa.py`, `auth/password.py`, `auth/step_up.py`.
Keep `auth/service.py` as a re-export façade if needed for backwards
compatibility during the migration.

### MVP decision

Deferred — Post-MVP.

### Why deferred

The split is a refactor, not a bug fix. It does not change behaviour
and would only churn unrelated lines if done now. Better to defer until
all auth-related Phase work is complete.

---

## TD-18 — Three documented `SecurityEvent` types are never emitted

**Related audit finding:** AUDIT-15
**Severity:** Low
**Type:** Documentation / Test coverage
**Status:** Deferred — Post-MVP

### Current state

`backend/app/models/security_event.py` lines 12–14 documents the event
types `BRUTE_FORCE`, `RATE_LIMIT_EXCEEDED`, `SUSPICIOUS_LOGIN`. None of
these strings appears anywhere else in the codebase. Lockout currently
emits `ACCOUNT_LOCKED` only.

### Risk

Auditor-facing documentation lists event types that will never appear
in the real stream. False expectations during incident review.

### Recommended mitigation

- `BRUTE_FORCE`: emit alongside `ACCOUNT_LOCKED` in `login` failure
  path (different severity, same trigger).
- `RATE_LIMIT_EXCEEDED`: emit from the planned rate limiter (TD-10).
- `SUSPICIOUS_LOGIN`: define triggers (new IP + new UA + outside
  business hours, etc.) or remove from the model documentation.

### MVP decision

Deferred — Post-MVP.

### Why deferred

Two of the three are blocked on Phase 8 work (rate limiter for
`RATE_LIMIT_EXCEEDED`; UX/policy decisions for `SUSPICIOUS_LOGIN`).
Adding `BRUTE_FORCE` alongside `ACCOUNT_LOCKED` is small and may be
brought forward.

---

## TD-19 — Transaction history query lacks composite indexes

**Related audit finding:** AUDIT-16
**Severity:** Low
**Type:** Performance
**Status:** Deferred — Post-MVP

### Current state

`backend/app/models/transaction.py` has single-column indexes on
`from_account_id` and `to_account_id`. The history query is
`WHERE (from_account_id = X OR to_account_id = X) ORDER BY created_at
DESC LIMIT N OFFSET M`. PostgreSQL must bitmap-or both indexes, sort,
then page.

### Risk

At 100 k+ transactions the query is slow and OFFSET pagination becomes
expensive.

### Recommended mitigation

Alembic migration adding two composite indexes:
`(from_account_id, created_at DESC)` and
`(to_account_id, created_at DESC)`.

### MVP decision

Deferred — Post-MVP.

### Why deferred

MVP data volume is too small to make the cost observable.

---

## TD-20 — Fragile `locked_until` timezone-reattach pattern in `login`

**Related audit finding:** AUDIT-17
**Severity:** Low
**Type:** Code quality
**Status:** Deferred — Post-MVP

### Current state

`backend/app/auth/service.py::login` lines 270–278 use two separate
`if user.locked_until is not None:` blocks. The second block references
`locked_until` which is only defined inside the first block. Works
today; brittle to refactor.

### Risk

Future refactor that removes or reorders the first block leaves the
second referencing an undefined variable. Caught by lint/types in
practice but the pattern is fragile.

### Recommended mitigation

Consolidate into a single block. The cleaner pattern is already used
in `dependencies/auth.py::get_current_user`.

### MVP decision

Deferred — Post-MVP.

### Why deferred

Pure cleanup with no behavioural change. Best done as part of TD-17
when the auth service is split.

---

## TD-21 — Password-reset request leaks email existence via response time

**Related audit finding:** AUDIT-18
**Severity:** Low
**Type:** Security gap (enumeration)
**Status:** Deferred — Post-MVP

### Current state

`backend/app/auth/service.py::request_password_reset` does extra work
on the email-exists path (token generation, hashing, two DB writes vs.
one). Response body is identical (per SR-18) but response time differs
by orders of magnitude. Login uses `_DUMMY_HASH` to flatten timing;
password-reset does not.

### Risk

A timing attacker can enumerate registered email addresses via the
unauthenticated reset endpoint.

### Recommended mitigation

Run a no-op token generation + hash on the unknown-email path to
flatten the timing budget. Or accept the residual leak and document
in `THREAT_MODEL.md`.

### MVP decision

Deferred — Post-MVP.

### Why deferred

Same control class as login enumeration prevention but lower impact.
Worth fixing once the rate limiter (TD-10) is in place, since
enumeration via this channel without rate limiting is the larger
concern.

---

# Section D — Documentation / consistency debt

These items are documentation drift. They do not require code changes
but must be corrected so the docs do not misrepresent the implementation.

---

## TD-22 — `IMPLEMENTATION_PLAN.md` Phase 7 / Phase 8 split is out of date

**Related audit finding:** AUDIT-20
**Severity:** Low
**Type:** Documentation
**Status:** Fixed — Phase 9 docs sync (this pass)

### Current state

`docs/IMPLEMENTATION_PLAN.md` line 228 reads "Phase 7 — Admin API +
Rate Limiting". The actual work split is Phase 7 = Admin API (PR #8),
Phase 8 = Rate Limiting. This was decided in conversation but the
plan was not updated.

### Risk

Future readers (including the thesis examiner) cannot reconcile the
plan with the commit history.

### Recommended mitigation

Update the plan to reflect:

- Phase 7 = Admin API (read-only + mutating).
- Phase 8 = Rate Limiting middleware.
- Phase 9 = Frontend demo + TOTP encryption at rest (TD-09).

### MVP decision

Fixed. `IMPLEMENTATION_PLAN.md` now reflects the three-phase split above. Phase
numbering in the Summary table and section headers is correct as of the Phase 9
docs sync.

---

# Section E — Suggested test additions

The following tests have been identified by the audit as missing. Each is
linked to the TD item it covers.

| Test name | Covers |
|---|---|
| `test_admin_deactivate_last_admin_blocked` | TD-02 |
| `test_admin_role_change_last_admin_blocked` | TD-02 |
| `test_admin_mutating_endpoint_captures_user_agent_in_audit` | TD-03 |
| `test_activate_auditor_role_returns_403` | TD-04 |
| `test_deactivate_auditor_role_returns_403` | TD-04 |
| `test_role_change_auditor_role_returns_403` | TD-04 |
| `test_concurrent_transfer_does_not_overdraft` | TD-05 |
| `test_step_up_totp_replay_within_window_rejected` | TD-06 |
| `test_refresh_token_reuse_revokes_sibling_db_tokens` | TD-07 |
| `test_disable_mfa_wrong_password_increments_lockout_counter` | TD-11 |
| `test_change_password_wrong_password_increments_lockout_counter` | TD-11 |
| `test_token_reuse_writes_audit_log_entry` | TD-12 |
| `test_password_reset_confirm_invalid_token_writes_audit_log` | TD-13 |
| `test_refresh_rejects_deactivated_user` | (consistency test, audit gap noted in AUDIT-21) |
