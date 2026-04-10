# CLAUDE.md — Project Standards and Workflow Rules

This file defines the implementation standards, conventions, and workflow rules for this project. All future implementation work in this repository must follow these guidelines.

This is a bachelor thesis project in Cybersecurity. The primary deliverable is a Zero Trust security subsystem for a financial web platform. Security correctness takes priority over feature completeness, clever abstractions, or development convenience.

---

## 1. Python Standards

- Follow **PEP 8** for all Python code.
- Use **type hints** on all function signatures, class attributes, and return types. Use `from __future__ import annotations` where needed for forward references.
- Prefer **clear and maintainable code** over clever or concise code. A security-critical function that is easy to read is more valuable than one that is compact.
- Keep files and modules **small and focused**. Each module should have one clear responsibility. If a service file is growing beyond ~200 lines, consider whether it has accumulated concerns that belong elsewhere.
- Write **docstrings** for all public service functions, dependency functions, and any function that implements a security control. The docstring should state what the function does, what it expects, and what security property it enforces. Example: `"""Verify the TOTP code and issue a step-up token. Raises HTTPException 401 if the code is invalid."""`
- Use **explicit imports** (`from app.core.security import hash_password`, not `from app.core import *`).
- Avoid **global mutable state**. Use dependency injection (`Depends()`) for all shared resources (DB session, Redis client, current user). Do not store request-scoped state in module-level variables.

---

## 2. Python Tooling Conventions

| Tool | Purpose | Config location |
|------|---------|----------------|
| **Poetry** | Dependency management, virtual environment, lock file | `pyproject.toml`, `poetry.lock` |
| **Ruff** | Linting, import ordering, style enforcement, security rules | `pyproject.toml` under `[tool.ruff]` |
| **pytest** | Test runner | `pyproject.toml` under `[tool.pytest.ini_options]`; asyncio mode = "auto" |

**Poetry is the only dependency manager.** Do not use `pip install` directly. All dependencies go through `poetry add` or `poetry add --group dev`. The `poetry.lock` file must be committed.

**Ruff is the only linting and formatting tool for Python.** Do not add Black, isort, flake8, or pylint. Ruff covers all of these:
- `E`, `F` — style and error rules (PEP 8, undefined names, unused imports)
- `I` — import ordering (replaces isort)
- `N` — naming conventions
- `S` — security anti-patterns (Bandit rules)
- `B` — likely bugs (flake8-bugbear)

Run before committing:
```
ruff check backend/
ruff format --check backend/
pytest backend/tests/ -v
```

All tests must pass and Ruff must report no errors before a phase is considered complete.

---

## 3. Backend Design Conventions

### Module separation

Maintain strict separation between layers. Do not mix concerns:

| Layer | Responsibility | What does NOT belong here |
|-------|---------------|--------------------------|
| `models/` | SQLAlchemy ORM definitions, enums | Business logic, validation |
| `schemas/` | Pydantic request/response schemas, field validation | DB queries, service calls |
| `dependencies/` | FastAPI `Depends()` functions for auth, RBAC, session, step-up | Business logic, DB mutations |
| `core/` | Config, DB engine, Redis client, JWT/hashing utilities, middleware | Route handlers, business logic |
| `*/service.py` | Business logic, DB queries, security operations | HTTP concerns (Request/Response objects where avoidable) |
| `*/router.py` | Route definitions, HTTP request parsing, response formatting | Business logic, direct DB queries |

### Route handlers

- Route handlers must be **thin**. They parse the request, call the service, return the response.
- All significant logic (validation beyond Pydantic, DB operations, security checks) belongs in the service layer.
- Security dependencies (`get_current_user`, `require_role`, `require_verified`, `require_step_up`) must be declared explicitly in the route handler signature using `Depends()`. Do not move them inside the function body.

### Security checks

- Every security check must be **explicit and visible**. Prefer a named dependency over an inline check buried in service logic.
- When a new endpoint is added, the first question is: what combination of dependencies does this endpoint require? That combination must be declared and never left as an assumption.
- All service functions that perform sensitive operations (token issuance, password verification, MFA verification, transfer execution) must emit an audit log entry for both success and failure.

---

## 4. Frontend Conventions

- Use **TypeScript** for all frontend code. Avoid `any` types.
- Use **modern React functional components and hooks** only. No class components.
- The frontend exists to **demonstrate security flows**, not to be a polished product. Build only what is needed to show the backend security mechanisms working in a browser: login, MFA setup, MFA verify, dashboard, step-up modal.
- **Do not invest in frontend complexity** until all backend security phases are complete. Frontend work starts in Phase 8.
- Use **ESLint** (with `@typescript-eslint`) for linting and **Prettier** for formatting. These two tools must not conflict — ESLint owns code quality rules, Prettier owns formatting. Both configs must be committed (`eslint.config.js`, `.prettierrc`).
- **npm** is the package manager. Do not use Yarn or pnpm. Commit `package-lock.json`.
- Enable **TypeScript strict mode** (`"strict": true` in `tsconfig.json`). Do not weaken it.
- The token refresh interceptor and auth state management are the most security-relevant parts of the frontend. These should be implemented carefully and commented clearly.
- **Do not store the access token in `localStorage`**. Keep it in memory. Document this decision inline.

---

## 5. Git and Workflow Conventions

- `main` is the **stable branch**. It should always be in a working state.
- Use **short-lived feature branches** named by phase or feature: `phase-2-auth`, `feature/step-up-auth`, `fix/token-rotation`.
- Make **small, focused commits**. One logical change per commit. Avoid bundling unrelated changes.
- Write **clear commit messages** using the conventional commit format with scope where applicable:
  - `feat(auth): add email_verification_token_hash to User model` — auth implementation steps
  - `feat(accounts): add AccountStatus enum and account_number field` — feature additions by module
  - `docs: clarify phase 2 auth plan and ADR-15` — documentation-only changes
  - `fix(auth): correct JTI blacklist TTL calculation` — bug fixes
  - `test(auth): add refresh token rotation tests` — test-only additions
  - Use `feat:` (no scope) only for cross-cutting infrastructure changes (Docker, Nginx, CI)
  - Never use `wip`, `fixed stuff`, or vague messages
- **Do not rewrite large sections of code without explanation.** If a significant refactor is needed, note it in a commit message or update `DECISIONS.md`.
- Keep implementation **aligned with the documentation**. If you deviate from the documented design, update the docs in the same commit.

---

## 6. Documentation Discipline

The `/docs` directory is the specification. It was written before implementation to ensure the thesis has a traceable, coherent design.

Rules:
- If an implementation decision **contradicts or significantly changes** the architecture, security behavior, or API surface documented in `/docs`, update the relevant file in the same commit. Do not let the code and documentation diverge silently.
- If a new significant design decision is made during implementation, add an entry to `DECISIONS.md`.
- If a security requirement changes (scope added, scope removed, mechanism changed), update `SECURITY_REQUIREMENTS.md` and note the change.
- `IMPLEMENTATION_PLAN.md` phase deliverables are a checklist — mark or note completed items as implementation progresses.
- `TEST_STRATEGY.md` defines the expected test coverage — if a new security mechanism is added, add a corresponding test scenario to the strategy before or alongside the implementation.

---

## 7. Security Implementation Discipline

- **Never hardcode secrets.** All credentials, keys, and passwords must come from environment variables via `core/config.py`. No exceptions.
- **Avoid insecure defaults.** If a demo-only shortcut is used (e.g., email tokens logged to console instead of sent), mark it explicitly with a comment: `# DEMO MODE: replace with real SMTP in production`.
- Every **protected endpoint** must have its authentication and authorization requirements explicitly declared. If an endpoint has no `Depends(get_current_user)` or equivalent, that must be intentional and documented.
- Security-sensitive flows (login, token refresh, step-up, transfer) must:
  1. Emit an audit log entry (success and failure)
  2. Be covered by at least one security-focused test
  3. Reject invalid inputs with an appropriate HTTP error, not silently fail
- When implementing a security control, think about **what an attacker would try**, not just the happy path. The relevant abuse cases are listed in `THREAT_MODEL.md`.
- Do not remove or weaken a security control to simplify an implementation. If a mechanism is too complex, document the tradeoff in `DECISIONS.md`.

---

## 8. Testing Discipline

- Write tests for **security controls first**, not just for happy-path functionality. A login endpoint without a test for failed login is incomplete.
- Add or update tests **in the same phase** as the implementation they cover. Do not defer test writing.
- The 20 MVP-critical tests defined in `TEST_STRATEGY.md` (T-01 through T-20) are non-negotiable. All must pass before the project is considered complete for thesis purposes.
- Each test must be **specific and meaningful**. Assert on status codes, response bodies, database state, and Redis state where relevant. A test that only checks `status_code == 200` for a security scenario is insufficient.
- Tests must remain **isolated**. Each test function must work with a fresh database and Redis state. No test should depend on the state produced by another test.
- When a security bug is found, write a **regression test** before fixing it.
