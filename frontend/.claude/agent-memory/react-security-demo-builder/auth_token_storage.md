---
name: Auth Token Storage Pattern
description: How access and refresh tokens are stored and bootstrapped in this app — the agreed security tradeoff
type: project
---

Access token is kept in module-level memory (`client.ts`), never written to any Web Storage.

Refresh token is persisted in `sessionStorage` under key `"rt"` via `setTokens()` / `clearTokens()` / `getRefreshToken()` in `client.ts`. This enables page-reload and same-session new-tab persistence without the long-lived risk of localStorage.

**Why:** Pure in-memory tokens caused instant logout on page refresh, breaking the demo flow. HttpOnly cookies are the production ideal but require backend coordination. sessionStorage is the chosen DEMO compromise — scoped to the browser tab session, cleared on tab close.

**How to apply:** `setTokens(access, refresh)` always writes both. `clearTokens()` removes both. On app mount, `providers.tsx` reads `sessionStorage.getItem("rt")` and calls `POST /auth/refresh` if present, then `GET /users/me` to hydrate user state. A mandatory inline comment marks this as DEMO-only.

There is an inline comment in `client.ts`:
```
// DEMO: refresh token stored in sessionStorage for page-reload UX.
// Production should use HttpOnly secure cookies instead.
```
