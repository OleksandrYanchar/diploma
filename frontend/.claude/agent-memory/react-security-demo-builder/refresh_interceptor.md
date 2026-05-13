---
name: Refresh Interceptor Design
description: How the axios 401 interceptor handles concurrent calls and 429 rate-limits on the refresh endpoint
type: project
---

The response interceptor in `client.ts` handles 401s with a single in-flight refresh guard:

- `isRefreshing` flag and `pendingRequests` / `pendingRejects` arrays queue concurrent 401s behind one `POST /auth/refresh` call.
- On refresh success: all queued requests are replayed with the new access token.
- On refresh 429: tokens are NOT cleared. `onRefreshRateLimited` callback fires to show "Too many requests — please wait" in the UI (Layout.tsx banner + LoginPage banner). Session is preserved.
- On refresh 401 / 403 / network error: tokens are cleared via `clearTokens()`, `onUnauthenticated` fires, user is redirected to `/login` with `sessionExpired = true` flag in AuthContext.

`AuthContextValue` exports `sessionExpired: boolean`, `rateLimitMessage: string | null`, and `clearRateLimitMessage: () => void` for UI consumption.

**Why:** Without the in-flight guard, password change or tab focus can fire multiple simultaneous refresh calls which triggers reuse detection on the backend (a security event). The 429 distinction prevents false session-expiry UX when the user is genuinely still authenticated but temporarily rate-limited.
