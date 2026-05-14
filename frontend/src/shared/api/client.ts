/**
 * Axios HTTP client with centralised auth header injection and 401 handling.
 *
 * Security design:
 *  - Access token is kept in-memory only (never localStorage/sessionStorage).
 *  - Refresh token is stored in an HttpOnly cookie set by the backend —
 *    not accessible to JavaScript. This is the correct production approach.
 *  - On 401 the interceptor attempts one silent refresh by posting to
 *    /auth/refresh with no body; the browser sends the HttpOnly cookie
 *    automatically via withCredentials.
 *  - If refresh fails (401/403 or other), auth state is cleared and the user is
 *    redirected to /login. If refresh returns 429, the session is NOT cleared —
 *    the rate-limit is transient and the user is still authenticated.
 *  - Concurrent 401s are queued behind a single in-flight refresh promise.
 *  - Tokens are never logged to the console.
 */
import axios, { type AxiosRequestConfig, type InternalAxiosRequestConfig } from "axios";
import { env } from "@/shared/config/env";

// In-memory access token — never written to any storage.
let accessToken: string | null = null;

/**
 * Write the access token to memory.
 * The refresh token is managed entirely by the browser via the HttpOnly
 * cookie set by the backend — no JS read/write required or possible.
 */
export function setTokens(access: string): void {
  accessToken = access;
}

/** Remove the in-memory access token. The HttpOnly refresh cookie is cleared
 *  by the backend on /auth/logout — no client-side removal needed. */
export function clearTokens(): void {
  accessToken = null;
}

export function getAccessToken(): string | null {
  return accessToken;
}

// Callback to notify AuthContext that auth state was cleared (session expired).
let onUnauthenticated: (() => void) | null = null;

// Callback to notify AuthContext of a transient rate-limit on refresh (429).
let onRefreshRateLimited: (() => void) | null = null;

export function registerUnauthenticatedHandler(handler: () => void): void {
  onUnauthenticated = handler;
}

export function registerRefreshRateLimitedHandler(handler: () => void): void {
  onRefreshRateLimited = handler;
}

export const apiClient = axios.create({
  baseURL: env.apiBaseUrl,
  headers: { "Content-Type": "application/json" },
  // withCredentials must be true so the browser includes the HttpOnly
  // zt_rt cookie on every request to the backend (same-origin or CORS).
  withCredentials: true,
});

// Request interceptor: attach Authorization header if token present.
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Guard against concurrent refresh calls.
// If a refresh is already in-flight, subsequent 401s queue here and retry
// once the single in-flight refresh settles.
let isRefreshing = false;
let pendingRequests: Array<(token: string) => void> = [];
let pendingRejects: Array<(err: unknown) => void> = [];

/**
 * Reset all interceptor queue state.
 * Must be called on logout so that any queued requests from the previous
 * session cannot leak into the next one. Without this, a logout that fires
 * mid-flight could leave isRefreshing=true or non-empty pending arrays across
 * the session boundary.
 */
export function resetInterceptorState(): void {
  isRefreshing = false;
  pendingRequests = [];
  pendingRejects = [];
}

function processPendingRequests(token: string): void {
  pendingRequests.forEach((resolve) => resolve(token));
  pendingRequests = [];
  pendingRejects = [];
}

function rejectPendingRequests(err: unknown): void {
  pendingRejects.forEach((reject) => reject(err));
  pendingRequests = [];
  pendingRejects = [];
}

// Response interceptor: on 401 attempt one silent token refresh per flight.
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retried?: boolean };

    // Only intercept 401s that are not from the refresh endpoint itself
    // and have not already been retried.
    if (
      error.response?.status === 401 &&
      !originalRequest._retried &&
      originalRequest.url !== "/auth/refresh"
    ) {
      if (isRefreshing) {
        // Queue this request — it will be replayed once the in-flight refresh settles.
        return new Promise((resolve, reject) => {
          pendingRequests.push((token: string) => {
            if (originalRequest.headers) {
              (originalRequest.headers as Record<string, string>)[
                "Authorization"
              ] = `Bearer ${token}`;
            }
            resolve(apiClient(originalRequest));
          });
          pendingRejects.push(reject);
        });
      }

      originalRequest._retried = true;
      isRefreshing = true;

      try {
        // POST /auth/refresh with no body — the browser automatically includes
        // the HttpOnly zt_rt cookie. withCredentials is set on the axios instance
        // but we also pass it explicitly here because this call uses the raw
        // axios singleton (not apiClient) to avoid triggering the interceptor again.
        // In production: POST /api/auth/refresh
        const response = await axios.post<{ access_token: string }>(
          `${env.apiBaseUrl}/auth/refresh`,
          undefined,
          { withCredentials: true }
        );

        const newAccess = response.data.access_token;

        setTokens(newAccess);
        processPendingRequests(newAccess);

        if (originalRequest.headers) {
          (originalRequest.headers as Record<string, string>)[
            "Authorization"
          ] = `Bearer ${newAccess}`;
        }

        return apiClient(originalRequest);
      } catch (refreshErr) {
        const status =
          axios.isAxiosError(refreshErr) ? refreshErr.response?.status : undefined;

        if (status === 429) {
          // Rate-limited on the refresh endpoint.
          // The session may still be valid — do NOT clear tokens or log out.
          // Notify UI so it can display a human-readable message.
          rejectPendingRequests(refreshErr);
          if (onRefreshRateLimited) onRefreshRateLimited();
          return Promise.reject(refreshErr);
        }

        // 401, 403, network error, or any other failure → session is gone.
        clearTokens();
        rejectPendingRequests(refreshErr);
        if (onUnauthenticated) onUnauthenticated();
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
