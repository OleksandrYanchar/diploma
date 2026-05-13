/**
 * Axios HTTP client with centralised auth header injection and 401 handling.
 *
 * Security design:
 *  - Access token is kept in-memory only (never localStorage/sessionStorage).
 *  - Refresh token is persisted in sessionStorage under key "rt" so that a
 *    page reload or new tab in the same session can silently re-authenticate.
 *    DEMO: refresh token stored in sessionStorage for page-reload UX.
 *    Production should use HttpOnly secure cookies instead.
 *  - On 401 the interceptor attempts one silent refresh using the refresh token.
 *    If refresh fails (401/403 or other), auth state is cleared and the user is
 *    redirected to /login. If refresh returns 429, the session is NOT cleared —
 *    the rate-limit is transient and the user is still authenticated.
 *  - Concurrent 401s are queued behind a single in-flight refresh promise.
 *  - Tokens are never logged to the console.
 */
import axios, { type AxiosRequestConfig, type InternalAxiosRequestConfig } from "axios";
import { env } from "@/shared/config/env";

/** sessionStorage key for the persisted refresh token. */
const RT_STORAGE_KEY = "rt";

// In-memory access token — never written to any storage.
let accessToken: string | null = null;

/**
 * Write both tokens: access token to memory, refresh token to sessionStorage.
 * DEMO: sessionStorage gives reload persistence without the XSS risk of
 * localStorage for long-lived credentials. Production should use HttpOnly cookies.
 */
export function setTokens(access: string, refresh: string): void {
  accessToken = access;
  sessionStorage.setItem(RT_STORAGE_KEY, refresh);
}

/** Remove all tokens from memory and sessionStorage. */
export function clearTokens(): void {
  accessToken = null;
  sessionStorage.removeItem(RT_STORAGE_KEY);
}

export function getAccessToken(): string | null {
  return accessToken;
}

/** Read the persisted refresh token from sessionStorage. */
export function getRefreshToken(): string | null {
  return sessionStorage.getItem(RT_STORAGE_KEY);
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
        const storedRefreshToken = getRefreshToken();
        if (!storedRefreshToken) throw new Error("No refresh token");

        const response = await axios.post<{ access_token: string; refresh_token: string }>(
          `${env.apiBaseUrl}/auth/refresh`,
          { refresh_token: storedRefreshToken }
        );

        const newAccess = response.data.access_token;
        const newRefresh = response.data.refresh_token;

        setTokens(newAccess, newRefresh);
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
