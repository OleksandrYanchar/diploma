/**
 * Axios HTTP client with centralised auth header injection and 401 handling.
 *
 * Security design:
 *  - Access token is kept in-memory only (never localStorage/sessionStorage).
 *  - On 401 the interceptor attempts one silent refresh using the refresh token
 *    (also kept in-memory). If refresh fails, auth state is cleared and the
 *    user is redirected to /login.
 *  - Tokens are never logged to the console.
 */
import axios, { type AxiosRequestConfig, type InternalAxiosRequestConfig } from "axios";
import { env } from "@/shared/config/env";

// In-memory token store — module-level so it survives re-renders.
// This is intentionally NOT stored in localStorage or sessionStorage.
// Trade-off: tokens are lost on page refresh (user must log in again),
// which is the correct behaviour for a security-sensitive application.
let accessToken: string | null = null;
let refreshToken: string | null = null;

// Callback to notify AuthContext that auth state was cleared.
let onUnauthenticated: (() => void) | null = null;

export function setTokens(access: string, refresh: string): void {
  accessToken = access;
  refreshToken = refresh;
}

export function clearTokens(): void {
  accessToken = null;
  refreshToken = null;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function getRefreshToken(): string | null {
  return refreshToken;
}

export function registerUnauthenticatedHandler(handler: () => void): void {
  onUnauthenticated = handler;
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

// Flag to prevent concurrent refresh attempts.
let isRefreshing = false;
let pendingRequests: Array<(token: string) => void> = [];

function processPendingRequests(token: string): void {
  pendingRequests.forEach((resolve) => resolve(token));
  pendingRequests = [];
}

// Response interceptor: on 401 attempt silent token refresh.
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retried?: boolean };

    // Only handle 401 on non-retry, non-refresh requests.
    if (
      error.response?.status === 401 &&
      !originalRequest._retried &&
      originalRequest.url !== "/auth/refresh"
    ) {
      if (isRefreshing) {
        // Queue this request to retry after the ongoing refresh completes.
        return new Promise((resolve, reject) => {
          pendingRequests.push((token: string) => {
            if (originalRequest.headers) {
              (originalRequest.headers as Record<string, string>)[
                "Authorization"
              ] = `Bearer ${token}`;
            }
            resolve(apiClient(originalRequest));
          });
          // Reject all pending if refresh ultimately fails.
          void reject;
        });
      }

      originalRequest._retried = true;
      isRefreshing = true;

      try {
        if (!refreshToken) throw new Error("No refresh token");

        const response = await axios.post<{ access_token: string; refresh_token: string }>(
          `${env.apiBaseUrl}/auth/refresh`,
          { refresh_token: refreshToken }
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
      } catch {
        // Refresh failed: clear everything and redirect to login.
        clearTokens();
        pendingRequests = [];
        if (onUnauthenticated) onUnauthenticated();
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
