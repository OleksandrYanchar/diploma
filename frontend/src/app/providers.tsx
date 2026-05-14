import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext, type AuthUser } from "@/lib/auth";
import {
  setTokens,
  clearTokens,
  resetInterceptorState,
  registerUnauthenticatedHandler,
  registerRefreshRateLimitedHandler,
  getAccessToken,
  apiClient,
} from "@/shared/api/client";
import axios from "axios";
import { env } from "@/shared/config/env";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
});

// ---------------------------------------------------------------------------
// Bootstrap singleton — module-level, initialized once per page-load.
//
// React StrictMode in development intentionally mounts → unmounts → remounts
// every component to expose side-effect bugs. A plain useEffect would therefore
// fire twice per page load. On the second fire it would re-submit the refresh
// request, which the backend could treat as a token reuse event (SR-08) and
// bulk-revoke all user tokens.
//
// Placing the fetch in a module-level variable makes it a true singleton: both
// mount invocations call getBootstrapUser() and get the same Promise back.
// Only one network request is ever made per page-load regardless of how many
// times React mounts the component.
//
// With HttpOnly cookies, the browser sends the zt_rt cookie atomically on each
// request. There is no client-side storage race — the browser guarantees the
// rotated cookie from the first /auth/refresh response is used on any
// subsequent request in that session.
// ---------------------------------------------------------------------------

interface BootstrapResult {
  user: AuthUser | null;
  rateLimited: boolean;
}

let _bootstrapPromise: Promise<BootstrapResult> | null = null;

/**
 * Reset the module-level bootstrap singleton.
 * Called after login() and logout() so that a subsequent page reload (or
 * re-login in the same JS runtime) re-runs the bootstrap flow rather than
 * returning the previous promise's cached result.
 * Not exported — only AuthProvider's login/logout callbacks call this.
 */
function resetBootstrap(): void {
  _bootstrapPromise = null;
}

/**
 * Attempt silent re-authentication on page load using the HttpOnly zt_rt cookie.
 * Returns the authenticated user on success, or null on any failure.
 * Subsequent calls within the same page-load return the same Promise
 * (singleton pattern — safe under React StrictMode double-mount).
 *
 * Priority order:
 * 1. Access token already in memory (normal in-app navigation) → skip refresh,
 *    call /users/me to validate and hydrate user state.
 * 2. No in-memory access token → POST /auth/refresh (cookie sent automatically),
 *    then /users/me.
 * 3. Any failure (401 first-visit, 401 expired, 500, network error) → null.
 *
 * The "session expired" banner is NOT driven from this path. It is driven
 * exclusively by the response interceptor's onUnauthenticated callback, which
 * fires when a mid-session API call returns 401. Bootstrap failures are always
 * silent — they could be a first visit, expired session, or server error, and
 * none of those cases warrant a "session expired" message on page load.
 */
function getBootstrapUser(): Promise<BootstrapResult> {
  if (_bootstrapPromise !== null) return _bootstrapPromise;

  const hasAccessToken = !!getAccessToken();

  _bootstrapPromise = (async (): Promise<BootstrapResult> => {
    try {
      if (!hasAccessToken) {
        // Page reload path: ask the backend to rotate the HttpOnly cookie and
        // return a fresh access token. The browser sends the zt_rt cookie
        // automatically because withCredentials is set on the axios instance.
        // In production: POST /api/auth/refresh
        const refreshRes = await axios.post<{ access_token: string }>(
          `${env.apiBaseUrl}/auth/refresh`,
          undefined,
          { withCredentials: true }
        );
        setTokens(refreshRes.data.access_token);
      }

      // Validate the (now-fresh) access token and populate user state.
      // In production: GET /api/users/me
      const userRes = await apiClient.get<AuthUser>("/users/me");
      return { user: userRes.data, rateLimited: false };
    } catch (err) {
      const is429 = axios.isAxiosError(err) && err.response?.status === 429;
      if (!is429) {
        // 401 (no cookie / expired), 500, or network error — session is gone.
        clearTokens();
      }
      // On 429: do not clear the in-memory access token. The cookie is still
      // valid. Reset the singleton so the next page load retries fresh rather
      // than serving this cached rate-limited result.
      if (is429) _bootstrapPromise = null;
      return { user: null, rateLimited: is429 };
    }
  })();

  return _bootstrapPromise;
}

function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [user, setUser] = useState<AuthUser | null>(null);
  // isLoading always starts true because we cannot detect from JavaScript
  // whether the HttpOnly zt_rt cookie is present. We always attempt bootstrap
  // and resolve quickly: the backend returns 401 fast on a first visit, and
  // on a reload it returns a fresh access token.
  const [isLoading, setIsLoading] = useState(true);
  // sessionExpired is set when a cookie existed but the session was revoked or
  // expired, so the login page can display an explanatory banner.
  const [sessionExpired, setSessionExpired] = useState(false);
  // rateLimited is set when the refresh endpoint returns 429. The user is
  // still considered authenticated; the UI should surface the message.
  const [rateLimitMessage, setRateLimitMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  const logout = useCallback(() => {
    clearTokens();
    // Drain any queued interceptor requests from the current session so they
    // cannot be replayed or resolved with a stale token after logout.
    resetInterceptorState();
    // Reset the singleton so the next login + page-reload bootstraps cleanly.
    resetBootstrap();
    setUser(null);
    setSessionExpired(false);
    setRateLimitMessage(null);
    queryClient.clear();
    navigate("/login");
  }, [navigate]);

  // Register global interceptor callbacks so client.ts can signal auth events.
  useEffect(() => {
    registerUnauthenticatedHandler(() => {
      clearTokens();
      setUser(null);
      setSessionExpired(true);
      queryClient.clear();
      navigate("/login");
    });
    registerRefreshRateLimitedHandler(() => {
      setRateLimitMessage("Too many requests — please wait a moment before retrying.");
    });
  }, [navigate]);

  const refreshUser = useCallback(async (): Promise<void> => {
    const res = await apiClient.get<AuthUser>("/users/me");
    setUser(res.data);
  }, []);

  /**
   * Bootstrap: attempt silent re-authentication on mount.
   *
   * Delegates to the module-level getBootstrapUser() singleton so that React
   * StrictMode's double-mount fires exactly one network request. Both mount
   * invocations subscribe to the same already-running promise.
   *
   * sessionExpired is NOT set from the bootstrap path. Any failure here
   * (first visit, expired cookie, or server error) is indistinguishable on the
   * client and none warrants a "session expired" banner on page load.
   * The banner is only shown when onUnauthenticated fires mid-session.
   */
  useEffect(() => {
    void getBootstrapUser().then(({ user: bootstrappedUser, rateLimited }) => {
      if (bootstrappedUser !== null) {
        setUser(bootstrappedUser);
      }
      if (rateLimited) {
        setRateLimitMessage(
          "Too many session refresh attempts — please try again shortly."
        );
      }
      setIsLoading(false);
    });
  }, []); // Empty dep array: runs once per mount; safe under StrictMode because
          // both mounts share the module-level singleton promise.

  const login = useCallback(
    (newUser: AuthUser, accessTok: string) => {
      setSessionExpired(false);
      setRateLimitMessage(null);
      setTokens(accessTok);
      setUser(newUser);
      // Reset the singleton so a subsequent page reload will bootstrap using
      // the newly issued HttpOnly cookie rather than the previous promise result.
      resetBootstrap();
    },
    []
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        sessionExpired,
        rateLimitMessage,
        login,
        logout,
        refreshUser,
        clearRateLimitMessage: () => setRateLimitMessage(null),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function Providers({ children }: { children: React.ReactNode }): React.ReactElement {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

export { AuthProvider };
