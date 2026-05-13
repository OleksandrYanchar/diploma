import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext, type AuthUser } from "@/lib/auth";
import {
  setTokens,
  clearTokens,
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
// fire twice per page load. On the second fire it reads the same (unrotated)
// refresh token from sessionStorage and re-submits it to /auth/refresh. The
// backend treats this as a reuse event (SR-08) and bulk-revokes all user
// tokens, logging the user out immediately.
//
// Placing the fetch in a module-level variable makes it a true singleton: both
// mount invocations call getBootstrapUser() and get the same Promise back.
// Only one network request is ever made per page-load regardless of how many
// times React mounts the component.
//
// Rapid F5 limitation: if the user reloads faster than the /auth/refresh
// network round-trip, the next page load reads the still-unrotated token from
// sessionStorage and triggers backend reuse detection. This is an inherent
// limitation of sessionStorage + server-side token rotation. The safest
// production fix is HttpOnly cookies (the browser manages the cookie
// atomically, so a second request carries the already-rotated cookie). For
// this demo the UX degrades gracefully: a clean "session expired" message is
// shown rather than a confusing broken state.
//
// DEMO: sessionStorage refresh token for reload persistence. Production should
// use HttpOnly secure cookies — they are browser-managed and immune to this
// race.
// ---------------------------------------------------------------------------
let _bootstrapPromise: Promise<AuthUser | null> | null = null;

/**
 * Reset the module-level bootstrap singleton.
 * Called after login() and logout() so that a subsequent page reload (or
 * re-login in the same JS runtime) re-runs the bootstrap flow with the new
 * token set rather than returning the previous promise's cached result.
 * Not exported — only AuthProvider's login/logout callbacks call this.
 */
function resetBootstrap(): void {
  _bootstrapPromise = null;
}

/**
 * Attempt silent re-authentication using any tokens available at the time of
 * the first call. Returns the authenticated user or null if no valid session
 * exists. Subsequent calls within the same page-load return the same Promise.
 */
function getBootstrapUser(): Promise<AuthUser | null> {
  if (_bootstrapPromise !== null) return _bootstrapPromise;

  // Snapshot token availability at the moment of the first call. Reading
  // sessionStorage here — before any React cleanup — ensures we see the token
  // that was written by the previous page load's setTokens() call.
  const storedRT = sessionStorage.getItem("rt");
  const hasAccessToken = !!getAccessToken();

  if (!storedRT && !hasAccessToken) {
    // No tokens at all — first visit or already logged out.
    _bootstrapPromise = Promise.resolve(null);
    return _bootstrapPromise;
  }

  _bootstrapPromise = (async (): Promise<AuthUser | null> => {
    try {
      if (!hasAccessToken && storedRT) {
        // Page reload path: exchange stored refresh token for a new access +
        // refresh pair. Write the rotated tokens immediately — before any
        // React effects can read sessionStorage again — so there is no window
        // in which the old token is visible.
        // In production: POST /api/auth/refresh (HttpOnly cookie carries the RT).
        const refreshRes = await axios.post<{
          access_token: string;
          refresh_token: string;
        }>(`${env.apiBaseUrl}/auth/refresh`, { refresh_token: storedRT });

        // setTokens writes access token to memory and refresh token to
        // sessionStorage atomically from the caller's perspective.
        setTokens(refreshRes.data.access_token, refreshRes.data.refresh_token);
      }

      // Validate the (now-fresh) access token and populate user state.
      // In production: GET /api/users/me
      const userRes = await apiClient.get<AuthUser>("/users/me");
      return userRes.data;
    } catch {
      // Refresh or /users/me failed — clear any stale tokens so subsequent
      // calls (e.g., from the 401 interceptor) do not try to use them.
      clearTokens();
      return null;
    }
  })();

  return _bootstrapPromise;
}

function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [user, setUser] = useState<AuthUser | null>(null);
  // isLoading starts true when there is any possibility of a silent re-auth
  // (either an in-memory token or a persisted refresh token in sessionStorage).
  // Starting it with a lazy initializer avoids a render with isLoading=false
  // when tokens ARE present — which could briefly show /login before bootstrap
  // completes.
  const [isLoading, setIsLoading] = useState(
    () => !!getAccessToken() || !!sessionStorage.getItem("rt")
  );
  // sessionExpired is set when silent refresh fails so the login page can
  // display an explanatory message rather than just appearing blank.
  const [sessionExpired, setSessionExpired] = useState(false);
  // rateLimited is set when the refresh endpoint returns 429. The user is
  // still considered authenticated; the UI should surface the message.
  const [rateLimitMessage, setRateLimitMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  const logout = useCallback(() => {
    clearTokens();
    // Reset the singleton so the next login + page-reload bootstraps cleanly
    // with the new token instead of returning this (now-invalid) promise.
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
   * Priority order (handled inside getBootstrapUser):
   * 1. Access token already in memory → call /users/me to validate and hydrate.
   * 2. Refresh token in sessionStorage → POST /auth/refresh, then /users/me.
   * 3. No tokens → resolve immediately with null.
   */
  useEffect(() => {
    // Capture whether a refresh token was present when this effect ran.
    // getBootstrapUser() may clear it on failure, so we snapshot it now.
    const hadRefreshToken = !!sessionStorage.getItem("rt");

    void getBootstrapUser().then((bootstrappedUser) => {
      if (bootstrappedUser) {
        setUser(bootstrappedUser);
      } else if (hadRefreshToken) {
        // A refresh token existed but bootstrap failed (expired, reused, or
        // revoked). Show the "session expired" banner on the login page.
        setSessionExpired(true);
      }
      // If neither condition is true the user simply has no session — first
      // visit or explicit logout. Do not set sessionExpired in that case.
      setIsLoading(false);
    });
  }, []); // Empty dep array: runs once per mount; safe under StrictMode because
          // both mounts share the module-level singleton promise.

  const login = useCallback(
    (newUser: AuthUser, accessTok: string, refreshTok: string) => {
      setSessionExpired(false);
      setRateLimitMessage(null);
      setTokens(accessTok, refreshTok);
      setUser(newUser);
      // Reset the singleton so a subsequent page reload will bootstrap with
      // the newly issued refresh token rather than the previous promise result.
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
