import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext, type AuthUser } from "@/lib/auth";
import {
  setTokens,
  clearTokens,
  registerUnauthenticatedHandler,
  registerRefreshRateLimitedHandler,
  getRefreshToken,
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

async function fetchCurrentUser(): Promise<AuthUser> {
  const res = await apiClient.get<AuthUser>("/users/me");
  return res.data;
}

function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [user, setUser] = useState<AuthUser | null>(null);
  // isLoading starts true when there is any possibility of a silent re-auth
  // (either an in-memory token or a persisted refresh token in sessionStorage).
  const [isLoading, setIsLoading] = useState(
    () => !!getAccessToken() || !!getRefreshToken()
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
    const data = await fetchCurrentUser();
    setUser(data);
  }, []);

  /**
   * Bootstrap: attempt silent re-authentication on mount.
   *
   * Priority order:
   * 1. If an access token is already in memory (normal navigation), validate it
   *    by calling /users/me and skip the refresh flow.
   * 2. If only a refresh token exists in sessionStorage (page reload / new tab),
   *    call POST /auth/refresh to obtain a fresh access token, then /users/me.
   * 3. If neither token exists, skip bootstrap entirely — user must log in.
   */
  useEffect(() => {
    const storedRefreshToken = getRefreshToken();
    const hasAccessToken = !!getAccessToken();

    // No tokens at all — isLoading was initialised to false, nothing to do.
    if (!hasAccessToken && !storedRefreshToken) {
      return;
    }

    let cancelled = false;

    async function bootstrap(): Promise<void> {
      try {
        if (!hasAccessToken && storedRefreshToken) {
          // Page reload path: exchange stored refresh token for a new access token.
          // DEMO: sessionStorage refresh token enables reload persistence.
          // Production should use HttpOnly secure cookies instead.
          const refreshRes = await axios.post<{
            access_token: string;
            refresh_token: string;
          }>(`${env.apiBaseUrl}/auth/refresh`, {
            refresh_token: storedRefreshToken,
          });

          if (!cancelled) {
            setTokens(refreshRes.data.access_token, refreshRes.data.refresh_token);
          }
        }

        // Validate current access token and populate user state.
        const data = await fetchCurrentUser();
        if (!cancelled) setUser(data);
      } catch {
        // Refresh or /users/me failed — treat as expired session.
        if (!cancelled) {
          clearTokens();
          setSessionExpired(true);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, []); // Intentionally empty: runs once on mount only.

  const login = useCallback(
    (newUser: AuthUser, accessTok: string, refreshTok: string) => {
      setSessionExpired(false);
      setRateLimitMessage(null);
      setTokens(accessTok, refreshTok);
      setUser(newUser);
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
