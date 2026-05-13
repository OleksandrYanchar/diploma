import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext, type AuthUser } from "@/lib/auth";
import {
  setTokens,
  clearTokens,
  registerUnauthenticatedHandler,
  getAccessToken,
  apiClient,
} from "@/shared/api/client";

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
  // If there is no in-memory token on mount, we are definitely not loading.
  // This avoids calling setState directly inside an effect.
  const [isLoading, setIsLoading] = useState(() => !!getAccessToken());
  const navigate = useNavigate();

  const logout = useCallback(() => {
    clearTokens();
    setUser(null);
    queryClient.clear();
    navigate("/login");
  }, [navigate]);

  // Register the global 401 handler so client.ts can call it.
  useEffect(() => {
    registerUnauthenticatedHandler(logout);
  }, [logout]);

  const refreshUser = useCallback(async (): Promise<void> => {
    const data = await fetchCurrentUser();
    setUser(data);
  }, []);

  // On mount: if there is a token in memory, validate it by fetching /users/me.
  useEffect(() => {
    if (!getAccessToken()) return;

    let cancelled = false;
    fetchCurrentUser()
      .then((data) => {
        if (!cancelled) setUser(data);
      })
      .catch(() => {
        // Token invalid or expired — treat as logged out.
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []); // Intentionally empty: runs once on mount only.

  const login = useCallback(
    (newUser: AuthUser, accessTok: string, refreshTok: string) => {
      setTokens(accessTok, refreshTok);
      setUser(newUser);
    },
    []
  );

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function Providers({ children }: { children: React.ReactNode }): React.ReactElement {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

export { AuthProvider };
