import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { apiClient } from "@/shared/api/client";

interface NavLinkProps {
  to: string;
  testId: string;
  children: React.ReactNode;
}

function NavLink({ to, testId, children }: NavLinkProps): React.ReactElement {
  return (
    <Link
      to={to}
      data-testid={`nav-${testId}`}
      className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors"
    >
      {children}
    </Link>
  );
}

export function Layout({ children }: { children: React.ReactNode }): React.ReactElement {
  const { user, logout, rateLimitMessage, clearRateLimitMessage } = useAuth();
  const navigate = useNavigate();

  async function handleLogout(): Promise<void> {
    try {
      // POST /auth/logout with no body — the browser sends the HttpOnly zt_rt
      // cookie automatically via withCredentials. The backend clears the cookie.
      await apiClient.post("/auth/logout");
    } catch {
      // Best-effort logout — clear client state regardless.
    }
    logout();
    navigate("/login");
  }

  const isAdmin = user?.role === "admin";
  const isAdminOrAuditor = user?.role === "admin" || user?.role === "auditor";

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-1">
              <Link
                to="/dashboard"
                className="text-white font-bold text-lg mr-4"
                data-testid="nav-brand"
              >
                ZeroTrust Bank
              </Link>
              <NavLink to="/accounts" testId="accounts">Account</NavLink>
              <NavLink to="/transfers" testId="transfers">Transfer</NavLink>
              <NavLink to="/transactions" testId="transactions">History</NavLink>
              <NavLink to="/profile" testId="profile">Profile</NavLink>
              <NavLink to="/mfa/setup" testId="mfa">MFA</NavLink>
              {isAdminOrAuditor && (
                <NavLink to="/admin/audit-logs" testId="admin">Admin</NavLink>
              )}
              {isAdmin && (
                <NavLink to="/admin/users" testId="admin-users">Users</NavLink>
              )}
            </div>
            <div className="flex items-center space-x-4">
              {user && (
                <span className="text-gray-400 text-sm" data-testid="nav-user-email">
                  {user.email}
                </span>
              )}
              <button
                onClick={() => void handleLogout()}
                data-testid="nav-logout"
                className="text-gray-300 hover:text-white text-sm font-medium transition-colors"
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Rate-limit banner: shown when the silent token refresh received 429. */}
      {rateLimitMessage && (
        <div
          className="bg-yellow-400 text-yellow-900 text-sm text-center py-2 px-4 flex items-center justify-center gap-4"
          data-testid="rate-limit-banner"
        >
          <span>{rateLimitMessage}</span>
          <button
            onClick={clearRateLimitMessage}
            className="underline font-semibold text-yellow-900 hover:text-yellow-700"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Unverified user banner */}
      {user && !user.is_verified && (
        <div
          className="bg-yellow-400 text-yellow-900 text-sm text-center py-2 px-4"
          data-testid="unverified-banner"
        >
          Email not verified. Check backend logs for your verification token.{" "}
          <Link to="/verify-email" className="underline font-semibold">
            Verify now
          </Link>
        </div>
      )}

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">{children}</main>
    </div>
  );
}
