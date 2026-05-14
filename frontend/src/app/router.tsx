import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Providers, AuthProvider } from "./providers";
import { Layout } from "./Layout";
import { useAuth } from "@/lib/auth";

// Auth pages
import { LoginPage } from "@/features/auth/pages/LoginPage";
import { RegisterPage } from "@/features/auth/pages/RegisterPage";
import { VerifyEmailPage } from "@/features/auth/pages/VerifyEmailPage";
import { PasswordResetRequestPage } from "@/features/auth/pages/PasswordResetRequestPage";
import { PasswordResetConfirmPage } from "@/features/auth/pages/PasswordResetConfirmPage";

// MFA pages
import { MfaSetupPage } from "@/features/mfa/pages/MfaSetupPage";
import { MfaEnablePage } from "@/features/mfa/pages/MfaEnablePage";
import { MfaDisablePage } from "@/features/mfa/pages/MfaDisablePage";
import { MfaLoginPage } from "@/features/mfa/pages/MfaLoginPage";

// Dashboard
import { DashboardPage } from "@/features/dashboard/pages/DashboardPage";

// Account / transfer / history
import { AccountPage } from "@/features/accounts/pages/AccountPage";
import { TransferPage } from "@/features/transfers/pages/TransferPage";
import { HistoryPage } from "@/features/transactions/pages/HistoryPage";

// Profile
import { ProfilePage } from "@/features/profile/pages/ProfilePage";
import { PasswordChangePage } from "@/features/profile/pages/PasswordChangePage";

// Admin
import { AdminUsersPage } from "@/features/admin/pages/AdminUsersPage";
import { AdminAuditLogsPage } from "@/features/admin/pages/AdminAuditLogsPage";
import { AdminSecurityEventsPage } from "@/features/admin/pages/AdminSecurityEventsPage";

/** Redirect to /login if not authenticated. */
function ProtectedRoute({ children }: { children: React.ReactNode }): React.ReactElement {
  const { user, isLoading } = useAuth();
  if (isLoading) return <div className="p-8 text-center text-gray-500">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

/** Redirect to /dashboard if not admin or auditor. */
function AdminRoute({
  children,
  allowAuditor = false,
}: {
  children: React.ReactNode;
  allowAuditor?: boolean;
}): React.ReactElement {
  const { user, isLoading } = useAuth();
  if (isLoading) return <div className="p-8 text-center text-gray-500">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  const isAdmin = user.role === "admin";
  const isAuditor = user.role === "auditor";
  if (!isAdmin && !(allowAuditor && isAuditor)) return <Navigate to="/dashboard" replace />;
  return <Layout>{children}</Layout>;
}

/** Redirect to /dashboard if already authenticated. */
function GuestRoute({ children }: { children: React.ReactNode }): React.ReactElement {
  const { user } = useAuth();
  if (user) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

function AppRoutes(): React.ReactElement {
  const { user, isLoading } = useAuth();

  if (isLoading) return <div className="p-8 text-center text-gray-500">Loading…</div>;

  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<GuestRoute><LoginPage /></GuestRoute>} />
      <Route path="/mfa/login" element={<MfaLoginPage />} />
      <Route path="/register" element={<GuestRoute><RegisterPage /></GuestRoute>} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/password-reset" element={<GuestRoute><PasswordResetRequestPage /></GuestRoute>} />
      <Route path="/password-reset/confirm" element={<GuestRoute><PasswordResetConfirmPage /></GuestRoute>} />

      {/* Protected routes */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/accounts"
        element={
          <ProtectedRoute>
            <AccountPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/transfers"
        element={
          <ProtectedRoute>
            <TransferPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/transactions"
        element={
          <ProtectedRoute>
            <HistoryPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <ProfilePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/profile/change-password"
        element={
          <ProtectedRoute>
            <PasswordChangePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/mfa/setup"
        element={
          <ProtectedRoute>
            <MfaSetupPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/mfa/enable"
        element={
          <ProtectedRoute>
            <MfaEnablePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/mfa/disable"
        element={
          <ProtectedRoute>
            <MfaDisablePage />
          </ProtectedRoute>
        }
      />

      {/* Admin routes */}
      <Route
        path="/admin"
        element={<Navigate to="/admin/users" replace />}
      />
      <Route
        path="/admin/users"
        element={
          <AdminRoute>
            <AdminUsersPage />
          </AdminRoute>
        }
      />
      <Route
        path="/admin/audit-logs"
        element={
          <AdminRoute allowAuditor>
            <AdminAuditLogsPage />
          </AdminRoute>
        }
      />
      <Route
        path="/admin/security-events"
        element={
          <AdminRoute allowAuditor>
            <AdminSecurityEventsPage />
          </AdminRoute>
        }
      />

      {/* Default redirect */}
      <Route
        path="/"
        element={<Navigate to={user ? "/dashboard" : "/login"} replace />}
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export function AppRouter(): React.ReactElement {
  return (
    <BrowserRouter>
      <Providers>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </Providers>
    </BrowserRouter>
  );
}
