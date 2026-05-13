/**
 * DashboardPage — authenticated user overview.
 *
 * Shows:
 *  - User identity (email, role)
 *  - Account balance summary (read-only, no edit controls)
 *  - MFA status with a link to enable/disable
 *  - Quick-action links: send transfer, view history, manage account
 *
 * This is distinct from /accounts which shows the full account detail view
 * (account number, currency, status badge, creation date).
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getMyAccount } from "@/features/accounts/api";
import { useAuth } from "@/lib/auth";
import { Card } from "@/shared/ui/Card";
import { Alert } from "@/shared/ui/Alert";
import { formatCurrency, formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

export function DashboardPage(): React.ReactElement {
  const { user } = useAuth();

  const {
    data: account,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["account", "me"],
    queryFn: getMyAccount,
    enabled: !!user?.is_verified,
  });

  return (
    <div className="space-y-6">
      {/* Identity summary */}
      <Card title="Welcome">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-500">Signed in as</p>
            <p
              className="text-lg font-semibold text-gray-900"
              data-testid="dashboard-email"
            >
              {user?.email}
            </p>
          </div>
          <span
            className="inline-block bg-indigo-600 text-white text-xs px-3 py-1 rounded-full font-medium capitalize"
            data-testid="dashboard-role"
          >
            {user?.role}
          </span>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Account balance summary */}
        <Card title="Account Balance">
          {!user?.is_verified && (
            <Alert
              type="warning"
              message="Verify your email to view your account."
            />
          )}
          {user?.is_verified && isLoading && (
            <p className="text-gray-400 text-sm">Loading…</p>
          )}
          {user?.is_verified && error && (
            <Alert type="error" message={extractErrorMessage(error)} />
          )}
          {user?.is_verified && account && (
            <div className="space-y-1">
              <p
                className="text-3xl font-bold text-indigo-600"
                data-testid="dashboard-balance"
              >
                {formatCurrency(account.balance, account.currency)}
              </p>
              <p className="text-xs text-gray-400">
                Last updated {formatDateTime(account.updated_at)}
              </p>
            </div>
          )}
        </Card>

        {/* MFA status */}
        <Card title="Security Status">
          {user?.mfa_enabled ? (
            <div data-testid="mfa-status-enabled">
              <div className="flex items-center gap-2 mb-2">
                <span className="inline-block w-2.5 h-2.5 rounded-full bg-green-500" />
                <span className="text-sm font-medium text-green-700">
                  MFA enabled
                </span>
              </div>
              <p className="text-xs text-gray-500 mb-3">
                Step-up authentication is active. High-value transfers ($1000+)
                will require TOTP confirmation.
              </p>
              <Link
                to="/mfa/setup"
                className="text-sm text-indigo-600 hover:underline"
                data-testid="mfa-manage-link"
              >
                Manage MFA
              </Link>
            </div>
          ) : (
            <div data-testid="mfa-status-disabled">
              <div className="flex items-center gap-2 mb-2">
                <span className="inline-block w-2.5 h-2.5 rounded-full bg-red-500" />
                <span className="text-sm font-medium text-red-700">
                  MFA not enabled
                </span>
              </div>
              <p className="text-xs text-gray-500 mb-3">
                High-value transfers ($1000+) require MFA. Enable it to unlock
                large transfers.
              </p>
              <Link
                to="/mfa/setup"
                className="text-sm text-indigo-600 hover:underline font-medium"
                data-testid="mfa-enable-link"
              >
                Enable MFA now
              </Link>
            </div>
          )}
        </Card>
      </div>

      {/* Quick actions */}
      <Card title="Quick Actions">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Link
            to="/transfers"
            className="block bg-indigo-600 text-white text-center rounded-lg py-3 hover:bg-indigo-700 font-medium text-sm"
            data-testid="action-transfer"
          >
            Send Transfer
          </Link>
          <Link
            to="/transactions"
            className="block bg-white border border-gray-200 text-gray-700 text-center rounded-lg py-3 hover:bg-gray-50 font-medium text-sm"
            data-testid="action-history"
          >
            View History
          </Link>
          <Link
            to="/accounts"
            className="block bg-white border border-gray-200 text-gray-700 text-center rounded-lg py-3 hover:bg-gray-50 font-medium text-sm"
            data-testid="action-account"
          >
            Account Details
          </Link>
          <Link
            to="/profile"
            className="block bg-white border border-gray-200 text-gray-700 text-center rounded-lg py-3 hover:bg-gray-50 font-medium text-sm"
            data-testid="action-profile"
          >
            Profile
          </Link>
        </div>
      </Card>
    </div>
  );
}
