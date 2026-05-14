import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getMyAccount } from "../api";
import { useAuth } from "@/lib/auth";
import { Card } from "@/shared/ui/Card";
import { Alert } from "@/shared/ui/Alert";
import { formatCurrency, formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

function accountStatusClass(status: string | undefined): string {
  switch (status?.toUpperCase()) {
    case "ACTIVE":   return "bg-green-100 text-green-800";
    case "FROZEN":   return "bg-yellow-100 text-yellow-800";
    case "INACTIVE": return "bg-red-100 text-red-800";
    default:         return "bg-gray-100 text-gray-500";
  }
}

export function AccountPage(): React.ReactElement {
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

  if (!user?.is_verified) {
    return (
      <Card title="My Account">
        <Alert
          type="warning"
          message="Email not verified. Verify your email to access your account. Check backend logs for your verification token."
        />
        <div className="mt-4">
          <Link to="/verify-email" className="text-indigo-600 hover:underline text-sm">
            Verify email
          </Link>
        </div>
      </Card>
    );
  }

  if (isLoading) {
    return <Card title="My Account"><p className="text-gray-500">Loading…</p></Card>;
  }

  if (error) {
    return (
      <Card title="My Account">
        <Alert type="error" message={extractErrorMessage(error)} />
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card title="My Account">
        <dl className="grid grid-cols-2 gap-4">
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Account Number</dt>
            <dd
              className="mt-1 text-lg font-mono font-semibold text-gray-900"
              data-testid="account-number"
            >
              {account?.account_number}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Balance</dt>
            <dd
              className="mt-1 text-2xl font-bold text-indigo-600"
              data-testid="account-balance"
            >
              {account ? formatCurrency(account.balance, account.currency) : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Status</dt>
            <dd className="mt-1">
              <span
                data-testid="account-status"
                className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${accountStatusClass(account?.status)}`}
              >
                {account?.status}
              </span>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Currency</dt>
            <dd className="mt-1 text-gray-900">{account?.currency}</dd>
          </div>
          <div className="col-span-2">
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Created</dt>
            <dd className="mt-1 text-gray-600 text-sm">
              {account ? formatDateTime(account.created_at) : "—"}
            </dd>
          </div>
        </dl>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Link
          to="/transfers"
          className="block bg-indigo-600 text-white text-center rounded-lg py-4 hover:bg-indigo-700 font-medium"
        >
          Send Transfer
        </Link>
        <Link
          to="/transactions"
          className="block bg-white border border-gray-200 text-gray-700 text-center rounded-lg py-4 hover:bg-gray-50 font-medium"
        >
          View History
        </Link>
      </div>
    </div>
  );
}
