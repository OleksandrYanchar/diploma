import { Link } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { Card } from "@/shared/ui/Card";
import { formatDateTime } from "@/lib/formatting";

export function ProfilePage(): React.ReactElement {
  const { user } = useAuth();

  if (!user) return <p>Not signed in.</p>;

  return (
    <div className="space-y-6 max-w-xl">
      <Card title="Profile">
        <dl className="space-y-4">
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Email</dt>
            <dd className="mt-1 text-gray-900">{user.email}</dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Email Verified</dt>
            <dd className="mt-1">
              {user.is_verified ? (
                <span className="text-green-700 font-medium">Yes</span>
              ) : (
                <span className="text-red-600 font-medium">
                  No —{" "}
                  <Link to="/verify-email" className="underline">
                    Verify now
                  </Link>
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">MFA Enabled</dt>
            <dd className="mt-1">
              {user.mfa_enabled ? (
                <span className="text-green-700 font-medium">
                  Yes —{" "}
                  <Link to="/mfa/disable" className="text-indigo-600 hover:underline text-sm">
                    Disable
                  </Link>
                </span>
              ) : (
                <span className="text-gray-600">
                  No —{" "}
                  <Link to="/mfa/setup" className="text-indigo-600 hover:underline text-sm">
                    Set up MFA
                  </Link>
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-gray-500 uppercase tracking-wide">Member Since</dt>
            <dd className="mt-1 text-gray-600 text-sm">{formatDateTime(user.created_at)}</dd>
          </div>
        </dl>
      </Card>

      <Card title="Security">
        <div className="space-y-3">
          <Link
            to="/profile/change-password"
            className="block text-indigo-600 hover:underline text-sm"
          >
            Change Password
          </Link>
          <Link to="/mfa/setup" className="block text-indigo-600 hover:underline text-sm">
            Manage Two-Factor Authentication
          </Link>
        </div>
      </Card>
    </div>
  );
}
