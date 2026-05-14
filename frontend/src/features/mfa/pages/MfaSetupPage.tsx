import { useState } from "react";
import { Link } from "react-router-dom";
import { setupMfa, type MfaSetupResponse } from "../api";
import { useAuth } from "@/lib/auth";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

/**
 * Calls POST /auth/mfa/setup, displays the QR code and raw TOTP secret.
 * User scans with their authenticator app, then proceeds to /mfa/enable.
 */
export function MfaSetupPage(): React.ReactElement {
  const { user } = useAuth();
  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSetup(): Promise<void> {
    setError(null);
    setIsLoading(true);
    try {
      const data = await setupMfa();
      setSetupData(data);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  if (!user?.is_verified) {
    return (
      <Card title="MFA Setup">
        <Alert type="warning" message="You must verify your email before setting up MFA." />
      </Card>
    );
  }

  if (user.mfa_enabled) {
    return (
      <Card title="MFA Setup">
        <Alert type="info" message="MFA is already enabled on your account." />
        <div className="mt-4">
          <Link to="/mfa/disable" className="text-indigo-600 hover:underline text-sm">
            Disable MFA
          </Link>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Set Up Two-Factor Authentication">
      {error && <Alert type="error" message={error} />}
      {!setupData ? (
        <div className="space-y-4">
          <p className="text-gray-600 text-sm">
            Protect your account with a TOTP authenticator app (Google Authenticator, Authy, etc.).
          </p>
          <Button onClick={() => void handleSetup()} isLoading={isLoading}>
            Generate QR Code
          </Button>
        </div>
      ) : (
        <div className="space-y-6">
          <div>
            <p className="text-sm text-gray-600 mb-3">
              Scan this QR code with your authenticator app:
            </p>
            <img
              src={`data:image/png;base64,${setupData.qr_code_base64}`}
              alt="TOTP QR Code"
              className="border border-gray-200 rounded"
              width={200}
              height={200}
            />
          </div>
          <div>
            <p className="text-sm text-gray-600 mb-1">Or enter the secret manually:</p>
            <code className="block bg-gray-100 rounded px-3 py-2 text-sm font-mono break-all">
              {setupData.secret}
            </code>
          </div>
          <Alert
            type="info"
            message="After scanning, click below to enter the code from your app and enable MFA."
          />
          <Link
            to="/mfa/enable"
            className="inline-block bg-indigo-600 text-white px-4 py-2 rounded text-sm hover:bg-indigo-700"
          >
            Proceed to enable MFA
          </Link>
        </div>
      )}
    </Card>
  );
}
