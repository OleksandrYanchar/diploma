import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { mfaLoginSchema, type MfaLoginFormValues } from "../schemas";
import { login, isMfaRequired } from "@/features/auth/api";
import { useAuth } from "@/lib/auth";
import { apiClient } from "@/shared/api/client";
import type { AuthUser } from "@/lib/auth";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

interface LocationState {
  email?: string;
  password?: string;
}

/**
 * Shown when the backend returns mfa_required:true on login.
 * Re-submits the original credentials with the TOTP code appended.
 */
export function MfaLoginPage(): React.ReactElement {
  const { login: authLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;
  const [serverError, setServerError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<MfaLoginFormValues>({ resolver: zodResolver(mfaLoginSchema) });

  if (!state?.email || !state?.password) {
    // If we landed here without credentials, go back to login.
    navigate("/login");
    return <></>;
  }

  async function onSubmit(values: MfaLoginFormValues): Promise<void> {
    setServerError(null);
    try {
      const result = await login({
        email: state!.email!,
        password: state!.password!,
        totp_code: values.totp_code,
      });

      if (isMfaRequired(result)) {
        setServerError("Invalid TOTP code. Try again.");
        return;
      }

      const userRes = await apiClient.get<AuthUser>("/users/me", {
        headers: { Authorization: `Bearer ${result.access_token}` },
      });
      authLogin(userRes.data, result.access_token, result.refresh_token);
      navigate("/dashboard");
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Two-Factor Authentication</h1>
          <p className="text-gray-500 mt-2 text-sm">
            Enter the 6-digit code from your authenticator app.
          </p>
        </div>
        <Card>
          <form
            data-testid="mfa-login-form"
            onSubmit={(e) => void handleSubmit(onSubmit)(e)}
            className="space-y-4"
          >
            {serverError && <Alert type="error" message={serverError} data-testid="mfa-required-banner" />}
            <Input
              label="TOTP Code"
              type="text"
              inputMode="numeric"
              maxLength={6}
              placeholder="000000"
              autoFocus
              error={errors.totp_code?.message}
              data-testid="totp-input"
              {...register("totp_code")}
            />
            <Button
              type="submit"
              isLoading={isSubmitting}
              className="w-full"
              data-testid="mfa-login-submit"
            >
              Verify
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}
