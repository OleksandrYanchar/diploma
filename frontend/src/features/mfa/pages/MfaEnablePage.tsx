import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { mfaEnableSchema, type MfaEnableFormValues } from "../schemas";
import { enableMfa } from "../api";
import { useAuth } from "@/lib/auth";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

/** Verifies the first TOTP code to confirm the secret is correctly set up, then enables MFA. */
export function MfaEnablePage(): React.ReactElement {
  const { refreshUser } = useAuth();
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<MfaEnableFormValues>({ resolver: zodResolver(mfaEnableSchema) });

  async function onSubmit(values: MfaEnableFormValues): Promise<void> {
    setServerError(null);
    try {
      await enableMfa(values.totp_code);
      await refreshUser();
      setSuccess(true);
      setTimeout(() => navigate("/profile"), 1500);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <Card title="Enable Two-Factor Authentication">
      {success ? (
        <Alert type="success" message="MFA enabled! Redirecting to profile…" />
      ) : (
        <form
          data-testid="mfa-enable-form"
          onSubmit={(e) => void handleSubmit(onSubmit)(e)}
          className="space-y-4"
        >
          {serverError && <Alert type="error" message={serverError} />}
          <p className="text-sm text-gray-600">
            Enter the 6-digit code from your authenticator app to confirm setup.
          </p>
          <Input
            label="TOTP Code"
            type="text"
            inputMode="numeric"
            maxLength={6}
            placeholder="000000"
            error={errors.totp_code?.message}
            data-testid="totp-input"
            {...register("totp_code")}
          />
          <Button
            type="submit"
            isLoading={isSubmitting}
            className="w-full"
            data-testid="mfa-enable-submit"
          >
            Enable MFA
          </Button>
        </form>
      )}
    </Card>
  );
}
