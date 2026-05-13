import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { mfaDisableSchema, type MfaDisableFormValues } from "../schemas";
import { disableMfa } from "../api";
import { useAuth } from "@/lib/auth";
import { Input } from "@/shared/ui/Input";
import { PasswordInput } from "@/shared/ui/PasswordInput";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

/** Requires password + current TOTP to disable MFA — prevents casual accidental removal. */
export function MfaDisablePage(): React.ReactElement {
  const { refreshUser } = useAuth();
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<MfaDisableFormValues>({ resolver: zodResolver(mfaDisableSchema) });

  async function onSubmit(values: MfaDisableFormValues): Promise<void> {
    setServerError(null);
    try {
      await disableMfa(values);
      await refreshUser();
      setSuccess(true);
      setTimeout(() => navigate("/profile"), 1500);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <Card title="Disable Two-Factor Authentication">
      <Alert
        type="warning"
        message="Disabling MFA reduces your account security. You must confirm with your current password and a valid TOTP code."
        data-testid="warning-alert"
      />
      <div className="mt-4">
        {success ? (
          <Alert type="success" message="MFA disabled. Redirecting to profile…" />
        ) : (
          <form
            data-testid="mfa-disable-form"
            onSubmit={(e) => void handleSubmit(onSubmit)(e)}
            className="space-y-4"
          >
            {serverError && <Alert type="error" message={serverError} />}
            <PasswordInput
              label="Current Password"
              autoComplete="current-password"
              error={errors.password?.message}
              {...register("password")}
            />
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
              variant="danger"
              isLoading={isSubmitting}
              className="w-full"
              data-testid="mfa-disable-submit"
            >
              Disable MFA
            </Button>
          </form>
        )}
      </div>
    </Card>
  );
}
