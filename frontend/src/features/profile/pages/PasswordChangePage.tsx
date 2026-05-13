import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { changePasswordSchema, type ChangePasswordFormValues } from "../schemas";
import { apiClient } from "@/shared/api/client";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

export function PasswordChangePage(): React.ReactElement {
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ChangePasswordFormValues>({ resolver: zodResolver(changePasswordSchema) });

  async function onSubmit(values: ChangePasswordFormValues): Promise<void> {
    setServerError(null);
    try {
      // In production: POST /api/v1/auth/password/change
      await apiClient.post("/auth/password/change", {
        current_password: values.current_password,
        new_password: values.new_password,
      });
      setSuccess(true);
      setTimeout(() => navigate("/profile"), 1500);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="max-w-md">
      <Card title="Change Password">
        {success ? (
          <Alert type="success" message="Password changed. Redirecting…" />
        ) : (
          <form
            data-testid="change-password-form"
            onSubmit={(e) => void handleSubmit(onSubmit)(e)}
            className="space-y-4"
          >
            {serverError && <Alert type="error" message={serverError} />}
            <Input
              label="Current Password"
              type="password"
              autoComplete="current-password"
              error={errors.current_password?.message}
              {...register("current_password")}
            />
            <Input
              label="New Password"
              type="password"
              autoComplete="new-password"
              error={errors.new_password?.message}
              {...register("new_password")}
            />
            <Input
              label="Confirm New Password"
              type="password"
              autoComplete="new-password"
              error={errors.confirm_password?.message}
              {...register("confirm_password")}
            />
            <Button
              type="submit"
              isLoading={isSubmitting}
              className="w-full"
              data-testid="change-password-submit"
            >
              Change Password
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}
