import { useEffect, useState } from "react";
import { Link, useSearchParams, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { passwordResetConfirmSchema, type PasswordResetConfirmFormValues } from "../schemas";
import { confirmPasswordReset } from "../api";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

export function PasswordResetConfirmPage(): React.ReactElement {
  const [searchParams] = useSearchParams();
  const tokenFromUrl = searchParams.get("token");
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<PasswordResetConfirmFormValues>({
    resolver: zodResolver(passwordResetConfirmSchema),
  });

  useEffect(() => {
    if (tokenFromUrl) setValue("token", tokenFromUrl);
  }, [tokenFromUrl, setValue]);

  async function onSubmit(values: PasswordResetConfirmFormValues): Promise<void> {
    setServerError(null);
    try {
      await confirmPasswordReset({ token: values.token, new_password: values.new_password });
      setSuccess(true);
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Set New Password</h1>
        </div>
        <Card>
          {success ? (
            <Alert type="success" message="Password reset! Redirecting to sign in…" />
          ) : (
            <form
              data-testid="password-reset-confirm-form"
              onSubmit={(e) => void handleSubmit(onSubmit)(e)}
              className="space-y-4"
            >
              {serverError && <Alert type="error" message={serverError} />}
              <Input
                label="Reset Token"
                type="text"
                placeholder="Paste token from backend logs"
                error={errors.token?.message}
                {...register("token")}
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
                data-testid="password-reset-confirm-submit"
              >
                Reset password
              </Button>
            </form>
          )}
          <div className="mt-4 text-sm text-center">
            <Link to="/login" className="text-indigo-600 hover:underline">
              Back to sign in
            </Link>
          </div>
        </Card>
      </div>
    </div>
  );
}
