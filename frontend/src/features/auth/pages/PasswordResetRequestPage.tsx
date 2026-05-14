import { useState } from "react";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { passwordResetRequestSchema, type PasswordResetRequestFormValues } from "../schemas";
import { requestPasswordReset } from "../api";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

export function PasswordResetRequestPage(): React.ReactElement {
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<PasswordResetRequestFormValues>({
    resolver: zodResolver(passwordResetRequestSchema),
  });

  async function onSubmit(values: PasswordResetRequestFormValues): Promise<void> {
    setServerError(null);
    try {
      await requestPasswordReset(values.email);
      // Always show success to prevent email enumeration (backend always returns 200).
      setSuccess(true);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Reset Password</h1>
        </div>
        <Card>
          {success ? (
            <div className="space-y-4">
              <Alert
                type="success"
                message="If an account exists with that email, a reset token has been sent. Check backend logs (DEMO MODE)."
              />
              <Link
                to="/password-reset/confirm"
                className="block text-center text-indigo-600 hover:underline text-sm"
              >
                Enter reset token
              </Link>
            </div>
          ) : (
            <form
              data-testid="password-reset-form"
              onSubmit={(e) => void handleSubmit(onSubmit)(e)}
              className="space-y-4"
            >
              {serverError && <Alert type="error" message={serverError} />}
              <Input
                label="Email"
                type="email"
                autoComplete="email"
                error={errors.email?.message}
                {...register("email")}
              />
              <Button
                type="submit"
                isLoading={isSubmitting}
                className="w-full"
                data-testid="password-reset-submit"
              >
                Send reset token
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
