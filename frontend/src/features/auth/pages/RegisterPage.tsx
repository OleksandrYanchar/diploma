import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { registerSchema, type RegisterFormValues } from "../schemas";
import { register as registerUser } from "../api";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";
import { PasswordRequirements } from "@/shared/ui/PasswordRequirements";

export function RegisterPage(): React.ReactElement {
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormValues>({ resolver: zodResolver(registerSchema) });
  const watchedPassword = watch("password", "");

  async function onSubmit(values: RegisterFormValues): Promise<void> {
    setServerError(null);
    try {
      await registerUser({ email: values.email, password: values.password });
      setSuccess(true);
      setTimeout(() => navigate("/verify-email"), 2000);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">ZeroTrust Bank</h1>
          <p className="text-gray-500 mt-2">Create your account</p>
        </div>
        <Card>
          {success ? (
            <Alert
              type="success"
              message="Account created! Check backend logs for your verification token. Redirecting…"
            />
          ) : (
            <form
              data-testid="register-form"
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
              <Input
                label="Password"
                type="password"
                autoComplete="new-password"
                error={errors.password?.message}
                {...register("password")}
              />
              <PasswordRequirements password={watchedPassword} />
              <Input
                label="Confirm Password"
                type="password"
                autoComplete="new-password"
                error={errors.confirmPassword?.message}
                {...register("confirmPassword")}
              />
              <Button
                type="submit"
                isLoading={isSubmitting}
                className="w-full"
                data-testid="register-submit"
              >
                Create account
              </Button>
            </form>
          )}
          <div className="mt-4 text-sm text-center text-gray-500">
            Already have an account?{" "}
            <Link to="/login" className="text-indigo-600 hover:underline">
              Sign in
            </Link>
          </div>
        </Card>
      </div>
    </div>
  );
}
