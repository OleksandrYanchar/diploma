import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { loginSchema, type LoginFormValues } from "../schemas";
import { login, isMfaRequired } from "../api";
import { useAuth } from "@/lib/auth";
import { apiClient } from "@/shared/api/client";
import type { AuthUser } from "@/lib/auth";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

export function LoginPage(): React.ReactElement {
  const { login: authLogin } = useAuth();
  const navigate = useNavigate();
  const [serverError, setServerError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({ resolver: zodResolver(loginSchema) });

  async function onSubmit(values: LoginFormValues): Promise<void> {
    setServerError(null);
    try {
      const result = await login(values);
      if (isMfaRequired(result)) {
        // Navigate to MFA login page, carrying the credentials for re-submission.
        navigate("/mfa/login", { state: { email: values.email, password: values.password } });
        return;
      }
      // Fetch user profile to populate auth state.
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
          <h1 className="text-3xl font-bold text-gray-900">ZeroTrust Bank</h1>
          <p className="text-gray-500 mt-2">Sign in to your account</p>
        </div>
        <Card>
          <form
            data-testid="login-form"
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
              autoComplete="current-password"
              error={errors.password?.message}
              {...register("password")}
            />
            <Button
              type="submit"
              isLoading={isSubmitting}
              className="w-full"
              data-testid="login-submit"
            >
              Sign in
            </Button>
          </form>
          <div className="mt-4 text-sm text-center space-y-2">
            <div>
              <Link to="/password-reset" className="text-indigo-600 hover:underline">
                Forgot password?
              </Link>
            </div>
            <div className="text-gray-500">
              No account?{" "}
              <Link to="/register" className="text-indigo-600 hover:underline">
                Register
              </Link>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
