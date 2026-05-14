import { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { verifyEmailSchema, type VerifyEmailFormValues } from "../schemas";
import { verifyEmail } from "../api";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { extractErrorMessage } from "@/shared/api/errors";

export function VerifyEmailPage(): React.ReactElement {
  const [searchParams] = useSearchParams();
  const tokenFromUrl = searchParams.get("token");
  const [serverError, setServerError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<VerifyEmailFormValues>({ resolver: zodResolver(verifyEmailSchema) });

  // Pre-fill token from URL query param if present.
  useEffect(() => {
    if (tokenFromUrl) setValue("token", tokenFromUrl);
  }, [tokenFromUrl, setValue]);

  async function onSubmit(values: VerifyEmailFormValues): Promise<void> {
    setServerError(null);
    try {
      await verifyEmail(values.token);
      setSuccess(true);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Verify Email</h1>
          <p className="text-gray-500 mt-2 text-sm">
            The verification token is printed to the backend Docker logs (DEMO MODE).
          </p>
        </div>
        <Card>
          {success ? (
            <div className="space-y-4">
              <Alert type="success" message="Email verified successfully!" />
              <Link to="/login" className="block text-center text-indigo-600 hover:underline text-sm">
                Sign in
              </Link>
            </div>
          ) : (
            <form
              data-testid="verify-email-form"
              onSubmit={(e) => void handleSubmit(onSubmit)(e)}
              className="space-y-4"
            >
              {serverError && <Alert type="error" message={serverError} />}
              <Input
                label="Verification Token"
                type="text"
                placeholder="Paste token from backend logs"
                error={errors.token?.message}
                {...register("token")}
              />
              <Button
                type="submit"
                isLoading={isSubmitting}
                className="w-full"
                data-testid="verify-email-submit"
              >
                Verify Email
              </Button>
            </form>
          )}
        </Card>
      </div>
    </div>
  );
}
