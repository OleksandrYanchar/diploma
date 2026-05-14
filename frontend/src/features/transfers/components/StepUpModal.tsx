import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { stepUpSchema, type StepUpFormValues } from "@/features/mfa/schemas";
import { requestStepUp } from "@/features/mfa/api";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { extractErrorMessage } from "@/shared/api/errors";

interface StepUpModalProps {
  amount: number;
  onSuccess: (stepUpToken: string) => void;
  onCancel: () => void;
}

/**
 * Modal overlay that requests a TOTP code and exchanges it for a step-up token.
 * Called when a transfer amount exceeds the step-up threshold (>= $1000).
 * Step-up tokens are single-use — the parent should use them immediately.
 */
export function StepUpModal({ amount, onSuccess, onCancel }: StepUpModalProps): React.ReactElement {
  const [serverError, setServerError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<StepUpFormValues>({ resolver: zodResolver(stepUpSchema) });

  async function onSubmit(values: StepUpFormValues): Promise<void> {
    setServerError(null);
    try {
      const { step_up_token } = await requestStepUp(values.totp_code);
      onSuccess(step_up_token);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 px-4"
      data-testid="step-up-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="step-up-title"
    >
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md p-6">
        <h2 id="step-up-title" className="text-lg font-semibold text-gray-900 mb-1">
          Step-Up Authentication Required
        </h2>
        <p className="text-sm text-gray-600 mb-4">
          Transfers of ${amount.toFixed(2)} or more require additional verification. Enter your
          TOTP code to continue.
        </p>

        <form
          data-testid="step-up-form"
          onSubmit={(e) => void handleSubmit(onSubmit)(e)}
          className="space-y-4"
        >
          {serverError && <Alert type="error" message={serverError} />}
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
          <div className="flex gap-3">
            <Button
              type="button"
              variant="secondary"
              onClick={onCancel}
              className="flex-1"
              data-testid="step-up-cancel"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              isLoading={isSubmitting}
              className="flex-1"
              data-testid="step-up-submit"
            >
              Authorize
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
