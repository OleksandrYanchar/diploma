import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { transferSchema, type TransferFormValues, STEP_UP_THRESHOLD } from "../schemas";
import { executeTransfer, type TransactionResponse } from "../api";
import { StepUpModal } from "../components/StepUpModal";
import { useAuth } from "@/lib/auth";
import { Input } from "@/shared/ui/Input";
import { Button } from "@/shared/ui/Button";
import { Alert } from "@/shared/ui/Alert";
import { Card } from "@/shared/ui/Card";
import { formatCurrency, formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

export function TransferPage(): React.ReactElement {
  const { user } = useAuth();
  const [serverError, setServerError] = useState<string | null>(null);
  const [successTx, setSuccessTx] = useState<TransactionResponse | null>(null);
  // pendingTransfer holds form values while waiting for step-up token.
  const [pendingTransfer, setPendingTransfer] = useState<TransferFormValues | null>(null);
  // Track amount separately to derive needsStepUp without using watch().
  const [amountInput, setAmountInput] = useState("");

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<TransferFormValues>({ resolver: zodResolver(transferSchema) });

  const amountValue = parseFloat(amountInput || "0");
  const needsStepUp = amountValue >= STEP_UP_THRESHOLD && !!user?.mfa_enabled;

  async function submitTransfer(values: TransferFormValues, stepUpToken?: string): Promise<void> {
    setServerError(null);
    try {
      const tx = await executeTransfer(
        {
          to_account_number: values.to_account_number,
          amount: parseFloat(values.amount),
          description: values.description || undefined,
        },
        stepUpToken
      );
      setSuccessTx(tx);
      reset();
      setAmountInput("");
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  }

  async function onSubmit(values: TransferFormValues): Promise<void> {
    setServerError(null);
    setSuccessTx(null);
    const amount = parseFloat(values.amount);
    if (amount >= STEP_UP_THRESHOLD) {
      // Store values and show step-up modal to collect TOTP.
      setPendingTransfer(values);
      return;
    }
    await submitTransfer(values);
  }

  function onStepUpSuccess(stepUpToken: string): void {
    if (!pendingTransfer) return;
    const values = pendingTransfer;
    setPendingTransfer(null);
    void submitTransfer(values, stepUpToken);
  }

  function onStepUpCancel(): void {
    setPendingTransfer(null);
  }

  return (
    <>
      {pendingTransfer && (
        <StepUpModal
          amount={parseFloat(pendingTransfer.amount)}
          onSuccess={onStepUpSuccess}
          onCancel={onStepUpCancel}
        />
      )}

      <div className="max-w-lg space-y-4">
        {/* MFA status indicator — always visible, not conditioned on amount. */}
        {user?.mfa_enabled ? (
          <Alert
            type="success"
            message="Step-up authentication is active. High-value transfers ($1000+) will require TOTP confirmation."
            data-testid="mfa-active-notice"
          />
        ) : (
          <Alert
            type="error"
            message="High-value transfers ($1000+) require MFA. Enable MFA in your profile before sending large transfers."
            data-testid="mfa-required-notice"
          />
        )}

        <Card title="Send Transfer">
          {successTx && (
            <Alert
              type="success"
              message={`Transfer of ${formatCurrency(successTx.amount)} sent successfully on ${formatDateTime(successTx.created_at)}.`}
            />
          )}
          <form
            data-testid="transfer-form"
            onSubmit={(e) => void handleSubmit(onSubmit)(e)}
            className="space-y-4 mt-4"
          >
            {serverError && <Alert type="error" message={serverError} />}
            <Input
              label="Recipient Account Number"
              type="text"
              placeholder="e.g. ACC-0000000001"
              error={errors.to_account_number?.message}
              {...register("to_account_number")}
            />
            <Input
              label="Amount (USD)"
              type="number"
              step="0.01"
              min="0.01"
              placeholder="0.00"
              error={errors.amount?.message}
              {...register("amount", {
                onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
                  setAmountInput(e.target.value),
              })}
            />
            <Input
              label="Description (optional)"
              type="text"
              placeholder="e.g. Rent payment"
              error={errors.description?.message}
              {...register("description")}
            />
            {needsStepUp && (
              <Alert
                type="info"
                message={`Transfers of $${STEP_UP_THRESHOLD}+ require step-up authentication (TOTP). You will be prompted after submitting.`}
                data-testid="step-up-notice"
              />
            )}
            {amountValue >= STEP_UP_THRESHOLD && !user?.mfa_enabled && (
              <Alert
                type="error"
                message="Transfers of $1000+ require MFA. Please enable MFA on your account first."
              />
            )}
            <Button
              type="submit"
              isLoading={isSubmitting}
              className="w-full"
              data-testid="transfer-submit"
              disabled={amountValue >= STEP_UP_THRESHOLD && !user?.mfa_enabled}
            >
              Send Transfer
            </Button>
          </form>
        </Card>
      </div>
    </>
  );
}
