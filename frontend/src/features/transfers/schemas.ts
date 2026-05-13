import { z } from "zod";

export const transferSchema = z.object({
  to_account_number: z.string().min(1, "Recipient account number is required"),
  amount: z
    .string()
    .min(1, "Amount is required")
    .refine((v) => !isNaN(parseFloat(v)) && parseFloat(v) > 0, {
      message: "Amount must be a positive number",
    }),
  description: z.string().optional(),
});

export type TransferFormValues = z.infer<typeof transferSchema>;

/** The backend threshold for requiring step-up auth. Must match backend STEP_UP_TRANSFER_THRESHOLD. */
export const STEP_UP_THRESHOLD = 1000;
