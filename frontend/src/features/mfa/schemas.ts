import { z } from "zod";

const totpCode = z
  .string()
  .min(6, "TOTP code must be 6 digits")
  .max(6, "TOTP code must be 6 digits")
  .regex(/^\d{6}$/, "TOTP code must be 6 digits");

export const mfaEnableSchema = z.object({ totp_code: totpCode });

export const mfaLoginSchema = z.object({ totp_code: totpCode });

export const mfaDisableSchema = z.object({
  password: z.string().min(1, "Password is required"),
  totp_code: totpCode,
});

export const stepUpSchema = z.object({ totp_code: totpCode });

export type MfaEnableFormValues = z.infer<typeof mfaEnableSchema>;
export type MfaLoginFormValues = z.infer<typeof mfaLoginSchema>;
export type MfaDisableFormValues = z.infer<typeof mfaDisableSchema>;
export type StepUpFormValues = z.infer<typeof stepUpSchema>;
