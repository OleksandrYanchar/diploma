import { z } from "zod";

export const PASSWORD_MIN_LENGTH = 12;

export interface PasswordRequirement {
  key: string;
  label: string;
  test: (password: string) => boolean;
}

export const PASSWORD_REQUIREMENTS: PasswordRequirement[] = [
  {
    key: "length",
    label: "At least 12 characters",
    test: (p) => p.length >= PASSWORD_MIN_LENGTH,
  },
  {
    key: "uppercase",
    label: "One uppercase letter (A–Z)",
    test: (p) => /[A-Z]/.test(p),
  },
  {
    key: "lowercase",
    label: "One lowercase letter (a–z)",
    test: (p) => /[a-z]/.test(p),
  },
  {
    key: "digit",
    label: "One number (0–9)",
    test: (p) => /[0-9]/.test(p),
  },
  {
    key: "special",
    label: "One special character",
    test: (p) => /[^A-Za-z0-9]/.test(p),
  },
];

export function getPasswordRequirementStatus(
  password: string
): Record<string, boolean> {
  return Object.fromEntries(
    PASSWORD_REQUIREMENTS.map((r) => [r.key, r.test(password)])
  );
}

export function isPasswordStrong(password: string): boolean {
  return PASSWORD_REQUIREMENTS.every((r) => r.test(password));
}

export const newPasswordField = z
  .string()
  .min(1, "Password is required")
  .refine(isPasswordStrong, "Password does not meet strength requirements");
