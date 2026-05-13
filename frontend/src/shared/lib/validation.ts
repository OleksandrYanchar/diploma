import { z } from "zod";

export const PASSWORD_MIN_LENGTH = 12;

export const newPasswordField = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`);
