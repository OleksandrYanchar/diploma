import { apiClient } from "@/shared/api/client";
import type { AuthUser } from "@/lib/auth";

export interface LoginRequest {
  email: string;
  password: string;
  totp_code?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  // refresh_token is no longer in the JSON body — it is delivered as an
  // HttpOnly cookie (zt_rt) set by the backend and is not accessible to JS.
}

export interface MFARequiredResponse {
  mfa_required: true;
  message: string;
}

export type LoginResponse = TokenResponse | MFARequiredResponse;

export function isMfaRequired(r: LoginResponse): r is MFARequiredResponse {
  return "mfa_required" in r && r.mfa_required === true;
}

// In production: POST /api/v1/auth/login
export async function login(data: LoginRequest): Promise<LoginResponse> {
  const res = await apiClient.post<LoginResponse>("/auth/login", data);
  return res.data;
}

// In production: POST /api/v1/auth/register
export async function register(data: { email: string; password: string }): Promise<AuthUser> {
  const res = await apiClient.post<AuthUser>("/auth/register", data);
  return res.data;
}

// In production: GET /api/v1/auth/verify-email?token=<token>
export async function verifyEmail(token: string): Promise<{ message: string }> {
  const res = await apiClient.get<{ message: string }>(`/auth/verify-email?token=${token}`);
  return res.data;
}

// In production: POST /api/v1/auth/password/reset/request
export async function requestPasswordReset(email: string): Promise<{ message: string }> {
  const res = await apiClient.post<{ message: string }>("/auth/password/reset/request", {
    email,
  });
  return res.data;
}

// In production: POST /api/v1/auth/password/reset/confirm
export async function confirmPasswordReset(data: {
  token: string;
  new_password: string;
}): Promise<{ message: string }> {
  const res = await apiClient.post<{ message: string }>("/auth/password/reset/confirm", data);
  return res.data;
}
