import { apiClient } from "@/shared/api/client";

export interface MfaSetupResponse {
  secret: string;
  qr_code_base64: string;
  issuer: string;
}

export interface StepUpResponse {
  step_up_token: string;
  expires_in: number;
}

// In production: POST /api/v1/auth/mfa/setup
export async function setupMfa(): Promise<MfaSetupResponse> {
  const res = await apiClient.post<MfaSetupResponse>("/auth/mfa/setup");
  return res.data;
}

// In production: POST /api/v1/auth/mfa/enable
export async function enableMfa(totp_code: string): Promise<{ detail: string }> {
  const res = await apiClient.post<{ detail: string }>("/auth/mfa/enable", { totp_code });
  return res.data;
}

// In production: POST /api/v1/auth/mfa/disable
export async function disableMfa(data: {
  password: string;
  totp_code: string;
}): Promise<{ detail: string }> {
  const res = await apiClient.post<{ detail: string }>("/auth/mfa/disable", data);
  return res.data;
}

// In production: POST /api/v1/auth/step-up
export async function requestStepUp(totp_code: string): Promise<StepUpResponse> {
  const res = await apiClient.post<StepUpResponse>("/auth/step-up", { totp_code });
  return res.data;
}
