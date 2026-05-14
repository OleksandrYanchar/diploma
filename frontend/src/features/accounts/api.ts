import { apiClient } from "@/shared/api/client";

export interface AccountResponse {
  id: string;
  account_number: string;
  status: string;
  balance: string;
  currency: string;
  created_at: string;
  updated_at: string;
}

// In production: GET /api/v1/accounts/me
// Auto-creates account with $1000 seed balance on first access.
export async function getMyAccount(): Promise<AccountResponse> {
  const res = await apiClient.get<AccountResponse>("/accounts/me");
  return res.data;
}
