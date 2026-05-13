import { apiClient } from "@/shared/api/client";

export interface TransferRequest {
  to_account_number: string;
  amount: number;
  description?: string;
}

export interface TransactionResponse {
  id: string;
  from_account_id: string;
  to_account_id: string;
  amount: string;
  transaction_type: string;
  status: string;
  description: string | null;
  created_at: string;
}

/**
 * Execute a transfer.
 * For amounts >= STEP_UP_TRANSFER_THRESHOLD, the caller must pass a step-up token.
 * The step-up token is sent in the X-Step-Up-Token header.
 * Step-up tokens are single-use — do not retry with the same token.
 *
 * In production: POST /api/v1/transactions/transfer
 */
export async function executeTransfer(
  data: TransferRequest,
  stepUpToken?: string
): Promise<TransactionResponse> {
  const headers: Record<string, string> = {};
  if (stepUpToken) {
    headers["X-Step-Up-Token"] = stepUpToken;
  }
  const res = await apiClient.post<TransactionResponse>("/transactions/transfer", data, {
    headers,
  });
  return res.data;
}
