import { apiClient } from "@/shared/api/client";
import type { TransactionResponse } from "@/features/transfers/api";

export interface TransactionHistoryResponse {
  items: TransactionResponse[];
  total: number;
  page: number;
  page_size: number;
}

// In production: GET /api/v1/transactions/history?page=<page>&page_size=<size>
export async function getTransactionHistory(
  page = 1,
  pageSize = 20
): Promise<TransactionHistoryResponse> {
  const res = await apiClient.get<TransactionHistoryResponse>(
    `/transactions/history?page=${page}&page_size=${pageSize}`
  );
  return res.data;
}
