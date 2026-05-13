import type { AxiosError } from "axios";

export interface ApiErrorBody {
  detail: string | { msg: string; type: string }[];
}

/**
 * Extract a human-readable error message from an Axios error.
 * Handles FastAPI's detail string and validation-error array shapes.
 */
export function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== "object") return "An unexpected error occurred.";

  const axiosError = error as AxiosError<ApiErrorBody>;
  const data = axiosError.response?.data;

  if (!data) {
    if (axiosError.message) return axiosError.message;
    return "Network error. Check your connection.";
  }

  if (typeof data.detail === "string") return data.detail;

  if (Array.isArray(data.detail)) {
    return data.detail.map((d) => d.msg).join("; ");
  }

  return "An unexpected error occurred.";
}
