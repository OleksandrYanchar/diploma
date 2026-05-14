/**
 * Centralised env var access. All Vite env vars must go through this module.
 * Never import import.meta.env directly elsewhere.
 */
export const env = {
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL as string,
} as const;
