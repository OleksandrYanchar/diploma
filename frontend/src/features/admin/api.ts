import { apiClient } from "@/shared/api/client";
import type { AuthUser } from "@/lib/auth";

export interface UserAdminView extends AuthUser {
  failed_login_count: number;
  locked_until: string | null;
}

export interface AuditLogResponse {
  id: string;
  user_id: string | null;
  action: string;
  ip_address: string | null;
  detail: string | null;
  created_at: string;
}

export interface SecurityEventResponse {
  id: string;
  event_type: string;
  user_id: string | null;
  ip_address: string | null;
  detail: string | null;
  created_at: string;
}

export type UserRole = "user" | "admin" | "auditor";

// In production: GET /api/v1/admin/users?limit=50&offset=0
export async function getAdminUsers(limit = 50, offset = 0): Promise<UserAdminView[]> {
  const res = await apiClient.get<UserAdminView[]>(
    `/admin/users?limit=${limit}&offset=${offset}`
  );
  return res.data;
}

// In production: POST /api/v1/admin/users/{id}/unlock
export async function unlockUser(id: string): Promise<UserAdminView> {
  const res = await apiClient.post<UserAdminView>(`/admin/users/${id}/unlock`);
  return res.data;
}

// In production: PATCH /api/v1/admin/users/{id}/activate
export async function activateUser(id: string): Promise<UserAdminView> {
  const res = await apiClient.patch<UserAdminView>(`/admin/users/${id}/activate`);
  return res.data;
}

// In production: PATCH /api/v1/admin/users/{id}/deactivate
export async function deactivateUser(id: string): Promise<UserAdminView> {
  const res = await apiClient.patch<UserAdminView>(`/admin/users/${id}/deactivate`);
  return res.data;
}

// In production: PATCH /api/v1/admin/users/{id}/role
export async function changeUserRole(id: string, role: UserRole): Promise<UserAdminView> {
  const res = await apiClient.patch<UserAdminView>(`/admin/users/${id}/role`, { role });
  return res.data;
}

// In production: GET /api/v1/admin/audit-logs?limit=50&offset=0
export async function getAuditLogs(limit = 50, offset = 0): Promise<AuditLogResponse[]> {
  const res = await apiClient.get<AuditLogResponse[]>(
    `/admin/audit-logs?limit=${limit}&offset=${offset}`
  );
  return res.data;
}

// In production: GET /api/v1/admin/security-events?limit=50&offset=0
export async function getSecurityEvents(limit = 50, offset = 0): Promise<SecurityEventResponse[]> {
  const res = await apiClient.get<SecurityEventResponse[]>(
    `/admin/security-events?limit=${limit}&offset=${offset}`
  );
  return res.data;
}
