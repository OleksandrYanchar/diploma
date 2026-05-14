import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getAdminUsers,
  unlockUser,
  activateUser,
  deactivateUser,
  changeUserRole,
  type UserAdminView,
  type UserRole,
} from "../api";
import { Card } from "@/shared/ui/Card";
import { Alert } from "@/shared/ui/Alert";
import { Button } from "@/shared/ui/Button";
import { formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

export function AdminUsersPage(): React.ReactElement {
  const qc = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const { data: users, isLoading, error } = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => getAdminUsers(),
  });

  function invalidate(): void {
    void qc.invalidateQueries({ queryKey: ["admin", "users"] });
  }

  const unlock = useMutation({
    mutationFn: (id: string) => unlockUser(id),
    onSuccess: invalidate,
    onError: (e) => setActionError(extractErrorMessage(e)),
  });

  const activate = useMutation({
    mutationFn: (id: string) => activateUser(id),
    onSuccess: invalidate,
    onError: (e) => setActionError(extractErrorMessage(e)),
  });

  const deactivate = useMutation({
    mutationFn: (id: string) => deactivateUser(id),
    onSuccess: invalidate,
    onError: (e) => setActionError(extractErrorMessage(e)),
  });

  const changeRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: UserRole }) => changeUserRole(id, role),
    onSuccess: invalidate,
    onError: (e) => setActionError(extractErrorMessage(e)),
  });

  return (
    <Card title="User Management">
      {actionError && (
        <div className="mb-4">
          <Alert type="error" message={actionError} />
        </div>
      )}
      {isLoading && <p className="text-gray-500">Loading…</p>}
      {error && <Alert type="error" message={extractErrorMessage(error)} />}
      {users && (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b text-left text-gray-500 text-xs uppercase tracking-wide">
                <th className="pb-2 pr-3">Email</th>
                <th className="pb-2 pr-3">Role</th>
                <th className="pb-2 pr-3">Active</th>
                <th className="pb-2 pr-3">Verified</th>
                <th className="pb-2 pr-3">MFA</th>
                <th className="pb-2 pr-3">Failed Logins</th>
                <th className="pb-2 pr-3">Locked Until</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u: UserAdminView) => (
                <tr key={u.id} className="border-b last:border-0 align-top">
                  <td className="py-3 pr-3 font-mono text-xs">{u.email}</td>
                  <td className="py-3 pr-3">
                    <select
                      value={u.role}
                      onChange={(e) =>
                        changeRole.mutate({ id: u.id, role: e.target.value as UserRole })
                      }
                      className="border border-gray-300 rounded px-1 py-0.5 text-xs"
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                      <option value="auditor">auditor</option>
                    </select>
                  </td>
                  <td className="py-3 pr-3">
                    <span
                      className={`text-xs font-medium ${u.is_active ? "text-green-700" : "text-red-600"}`}
                    >
                      {u.is_active ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="py-3 pr-3">
                    <span
                      className={`text-xs ${u.is_verified ? "text-green-700" : "text-gray-400"}`}
                    >
                      {u.is_verified ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="py-3 pr-3">
                    <span className={`text-xs ${u.mfa_enabled ? "text-green-700" : "text-gray-400"}`}>
                      {u.mfa_enabled ? "On" : "Off"}
                    </span>
                  </td>
                  <td className="py-3 pr-3 text-center">{u.failed_login_count}</td>
                  <td className="py-3 pr-3 text-xs text-gray-600">
                    {u.locked_until ? formatDateTime(u.locked_until) : "—"}
                  </td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {u.locked_until && (
                        <Button
                          variant="secondary"
                          onClick={() => unlock.mutate(u.id)}
                          className="text-xs px-2 py-1"
                        >
                          Unlock
                        </Button>
                      )}
                      {u.is_active ? (
                        <Button
                          variant="danger"
                          onClick={() => deactivate.mutate(u.id)}
                          className="text-xs px-2 py-1"
                        >
                          Deactivate
                        </Button>
                      ) : (
                        <Button
                          variant="primary"
                          onClick={() => activate.mutate(u.id)}
                          className="text-xs px-2 py-1"
                        >
                          Activate
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
