import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getAuditLogs } from "../api";
import { Card } from "@/shared/ui/Card";
import { Alert } from "@/shared/ui/Alert";
import { Button } from "@/shared/ui/Button";
import { formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

const PAGE_SIZE = 50;

export function AdminAuditLogsPage(): React.ReactElement {
  const [offset, setOffset] = useState(0);

  const { data, isLoading, error } = useQuery({
    queryKey: ["admin", "audit-logs", offset],
    queryFn: () => getAuditLogs(PAGE_SIZE, offset),
  });

  return (
    <Card title="Audit Logs">
      {isLoading && <p className="text-gray-500">Loading…</p>}
      {error && <Alert type="error" message={extractErrorMessage(error)} />}
      {data && (
        <>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b text-left text-gray-500 text-xs uppercase tracking-wide">
                  <th className="pb-2 pr-4">Timestamp</th>
                  <th className="pb-2 pr-4">Action</th>
                  <th className="pb-2 pr-4">User ID</th>
                  <th className="pb-2 pr-4">IP</th>
                  <th className="pb-2">Detail</th>
                </tr>
              </thead>
              <tbody>
                {data.map((log) => (
                  <tr key={log.id} className="border-b last:border-0">
                    <td className="py-2 pr-4 whitespace-nowrap text-gray-600">
                      {formatDateTime(log.created_at)}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{log.action}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-gray-500">
                      {log.user_id ?? "—"}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{log.ip_address ?? "—"}</td>
                    <td className="py-2 text-xs text-gray-600 max-w-xs truncate">
                      {log.detail ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.length === 0 && (
            <p className="text-gray-500 text-sm mt-2">No audit logs found.</p>
          )}
          <div className="mt-4 flex gap-2">
            <Button
              variant="secondary"
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              disabled={offset === 0}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
              disabled={data.length < PAGE_SIZE}
            >
              Next
            </Button>
          </div>
        </>
      )}
    </Card>
  );
}
