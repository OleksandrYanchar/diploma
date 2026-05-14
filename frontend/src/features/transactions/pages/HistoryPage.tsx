import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getTransactionHistory } from "../api";
import { getMyAccount } from "@/features/accounts/api";
import { Card } from "@/shared/ui/Card";
import { Alert } from "@/shared/ui/Alert";
import { Button } from "@/shared/ui/Button";
import { formatCurrency, formatDateTime } from "@/lib/formatting";
import { extractErrorMessage } from "@/shared/api/errors";

const PAGE_SIZE = 20;

export function HistoryPage(): React.ReactElement {
  const [page, setPage] = useState(1);

  const { data, isLoading, error } = useQuery({
    queryKey: ["transactions", page],
    queryFn: () => getTransactionHistory(page, PAGE_SIZE),
  });

  // Fetch account id to determine transaction direction (in/out).
  // Uses the same query key as AccountPage so it hits the React Query cache.
  const { data: account } = useQuery({
    queryKey: ["account", "me"],
    queryFn: getMyAccount,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1;

  return (
    <Card title="Transaction History">
      {isLoading && <p className="text-gray-500">Loading…</p>}
      {error && <Alert type="error" message={extractErrorMessage(error)} />}
      {data && data.items.length === 0 && (
        <p className="text-gray-500 text-sm">No transactions yet.</p>
      )}
      {data && data.items.length > 0 && (
        <>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b text-left text-gray-500 text-xs uppercase tracking-wide">
                  <th className="pb-2 pr-4">Date</th>
                  <th className="pb-2 pr-4">Type</th>
                  <th className="pb-2 pr-4">Amount</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2">Description</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((tx) => {
                  const isIncoming = account && tx.to_account_id === account.id;
                  const isOutgoing = account && tx.from_account_id === account.id;
                  const prefix = isIncoming ? "+" : isOutgoing ? "−" : "";
                  const amountClass = isIncoming
                    ? "text-green-600 font-mono font-semibold"
                    : "text-gray-900 font-mono font-medium";

                  return (
                    <tr
                      key={tx.id}
                      data-testid={`transaction-row-${tx.id}`}
                      className="border-b last:border-0 hover:bg-gray-50"
                    >
                      <td className="py-3 pr-4 text-gray-600 whitespace-nowrap">
                        {formatDateTime(tx.created_at)}
                      </td>
                      <td className="py-3 pr-4 capitalize">{tx.transaction_type}</td>
                      <td
                        className={`py-3 pr-4 ${amountClass}`}
                        data-testid="transaction-amount"
                        data-direction={isIncoming ? "in" : isOutgoing ? "out" : "unknown"}
                      >
                        {prefix}{formatCurrency(tx.amount)}
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                            tx.status === "completed"
                              ? "bg-green-100 text-green-800"
                              : tx.status === "failed"
                                ? "bg-red-100 text-red-800"
                                : "bg-yellow-100 text-yellow-800"
                          }`}
                        >
                          {tx.status}
                        </span>
                      </td>
                      <td className="py-3 text-gray-600">{tx.description ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center justify-between text-sm">
            <span className="text-gray-500">
              Page {data.page} of {totalPages} ({data.total} transactions)
            </span>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
              >
                Previous
              </Button>
              <Button
                variant="secondary"
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </Card>
  );
}
