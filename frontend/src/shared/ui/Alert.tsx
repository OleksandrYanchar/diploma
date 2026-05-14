interface AlertProps {
  type: "success" | "error" | "info" | "warning";
  message: string;
  "data-testid"?: string;
}

const styles: Record<string, string> = {
  success: "bg-green-50 border-green-400 text-green-800",
  error: "bg-red-50 border-red-400 text-red-800",
  info: "bg-blue-50 border-blue-400 text-blue-800",
  warning: "bg-yellow-50 border-yellow-400 text-yellow-800",
};

export function Alert({ type, message, "data-testid": testId }: AlertProps): React.ReactElement {
  return (
    <div
      role="alert"
      data-testid={testId ?? (type === "error" ? "error-alert" : "success-alert")}
      className={`rounded-md border px-4 py-3 text-sm ${styles[type]}`}
    >
      {message}
    </div>
  );
}
