import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger";
  isLoading?: boolean;
}

export function Button({
  variant = "primary",
  isLoading = false,
  disabled,
  children,
  className = "",
  ...rest
}: ButtonProps): React.ReactElement {
  const base =
    "inline-flex items-center justify-center px-4 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors";

  const variants: Record<string, string> = {
    primary: "bg-indigo-600 text-white hover:bg-indigo-700 focus:ring-indigo-500",
    secondary: "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50 focus:ring-indigo-500",
    danger: "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500",
  };

  return (
    <button
      className={`${base} ${variants[variant]} ${className}`}
      disabled={disabled || isLoading}
      {...rest}
    >
      {isLoading ? (
        <>
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          Loading...
        </>
      ) : (
        children
      )}
    </button>
  );
}
