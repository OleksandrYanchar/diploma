import { PASSWORD_REQUIREMENTS } from "@/shared/lib/validation";

interface Props {
  password: string;
}

export function PasswordRequirements({ password }: Props): React.ReactElement {
  return (
    <ul
      data-testid="password-requirements"
      className="mt-2 space-y-1 text-sm"
    >
      {PASSWORD_REQUIREMENTS.map((req) => {
        const met = req.test(password);
        return (
          <li
            key={req.key}
            data-testid={`password-req-${req.key}`}
            data-met={met}
            className={`flex items-center gap-2 ${met ? "text-green-600" : "text-gray-400"}`}
          >
            <span aria-hidden="true">{met ? "✓" : "○"}</span>
            <span>{req.label}</span>
          </li>
        );
      })}
    </ul>
  );
}
