import { statusLabel, statusColor } from "@/lib/rule-helpers";

interface StatusBadgeProps {
  enabled: boolean;
}
export default function StatusBadge({ enabled }: StatusBadgeProps) {
  return (
    <span className={`flex items-center gap-1 ${statusColor(enabled)}`}>
      <span
        className={`h-2 w-2 rounded-full ${
          enabled ? "bg-green-500" : "bg-gray-400"
        }`}
      ></span>
      {statusLabel(enabled)}
    </span>
  );
}
