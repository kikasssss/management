import { priorityColor, priorityLabel } from "@/lib/rule-helpers";
interface PriorityBadgeProps {
  priority: 1 | 2 | 3;
}


export default function PriorityBadge({ priority }: PriorityBadgeProps) {
  return (
    <span className={`px-2 py-0.5 text-xs rounded-full border ${priorityColor(priority)}`}>
      {priorityLabel(priority)}
    </span>
  );
}
