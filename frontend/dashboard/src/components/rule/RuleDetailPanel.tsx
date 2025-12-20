import type { RuleType } from "@/types/types";
interface RuleDetailPanelProps {
  rule: RuleType | null;
  sensors: string[];
  onClose: () => void;
}

export default function RuleDetailPanel({ rule }: RuleDetailPanelProps) {
  if (!rule)
    return (
      <div className="text-gray-400 text-sm">Select a rule to view details.</div>
    );

  return (
    <div className="space-y-3 text-sm">
      <div>
        <div className="text-xs text-gray-500">SID</div>
        <div className="font-mono">{rule.sid}</div>
      </div>

      <div>
        <div className="text-xs text-gray-500">Message</div>
        <div>{rule.msg}</div>
      </div>

      <div>
        <div className="text-xs text-gray-500">MITRE Techniques</div>
        <div className="flex flex-col gap-1">
          <span className="bg-indigo-100 text-indigo-700 px-2 py-0.5 text-xs rounded-full w-fit">
            {rule.mitre?.tactic}
          </span>
          <span className="bg-indigo-100 text-indigo-700 px-2 py-0.5 text-xs rounded-full w-fit">
            {rule.mitre?.technique}
          </span>
        </div>
      </div>

      <div>
        <div className="text-xs text-gray-500">Full Rule</div>
        <div>{rule.raw}</div>
      </div>
    </div>
  );
}
