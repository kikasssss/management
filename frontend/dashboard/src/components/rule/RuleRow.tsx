"use client";

import RulePriorityBadge from "./PriorityBadge";
import RuleStatusBadge from "./StatusBadge";
import type { RuleType } from "@/types/types";
import { priorityMap } from "@/lib/rule-helpers";

interface RuleRowProps {
  rule: RuleType;
  onView: (rule: RuleType) => void;
  onApply: (rule: RuleType) => void;
}
export type RulePriorityText = "High" | "Medium" | "Low";


export default function RuleRow({ rule, onView, onApply}:RuleRowProps) {
  return (
    <tr className="border-t hover:bg-gray-50 transition">
      <td className="px-3 py-2">{rule.sid}</td>

      <td className="px-3 py-2 font-medium">{rule.msg}</td>

      <td className="px-3 py-2">{rule.category}</td>

      <td className="px-3 py-2 uppercase">{rule.proto}</td>

      <td className="px-3 py-2">
        <RulePriorityBadge priority={priorityMap[rule.priority]} />
      </td>

      <td className="px-3 py-2">
        <RuleStatusBadge enabled={rule.status.toLowerCase() === "enabled"} />      
      </td>

      <td className="px-3 py-2">{rule.hits24h}</td>

      <td className="px-3 py-2 text-blue-600 underline cursor-pointer text-center">
        <span onClick={() => onView(rule)}>View</span>
      </td>

      <td className="px-3 py-2 text-blue-600 underline cursor-pointer text-center">
        <span onClick={() => onApply(rule)}>Apply</span>
      </td>
    </tr>
  );
}
