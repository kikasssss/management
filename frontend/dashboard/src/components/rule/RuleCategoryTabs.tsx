"use client";

import { useState } from "react";

export type RuleCategory = "all" | "snort" | "ti";

interface Props {
  onChange: (category: RuleCategory) => void;
  defaultValue?: RuleCategory;
}

export default function RuleCategoryTabs({
  onChange,
  defaultValue = "all",
}: Props) {
  const [active, setActive] = useState<RuleCategory>(defaultValue);

  const tabs: { id: RuleCategory; label: string }[] = [
    { id: "all", label: "All Rules" },
    { id: "snort", label: "Snort Default Rules" },
    { id: "ti", label: "Threat Intelligence Rules" },
  ];

  const handleClick = (id: RuleCategory) => {
    setActive(id);
    onChange(id);
  };

  return (
    <div className="flex gap-2 mb-4">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => handleClick(tab.id)}
          className={`px-4 py-2 rounded-lg text-sm border transition
            ${
              active === tab.id
                ? "bg-blue-600 text-white border-blue-600"
                : "bg-white text-gray-700 border-gray-300 hover:bg-gray-100"
            }
          `}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
