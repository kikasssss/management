"use client";

import { useState } from "react";

interface ApplyFullRulesetModalProps {
  sensors: string[];
  onClose: () => void;
}

export default function ApplyFullRulesetModal({ sensors, onClose }: ApplyFullRulesetModalProps) {
  const [selected, setSelected] = useState<string[]>([]);

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center">
      <div className="bg-white p-6 rounded-xl shadow-lg w-[400px]">
        <h2 className="text-lg font-semibold mb-4">
          Apply Full Ruleset to Sensors
        </h2>

        <div className="space-y-3">
          {sensors.map((s) => (
            <label key={s} className="flex items-center gap-2">
              <input
                type="checkbox"
                value={s}
                checked={selected.includes(s)}
                onChange={(e) => {
                  const val = e.target.value;
                  setSelected((prev) =>
                    prev.includes(val)
                      ? prev.filter((x) => x !== val)
                      : [...prev, val]
                  );
                }}
              />
              {s}
            </label>
          ))}
        </div>

        <div className="flex justify-end mt-6 gap-2">
          <button
            className="px-4 py-2 border rounded-lg"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            className="px-4 py-2 bg-blue-600 text-white rounded-lg"
            onClick={() => {
              onClose();
            }}
          >
            Apply Full
          </button>
        </div>
      </div>
    </div>
  );
}
