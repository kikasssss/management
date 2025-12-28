"use client";

import type { GPTAnalysisResult } from "@/types/types";

interface Props {
  analysis: GPTAnalysisResult;
}

function riskColor(level: "low" | "medium" | "high") {
  switch (level) {
    case "high":
      return "text-red-700 bg-red-50 border-red-200";
    case "medium":
      return "text-orange-700 bg-orange-50 border-orange-200";
    default:
      return "text-green-700 bg-green-50 border-green-200";
  }
}

export default function AIAnalysisResult({ analysis }: Props) {
  return (
    <div className="mt-3 border rounded-lg bg-gray-50 p-3 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold text-gray-700">
          🤖 AI Analysis Result
        </h4>

        <span
          className={`text-xs px-2 py-0.5 border rounded ${riskColor(
            analysis.risk_level
          )}`}
        >
          Risk: {analysis.risk_level.toUpperCase()}
        </span>
      </div>

      {/* Core verdict */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="border rounded p-2 bg-white">
          <div className="text-gray-500">Attack chain</div>
          <div className="font-medium">
            {analysis.attack_chain ? "Detected" : "Not detected"}
          </div>
        </div>

        <div className="border rounded p-2 bg-white">
          <div className="text-gray-500">Lateral movement</div>
          <div className="font-medium">
            {analysis.lateral_movement.detected ? "Detected" : "Not detected"}
          </div>
        </div>

        <div className="border rounded p-2 bg-white col-span-2">
          <div className="text-gray-500">Confidence</div>
          <div className="flex items-center gap-2">
            <div className="w-full h-2 bg-gray-200 rounded">
              <div
                className="h-2 rounded bg-indigo-500"
                style={{ width: `${analysis.confidence * 100}%` }}
              />
            </div>
            <span className="text-[11px]">
              {(analysis.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </div>
      </div>

      {/* Findings */}
      {analysis.top_findings?.length > 0 && (
        <div className="text-xs">
          <div className="text-gray-600 font-medium mb-1">
            Key findings
          </div>
          <ul className="list-disc pl-4 space-y-0.5">
            {analysis.top_findings.slice(0, 4).map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Lateral evidence */}
      {analysis.lateral_movement.detected &&
        analysis.lateral_movement.evidence?.length > 0 && (
          <div className="text-xs">
            <div className="text-gray-600 font-medium mb-1">
              Lateral movement evidence
            </div>
            <ul className="list-disc pl-4 space-y-0.5">
              {analysis.lateral_movement.evidence.slice(0, 4).map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>
        )}

      {/* Recommendations */}
      {analysis.recommended_actions?.length > 0 && (
        <div className="text-xs">
          <div className="text-gray-600 font-medium mb-1">
            Recommended actions
          </div>
          <ul className="list-disc pl-4 space-y-0.5">
            {analysis.recommended_actions.slice(0, 4).map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
