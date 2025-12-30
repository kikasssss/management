"use client";

import { useMemo, useState } from "react";
import AIAnalysisResult from "./AIAnalysisResult";
import type {
  LateralContext,
  LateralRunResponse,
  GPTAnalysisResult,
} from "@/types/types";

function getApiBase() {
  return process.env.NEXT_PUBLIC_API_BASE ?? "http://100.100.100.100:5000";
}

export default function LateralCorrelationPanel() {
  const API_BASE = useMemo(() => getApiBase(), []);

  const [sinceMinutes, setSinceMinutes] = useState(10);
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);

  const [contexts, setContexts] = useState<LateralContext[]>([]);
  const [aiMap, setAiMap] = useState<Record<string, GPTAnalysisResult>>({});
  const [aiLoadingKey, setAiLoadingKey] = useState<string | null>(null);

  function keyOf(c: LateralContext) {
    return `${c.actor_ip}|${c.targets.join(",")}`;
  }

  async function runLateral() {
    setLoading(true);
    setHasRun(true);
    try {
      const res = await fetch(
        `${API_BASE}/api/v1/correlation/run_lateral_from_mongo`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            since_minutes: sinceMinutes,
            limit: 500,
          }),
        }
      );

      const json = (await res.json()) as LateralRunResponse;
      if (json.status === "ok") {
        setContexts(json.lateral_contexts ?? []);
      } else {
        setContexts([]);
      }
    } finally {
      setLoading(false);
    }
  }

  async function analyzeWithAI(ctx: LateralContext) {
    const key = keyOf(ctx);
    setAiLoadingKey(key);
    try {
      const res = await fetch(
        `${API_BASE}/api/v1/correlation/run_lateral_with_ai`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ lateral_context: ctx }),
        }
      );

      const json = await res.json();
      if (json?.status === "ok" && json.analysis) {
        setAiMap((prev) => ({ ...prev, [key]: json.analysis }));
      }
    } finally {
      setAiLoadingKey(null);
    }
  }

  return (
    <section className="rounded-xl border bg-white shadow-sm p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold">
            Lateral Movement (Multi-Host)
          </h2>
          <div className="text-[11px] text-gray-500">
            Aggregate attack windows by actor IP to identify lateral candidates.
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={sinceMinutes}
            onChange={(e) => setSinceMinutes(Number(e.target.value))}
            className="border rounded px-2 py-1 text-xs"
          >
            <option value={5}>5 min</option>
            <option value={10}>10 min</option>
            <option value={15}>15 min</option>
          </select>

          <button
            onClick={runLateral}
            disabled={loading}
            className="px-3 py-1.5 text-xs rounded bg-indigo-600 text-white disabled:opacity-50"
          >
            {loading ? "Running…" : "Run Lateral"}
          </button>
        </div>
      </div>

      {/* Empty states */}
      {!hasRun && (
        <div className="text-xs text-gray-500">
          Lateral correlation has not been run yet.
        </div>
      )}

      {hasRun && !loading && contexts.length === 0 && (
        <div className="text-xs text-gray-500">
          No lateral candidates found.
        </div>
      )}

      {/* List */}
      {contexts.length > 0 && (
        <div className="space-y-2 max-h-[420px] overflow-y-auto pr-2">
          {contexts.map((c) => {
            const key = keyOf(c);
            const ai = aiMap[key];

            return (
              <div key={key} className="border rounded-lg p-3 space-y-2">
                <div className="flex justify-between gap-3">
                  <div className="space-y-1">
                    <div className="text-xs font-semibold">
                      Actor: {c.actor_ip}
                    </div>

                    <div className="flex flex-wrap gap-1 text-[11px]">
                      {c.targets.map((t) => (
                        <span
                          key={t}
                          className="border rounded px-2 py-0.5 bg-gray-50"
                        >
                          {t}
                        </span>
                      ))}
                    </div>

                    <div className="text-[11px] text-gray-600">
                      Sessions: {c.sessions.length}
                    </div>
                  </div>

                  <button
                    onClick={() => analyzeWithAI(c)}
                    disabled={aiLoadingKey === key}
                    className="px-3 py-1.5 text-xs rounded border bg-white hover:bg-gray-50 disabled:opacity-50"
                  >
                    {aiLoadingKey === key
                      ? "Analyzing…"
                      : ai
                      ? "Re-analyze (AI)"
                      : "Analyze with AI"}
                  </button>
                </div>

                {ai && <AIAnalysisResult analysis={ai} />}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
