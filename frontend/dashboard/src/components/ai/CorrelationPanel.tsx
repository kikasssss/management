"use client";

import { useMemo, useState } from "react";
import AIAnalysisResult from "./AIAnalysisResult";
type ConfidenceHint = "low" | "medium" | "high";
type RiskLevel = "low" | "medium" | "high";

type AttackWindowSummary = {
  actor_ip: string;
  target_ip: string;
  time?: { start: string; end: string };
  statistics: { event_count: number; behavior_frequency?: Record<string, number> };
  interpretation: {
    dominant_tactic?: string | null;
    confidence_hint: ConfidenceHint;
    lateral_movement?: boolean;
  };
  evidence?: { message_frequency?: Record<string, number> };
};

type CorrelationWindowResult = {
  summary: AttackWindowSummary;
  ai_triggered: boolean; // should be false from /run_from_mongo
  analysis: null;
};

type CorrelationRunResponse = {
  status: "ok";
  event_count: number;
  window_count: number;
  results: CorrelationWindowResult[];
};

type GPTAnalysisResult = {
  attack_chain: boolean;
  suspected_stages: string[];
  top_findings: string[];
  lateral_movement: { detected: boolean; evidence: string[] };
  confidence: number; // 0..1
  risk_level: RiskLevel;
  recommended_actions: string[];
};

type GPTAnalysisResponse = {
  status: "ok";
  analysis: GPTAnalysisResult;
};

function getApiBase() {
  // Ưu tiên env, fallback theo code cũ của bạn
  return process.env.NEXT_PUBLIC_API_BASE ?? "http://100.100.100.100:5000";
}

function hintBadge(h: ConfidenceHint) {
  switch (h) {
    case "high":
      return "bg-green-100 text-green-700 border-green-200";
    case "medium":
      return "bg-yellow-100 text-yellow-700 border-yellow-200";
    default:
      return "bg-gray-100 text-gray-600 border-gray-200";
  }
}

function riskBadge(r: RiskLevel) {
  switch (r) {
    case "high":
      return "bg-red-100 text-red-700 border-red-200";
    case "medium":
      return "bg-orange-100 text-orange-700 border-orange-200";
    default:
      return "bg-green-100 text-green-700 border-green-200";
  }
}

function windowKey(s: AttackWindowSummary) {
  // Key ổn định cho cache AI; ưu tiên time nếu có
  const start = s.time?.start ?? "";
  const end = s.time?.end ?? "";
  return `${s.actor_ip}|${s.target_ip}|${start}|${end}`;
}

export default function CorrelationPanel() {
  const API_BASE = useMemo(() => getApiBase(), []);

  const [sinceMinutes, setSinceMinutes] = useState<number>(5);
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);

  const [runMeta, setRunMeta] = useState<{ event_count: number; window_count: number } | null>(null);
  const [windows, setWindows] = useState<CorrelationWindowResult[]>([]);

  // Cache AI result theo windowKey
  const [aiMap, setAiMap] = useState<Record<string, GPTAnalysisResult>>({});
  const [aiLoadingKey, setAiLoadingKey] = useState<string | null>(null);

  async function runCorrelation() {
    setLoading(true);
    setHasRun(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/correlation/run_from_mongo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ since_minutes: sinceMinutes }),
      });

      const json = (await res.json()) as CorrelationRunResponse;

      if (json?.status === "ok") {
        setRunMeta({ event_count: json.event_count, window_count: json.window_count });
        setWindows(json.results ?? []);
      } else {
        setRunMeta(null);
        setWindows([]);
      }
    } finally {
      setLoading(false);
    }
  }

  async function analyzeWithAI(summary: AttackWindowSummary) {
    const key = windowKey(summary);
    setAiLoadingKey(key);
    try {
      const res = await fetch(`${API_BASE}/api/v1/correlation/run_with_ai`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ summary }),
      });

      const json = (await res.json()) as GPTAnalysisResponse;
      if (json?.status === "ok" && json.analysis) {
        setAiMap((prev) => ({ ...prev, [key]: json.analysis }));
      }
    } finally {
      setAiLoadingKey(null);
    }
  }

  const topEvidence = (s: AttackWindowSummary) => {
    const mf = s.evidence?.message_frequency ?? {};
    const entries = Object.entries(mf).sort((a, b) => b[1] - a[1]);
    return entries.slice(0, 2);
  };

  return (
    <section className="rounded-xl border bg-white shadow-sm p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="space-y-0.5">
          <h2 className="text-sm font-semibold">Attack Correlation</h2>
          <div className="text-[11px] text-gray-500">
            Build windows from Mongo normalized events. AI runs per-window (manual).
          </div>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-600 flex items-center gap-2">
            Lookback
            <select
              value={sinceMinutes}
              onChange={(e) => setSinceMinutes(Number(e.target.value))}
              className="border rounded px-2 py-1 text-xs"
            >
              <option value={3}>3 min</option>
              <option value={5}>5 min</option>
              <option value={10}>10 min</option>
              <option value={15}>15 min</option>
            </select>
          </label>

          <button
            onClick={runCorrelation}
            disabled={loading}
            className="px-3 py-1.5 text-xs rounded bg-indigo-600 text-white disabled:opacity-50"
          >
            {loading ? "Running…" : "Run Correlation"}
          </button>
        </div>
      </div>

      {/* Meta */}
      {runMeta && (
        <div className="text-xs text-gray-600 flex items-center gap-3">
          <span>
            Events: <b>{runMeta.event_count}</b>
          </span>
          <span>
            Windows: <b>{runMeta.window_count}</b>
          </span>
        </div>
      )}

      {/* Empty states */}
      {!hasRun && <div className="text-xs text-gray-500">Correlation has not been run yet.</div>}
      {hasRun && !loading && windows.length === 0 && (
        <div className="text-xs text-gray-500">No attack windows detected for this lookback.</div>
      )}

      {/* Window list */}
      {windows.length > 0 && (
        <div className="space-y-2 max-h-[520px] overflow-y-auto pr-2 ">
          {windows.map((w, idx) => {
            const s = w.summary;
            const key = windowKey(s);
            const ai = aiMap[key];
            const evidence = topEvidence(s);

            return (
              <div key={`${key}-${idx}`} className="border rounded-lg p-3 space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="text-xs">
                      <span className="font-semibold">{s.actor_ip}</span>
                      <span className="text-gray-400"> → </span>
                      <span className="font-semibold">{s.target_ip}</span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-gray-600">
                      <span className={`border px-2 py-0.5 rounded ${hintBadge(s.interpretation.confidence_hint)}`}>
                        hint: {s.interpretation.confidence_hint}
                      </span>

                      <span className="border px-2 py-0.5 rounded bg-gray-50">
                        events: {s.statistics?.event_count ?? 0}
                      </span>

                      {typeof s.interpretation.lateral_movement === "boolean" && (
                        <span className="border px-2 py-0.5 rounded bg-gray-50">
                          LM proxy: {s.interpretation.lateral_movement ? "yes" : "no"}
                        </span>
                      )}

                      {s.interpretation.dominant_tactic ? (
                        <span className="border px-2 py-0.5 rounded bg-gray-50">
                          tactic: {s.interpretation.dominant_tactic}
                        </span>
                      ) : null}
                    </div>

                    {/* Evidence (message_frequency) */}
                    {evidence.length > 0 && (
                      <div className="text-[11px] text-gray-700">
                        <div className="text-gray-500">Evidence (top rule messages):</div>
                        <ul className="list-disc pl-4">
                          {evidence.map(([msg, c]) => (
                            <li key={msg}>
                              <span className="font-medium">{c}×</span> {msg}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col items-end gap-2">
                    <button
                      onClick={() => analyzeWithAI(s)}
                      disabled={aiLoadingKey === key}
                      className="px-3 py-1.5 text-xs rounded border bg-white hover:bg-gray-50 disabled:opacity-50"
                      title="Run GPT analysis for this window"
                    >
                      {aiLoadingKey === key ? "Analyzing…" : ai ? "Re-analyze (AI)" : "Analyze with AI"}
                    </button>

                    {ai && (
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className={`border px-2 py-0.5 rounded ${riskBadge(ai.risk_level)}`}>
                          risk: {ai.risk_level}
                        </span>
                        <span className="border px-2 py-0.5 rounded bg-gray-50">
                          conf: {(ai.confidence * 100).toFixed(0)}%
                        </span>
                        <span className="border px-2 py-0.5 rounded bg-gray-50">
                          chain: {ai.attack_chain ? "yes" : "no"}
                        </span>
                        <span className="border px-2 py-0.5 rounded bg-gray-50">
                          LM: {ai.lateral_movement?.detected ? "yes" : "no"}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* AI details */}
                {ai && <AIAnalysisResult analysis={ai} />}        


              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
