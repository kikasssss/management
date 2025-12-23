"use client";

import { useState } from "react";

type CorrelationIncident = {
  incident_id: string;
  created_at: string;
  actor_ip: string;
  target_ip: string;
  risk_level: string;
  confidence: number;
  lateral_movement: boolean;
};

export default function CorrelationPanel() {
  const [enableAI, setEnableAI] = useState(false);
  const [loading, setLoading] = useState(false);
  const [incidents, setIncidents] = useState<CorrelationIncident[]>([]);

  async function runCorrelation() {
    setLoading(true);
    try {
      const res = await fetch(
        "http://100.100.100.100:5000/api/v1/correlation/run",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            events: [], // 👉 backend sẽ lấy events thật sau
            enable_ai: enableAI,
          }),
        }
      );

      const json = await res.json();
      if (json.results) {
        setIncidents(
          json.results
            .filter((r: any) => r.incident_id)
            .map((r: any) => ({
              incident_id: r.incident_id,
              created_at: new Date().toISOString(),
              actor_ip: r.summary.actor_ip,
              target_ip: r.summary.target_ip,
              risk_level: r.analysis?.risk_level ?? "low",
              confidence: r.analysis?.confidence ?? 0,
              lateral_movement:
                r.analysis?.lateral_movement?.detected ?? false,
            }))
        );
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="rounded-xl border bg-white shadow-sm p-4 space-y-4">

      {/* ===== Header ===== */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">
          Attack Correlation
        </h2>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1 text-xs">
            <input
              type="checkbox"
              checked={enableAI}
              onChange={(e) => setEnableAI(e.target.checked)}
            />
            Enable AI
          </label>

          <button
            onClick={runCorrelation}
            disabled={loading}
            className="px-3 py-1 text-xs rounded bg-indigo-600 text-white disabled:opacity-50"
          >
            {loading ? "Running…" : "Run Correlation"}
          </button>
        </div>
      </div>

      {/* ===== Incident Table ===== */}
      {incidents.length === 0 ? (
        <div className="text-xs text-gray-500">
          No correlation incidents yet.
        </div>
      ) : (
        <table className="w-full text-xs border">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-2 py-1 text-left">Actor</th>
              <th className="px-2 py-1 text-left">Target</th>
              <th className="px-2 py-1">Risk</th>
              <th className="px-2 py-1">AI</th>
              <th className="px-2 py-1">LM</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={i.incident_id} className="border-t">
                <td className="px-2 py-1">{i.actor_ip}</td>
                <td className="px-2 py-1">{i.target_ip}</td>
                <td className="px-2 py-1 text-center">
                  {i.risk_level}
                </td>
                <td className="px-2 py-1 text-center">
                  ✓
                </td>
                <td className="px-2 py-1 text-center">
                  {i.lateral_movement ? "✓" : "✗"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
