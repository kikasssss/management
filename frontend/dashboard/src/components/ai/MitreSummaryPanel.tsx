"use client";

import { useEffect, useState } from "react";

interface SummaryItem {
  name: string;
  count: number;
  percent: number;
}

interface MitreSummary {
  total_logs: number;
  by_tactic: SummaryItem[];
  by_technique: SummaryItem[];
  sensor_id: string;
  date: string;
}

export default function MitreSummaryPanel() {
  // ===== local state =====
  const [date, setDate] = useState(
    new Date().toISOString().slice(0, 10)
  );
  const [sensorId, setSensorId] = useState("ALL");
  const [data, setData] = useState<MitreSummary | null>(null);
  const [loading, setLoading] = useState(false);

  // ===== fetch summary =====
  useEffect(() => {
    async function load() {
      setLoading(true);
      setData(null);

      const url =
        `http://100.100.100.100:5000/api/v1/mitre/summary` +
        `?date=${date}` +
        (sensorId !== "ALL" ? `&sensor_id=${sensorId}` : "");

      try {
        const res = await fetch(url);
        const json = await res.json();
        setData(json);
      } catch (err) {
        console.error("Failed to fetch MITRE summary", err);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, [date, sensorId]);

  return (
    <section className="rounded-xl border bg-white p-4 shadow-sm">

      {/* ===== HEADER ===== */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold">
          MITRE ATT&CK Summary
        </h2>

        <div className="flex items-center gap-2">
          {/* DATE */}
          <input
            type="date"
            value={date}
            onChange={(e) => setDate(e.target.value)}
            className="rounded-md border px-2 py-1 text-xs"
          />

          {/* SENSOR */}
          <select
            value={sensorId}
            onChange={(e) => setSensorId(e.target.value)}
            className="rounded-md border px-2 py-1 text-xs"
          >
            <option value="ALL">All sensors</option>
            <option value="snort_dmz">snort_dmz</option>
            <option value="snort_client">snort_client</option>
            <option value="snort_server">snort_server</option>
          </select>
        </div>
      </div>

      {loading || !data ? (
        <div className="text-xs text-gray-500">
          Loading summary…
        </div>
      ) : (
        <>
          {/* META */}
          <div className="text-xs text-gray-500 mb-4">
            Sensor: <b>{data.sensor_id}</b> · Date: <b>{data.date}</b> ·
            Total logs: <b>{data.total_logs}</b>
          </div>

          {/* TACTIC */}
          <div className="mb-4">
            <h3 className="text-xs font-medium mb-2">
              Tactic Distribution
            </h3>

            {data.by_tactic.map((t) => (
              <div key={t.name} className="mb-2">
                <div className="flex justify-between text-xs">
                  <span>{t.name}</span>
                  <span>{t.percent.toFixed(1)}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded">
                  <div
                    className="h-2 bg-indigo-600 rounded"
                    style={{ width: `${t.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* TECHNIQUE */}
          <div>
            <h3 className="text-xs font-medium mb-2">
              Top Techniques
            </h3>

            {data.by_technique.slice(0, 5).map((t) => (
              <div
                key={t.name}
                className="flex justify-between text-xs mb-1"
              >
                <span>{t.name}</span>
                <span>{t.count}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
