"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import type { SensorLog } from "@/types/types";
import SensorLogTable from "./SensorLogTable";

export default function SensorLogViewer() {
  const [logs, setLogs] = useState<SensorLog[]>([]);
  const [selectedSensor, setSelectedSensor] = useState("ALL");
  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const [nextCursor, setNextCursor] =
    useState<[string, string] | null>(null);

  /* -------- FETCH LOGS -------- */
  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/elastic/logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          start: from || undefined,
          end: to || undefined,
          cursor: nextCursor || undefined,
        }),
      });

      if (!res.ok) throw new Error();

      const data: {
        logs: SensorLog[];
        nextCursor: [string, string] | null;
      } = await res.json();

      setLogs(data.logs);
      setNextCursor(data.nextCursor);
    } catch {
      setError("Failed to load logs");
    } finally {
      setLoading(false);
    }
  }, [from, to]);

  /* -------- LOAD DEFAULT (LATEST) -------- */
  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  /* -------- SENSOR LIST -------- */
  const sensors = useMemo(
    () => Array.from(new Set(logs.map((l) => l.sensor))),
    [logs]
  );

  /* -------- FILTER (SEARCH + SENSOR) -------- */
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (selectedSensor !== "ALL" && log.sensor !== selectedSensor)
        return false;

      if (search) {
        const key = search.toLowerCase();
        return JSON.stringify(log).toLowerCase().includes(key);
      }

      return true;
    });
  }, [logs, search, selectedSensor]);

  return (
    <section className="bg-white border rounded-xl p-4 shadow-sm space-y-4">
      <h2 className="text-lg font-semibold">Sensor Logs</h2>

      {/* ===== TIME FILTER ===== */}
      <div className="flex gap-2 items-center">
        <input
          type="datetime-local"
          className="border rounded-lg p-2 text-sm"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />

        <span>?</span>

        <input
          type="datetime-local"
          className="border rounded-lg p-2 text-sm"
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />

        <button
          className="px-3 py-2 text-sm bg-black text-white rounded-lg"
          onClick={() => {
            setNextCursor(null);
            fetchLogs();
          }}
        >
          Apply
        </button>
      </div>

      {/* ===== TOOLBAR ===== */}
      <div className="flex items-center gap-3">
        {/* SEARCH */}
        <input
          type="text"
          placeholder="Search logs (IP, rule, msg...)"
          className="flex-1 px-3 py-2 border rounded-lg shadow-sm text-sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        {/* SENSOR FILTER */}
        <select
          className="px-3 py-2 border rounded-lg text-sm min-w-[180px]"
          value={selectedSensor}
          onChange={(e) => setSelectedSensor(e.target.value)}
        >
          <option value="ALL">All sensors</option>
          {sensors.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>


      {/* ===== CONTENT ===== */}
      {loading && <p>Loading logs...</p>}
      {error && <p className="text-red-500">{error}</p>}

      {!loading && !error && (
        <div className="max-h-[600px] overflow-y-auto border rounded-lg">
          <SensorLogTable logs={filteredLogs} />
        </div>
      )}

      {!loading && !error && filteredLogs.length === 0 && (
        <p>No logs for this filter.</p>
      )}
    </section>
  );
}
