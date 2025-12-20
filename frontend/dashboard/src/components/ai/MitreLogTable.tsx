"use client";
import { useState, useMemo, useEffect } from "react";
import type { MitreLog } from "@/types/types";
import { fetchMitreLogs } from "@/lib/api";
function formatTime(ts: string) {
  return new Date(ts).toLocaleString();
}

export default function MitreLogTable({ logs }: { logs: MitreLog[] }) {
  const [selectedSensor, setSelectedSensor] = useState<string>("ALL");
  const [search, setSearch] = useState("");

  const sensors = useMemo(() => {
    return Array.from(new Set(logs.map((l) => l.sensor_id)));
  }, [logs]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchSensor =
        selectedSensor === "ALL" || log.sensor_id === selectedSensor;

      const keyword = search.toLowerCase();
      const matchSearch =
        !search ||
        log.msg.toLowerCase().includes(keyword) ||
        log.tactic.toLowerCase().includes(keyword) ||
        log.technique.toLowerCase().includes(keyword) ||
        log.src_ip?.includes(keyword) ||
        log.dst_ip?.includes(keyword);

      return matchSensor && matchSearch;
    });
  }, [logs, selectedSensor, search]);

  return (
    <section className="rounded-xl border bg-white shadow-sm flex flex-col">

      {/* ===== HEADER ===== */}
      <div className="px-4 py-3 border-b">
        <h2 className="text-sm font-semibold">
          MITRE ATT&CK – Sensor Logs
        </h2>
      </div>

      {/* ===== FILTER BAR ===== */}
      <div className="px-4 py-3 border-b space-y-2">

        {/* SENSOR FILTER */}
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setSelectedSensor("ALL")}
            className={`px-3 py-1 rounded-full text-xs border
              ${selectedSensor === "ALL"
                ? "bg-indigo-600 text-white"
                : "bg-white"}
            `}
          >
            All
          </button>

          {sensors.map((sensor) => (
            <button
              key={sensor}
              onClick={() => setSelectedSensor(sensor)}
              className={`px-3 py-1 rounded-full text-xs border
                ${selectedSensor === sensor
                  ? "bg-indigo-600 text-white"
                  : "bg-white"}
              `}
            >
              {sensor}
            </button>
          ))}
        </div>

        {/* SEARCH */}
        <input
          type="text"
          placeholder="Search msg, tactic, technique, IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-md border px-3 py-1.5 text-xs"
        />
      </div>

      {/* ===== TABLE (SCROLLABLE) ===== */}
      <div className="max-h-[420px] overflow-y-auto">
        <table className="w-full text-xs">

          {/* TABLE HEADER */}
          <thead className="sticky top-0 bg-gray-50 text-gray-600 uppercase z-10">
            <tr>
              <th className="px-2 py-2 text-left">Time</th>
              <th className="px-2 py-2 text-left">Sensor</th>
              <th className="px-2 py-2 text-left">Traffic</th>
              <th className="px-2 py-2 text-left">Message</th>
              <th className="px-2 py-2 text-left">Tactic</th>
              <th className="px-2 py-2 text-left">Technique</th>
              <th className="px-2 py-2 text-right">Conf.</th>
            </tr>
          </thead>

          {/* TABLE BODY */}
          <tbody>
            {filteredLogs.map((item) => (
              <tr
                key={item._id}
                className="border-t hover:bg-gray-50"
              >
                <td className="px-2 py-1">
                  {formatTime(item.timestamp)}
                </td>

                <td className="px-2 py-1 font-medium">
                  {item.sensor_id}
                </td>

                <td className="px-2 py-1 text-gray-600">
                  {item.src_ip}:{item.src_port} → {item.dst_ip}:{item.dst_port}
                  <div className="text-gray-400">{item.proto}</div>
                </td>

                <td className="px-2 py-1">
                  {item.msg}
                </td>

                <td className="px-2 py-1 font-medium">
                  {item.tactic}
                </td>

                <td className="px-2 py-1 text-gray-600">
                  {item.technique}
                </td>

                <td className="px-2 py-1 text-right font-semibold text-indigo-600">
                  {(item.confidence * 100).toFixed(1)}%
                </td>
              </tr>
            ))}

            {filteredLogs.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-6 text-gray-400">
                  No logs found
                </td>
              </tr>
            )}
          </tbody>

        </table>
      </div>
    </section>
  );

}
