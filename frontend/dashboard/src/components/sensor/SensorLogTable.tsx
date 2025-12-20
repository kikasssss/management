"use client";

import { useState } from "react";
import type { SensorLog } from "@/types/types";

interface SensorLogTableProps {
  logs: SensorLog[];
}

export default function SensorLogTable({ logs }: SensorLogTableProps) {
  const [selectedLog, setSelectedLog] = useState<SensorLog | null>(null);

  return (
    <div className="overflow-x-auto rounded-xl border">
      <table className="w-full text-sm bg-white">
        <thead className="bg-gray-50 text-xs uppercase text-gray-600">
          <tr>
            <th className="px-3 py-2 text-left">@timestamp</th>
            <th className="px-3 py-2 text-left">src_ip</th>
            <th className="px-3 py-2 text-left">src_port</th>
            <th className="px-3 py-2 text-left">dst_ip</th>
            <th className="px-3 py-2 text-left">dst_port</th>
            <th className="px-3 py-2 text-left">proto</th>
            <th className="px-3 py-2 text-left">rule</th>
            <th className="px-3 py-2 text-left">action</th>
            <th className="px-3 py-2 text-left">class</th>
            <th className="px-3 py-2 text-left">direction</th>
            <th className="px-3 py-2 text-left">msg</th>
            <th className="px-3 py-2 text-left">pkt_gen</th>
            <th className="px-3 py-2 text-left">pkt_len</th>
            <th className="px-3 py-2 text-left">pkt_num</th>
            <th className="px-3 py-2 text-left">sensor</th>
          </tr>
        </thead>

        <tbody>
          {logs.map((log, idx) => (
            <tr
              key={log.id ?? idx}
              className="border-t hover:bg-gray-50 cursor-pointer"
              onClick={() => setSelectedLog(log)}
            >
              <td className="px-3 py-2">{log.timestamp}</td>
              <td className="px-3 py-2">{log.traffic.src_ip}</td>
              <td className="px-3 py-2">{log.traffic.src_port}</td>
              <td className="px-3 py-2">{log.traffic.dst_ip}</td>
              <td className="px-3 py-2">{log.traffic.dst_port}</td>
              <td className="px-3 py-2">{log.traffic.proto}</td>
              <td className="px-3 py-2">{log.rule}</td>
              <td className="px-3 py-2">{log.action}</td>
              <td className="px-3 py-2">{log.class}</td>
              <td className="px-3 py-2">{log.direction}</td>
              <td className="px-3 py-2">{log.msg}</td>
              <td className="px-3 py-2">{log.pkt_gen}</td>
              <td className="px-3 py-2">{log.pkt_len}</td>
              <td className="px-3 py-2">{log.pkt_num}</td>
              <td className="px-3 py-2">{log.sensor}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {logs.length === 0 && (
        <p className="text-center p-4 text-gray-500 text-sm">
          No logs to display.
        </p>
      )}

      {/* MODAL JSON */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-xl shadow-xl w-[600px] max-h-[80vh] overflow-auto">
            <h2 className="text-lg font-bold mb-3">Log Details (JSON)</h2>
            <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
              {JSON.stringify(selectedLog, null, 2)}
            </pre>
            <button
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg"
              onClick={() => setSelectedLog(null)}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
