"use client";

import { Circle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SensorInfo, SensorStatus } from "@/types/types";

interface SensorTableProps {
  sensors: SensorInfo[];
}

const statusColor: Record<SensorStatus, string> = {
  active: "text-green-500",
  warning: "text-yellow-500",
  critical: "text-red-500",
  offline: "text-gray-300",
};

export default function SensorTable({ sensors }: SensorTableProps) {
  return (
    <table className="w-full border rounded-lg bg-white shadow-sm text-sm mt-6">
      <thead className="bg-gray-50">
        <tr>
          {["ID", "Hostname", "IP", "Status", "Zone", "Type", "Last Update"].map(
            (h) => (
              <th key={h} className="px-4 py-2 text-left">
                {h}
              </th>
            )
          )}
        </tr>
      </thead>

      <tbody>
        {sensors.map((s) => (
          <tr
            key={s.id ?? `${s.hostname}-${s.ip}`}
            className="border-t hover:bg-gray-50"
          >
            <td className="px-4 py-2">{s.id ?? "-"}</td>
            <td className="px-4 py-2">{s.hostname}</td>
            <td className="px-4 py-2">{s.ip}</td>

            <td className="px-4 py-2 flex items-center gap-1">
              <Circle
                className={cn(
                  "h-3 w-3",
                  statusColor[s.status] ?? "text-gray-400"
                )}
              />
              {s.status}
            </td>

            <td className="px-4 py-2">{s.zone ?? "Unknown"}</td>
            <td className="px-4 py-2">{s.type ?? "Snort"}</td>
            <td className="px-4 py-2">{s.lastUpdate ?? "-"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
