"use client";

import type { SensorInfo, SensorStatus } from "@/types/types";

interface SensorTableProps {
  sensors: SensorInfo[];
}

export default function SensorTable({ sensors }: SensorTableProps) {
  return (
    <table className="w-full border rounded-lg bg-white shadow-sm text-sm mt-6">
      <thead className="bg-gray-50">
        <tr>
          {["ID", "Hostname", "IP", "Status", "Zone", "Type", "Last Update", "Rule Version"].map((h) => (
            <th key={h} className="px-4 py-2 text-left">{h}</th>
          ))}
        </tr>
      </thead>

      <tbody>
        {Array.isArray(sensors) && sensors.map((s) => (
          <tr key={s.sensor_id} className="border-t hover:bg-gray-50">
            <td className="px-4 py-2">{s.sensor_id}</td>
            <td className="px-4 py-2">{s.hostname}</td>
            <td className="px-4 py-2">{s.ip_address}</td>
            <td className="px-4 py-2">{s.status}</td>
            <td className="px-4 py-2">Unknown</td>
            <td className="px-4 py-2">Snort</td>
            <td className="px-4 py-2">{new Date(s.last_seen).toLocaleString()}</td>
            <td className="px-4 py-2">{s.rule_version}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
