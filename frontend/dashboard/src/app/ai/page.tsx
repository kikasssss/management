"use client";

import { useEffect, useState } from "react";
import MitreLogTable from "@/components/ai/MitreLogTable";
import MitreSummaryPanel from "@/components/ai/MitreSummaryPanel";
import AttackChainView from "@/components/ai/AttackChainView";
import type { MitreLog } from "@/types/types";

export default function AIPage() {
  const [logs, setLogs] = useState<MitreLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastTime, setLastTime] = useState<string | null>(null);

  // 👉 sensor dùng chung cho log + summary
  const [selectedSensor, setSelectedSensor] = useState("ALL");

  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;

    async function loadInitial() {
      try {
        const res = await fetch(
          "http://100.100.100.100:5000/api/v1/mitre/results?limit=50"
        );
        const json = await res.json();

        setLogs(json.data || []);
        if (json.data?.length > 0) {
          setLastTime(json.data[0].created_at);
        }
      } finally {
        setLoading(false);
      }
    }

    async function loadIncremental() {
      if (!lastTime) return;

      const res = await fetch(
        `http://100.100.100.100:5000/api/v1/mitre/results?after=${lastTime}`
      );
      const json = await res.json();

      if (json.data?.length > 0) {
        setLogs((prev) => [...json.data, ...prev]);
        setLastTime(json.data[0].created_at);
      }
    }

    loadInitial();
    timer = setInterval(loadIncremental, 5000);
    return () => clearInterval(timer);
  }, [lastTime]);

  return (
    <div className="p-6 space-y-6">

      {loading ? (
        <div className="text-xs text-gray-500">
          Loading MITRE logs…
        </div>
      ) : (
        <MitreLogTable
          logs={logs}
          onSensorChange={setSelectedSensor}
        />
      )}

      {/* 👉 Summary TỰ QUẢN LÝ DATE */}
      <MitreSummaryPanel sensorId={selectedSensor} />

      <AttackChainView chains={[]} />
    </div>
  );
}
