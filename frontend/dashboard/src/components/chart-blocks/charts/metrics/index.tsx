"use client";

import { useEffect, useState } from "react";
import Container from "@/components/container";
import MetricCard from "./components/metric-card";
import { fetchDashboardMetrics } from "./components/dashboard";
import { DashboardMetrics } from "@/types/types";

export default function Metrics() {
  const [data, setData] = useState<DashboardMetrics | null>(null);

  useEffect(() => {
    fetchDashboardMetrics()
      .then(setData)
      .catch(console.error);
  }, []);

  if (!data) return null;

  const metrics = [
    {
      title: "Total Alerts (Today)",
      value: data.totalAlerts.toLocaleString(),
      change: 0,
    },
    {
      title: "Active Sensors",
      value: data.activeSensors.toString(),
      change: 0,
    },
    {
      title: "Most Active Sensor",
      value: data.mostActiveSensor
        ? data.mostActiveSensor.name
        : "N/A",
      change: 0,
    },
    {
      title: "Average Alerts",
      value: `${data.avgAlertsPerSecond}/s`,
      change: 0,
    },
  ];

  return (
    <Container className="grid grid-cols-1 gap-y-6 border-b border-border py-4 phone:grid-cols-2 laptop:grid-cols-4">
      {metrics.map((m) => (
        <MetricCard key={m.title} {...m} />
      ))}
    </Container>
  );
}
