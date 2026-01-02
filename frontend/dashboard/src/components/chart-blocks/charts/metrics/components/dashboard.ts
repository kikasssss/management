import { DashboardMetrics } from "@/types/types";

export async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  const res = await fetch("/api/elastic/metric", {
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error("Failed to fetch dashboard metrics");
  }

  const json = await res.json();
  return json.data;
}
