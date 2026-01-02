import type { SensorMetric } from "@/types/types";

export async function fetchSensorChartData(
  start?: string,
  end?: string
): Promise<SensorMetric[]> {
  const res = await fetch("/api/elastic/avg", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ start, end }),
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error("Failed to fetch sensor chart data");
  }

  const json = await res.json();
  return json.data;
}
