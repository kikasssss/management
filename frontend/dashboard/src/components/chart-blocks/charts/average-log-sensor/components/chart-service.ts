import type { SensorMetric } from "@/types/types";

const BASE_URL =
  process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";

export async function fetchSensorChartData(
  start?: string,
  end?: string
): Promise<SensorMetric[]> {
  const res = await fetch(`${BASE_URL}/api/elastic/avg`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ start, end }),
    cache: "no-store",
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(err);
  }

  const json = await res.json();
  return json.data;
}
