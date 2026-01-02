import { elastic } from "@/lib/elastic";
import { DashboardMetrics } from "@/types/types";

export async function GET() {
  try {
    const query = {
      size: 0,
      query: {
        range: {
          "@timestamp": {
            gte: "now/d",
            lte: "now",
          },
        },
      },
      aggs: {
        total_alerts: {
          value_count: { field: "_id" },
        },
        active_sensors: {
          cardinality: { field: "source.keyword" },
        },
        most_active_sensor: {
          terms: {
            field: "source.keyword",
            size: 1,
            order: { _count: "desc" },
          },
        },
      },
    };

    const res: any = await elastic.rawSearch("snort-alert-*", query);

    const aggs = res.aggregations;

    const totalAlerts = aggs.total_alerts.value;
    const activeSensors = aggs.active_sensors.value;
    const top = aggs.most_active_sensor.buckets[0] ?? null;

    const secondsToday =
      Math.floor(
        (Date.now() -
          new Date(new Date().setHours(0, 0, 0, 0)).getTime()) / 1000
      ) || 1;

    const data: DashboardMetrics = {
      totalAlerts,
      activeSensors,
      mostActiveSensor: top
        ? { name: top.key, count: top.doc_count }
        : null,
      avgAlertsPerSecond: Math.round(totalAlerts / secondsToday),
    };

    return Response.json({ data });
  } catch (err: any) {
    console.error("Dashboard metric error:", err);
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500 }
    );
  }
}
