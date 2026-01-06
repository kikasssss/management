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

        /* ===== AVG LOG / SECOND (ĐÚNG) ===== */
        per_second: {
          date_histogram: {
            field: "@timestamp",
            fixed_interval: "1s",
            min_doc_count: 0,
          },
        },
        avg_alerts_per_second: {
          avg_bucket: {
            buckets_path: "per_second._count",
          },
        },
      },
    };

    const res: any = await elastic.rawSearch("snort-alert-*", query);
    const aggs = res.aggregations;

    const totalAlerts = aggs.total_alerts.value;
    const activeSensors = aggs.active_sensors.value;
    const top = aggs.most_active_sensor.buckets[0] ?? null;

    const data: DashboardMetrics = {
      totalAlerts,
      activeSensors,
      mostActiveSensor: top
        ? { name: top.key, count: top.doc_count }
        : null,

      // 👉 GIỮ NGUYÊN TÊN FIELD
      avgAlertsPerSecond: Number(
        aggs.avg_alerts_per_second?.value?.toFixed(2) ?? 0
      ),
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
