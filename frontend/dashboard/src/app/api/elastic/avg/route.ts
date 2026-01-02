import { elastic } from "@/lib/elastic";
import type { SensorMetric } from "@/types/types";

const SENSOR_MAP: Record<string, SensorMetric["type"]> = {
  snort_client: "Client",
  snort_dmz: "DMZ",
  snort_server: "ServerFarm",
};

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const from = searchParams.get("from") ?? "now-24h";
    const to = searchParams.get("to") ?? "now";

    const query = {
      size: 0,
      query: {
        bool: {
          filter: [
            { term: { log_type: "snort_alert" } },
            {
              range: {
                "@timestamp": {
                  gte: from,
                  lte: to,
                },
              },
            },
          ],
        },
      },
      aggs: {
        by_time: {
          date_histogram: {
            field: "@timestamp",
            calendar_interval: "day",
          },
          aggs: {
            by_sensor: {
              terms: {
                field: "source.keyword",
                size: 5,
              },
            },
          },
        },
      },
    };

    const res: any = await elastic.rawSearch("snort-alert-*", query);

    const buckets = res.aggregations.by_time.buckets;
    const data: SensorMetric[] = [];

    for (const timeBucket of buckets) {
      const date = timeBucket.key_as_string.slice(0, 10);

      for (const sensor of timeBucket.by_sensor.buckets) {
        const mapped = SENSOR_MAP[sensor.key];
        if (!mapped) continue;

        data.push({
          date,
          type: mapped,
          value: sensor.doc_count,
        });
      }
    }

    return Response.json({ data });
  } catch (err: any) {
    console.error("AVG SENSOR API ERROR:", err);
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500 }
    );
  }
}
