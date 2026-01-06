import { elastic } from "@/lib/elastic";
import type {
  SnortElasticSource,
  ElasticHit,
  ApiRequestBody,
} from "@/types/elastic";

/* -------- API HANDLER -------- */

export async function POST(req: Request): Promise<Response> {
  const body: ApiRequestBody = await req.json().catch(() => ({}));
  const { start, end, cursor } = body;

  const query =
    start && end
      ? {
          range: {
            "@timestamp": {
              gte: start,
              lte: end,
            },
          },
        }
      : { match_all: {} };

  const raw = await elastic.search<SnortElasticSource>("snort-alert-*", {
    query,
    size: 1000,
    sort: [
      { "@timestamp": "desc" },
      { "_id": "desc" },
    ],
    ...(cursor ? { search_after: cursor } : {}),
  });

  const hits = raw as ElasticHit<SnortElasticSource>[];

  const logs = hits.map((item) => {
    const s = item._source.snort ?? {};

    return {
      id: item._id,
      sort: item.sort,

      /* ✅ CHỈ DÙNG @timestamp */
      timestamp: item._source["@timestamp"],

      traffic: {
        src_ip: s.src_ap?.split(":")[0] ?? null,
        src_port: s.src_ap?.split(":")[1] ?? null,
        dst_ip: s.dst_ap?.split(":")[0] ?? null,
        dst_port: s.dst_ap?.split(":")[1] ?? null,
        proto: s.proto ?? null,
      },

      rule: s.rule ?? "None",
      msg: s.msg ?? "None",
      class: s.class ?? "None",
      action: s.action ?? "None",
      direction: s.dir ?? "None",

      pkt_gen: s.pkt_gen ?? null,
      pkt_len: s.pkt_len ?? null,
      pkt_num: s.pkt_num ?? null,

      sensor: item._source.source ?? "unknown",
    };
  });

  return Response.json({
    logs,
    nextCursor: hits.at(-1)?.sort ?? null,
  });
}
