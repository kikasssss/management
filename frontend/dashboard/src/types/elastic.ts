/* ===== ELASTIC / SNORT TYPES ===== */

export interface SnortFields {
  timestamp?: string;
  src_ap?: string;
  dst_ap?: string;
  proto?: string;
  msg?: string;
  rule?: string;
  class?: string;
  action?: string;
  dir?: string;
  pkt_gen?: number;
  pkt_len?: number;
  pkt_num?: number;
}

export interface SnortElasticSource {
  "@timestamp": string;
  source?: string;
  snort?: SnortFields;
}

/* Generic hit tr? v? t? Elasticsearch */
export interface ElasticHit<T> {
  _id: string;
  _source: T;
  sort?: [string, string]; // dùng cho search_after
}

/* Body g?i t? frontend */
export interface ApiRequestBody {
  start?: string;
  end?: string;
  cursor?: [string, string];
}
