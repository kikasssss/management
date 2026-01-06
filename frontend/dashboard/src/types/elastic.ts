/* ===== ELASTIC / SNORT TYPES ===== */

/**
 * Tru?ng log g?c do Snort sinh ra
 * ? KHÔNG dùng cho filter / sort / chart
 */
export interface SnortFields {
  /** Timestamp g?c c?a Snort (string, không timezone) */
  timestamp?: string;

  src_ap?: string;
  dst_ap?: string;
  proto?: string;
  msg?: string;
  rule?: string;
  class?: string;
  action?: string;
  dir?: string;
  pkt_gen?: string;
  pkt_len?: number;
  pkt_num?: number;
}

/**
 * Document chu?n trong Elasticsearch
 */
export interface SnortElasticSource {
  /**
   * ? Timestamp CHU?N c?a h? th?ng (Elastic ingest time)
   * ISO-8601, dùng cho m?i x? lý th?i gian
   */
  "@timestamp": string;

  /** Sensor name (snort_client | snort_dmz | snort_server) */
  source?: string;

  /** Payload g?c t? Snort */
  snort?: SnortFields;
}

/* Generic hit tr? v? t? Elasticsearch */
export interface ElasticHit<T> {
  _id: string;
  _source: T;

  /**
   * Dùng cho search_after
   * sort[0] = @timestamp
   * sort[1] = _id
   */
  sort?: [string, string];
}

/* Body g?i t? frontend */
export interface ApiRequestBody {
  /** ISO-8601 time (map vào @timestamp) */
  start?: string;
  end?: string;

  /** search_after cursor */
  cursor?: [string, string];
}
