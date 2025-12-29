# services/mitre_worker.py

import time
from elasticsearch import Elasticsearch

import config
from AI_MITRE.Catboost.preprocessing.normalize_elastic import normalize_elastic_log
from AI_MITRE.Catboost.inference.engine import MitreEngine
from services.mitre_storage import save_mitre_result
from services.pipeline_offset import set_mitre_offset
import warnings
from elasticsearch import ElasticsearchWarning
# =========================
# CONFIG
# =========================
ELASTIC_URL = "http://localhost:9200"
ELASTIC_INDEX = "snort-alert-*"
BATCH_SIZE = 200
POLL_INTERVAL = 1  # seconds

# =========================
# INIT
# =========================
es = Elasticsearch(ELASTIC_URL)
engine = MitreEngine()


warnings.filterwarnings(
    "ignore",
    category=ElasticsearchWarning
)
# =========================
# METADATA EXTRACTOR
# =========================
def extract_metadata(hit: dict) -> dict:
    """
    Trích metadata từ Elasticsearch hit
    (KHÔNG ảnh hưởng normalize / AI)
    """

    src = hit.get("_source", {})
    snort = src.get("snort", {})

    def split_ip_port(value):
        if value and ":" in value:
            ip, port = value.rsplit(":", 1)
            try:
                return ip, int(port)
            except Exception:
                return ip, None
        return None, None

    src_ip, src_port = split_ip_port(snort.get("src_ap"))
    dst_ip, dst_port = split_ip_port(snort.get("dst_ap"))

    return {
        # 🔗 LINK ELASTIC
        "elastic_index": hit.get("_index"),
        "elastic_id": hit.get("_id"),

        # TIME
        "timestamp": src.get("@timestamp"),

        # SENSOR
        "sensor_id": src.get("source") or src.get("agent", {}).get("id"),

        # NETWORK
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": snort.get("proto"),

        # MESSAGE
        "msg": snort.get("msg"),

        # DEBUG / OPTIONAL
        "rule": snort.get("rule"),
        "action": snort.get("action"),
        "class": snort.get("class"),
    }

# =========================
# FETCH LOGS FROM ELASTIC
# =========================
def fetch_logs(search_after=None):
    """
    FIX QUAN TRỌNG:
    - KHÔNG dùng _shard_doc (vì không có PIT)
    - Dùng @timestamp + _id để search_after an toàn
    """
    query = {
        "size": BATCH_SIZE,
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"}          # 🔥 FIX: thay _shard_doc
        ],
        "query": {"match_all": {}}
    }

    if search_after:
        query["search_after"] = search_after

    resp = es.search(index=ELASTIC_INDEX, body=query)
    return resp["hits"]["hits"]

# =========================
# MAIN LOOP
# =========================
def run_forever():
    print("[MITRE] Worker started")
    search_after = None

    while True:
        try:
            hits = fetch_logs(search_after)
            if not hits:
                time.sleep(POLL_INTERVAL)
                continue

            print(f"[MITRE] Got {len(hits)} logs")

            for hit in hits:
                try:
                    meta = extract_metadata(hit)
                    features = normalize_elastic_log(hit)
                    mitre_result = engine.process_log(features)

                    if mitre_result:
                        save_mitre_result(meta, mitre_result)

                except Exception as e:
                    # Lỗi 1 event thì bỏ qua event đó
                    print("[MITRE][EVENT ERROR]", e)

            # ✅ cập nhật checkpoint + offset theo sort cuối cùng
            search_after = hits[-1]["sort"]
            set_mitre_offset(search_after)

            # nghỉ nhẹ để tránh CPU 100%
            time.sleep(0.05)

        except Exception as e:
            print("[MITRE][ERROR]", e)
            time.sleep(POLL_INTERVAL)

def start_worker():
    run_forever()
