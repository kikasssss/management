# services/mitre_worker.py

import time
import warnings
from elasticsearch import Elasticsearch, ElasticsearchWarning

from AI_MITRE.Catboost.preprocessing.normalize_elastic import normalize_elastic_log
from AI_MITRE.Catboost.inference.engine import MitreEngine
from services.mitre_storage import save_mitre_result
from services.pipeline_offset import set_mitre_offset

# =========================
# CONFIG
# =========================
ELASTIC_URL = "http://localhost:9200"
ELASTIC_INDEX = "snort-alert-*"
BATCH_SIZE = 200
POLL_INTERVAL = 0.1  # seconds

# =========================
# INIT
# =========================
es = Elasticsearch(ELASTIC_URL)
engine = MitreEngine()

warnings.filterwarnings("ignore", category=ElasticsearchWarning)


def extract_metadata(hit: dict) -> dict:
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
        "elastic_index": hit.get("_index"),
        "elastic_id": hit.get("_id"),
        "timestamp": src.get("@timestamp"),
        "sensor_id": src.get("source") or src.get("agent", {}).get("id"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": snort.get("proto"),
        "msg": snort.get("msg"),
        "rule": snort.get("rule"),
        "action": snort.get("action"),
        "class": snort.get("class"),
    }


def fetch_logs(search_after=None):
    """
    IMPORTANT: No PIT here -> do NOT use _shard_doc.
    Use @timestamp + _id so search_after is stable.
    """
    query = {
        "size": BATCH_SIZE,
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"},
        ],
        "query": {"match_all": {}},
    }
    if search_after:
        query["search_after"] = search_after

    resp = es.search(index=ELASTIC_INDEX, body=query)
    return resp["hits"]["hits"]


def run_forever():
    print("[MITRE] Worker started")
    search_after = None

    while True:
        try:
            hits = fetch_logs(search_after)
            if not hits:
                time.sleep(POLL_INTERVAL)
                continue

            # debug nhẹ
            print(f"[MITRE] Got {len(hits)} logs")

            for hit in hits:
                sort_key = hit.get("sort")

                try:
                    meta = extract_metadata(hit)
                    features = normalize_elastic_log(hit)
                    mitre_result = engine.process_log(features)

                    # ===== TÁCH processed vs mapped =====
                    if mitre_result:
                        mitre_doc = {
                            "mitre_processed": True,
                            "mitre_mapped": True,
                            "tactic": mitre_result.get("tactic"),
                            "technique": mitre_result.get("technique"),
                            "confidence": mitre_result.get("confidence", 0),
                            "tactic_confidence": mitre_result.get("tactic_confidence", 0),
                            "technique_confidence": mitre_result.get("technique_confidence", 0),
                        }
                    else:
                        # 🔥 LOG BENIGN / KHÔNG MAP
                        mitre_doc = {
                            "mitre_processed": True,
                            "mitre_mapped": False,
                            "tactic": None,
                            "technique": None,
                            "confidence": 0,
                            "tactic_confidence": 0,
                            "technique_confidence": 0,
                        }

                    save_mitre_result(meta, mitre_doc)

                except Exception as e:
                    print("[MITRE][EVENT ERROR]", e)

                finally:
                    # OFFSET LUÔN PHẢI ĐI
                    if sort_key:
                        set_mitre_offset(sort_key)

            # advance local cursor too
            search_after = hits[-1].get("sort")
            time.sleep(0.05)

        except Exception as e:
            print("[MITRE][ERROR]", e)
            time.sleep(POLL_INTERVAL)


def start_worker():
    run_forever()
