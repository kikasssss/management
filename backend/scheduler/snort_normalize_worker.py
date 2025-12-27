"""
Realtime Snort Normalize Worker
--------------------------------
Elasticsearch (raw snort logs) -> normalize -> MongoDB (normalized_events)

Run:
    python3 -m scheduler.snort_normalize_worker
"""

import json
import os
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from elasticsearch import Elasticsearch
from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection

import config
from AI_MITRE.AI.schema.snort_event_normalizer import normalize_snort_event


# =========================
# CONFIG
# =========================

ELASTIC_INDEX = "snort-alert-*"
BATCH_SIZE = 500
POLL_INTERVAL = 3
CHECKPOINT_FILE = "data/snort_normalize_checkpoint.json"


# =========================
# HELPERS
# =========================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_checkpoint_file():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump({"search_after": None}, f)


def load_checkpoint() -> Optional[list]:
    ensure_checkpoint_file()
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            data = json.load(f)
        return data.get("search_after")
    except Exception:
        return None


def save_checkpoint(search_after: list):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({"search_after": search_after}, f)


# =========================
# DB / ELASTIC
# =========================

def get_es_client() -> Elasticsearch:
    return Elasticsearch("http://localhost:9200")


def get_mongo_collection() -> Collection:
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    col = db[config.MONGO_COL_NORMALIZED]

    # Index SOC-friendly
    col.create_index([("timestamp", -1)])
    col.create_index([("sensor_id", 1), ("timestamp", -1)])
    col.create_index([("actor.ip", 1), ("target.ip", 1), ("timestamp", -1)])

    return col


# =========================
# ELASTIC QUERY
# =========================

def build_es_query(search_after: Optional[list] = None) -> Dict[str, Any]:
    body = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-10m"
                }
            }
        },
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"}
        ],
        "size": BATCH_SIZE,
    }

    if search_after:
        body["search_after"] = search_after

    return body


# =========================
# NORMALIZE
# =========================

def normalize_hit(hit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src = hit.get("_source", {})
    if not src or "snort" not in src or "@timestamp" not in src:
        return None

    log = dict(src)
    log["_id"] = hit["_id"]

    event = normalize_snort_event(log)

    # Guard tối thiểu cho correlation
    if not event.get("timestamp"):
        return None
    if not event.get("actor", {}).get("ip"):
        return None
    if not event.get("target", {}).get("ip"):
        return None

    event["_ingested_at"] = utc_now_iso()
    return event


def upsert_events(col: Collection, events: List[Dict[str, Any]]):
    if not events:
        return

    ops = []
    for ev in events:
        ev["_id"] = ev["elastic_id"]
        ops.append(
            UpdateOne(
                {"_id": ev["_id"]},
                {"$set": ev},
                upsert=True,
            )
        )

    col.bulk_write(ops, ordered=False)


# =========================
# WORKER LOOP
# =========================

def run():
    print("[*] Starting Snort Normalize Worker")

    es = get_es_client()
    col = get_mongo_collection()

    search_after = load_checkpoint()
    print(f"[*] Loaded checkpoint search_after={search_after}")

    while True:
        try:
            query = build_es_query(search_after)
            res = es.search(index=ELASTIC_INDEX, body=query)
            hits = res.get("hits", {}).get("hits", [])

            if not hits:
                time.sleep(POLL_INTERVAL)
                continue

            events: List[Dict[str, Any]] = []
            for hit in hits:
                try:
                    ev = normalize_hit(hit)
                    if ev:
                        events.append(ev)
                except Exception:
                    continue

            upsert_events(col, events)

            # Update checkpoint using search_after
            search_after = hits[-1]["sort"]
            save_checkpoint(search_after)

            print(
                f"[+] fetched={len(hits)} "
                f"normalized={len(events)} "
                f"search_after={search_after}"
            )

            # Small sleep to avoid tight loop
            time.sleep(0.2)

        except KeyboardInterrupt:
            print("\n[!] Worker stopped by user")
            break
        except Exception as e:
            print("[!] Worker error:", e)
            traceback.print_exc()
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
