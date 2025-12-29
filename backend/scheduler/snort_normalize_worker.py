"""
Realtime Snort Normalize Worker (PIT enabled)
---------------------------------------------
Elasticsearch -> normalize -> MongoDB

- search_after
- _shard_doc
- Point In Time (PIT)
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

from services.pipeline_offset import get_mitre_offset
# =========================
# CONFIG
# =========================

ELASTIC_INDEX = "snort-alert-*"
BATCH_SIZE = 500
POLL_INTERVAL = 2
CHECKPOINT_FILE = "data/snort_normalize_checkpoint.json"
PIT_KEEP_ALIVE = "2m"

def sort_leq(a: list, b: list) -> bool:
    """
    So sánh lexicographic cho [timestamp(str), shard_doc(int)].
    ISO timestamp so theo string là đúng thứ tự thời gian.
    """
    if a is None or b is None:
        return False
    if a[0] != b[0]:
        return a[0] <= b[0]
    return a[1] <= b[1]
# =========================
# TIME
# =========================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =========================
# CHECKPOINT
# =========================

def ensure_checkpoint_file():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump({"search_after": None}, f)


def load_checkpoint() -> Optional[list]:
    ensure_checkpoint_file()
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f).get("search_after")
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

    col.create_index([("timestamp", -1)])
    col.create_index([("sensor_id", 1), ("timestamp", -1)])
    col.create_index([("actor.ip", 1), ("target.ip", 1), ("timestamp", -1)])

    return col


# =========================
# PIT + QUERY
# =========================

def open_pit(es: Elasticsearch) -> str:
    res = es.open_point_in_time(
        index=ELASTIC_INDEX,
        keep_alive=PIT_KEEP_ALIVE
    )
    return res["id"]


def close_pit(es: Elasticsearch, pit_id: str):
    try:
        es.close_point_in_time(body={"id": pit_id})
    except Exception:
        pass


def build_es_query(
    pit_id: str,
    search_after: Optional[list]
) -> Dict[str, Any]:

    body = {
        "size": BATCH_SIZE,
        "pit": {
            "id": pit_id,
            "keep_alive": PIT_KEEP_ALIVE
        },
        "sort": [
            {"@timestamp": "asc"},
            {"_shard_doc": "asc"}
        ]
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

    if not event.get("timestamp"):
        return None
    if not event.get("actor", {}).get("ip"):
        return None
    if not event.get("target", {}).get("ip"):
        return None

    event["_ingested_at"] = utc_now()
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
                upsert=True
            )
        )

    col.bulk_write(ops, ordered=False)


# =========================
# WORKER LOOP
# =========================
def run():
    print("[*] Starting Snort Normalize Worker (PIT)")

    es = get_es_client()
    col = get_mongo_collection()

    search_after = load_checkpoint()
    pit_id = None

    try:
        pit_id = open_pit(es)
        print(f"[*] PIT opened: {pit_id}")

        while True:
            try:
                offset_sort = get_mitre_offset()
                if not offset_sort:
                    # MITRE chưa chạy/ chưa set offset
                    time.sleep(POLL_INTERVAL)
                    continue

                query = build_es_query(pit_id, search_after)
                res = es.search(body=query)

                hits = res.get("hits", {}).get("hits", [])
                if not hits:
                    time.sleep(POLL_INTERVAL)
                    continue

                # ✅ chỉ lấy các hit <= offset_sort
                allowed = []
                for h in hits:
                    hs = h.get("sort")
                    if hs and sort_leq(hs, offset_sort):
                        allowed.append(h)
                    else:
                        break  # vì hits đã sort asc, vượt offset thì dừng luôn

                if not allowed:
                    # batch này toàn log mới hơn offset => chờ MITRE tiến lên
                    time.sleep(POLL_INTERVAL)
                    continue

                events = []
                for hit in allowed:
                    ev = normalize_hit(hit)
                    if ev:
                        events.append(ev)

                upsert_events(col, events)

                # ✅ chỉ advance checkpoint tới cái cuối cùng đã xử lý (<= offset)
                search_after = allowed[-1]["sort"]
                save_checkpoint(search_after)

                print(
                    f"[+] fetched={len(hits)} "
                    f"allowed={len(allowed)} "
                    f"normalized={len(events)} "
                    f"search_after={search_after} "
                    f"mitre_offset={offset_sort}"
                )

                time.sleep(0.05)

            except Exception as e:
                print("[!] Worker inner error:", e)
                traceback.print_exc()
                time.sleep(POLL_INTERVAL)

    finally:
        if pit_id:
            close_pit(es, pit_id)
            print("[*] PIT closed")
