"""
Realtime Snort Normalize Worker (PIT enabled, MITRE-offset gated)
-----------------------------------------------------------------
Elasticsearch -> normalize -> MongoDB

Core rules:
- Use PIT + search_after
- Sort key: [@timestamp, _id]  (stable, avoids int/str mismatch)
- Process only documents with sort <= mitre_offset
- Maintain its own normalize offset: normalize_snort
"""

import json
import os
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from elasticsearch import Elasticsearch
from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection

import config
from AI_MITRE.AI.schema.snort_event_normalizer import normalize_snort_event
from services.pipeline_offset import get_offset, set_offset, OFFSET_NORMALIZE, get_mitre_offset

# =========================
# CONFIG
# =========================
ELASTIC_URL = "http://localhost:9200"
ELASTIC_INDEX = "snort-alert-*"

BATCH_SIZE = 500
POLL_INTERVAL = 2

CHECKPOINT_FILE = "data/snort_normalize_checkpoint.json"
PIT_KEEP_ALIVE = "2m"

# Throttle waiting logs (avoid spam)
WAIT_LOG_EVERY_SEC = 10


# =========================
# TIME
# =========================
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =========================
# CHECKPOINT FILE (fallback)
# =========================
def ensure_checkpoint_file():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump({"search_after": None}, f)


def load_checkpoint_file() -> Optional[list]:
    ensure_checkpoint_file()
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f).get("search_after")
    except Exception:
        return None


def save_checkpoint_file(search_after: list):
    ensure_checkpoint_file()
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({"search_after": search_after}, f)


# =========================
# DB / ELASTIC
# =========================
def get_es_client() -> Elasticsearch:
    return Elasticsearch(ELASTIC_URL)


def get_mongo_collection() -> Collection:
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    col = db[config.MONGO_COL_NORMALIZED]

    col.create_index([("timestamp", -1)])
    col.create_index([("sensor_id", 1), ("timestamp", -1)])
    col.create_index([("actor.ip", 1), ("target.ip", 1), ("timestamp", -1)])
    col.create_index([("elastic_id", 1)], unique=True)

    return col


# =========================
# PIT + QUERY
# =========================
def open_pit(es: Elasticsearch) -> Optional[str]:
    try:
        res = es.open_point_in_time(index=ELASTIC_INDEX, keep_alive=PIT_KEEP_ALIVE)
        return res.get("id")
    except Exception as e:
        print("[Normalize][PIT] open failed:", e)
        return None


def close_pit(es: Elasticsearch, pit_id: str):
    try:
        es.close_point_in_time(body={"id": pit_id})
    except Exception:
        pass


def build_es_query(pit_id: str, search_after: Optional[list]) -> Dict[str, Any]:
    """
    Sort key fixed to: [@timestamp asc, _id asc]
    This must match MITRE offset sort schema too.
    """
    body: Dict[str, Any] = {
        "size": BATCH_SIZE,
        "pit": {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE},
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"},
        ],
    }
    if search_after:
        body["search_after"] = search_after
    return body


# =========================
# SORT COMPARE
# =========================
def _ts_to_int(ts: Any) -> int:
    """
    ES sort for @timestamp might come as int (epoch millis) or string.
    Normalize to int epoch millis when possible; fallback to string compare via hashing is not safe.
    """
    if ts is None:
        return 0
    if isinstance(ts, int):
        return ts
    if isinstance(ts, float):
        return int(ts)
    # if iso string
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            # worst-case: stable fallback
            return 0
    return 0


def sort_leq(a: Optional[list], b: Optional[list]) -> bool:
    """
    Compare Elasticsearch sort keys: [@timestamp, _id]
    @timestamp: int(epoch ms) or iso string
    _id: string
    """
    if not a or not b or len(a) < 2 or len(b) < 2:
        return False

    a_ts = _ts_to_int(a[0])
    b_ts = _ts_to_int(b[0])

    if a_ts < b_ts:
        return True
    if a_ts > b_ts:
        return False

    # same timestamp
    return str(a[1]) <= str(b[1])


# =========================
# NORMALIZE
# =========================
def normalize_hit(hit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src = hit.get("_source", {})
    if not src or "snort" not in src:
        return None

    ts_raw = src.get("@timestamp")
    if not ts_raw:
        return None

    try:
        event_ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

    # pass original log to normalizer
    log = dict(src)
    log["_id"] = hit.get("_id")

    event = normalize_snort_event(log)
    if not event:
        return None

    # enforce required fields
    event["timestamp"] = event_ts
    event["_ingested_at"] = utc_now()
    event["stage"] = "normalized"
    event["elastic_id"] = hit.get("_id")

    if not event.get("actor", {}).get("ip"):
        return None
    if not event.get("target", {}).get("ip"):
        return None

    return event


def upsert_events(col: Collection, events: List[Dict[str, Any]]):
    if not events:
        return

    ops = []
    for ev in events:
        ev_id = ev.get("elastic_id")
        if not ev_id:
            continue
        ev["_id"] = ev_id  # dedupe by elastic_id
        ops.append(
            UpdateOne(
                {"_id": ev_id},
                {"$set": ev},
                upsert=True
            )
        )

    if ops:
        col.bulk_write(ops, ordered=False)


# =========================
# OFFSET LOAD/SAVE
# =========================
def load_search_after_from_offsets() -> Optional[list]:
    """
    Prefer Mongo normalize offset; fallback to checkpoint file.
    """
    try:
        sa = get_offset(OFFSET_NORMALIZE)
        if sa:
            return sa
    except Exception:
        pass
    return load_checkpoint_file()


def persist_search_after(search_after: list):
    """
    Save both Mongo offset and checkpoint file.
    """
    try:
        set_offset(OFFSET_NORMALIZE, search_after)
    except Exception as e:
        print("[Normalize][WARN] set_offset failed:", e)

    try:
        save_checkpoint_file(search_after)
    except Exception as e:
        print("[Normalize][WARN] save_checkpoint_file failed:", e)


# =========================
# WORKER LOOP
# =========================
def run():
    print("[*] Starting Snort Normalize Worker (PIT + MITRE-offset gated)")

    es = get_es_client()
    col = get_mongo_collection()

    search_after = load_search_after_from_offsets()
    pit_id: Optional[str] = None

    # open PIT retry
    while pit_id is None:
        pit_id = open_pit(es)
        if pit_id is None:
            time.sleep(POLL_INTERVAL)

    print(f"[*] PIT opened")

    last_wait_log_at = 0.0

    try:
        while True:
            try:
                # 1) read MITRE offset realtime
                mitre_offset = get_mitre_offset()
                if not mitre_offset:
                    now = time.time()
                    if now - last_wait_log_at > WAIT_LOG_EVERY_SEC:
                        print("[Normalize] waiting for mitre offset...")
                        last_wait_log_at = now
                    time.sleep(POLL_INTERVAL)
                    continue

                # 2) query ES with PIT
                query = build_es_query(pit_id, search_after)
                res = es.search(body=query)

                hits = res.get("hits", {}).get("hits", [])
                if not hits:
                    time.sleep(POLL_INTERVAL)
                    continue

                # 3) allow only docs <= mitre_offset
                allowed = []
                for h in hits:
                    hs = h.get("sort")
                    if hs and sort_leq(hs, mitre_offset):
                        allowed.append(h)
                    else:
                        break

                if not allowed:
                    # 🔥 vẫn phải tiến offset để tránh kẹt
                    search_after = hits[-1]["sort"]
                    set_offset(OFFSET_NORMALIZE, search_after)
                    save_checkpoint_file(search_after)

                    print(
                        "[Normalize][SKIP] advance offset | "
                        f"search_after={search_after} | "
                        f"mitre_offset={mitre_offset}"
                    )

                    time.sleep(POLL_INTERVAL)
                    continue
                # 4) normalize + upsert
                events: List[Dict[str, Any]] = []
                for hit in allowed:
                    ev = normalize_hit(hit)
                    if ev:
                        events.append(ev)

                upsert_events(col, events)

                # 5) advance offsets to last allowed (NOT last fetched)
                search_after = allowed[-1]["sort"]
                persist_search_after(search_after)

                print(
                    f"[+] fetched={len(hits)} "
                    f"allowed={len(allowed)} "
                    f"normalized={len(events)} "
                    f"search_after={search_after} "
                    f"mitre_offset={mitre_offset}"
                )

                time.sleep(0.05)

            except Exception as e:
                msg = str(e)

                # PIT can expire or become invalid -> reopen
                if "point_in_time" in msg.lower() or "pit" in msg.lower() or "null_pointer_exception" in msg.lower():
                    print("[Normalize][PIT] invalid/expired -> reopening PIT:", e)
                    try:
                        if pit_id:
                            close_pit(es, pit_id)
                    except Exception:
                        pass
                    pit_id = None
                    while pit_id is None:
                        pit_id = open_pit(es)
                        if pit_id is None:
                            time.sleep(POLL_INTERVAL)
                    print("[Normalize][PIT] reopened")
                    continue

                print("[Normalize][ERROR]", e)
                traceback.print_exc()
                time.sleep(POLL_INTERVAL)

    finally:
        if pit_id:
            close_pit(es, pit_id)
            print("[*] PIT closed")
