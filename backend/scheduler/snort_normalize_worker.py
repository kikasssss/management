"""
Realtime Snort Normalize Worker (search_after, independent)
-----------------------------------------------------------
Elasticsearch -> normalize -> MongoDB

Core rules:
- NO PIT (PIT is snapshot -> not suitable for realtime tailing)
- Use search_after with stable sort key: [@timestamp, _id]
- Normalize ALL Snort logs
- Maintain its own offset: OFFSET_NORMALIZE
- NEVER depend on MITRE
- Print clear timestamps + progress markers for debugging
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
from services.pipeline_offset import get_offset, set_offset, OFFSET_NORMALIZE


# =========================
# CONFIG
# =========================
ELASTIC_URL = "http://localhost:9200"
ELASTIC_INDEX = "snort-alert-*"

BATCH_SIZE = 500
POLL_INTERVAL = 1.5

CHECKPOINT_FILE = "data/snort_normalize_checkpoint.json"

# spam control
NO_LOG_EVERY_SEC = 10


# =========================
# TIME
# =========================
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ts() -> str:
    return utc_now().isoformat()


# =========================
# CHECKPOINT FILE
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
# CLIENTS
# =========================
def get_es() -> Elasticsearch:
    # consider adding retries/timeouts later if needed
    return Elasticsearch(ELASTIC_URL)


def get_normalized_collection() -> Collection:
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    col = db[config.MONGO_COL_NORMALIZED]

    col.create_index([("timestamp", -1)])
    col.create_index([("sensor_id", 1), ("timestamp", -1)])
    col.create_index([("actor.ip", 1), ("target.ip", 1), ("timestamp", -1)])
    col.create_index([("elastic_id", 1)], unique=True)

    return col


# =========================
# ES QUERY (NO PIT)
# =========================
def build_query(search_after: Optional[list]) -> Dict[str, Any]:
    """
    Realtime tailing query:
    - stable sort: [@timestamp asc, _id asc]
    - search_after continues from last processed hit
    """
    body: Dict[str, Any] = {
        "size": BATCH_SIZE,
        "sort": [
            {"@timestamp": "asc"},
            {"_id": "asc"},
        ],
        "query": {"match_all": {}},
    }
    if search_after:
        body["search_after"] = search_after
    return body


# =========================
# NORMALIZE
# =========================
def normalize_hit(hit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src = hit.get("_source", {})
    if not src or "snort" not in src:
        return None

    raw_ts = src.get("@timestamp")
    if not raw_ts:
        return None

    try:
        event_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).astimezone(timezone.utc)
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

    # must have actor/target ip
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
                upsert=True,
            )
        )

    if ops:
        col.bulk_write(ops, ordered=False)


# =========================
# OFFSET
# =========================
def load_search_after() -> Optional[list]:
    """
    Prefer Mongo offset; fallback to checkpoint file.
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
        print(f"[{ts()}][Normalize][WARN] set_offset failed:", e)

    try:
        save_checkpoint_file(search_after)
    except Exception as e:
        print(f"[{ts()}][Normalize][WARN] checkpoint save failed:", e)


# =========================
# WORKER LOOP
# =========================
def run():
    print(f"[{ts()}][Normalize] START worker (NO PIT, independent)")
    print(f"[{ts()}][Normalize] elastic={ELASTIC_URL} index={ELASTIC_INDEX}")
    print(f"[{ts()}][Normalize] batch_size={BATCH_SIZE} poll_interval={POLL_INTERVAL}s")

    es = get_es()
    col = get_normalized_collection()

    search_after = load_search_after()
    print(f"[{ts()}][Normalize] loaded search_after={search_after}")

    last_no_log_at = 0.0

    while True:
        try:
            start_batch = utc_now()

            query = build_query(search_after)
            res = es.search(index=ELASTIC_INDEX, body=query)
            hits = res.get("hits", {}).get("hits", [])

            if not hits:
                now = time.time()
                if now - last_no_log_at > NO_LOG_EVERY_SEC:
                    print(f"[{ts()}][Normalize] no new logs, sleeping...")
                    last_no_log_at = now
                time.sleep(POLL_INTERVAL)
                continue

            # normalize
            events: List[Dict[str, Any]] = []
            for hit in hits:
                ev = normalize_hit(hit)
                if ev:
                    events.append(ev)

            upsert_events(col, events)

            # advance to last fetched hit
            search_after = hits[-1].get("sort")
            if search_after:
                persist_search_after(search_after)

            end_batch = utc_now()
            latency = (end_batch - start_batch).total_seconds()

            # debug: show batch head/tail timestamps if present
            first_src = hits[0].get("_source", {})
            last_src = hits[-1].get("_source", {})
            first_ts = first_src.get("@timestamp")
            last_ts = last_src.get("@timestamp")

            print(
                f"[{ts()}][Normalize][OK] "
                f"fetched={len(hits)} normalized={len(events)} "
                f"latency={latency:.3f}s "
                f"range_ts={first_ts}..{last_ts} "
                f"search_after={search_after}"
            )

            # tiny sleep to reduce CPU tight loop
            time.sleep(0.05)

        except Exception as e:
            print(f"[{ts()}][Normalize][ERROR]", e)
            traceback.print_exc()
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
