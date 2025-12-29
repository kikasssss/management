# services/pipeline_offset.py
from datetime import datetime, timezone
from pymongo import MongoClient
import config

client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
col = db["pipeline_offsets"]

OFFSET_ID = "mitre_snort"

def set_mitre_offset(sort_value: list):
    """
    sort_value phải cùng format với ES sort của worker:
    ví dụ: ["2025-12-29T07:00:00.123Z", 123456]
    """
    col.update_one(
        {"_id": OFFSET_ID},
        {"$set": {"sort": sort_value, "updated_at": datetime.now(timezone.utc)}},
        upsert=True
    )

def get_mitre_offset() -> list | None:
    doc = col.find_one({"_id": OFFSET_ID})
    return doc.get("sort") if doc else None
