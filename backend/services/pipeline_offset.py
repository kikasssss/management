# services/pipeline_offset.py

from datetime import datetime, timezone
from pymongo import MongoClient
from typing import Optional, List
import config

# =========================
# DB INIT
# =========================

client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
col = db["pipeline_offsets"]

# =========================
# OFFSET IDS (RÕ RÀNG)
# =========================

OFFSET_MITRE = "mitre_snort"
OFFSET_NORMALIZE = "normalize_snort"

# (sau này nếu cần)
# OFFSET_CORRELATION = "correlation_snort"

# =========================
# GENERIC OFFSET API
# =========================

def set_offset(offset_id: str, sort_value: List):
    """
    sort_value phải cùng format với ES sort:
    ví dụ: ["2025-12-29T07:00:00.123Z", 123456]
    """
    if not sort_value:
        return

    col.update_one(
        {"_id": offset_id},
        {
            "$set": {
                "sort": sort_value,
                "updated_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )


def get_offset(offset_id: str) -> Optional[List]:
    doc = col.find_one({"_id": offset_id})
    return doc.get("sort") if doc else None

# =========================
# BACKWARD COMPAT (MITRE)
# =========================
# ⚠️ Giữ để KHÔNG PHÁ code cũ

def set_mitre_offset(sort_value: List):
    set_offset(OFFSET_MITRE, sort_value)


def get_mitre_offset() -> Optional[List]:
    return get_offset(OFFSET_MITRE)
