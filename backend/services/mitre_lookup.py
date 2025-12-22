# services/mitre_lookup.py

from pymongo import MongoClient
import config

client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
mitre_col = db[config.MONGO_COL_MITRE]


def get_mitre_by_elastic_id(elastic_id: str) -> dict | None:
    """
    Truy xuất mapping MITRE theo elastic_id
    """
    doc = mitre_col.find_one(
        {"elastic_id": elastic_id},
        {
            "_id": 0,  # không cần Mongo internal id
            "elastic_id": 1,
            "tactic": 1,
            "technique": 1,
            "confidence": 1,
            "tactic_confidence": 1,
            "technique_confidence": 1
        }
    )

    return doc

