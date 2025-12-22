from datetime import datetime
from typing import Dict, Any
from pymongo.collection import Collection


def save_correlation_result_to_mongo(
    *,
    collection: Collection,
    window_summary: Dict[str, Any],
    gpt_result: Dict[str, Any],
    engine_name: str = "gpt-5-mini",
    engine_version: str = "v1",
) -> str:
    """
    Save GPT correlation (incident-level) result to MongoDB.

    Args:
        collection: MongoDB collection (e.g. db["correlation_results"])
        window_summary: Output of attack_window_summary
        gpt_result: Parsed JSON output from GPT correlation engine
        engine_name: LLM model name
        engine_version: Correlation logic version

    Returns:
        Inserted document ID (str)
    """

    doc = {
        "created_at": datetime.utcnow(),

        # ===== Attack Window Context =====
        "window": {
            "actor_ip": window_summary.get("actor_ip"),
            "target_ip": window_summary.get("target_ip"),
            "start": window_summary.get("time", {}).get("start"),
            "end": window_summary.get("time", {}).get("end"),
            "duration_seconds": window_summary.get("time", {}).get("duration_seconds"),
            "event_ids": window_summary.get("event_ids", []),
        },

        # ===== GPT Correlation Analysis =====
        "analysis": {
            "attack_chain": gpt_result.get("attack_chain"),
            "suspected_stages": gpt_result.get("suspected_stages", []),
            "lateral_movement": gpt_result.get("lateral_movement", {}),
            "confidence": gpt_result.get("confidence"),
            "risk_level": gpt_result.get("risk_level"),
            "top_findings": gpt_result.get("top_findings", []),
            "recommended_actions": gpt_result.get("recommended_actions", []),
        },

        # ===== Metadata =====
        "meta": {
            "engine": engine_name,
            "engine_version": engine_version,
            "source": "ai_correlation",
        },
    }

    result = collection.insert_one(doc)
    return str(result.inserted_id)
