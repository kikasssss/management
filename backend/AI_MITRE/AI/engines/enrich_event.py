from typing import Dict, Any
from services.mitre_lookup import get_mitre_by_elastic_id


def enrich_event_with_mitre(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich normalized Snort event bằng MITRE mapping.
    - Reuse services.mitre_lookup
    - KHÔNG query DB trực tiếp
    - KHÔNG chạy lại CatBoost
    """

    elastic_id = event.get("elastic_id")
    if not elastic_id:
        return event

    mitre = get_mitre_by_elastic_id(elastic_id)
    if not mitre:
        return event

    event["mitre"] = {
        "tactic": mitre.get("tactic"),
        "technique": mitre.get("technique"),
        "confidence": mitre.get("confidence"),
        "tactic_confidence": mitre.get("tactic_confidence"),
        "technique_confidence": mitre.get("technique_confidence"),
        "source": "catboost",
    }

    return event
