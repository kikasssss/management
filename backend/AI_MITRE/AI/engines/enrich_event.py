from typing import Dict, Any
from services.mitre_lookup import get_mitre_by_elastic_id


def enrich_event_with_mitre(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich normalized Snort event bằng MITRE mapping.
    - Reuse services.mitre_lookup
    - KHÔNG query DB trực tiếp
    - KHÔNG chạy lại CatBoost
    """

    # ===== Ensure MITRE schema always exists =====
    event.setdefault("mitre", {
        "tactic": None,
        "technique": None,
        "confidence": 0.0,
        "tactic_confidence": None,
        "technique_confidence": None,
        "source": "none",
    })

    elastic_id = event.get("elastic_id")
    if not elastic_id:
        return event

    mitre = get_mitre_by_elastic_id(elastic_id)
    if not mitre:
        return event

    # ===== Overwrite only when mapping exists =====
    event["mitre"] = {
        "tactic": mitre.get("tactic"),
        "technique": mitre.get("technique"),
        "confidence": mitre.get("confidence", 0.0),
        "tactic_confidence": mitre.get("tactic_confidence"),
        "technique_confidence": mitre.get("technique_confidence"),
        "source": "catboost",
    }

    return event
