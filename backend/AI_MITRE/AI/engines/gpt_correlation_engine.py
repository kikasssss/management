import json
from typing import Dict, Any, Optional
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
from AI_MITRE.AI.prompts.gpt_correlation_prompt import CORRELATION_INSTRUCTIONS


def _validate_result(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate + normalize nhẹ để dashboard/Mongo không vỡ.
    """
    # required top-level keys
    required = [
        "attack_chain",
        "suspected_stages",
        "top_findings",
        "lateral_movement",
        "confidence",
        "risk_level",
        "recommended_actions",
    ]
    for k in required:
        if k not in obj:
            raise ValueError(f"Missing key: {k}")

    lm = obj.get("lateral_movement", {})
    if not isinstance(lm, dict) or "detected" not in lm or "evidence" not in lm:
        raise ValueError("Invalid lateral_movement object")

    # clamp confidence
    try:
        conf = float(obj["confidence"])
    except Exception:
        conf = 0.0
    obj["confidence"] = max(0.0, min(1.0, conf))

    if obj["risk_level"] not in ("low", "medium", "high"):
        obj["risk_level"] = "low"

    # ensure lists
    for lk in ("suspected_stages", "top_findings", "recommended_actions"):
        if not isinstance(obj.get(lk), list):
            obj[lk] = []

    if not isinstance(lm.get("evidence"), list):
        obj["lateral_movement"]["evidence"] = []

    return obj


class GPTCorrelationEngine:
    def __init__(self, client: Optional[OpenAIResponsesClient] = None) -> None:
        self.client = client or OpenAIResponsesClient()

    def correlate_window(self, window_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Input: output của summarize_attack_window(window)
        Output: JSON correlation result (ready to save + show dashboard)
        """

        user_input = {
            "window_summary": window_summary
        }

        # Keep input compact & deterministic
        user_text = (
            "The following input is provided in JSON format.\n"
            "You must return a valid JSON object as output.\n\n"
            + json.dumps(user_input, ensure_ascii=False)
        )
        result = self.client.create_json_response(
            instructions=CORRELATION_INSTRUCTIONS,
            user_input=user_text,
            max_output_tokens=1200,
        )

        return _validate_result(result)
