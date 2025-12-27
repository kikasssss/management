"""
correlation_service.py

Orchestrates the full correlation pipeline:
Events -> Attack Window -> Summary -> Maturity Check -> (Optional) GPT Correlation -> Storage
"""

from typing import List, Dict, Any, Optional
from pymongo.collection import Collection

from AI_MITRE.AI.correlation.attack_window_builder import build_attack_windows
from AI_MITRE.AI.correlation.attack_window_summary import summarize_attack_window
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine
from services.correlation_storage import save_correlation_result_to_mongo


# ============================================================
# Heuristic: decide whether a window is mature enough for AI
# ============================================================

def should_call_ai(summary):
    stats = summary.get("statistics", {})
    interp = summary.get("interpretation", {})

    event_count = stats.get("event_count", 0)
    unique_behaviors = stats.get("unique_behaviors", 0)

    dominant_tactic = interp.get("dominant_tactic")
    confidence_hint = interp.get("confidence_hint")
    burst = interp.get("burst_activity", False)
    multi_sensor = interp.get("multi_sensor", False)

    # 1. quá ít event
    if event_count < 2:
        return False

    # 2. hành vi nghèo
    if unique_behaviors < 2 and not burst:
        return False

    # 3. có tín hiệu đủ mạnh (KHÔNG ép tactic)
    if not (dominant_tactic or burst or multi_sensor):
        return False

    # 4. confidence thấp → bỏ
    if confidence_hint == "low":
        return False

    return True


# ============================================================
# Main pipeline
# ============================================================

def run_correlation_pipeline(
    *,
    events: List[Dict[str, Any]],
    correlation_collection: Collection,
    enable_ai: bool = False,
    gpt_engine: Optional[GPTCorrelationEngine] = None,
) -> List[Dict[str, Any]]:
    """
    Run correlation pipeline on a list of normalized events.

    Args:
        events: List of normalized security events
        correlation_collection: MongoDB collection for correlation results
        enable_ai: Whether GPT correlation is globally enabled
        gpt_engine: GPTCorrelationEngine instance (required if enable_ai=True)

    Returns:
        Per-window results with:
        - summary
        - analysis (GPT or None)
        - ai_triggered (bool)
        - incident_id (if GPT ran)
    """

    if enable_ai and gpt_engine is None:
        raise ValueError("gpt_engine must be provided when enable_ai=True")

    results: List[Dict[str, Any]] = []

    # =========================
    # 1. Build attack windows
    # =========================
    windows = build_attack_windows(events)

    # =========================
    # 2. Process each window
    # =========================
    for window in windows:
        summary = summarize_attack_window(window)

        ai_allowed = enable_ai and should_call_ai(summary)

        # =========================
        # 3. GPT correlation (if allowed)
        # =========================
        if ai_allowed:
            gpt_result = gpt_engine.correlate_window(summary)

            incident_id = save_correlation_result_to_mongo(
                collection=correlation_collection,
                window_summary=summary,
                gpt_result=gpt_result,
            )

            results.append(
                {
                    "incident_id": incident_id,
                    "summary": summary,
                    "analysis": gpt_result,
                    "ai_triggered": True,
                }
            )

        else:
            # ---- No AI: store summary only (optional future use)
            results.append(
                {
                    "summary": summary,
                    "analysis": None,
                    "ai_triggered": False,
                }
            )

    return results
