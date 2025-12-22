"""
correlation_service.py

Orchestrates the full correlation pipeline:
Events -> Attack Window -> Summary -> (Optional) GPT Correlation -> Storage
"""

from typing import List, Dict, Any, Optional
from pymongo.collection import Collection

from AI_MITRE.AI.correlation.attack_window_builder import build_attack_windows
from AI_MITRE.AI.correlation.attack_window_summary import summarize_attack_window
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine
from services.correlation_storage import save_correlation_result_to_mongo


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
        enable_ai: Whether to run GPT-based correlation
        gpt_engine: GPTCorrelationEngine instance (required if enable_ai=True)

    Returns:
        List of results per attack window:
        - If enable_ai=False: returns summaries only
        - If enable_ai=True: returns incident_id + summary
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
        # ---- Summarize window ----
        summary = summarize_attack_window(window)

        # ---- AI correlation (optional) ----
        if enable_ai:
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
                }
            )

        else:
            # ---- No AI: return summary only ----
            results.append(
                {
                    "summary": summary,
                    "analysis": None,
                }
            )

    return results
