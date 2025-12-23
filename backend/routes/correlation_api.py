"""
correlation_routes.py

API layer cho AI correlation pipeline
- Nhận event đã normalize
- Chạy attack window + summary
- (Tuỳ chọn) gọi GPT correlation
- Lưu kết quả vào MongoDB
"""

from flask import Blueprint, request, jsonify

from services.correlation_service import run_correlation_pipeline
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
import os

correlation_bp = Blueprint("correlation", __name__, url_prefix="/api/v1/correlation")


# ======================================================
# Helper: init GPT engine (lazy)
# ======================================================

def _init_gpt_engine():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = OpenAIResponsesClient(
        api_key=api_key,
        model="gpt-5-mini",   # model bạn đang dùng
    )

    return GPTCorrelationEngine(client)


# ======================================================
# POST /api/v1/correlation/run
# ======================================================
@correlation_bp.route("/run", methods=["POST"])
def run_correlation():
    """
    Body:
    {
      "events": [ normalized_events ],
      "enable_ai": true | false
    }
    """

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    events = data.get("events")
    if not events or not isinstance(events, list):
        return jsonify({"error": "events must be a list"}), 400

    enable_ai = bool(data.get("enable_ai", False))

    # init GPT engine nếu cần
    gpt_engine = None
    if enable_ai:
        try:
            gpt_engine = _init_gpt_engine()
        except Exception as e:
            return jsonify({
                "error": "GPT engine init failed",
                "detail": str(e)
            }), 500

    try:
        results = run_correlation_pipeline(
            events=events,
            enable_ai=enable_ai,
            gpt_engine=gpt_engine
        )

        return jsonify({
            "status": "ok",
            "enable_ai": enable_ai,
            "window_count": len(results),
            "results": results
        })

    except Exception as e:
        return jsonify({
            "error": "Correlation pipeline failed",
            "detail": str(e)
        }), 500
