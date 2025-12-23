"""
correlation_routes.py

API layer for attack correlation pipeline.

Flow:
Frontend
 → POST /api/v1/correlation/run
 → run_correlation_pipeline()
 → (Heuristic maturity check)
 → (Optional) GPT correlation
 → MongoDB
"""

from flask import Blueprint, request, jsonify
from pymongo import MongoClient
import os
import config

from services.correlation_service import run_correlation_pipeline
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine


correlation_bp = Blueprint(
    "correlation",
    __name__,
    url_prefix="/api/v1/correlation/run"
)


# ======================================================
# Helper: init Mongo collection
# ======================================================

def _get_correlation_collection():
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    return db[config.MONGO_COL_CORRELATION]


# ======================================================
# Helper: init GPT engine (lazy, only when needed)
# ======================================================

def _init_gpt_engine():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = OpenAIResponsesClient(
        api_key=api_key,
        model="gpt-5-mini-2025-08-07",
    )

    return GPTCorrelationEngine(client)


# ======================================================
# POST /api/v1/correlation/run
# ======================================================

@correlation_bp.route("/run", methods=["POST"])
def run_correlation():
    """
    Run correlation on a batch of normalized events.

    Request body:
    {
      "events": [ ... normalized events ... ],
      "enable_ai": true | false
    }
    """

    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "Invalid JSON body"}), 400

    events = payload.get("events")
    if not events or not isinstance(events, list):
        return jsonify({"error": "`events` must be a non-empty list"}), 400

    enable_ai = bool(payload.get("enable_ai", False))

    # Mongo collection
    try:
        correlation_collection = _get_correlation_collection()
    except Exception as e:
        return jsonify({
            "error": "MongoDB connection failed",
            "detail": str(e)
        }), 500

    # GPT engine (only if AI enabled)
    gpt_engine = None
    if enable_ai:
        try:
            gpt_engine = _init_gpt_engine()
        except Exception as e:
            return jsonify({
                "error": "Failed to initialize GPT engine",
                "detail": str(e)
            }), 500

    # =========================
    # Run pipeline
    # =========================
    try:
        results = run_correlation_pipeline(
            events=events,
            correlation_collection=correlation_collection,
            enable_ai=enable_ai,
            gpt_engine=gpt_engine,
        )

        return jsonify({
            "status": "ok",
            "enable_ai": enable_ai,
            "window_count": len(results),
            "results": results,
        })

    except Exception as e:
        return jsonify({
            "error": "Correlation pipeline failed",
            "detail": str(e)
        }), 500


@correlation_bp.route("/incidents", methods=["GET"])
def list_incidents():
    """
    Query params (optional):
      - limit (default: 20)
      - skip  (default: 0)
      - risk_level (low|medium|high)
    """

    limit = int(request.args.get("limit", 20))
    skip = int(request.args.get("skip", 0))
    risk_level = request.args.get("risk_level")

    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    collection = db[config.MONGO_COL_CORRELATION]

    query = {}
    if risk_level:
        query["analysis.risk_level"] = risk_level

    cursor = (
        collection
        .find(query, {
            "window": 1,
            "analysis.attack_chain": 1,
            "analysis.lateral_movement.detected": 1,
            "analysis.risk_level": 1,
            "analysis.confidence": 1,
            "created_at": 1
        })
        .sort("created_at", DESCENDING)
        .skip(skip)
        .limit(limit)
    )

    incidents = []
    for doc in cursor:
        incidents.append({
            "incident_id": str(doc["_id"]),
            "created_at": doc.get("created_at"),
            "actor_ip": doc.get("window", {}).get("actor_ip"),
            "target_ip": doc.get("window", {}).get("target_ip"),
            "attack_chain": doc.get("analysis", {}).get("attack_chain"),
            "lateral_movement": doc.get("analysis", {}).get("lateral_movement", {}).get("detected"),
            "risk_level": doc.get("analysis", {}).get("risk_level"),
            "confidence": doc.get("analysis", {}).get("confidence"),
        })

    return jsonify({
        "status": "ok",
        "count": len(incidents),
        "incidents": incidents
    })


@correlation_bp.route("/incidents/<incident_id>", methods=["GET"])
def get_incident_detail(incident_id):
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    collection = db[config.MONGO_COL_CORRELATION]

    try:
        doc = collection.find_one({"_id": ObjectId(incident_id)})
    except Exception:
        return jsonify({"error": "Invalid incident_id"}), 400

    if not doc:
        return jsonify({"error": "Incident not found"}), 404

    result = {
        "incident_id": str(doc["_id"]),
        "created_at": doc.get("created_at"),
        "window": doc.get("window"),
        "analysis": doc.get("analysis"),
        "meta": doc.get("meta"),
    }

    return jsonify({
        "status": "ok",
        "incident": result
    })
