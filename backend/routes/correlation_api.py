"""
correlation_routes.py

API layer for attack correlation pipeline.
"""

from flask import Blueprint, request, jsonify
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
import os
import config

from services.correlation_service import run_correlation_pipeline
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine
from services.correlation_service import run_correlation_pipeline

correlation_bp = Blueprint(
    "correlation",
    __name__,
    url_prefix="/api/v1/correlation"
)


# ======================================================
# Helpers
# ======================================================

def _get_db():
    client = MongoClient(config.MONGO_URI)
    return client[config.MONGO_DB]


def _get_correlation_collection():
    db = _get_db()
    return db[config.MONGO_COL_CORRELATION]


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
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "Invalid JSON body"}), 400

    events = payload.get("events", [])
    enable_ai = bool(payload.get("enable_ai", False))

    if not isinstance(events, list):
        return jsonify({"error": "`events` must be a list"}), 400

    try:
        collection = _get_correlation_collection()
    except Exception as e:
        return jsonify({"error": "Mongo connection failed", "detail": str(e)}), 500

    gpt_engine = None
    if enable_ai:
        try:
            gpt_engine = _init_gpt_engine()
        except Exception as e:
            return jsonify({"error": "GPT init failed", "detail": str(e)}), 500

    try:
        results = run_correlation_pipeline(
            events=events,
            correlation_collection=collection,
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


# ======================================================
# GET /api/v1/correlation/incidents
# ======================================================

@correlation_bp.route("/incidents", methods=["GET"])
def list_incidents():
    limit = int(request.args.get("limit", 20))
    skip = int(request.args.get("skip", 0))
    risk_level = request.args.get("risk_level")

    collection = _get_correlation_collection()

    query = {}
    if risk_level:
        query["analysis.risk_level"] = risk_level

    cursor = (
        collection.find(query, {
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


# ======================================================
# GET /api/v1/correlation/incidents/<id>
# ======================================================

@correlation_bp.route("/incidents/<incident_id>", methods=["GET"])
def get_incident_detail(incident_id):
    collection = _get_correlation_collection()

    try:
        doc = collection.find_one({"_id": ObjectId(incident_id)})
    except Exception:
        return jsonify({"error": "Invalid incident_id"}), 400

    if not doc:
        return jsonify({"error": "Incident not found"}), 404

    return jsonify({
        "status": "ok",
        "incident": {
            "incident_id": str(doc["_id"]),
            "created_at": doc.get("created_at"),
            "window": doc.get("window"),
            "analysis": doc.get("analysis"),
            "meta": doc.get("meta"),
        }
    })

@correlation_bp.route("/run_from_mongo", methods=["POST"])
def run_correlation_from_mongo():
    payload = request.get_json(force=True, silent=True) or {}

    since_minutes = int(payload.get("since_minutes", 10))
    limit = int(payload.get("limit", 2000))

    from datetime import datetime, timedelta, timezone

    since_ts = (
        datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    ).isoformat()

    db = _get_db()
    events_col = db[config.MONGO_COL_NORMALIZED]

    cursor = (
        events_col
        .find({"timestamp": {"$gte": since_ts}}, {"_id": 0})
        .sort("timestamp", 1)
        .limit(limit)
    )

    events = list(cursor)

    if not events:
        return jsonify({
            "status": "ok",
            "window_count": 0,
            "results": []
        })

    # Minimal validation only
    valid_events = [
        ev for ev in events
        if ev.get("timestamp")
        and ev.get("actor", {}).get("ip")
        and ev.get("target", {}).get("ip")
    ]

    results = run_correlation_pipeline(
        events=valid_events,
        correlation_collection=None,
        enable_ai=False,
        gpt_engine=None,
    )

    return jsonify({
        "status": "ok",
        "event_count": len(valid_events),
        "window_count": len(results),
        "results": results,
    })
@correlation_bp.route("/run_with_ai", methods=["POST"])
def run_correlation_with_ai():
    payload = request.get_json(force=True, silent=True) or {}

    summary = payload.get("summary")
    if not summary:
        return jsonify({"error": "summary is required"}), 400

    # Init GPT engine
    gpt_engine = GPTCorrelationEngine()

    try:
        # Run GPT only on this summary
        ai_result = gpt_engine.correlate_window(summary)

    except Exception as e:
        return jsonify({
            "error": "GPT correlation failed",
            "detail": str(e)
        }), 500

    return jsonify({
        "status": "ok",
        "analysis": ai_result
    })
