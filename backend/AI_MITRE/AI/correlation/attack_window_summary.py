"""
attack_window_summary.py

Tóm tắt attack window thành dạng có ý nghĩa
(phục vụ MITRE reasoning & AI correlation)
"""

from typing import Dict, Any
from collections import Counter
from datetime import datetime


def extract_message(ev: Dict[str, Any]) -> str | None:
    """
    Extract rule message from normalized Snort event
    """
    return (
        ev.get("rule", {}).get("message")
    )


# =========================
# Helper
# =========================

def parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


# =========================
# Core summarizer
# =========================

def summarize_attack_window(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tóm tắt 1 attack window đã được build
    """

    # ===== Basic info =====
    actor_ip = window.get("actor_ip")
    target_ip = window.get("target_ip")
    events = window.get("events", [])
    behaviors = window.get("behaviors", [])
    sensors = window.get("sensors", [])
    event_count = window.get("event_count", len(events))

    # ===== Time =====
    start_ts = parse_ts(window["window_start"])
    end_ts = parse_ts(window["window_end"])
    duration_seconds = max((end_ts - start_ts).total_seconds(), 0.0)

    # ===== Behavior statistics =====
    behavior_counter = Counter(behaviors)
    primary_behavior = (
        behavior_counter.most_common(1)[0][0]
        if behavior_counter else None
    )
    secondary_behaviors = [
        b for b, _ in behavior_counter.most_common()[1:]
    ]

    # ===== MITRE aggregation (event-level, optional) =====
    mitre_events = window.get("mitre_events", [])

    tactics = [
        m.get("tactic")
        for m in mitre_events
        if m and m.get("tactic")
    ]
    techniques = [
        m.get("technique")
        for m in mitre_events
        if m and m.get("technique")
    ]

    tactic_counter = Counter(tactics)
    technique_counter = Counter(techniques)

    dominant_tactic = (
        tactic_counter.most_common(1)[0][0]
        if tactic_counter else None
    )
    dominant_technique = (
        technique_counter.most_common(1)[0][0]
        if technique_counter else None
    )

    # ===== NEW: MITRE coverage (defensive, không đổi format) =====
    mitre_event_coverage = sum(
        1 for m in mitre_events
        if m and (m.get("tactic") or m.get("technique"))
    )

    # ===== Heuristic signals =====
    burst_activity = event_count >= 5 and duration_seconds <= 10
    multi_sensor = len(sensors) > 1

    # ===== Lateral Movement proxy (QUAN TRỌNG) =====
    lateral_behaviors = (
        "SMB access attempt",
        "RDP connection attempt",
        "SSH login attempt",
        "WinRM access attempt",
    )

    lateral_proxy = (
        primary_behavior in lateral_behaviors
        and (multi_sensor or burst_activity)
    )

    # ===== Confidence hint (KHÔNG kết luận) =====
    if lateral_proxy:
        confidence_hint = "high"
    elif dominant_tactic and event_count >= 3:
        confidence_hint = "medium"
    elif multi_sensor and event_count >= 3:
        confidence_hint = "low"
    elif event_count >= 2:
        confidence_hint = "low"
    else:
        confidence_hint = "low"

    # =========================
    messages = []
    for ev in events:
        msg = extract_message(ev)
        if msg:
            messages.append(msg)

    message_frequency = dict(Counter(messages))

    # ===== Summary output =====
    summary = {
        "actor_ip": actor_ip,
        "target_ip": target_ip,

        "time": {
            "start": window["window_start"],
            "end": window["window_end"],
            "duration_seconds": duration_seconds,
        },

        "statistics": {
            "event_count": event_count,
            "unique_behaviors": len(behavior_counter),
            "behavior_frequency": dict(behavior_counter),
            "unique_tactics": len(tactic_counter),
            "tactic_frequency": dict(tactic_counter),
            "technique_frequency": dict(technique_counter),

            # NEW: giúp phân biệt chưa-map vs clean
            "mitre_event_coverage": mitre_event_coverage,
        },

        "interpretation": {
            "primary_behavior": primary_behavior,
            "secondary_behaviors": secondary_behaviors,

            # event-level MITRE (nếu có)
            "dominant_tactic": dominant_tactic,
            "dominant_technique": dominant_technique,

            # heuristic signals
            "burst_activity": burst_activity,
            "multi_sensor": multi_sensor,

            # lateral movement proxy
            "lateral_proxy": lateral_proxy,

            # final hint for orchestration / AI trigger
            "confidence_hint": confidence_hint,
        },

        # ===== Keep raw reference (important for explainability) =====
        "event_ids": [
            e.get("elastic_id")
            for e in events
            if e.get("elastic_id")
        ],
        "evidence": {
            "message_frequency": message_frequency
        }
    }

    return summary
