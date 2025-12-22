"""
attack_window_summary.py

Tóm tắt attack window thành dạng có ý nghĩa
(phục vụ MITRE mapping & AI reasoning)
"""

from typing import Dict, Any
from collections import Counter
from datetime import datetime


# =========================
# Core summarizer
# =========================

def summarize_attack_window(window: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tạo summary cho một attack window
    """

    behaviors = window.get("behaviors", [])
    sensors = window.get("sensors", [])
    event_count = window.get("event_count", len(behaviors))

    # Thời gian
    start = datetime.fromisoformat(window["window_start"])
    end = datetime.fromisoformat(window["window_end"])
    duration_seconds = max((end - start).total_seconds(), 0.0)

    # Thống kê behavior
    behavior_counter = Counter(behaviors)
    primary_behavior = behavior_counter.most_common(1)[0][0] if behavior_counter else None
    secondary_behaviors = [
        b for b, _ in behavior_counter.most_common()[1:]
    ]

    # Heuristic đơn giản
    burst_activity = event_count >= 5 and duration_seconds <= 10
    multi_sensor = len(sensors) > 1

    # Confidence hint (chỉ là gợi ý, KHÔNG kết luận)
    if burst_activity and event_count >= 8:
        confidence_hint = "high"
    elif event_count >= 3:
        confidence_hint = "medium"
    else:
        confidence_hint = "low"

    summary = {
        "actor_ip": window.get("actor_ip"),
        "target_ip": window.get("target_ip"),

        "time": {
            "start": window.get("window_start"),
            "end": window.get("window_end"),
            "duration_seconds": duration_seconds
        },

        "statistics": {
            "event_count": event_count,
            "unique_behaviors": len(behavior_counter),
            "behavior_frequency": dict(behavior_counter)
        },

        "interpretation": {
            "primary_behavior": primary_behavior,
            "secondary_behaviors": secondary_behaviors,
            "burst_activity": burst_activity,
            "multi_sensor": multi_sensor,
            "confidence_hint": confidence_hint
        }
    }

    return summary

