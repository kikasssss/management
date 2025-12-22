"""
attack_window_builder.py

Gom các security event (đã normalize) thành attack window
Phục vụ AI correlation & suy luận chuỗi tấn công
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta


# =========================
# Config
# =========================

DEFAULT_WINDOW_SECONDS = 180  # 3 phút


# =========================
# Helper
# =========================

def parse_ts(ts: str) -> datetime:
    """
    Parse ISO timestamp → datetime
    """
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


# =========================
# Core builder
# =========================

def build_attack_windows(
    events: List[Dict[str, Any]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS
) -> List[Dict[str, Any]]:
    """
    Gom event thành attack windows
    """

    if not events:
        return []

    # sort theo thời gian
    events = sorted(events, key=lambda e: e.get("timestamp"))

    windows = []
    current = None

    for event in events:
        ts = parse_ts(event["timestamp"])
        actor_ip = event["actor"]["ip"]
        target_ip = event["target"]["ip"]

        if not current:
            current = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,
                "sensors": set([event.get("sensor")]),
                "behaviors": [event.get("behavior")],
                "events": [event],
            }
            continue

        # điều kiện cùng window
        same_actor = actor_ip == current["actor_ip"]
        same_target = target_ip == current["target_ip"]
        within_time = (ts - current["window_end"]).total_seconds() <= window_seconds

        if same_actor and same_target and within_time:
            current["window_end"] = ts
            current["sensors"].add(event.get("sensor"))
            current["behaviors"].append(event.get("behavior"))
            current["events"].append(event)
        else:
            # đóng window cũ
            current["sensors"] = list(current["sensors"])
            windows.append(current)

            # mở window mới
            current = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,
                "sensors": set([event.get("sensor")]),
                "behaviors": [event.get("behavior")],
                "events": [event],
            }

    # đóng window cuối
    if current:
        current["sensors"] = list(current["sensors"])
        windows.append(current)

    # format lại timestamp
    for w in windows:
        w["window_start"] = w["window_start"].isoformat()
        w["window_end"] = w["window_end"].isoformat()

    return windows
