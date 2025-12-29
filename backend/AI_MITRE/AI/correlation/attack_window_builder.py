"""
attack_window_builder.py

Gom các security event (đã normalize + enrich MITRE)
thành attack window phục vụ correlation
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone

DEFAULT_WINDOW_SECONDS = 300


# =========================
# Helper
# =========================

def parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


# =========================
# Core builder
# =========================

def build_attack_windows(
    events: List[Dict[str, Any]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    allow_open_window: bool = True
) -> List[Dict[str, Any]]:

    if not events:
        return []

    # sort theo timestamp (GIỮ NGUYÊN)
    events = sorted(events, key=lambda e: e["timestamp"])

    windows = []
    current = None

    # now luôn là UTC-aware
    now = datetime.now(timezone.utc)

    for event in events:
        ts = event["timestamp"]

        # === FIX: đảm bảo ts là timezone-aware ===
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        actor_ip = event["actor"]["ip"]
        target_ip = event["target"]["ip"]

        if not current:
            current = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,

                # aggregation fields (GIỮ NGUYÊN)
                "events": [event],
                "behaviors": [event.get("behavior")],
                "sensors": set([event.get("sensor_id")]),
                "mitre_events": [
                    event.get("mitre")
                ] if event.get("mitre") else [],

                # realtime flag
                "status": "open",
            }
            continue

        # === FIX: normalize timezone window_end ===
        window_end = current["window_end"]
        if window_end.tzinfo is None:
            window_end = window_end.replace(tzinfo=timezone.utc)

        same_actor = actor_ip == current["actor_ip"]
        same_target = target_ip == current["target_ip"]
        within_time = (ts - window_end).total_seconds() <= window_seconds

        if same_actor and same_target and within_time:
            current["window_end"] = ts
            current["events"].append(event)
            current["behaviors"].append(event.get("behavior"))
            current["sensors"].add(event.get("sensor_id"))

            if event.get("mitre"):
                current["mitre_events"].append(event["mitre"])

        else:
            # đóng window cũ
            current["sensors"] = list(current["sensors"])
            current["event_count"] = len(current["events"])
            current["status"] = "closed"
            windows.append(current)

            # mở window mới
            current = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,
                "events": [event],
                "behaviors": [event.get("behavior")],
                "sensors": set([event.get("sensor_id")]),
                "mitre_events": [
                    event.get("mitre")
                ] if event.get("mitre") else [],
                "status": "open",
            }

    # =========================
    # xử lý window cuối (ĐOẠN BẠN HỎI)
    # =========================
    if current:
        window_end = current["window_end"]

        # === FIX: normalize timezone ===
        if window_end.tzinfo is None:
            window_end = window_end.replace(tzinfo=timezone.utc)

        age = (now - window_end).total_seconds()

        current["sensors"] = list(current["sensors"])
        current["event_count"] = len(current["events"])

        if age >= window_seconds:
            current["status"] = "closed"
            windows.append(current)
        elif allow_open_window:
            current["status"] = "open"
            windows.append(current)

    # format timestamp output (GIỮ NGUYÊN)
    for w in windows:
        w["window_start"] = w["window_start"].isoformat()
        w["window_end"] = w["window_end"].isoformat()

    return windows
