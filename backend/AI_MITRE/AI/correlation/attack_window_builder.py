"""
attack_window_builder.py

Gom các security event (đã normalize + enrich MITRE)
thành attack window phục vụ correlation
(MULTI-SENSOR SAFE, SESSION-BASED)
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone

DEFAULT_WINDOW_SECONDS = 300


# =========================
# Helper
# =========================

def parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow().replace(tzinfo=timezone.utc)


def normalize_ts(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


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

    # sort theo timestamp (bắt buộc cho session window)
    events = sorted(events, key=lambda e: e["timestamp"])

    now = datetime.now(timezone.utc)

    # active windows theo key (actor_ip, target_ip)
    active_windows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    finished_windows: List[Dict[str, Any]] = []

    for event in events:
        ts = normalize_ts(event["timestamp"])

        actor_ip = event["actor"]["ip"]
        target_ip = event["target"]["ip"]
        key = (actor_ip, target_ip)

        # =========================
        # MỞ WINDOW MỚI
        # =========================
        if key not in active_windows:
            active_windows[key] = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,

                "events": [event],
                "behaviors": [event.get("behavior")],
                "sensors": set([event.get("sensor_id")]),
                "mitre_events": [event.get("mitre")] if event.get("mitre") else [],

                "status": "open",
            }
            continue

        window = active_windows[key]
        window_end = normalize_ts(window["window_end"])

        gap = (ts - window_end).total_seconds()

        # =========================
        # CÙNG SESSION
        # =========================
        if gap <= window_seconds:
            window["window_end"] = ts
            window["events"].append(event)
            window["behaviors"].append(event.get("behavior"))
            window["sensors"].add(event.get("sensor_id"))

            if event.get("mitre"):
                window["mitre_events"].append(event["mitre"])

        # =========================
        # ĐỨT SESSION → ĐÓNG WINDOW
        # =========================
        else:
            window["sensors"] = list(window["sensors"])
            window["event_count"] = len(window["events"])
            window["status"] = "closed"
            finished_windows.append(window)

            # mở window mới cho cùng key
            active_windows[key] = {
                "window_start": ts,
                "window_end": ts,
                "actor_ip": actor_ip,
                "target_ip": target_ip,

                "events": [event],
                "behaviors": [event.get("behavior")],
                "sensors": set([event.get("sensor_id")]),
                "mitre_events": [event.get("mitre")] if event.get("mitre") else [],

                "status": "open",
            }

    # =========================
    # XỬ LÝ CÁC WINDOW CÒN MỞ
    # =========================
    for window in active_windows.values():
        window_end = normalize_ts(window["window_end"])
        age = (now - window_end).total_seconds()

        window["sensors"] = list(window["sensors"])
        window["event_count"] = len(window["events"])

        if age >= window_seconds:
            window["status"] = "closed"
            finished_windows.append(window)
        elif allow_open_window:
            window["status"] = "open"
            finished_windows.append(window)

    # =========================
    # FORMAT TIMESTAMP OUTPUT
    # =========================
    for w in finished_windows:
        w["window_start"] = w["window_start"].isoformat()
        w["window_end"] = w["window_end"].isoformat()

    return finished_windows
