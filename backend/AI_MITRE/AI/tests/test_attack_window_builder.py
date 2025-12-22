from AI_MITRE.AI.correlation.attack_window_builder import build_attack_windows

# ===== Fake events (giống event thật của bạn) =====
events = [
    {
        "timestamp": "2025-12-11T12:27:25.724Z",
        "elastic_id": "id-1",
        "sensor_id": "snort_dmz",
        "actor": {"ip": "192.168.114.1"},
        "target": {"ip": "239.255.255.250"},
        "behavior": "UPnP discovery scan",
        "mitre": {
            "tactic": "Reconnaissance",
            "technique": "T1595",
            "confidence": 0.65
        }
    },
    {
        "timestamp": "2025-12-11T12:27:30.000Z",
        "elastic_id": "id-2",
        "sensor_id": "snort_dmz",
        "actor": {"ip": "192.168.114.1"},
        "target": {"ip": "239.255.255.250"},
        "behavior": "UPnP discovery scan",
        "mitre": {
            "tactic": "Reconnaissance",
            "technique": "T1595",
            "confidence": 0.66
        }
    }
]

windows = build_attack_windows(events)

print("Number of windows:", len(windows))
print(windows[0])
