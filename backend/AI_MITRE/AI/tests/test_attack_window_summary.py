from AI_MITRE.AI.correlation.attack_window_summary import summarize_attack_window

window = {
    "window_start": "2025-12-11T12:27:25.724000+00:00",
    "window_end": "2025-12-11T12:27:30.000000+00:00",
    "actor_ip": "192.168.114.1",
    "target_ip": "239.255.255.250",
    "event_count": 2,
    "behaviors": ["UPnP discovery scan", "UPnP discovery scan"],
    "sensors": ["snort_dmz"],
    "mitre_events": [
        {"tactic": "Reconnaissance", "technique": "T1595", "confidence": 0.65},
        {"tactic": "Reconnaissance", "technique": "T1595", "confidence": 0.66},
    ],
    "events": [
        {"elastic_id": "id-1"},
        {"elastic_id": "id-2"},
    ],
}

summary = summarize_attack_window(window)
print(summary)
