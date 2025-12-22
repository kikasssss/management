import os
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine

def main():
    if not os.getenv("OPENAI_API_KEY"):
        print("Set OPENAI_API_KEY before running this test.")
        return

    summary = {
        "actor_ip": "192.168.114.1",
        "target_ip": "239.255.255.250",
        "time": {
            "start": "2025-12-11T12:27:25.724000+00:00",
            "end": "2025-12-11T12:27:30.000000+00:00",
            "duration_seconds": 4.276,
        },
        "statistics": {
            "event_count": 2,
            "unique_behaviors": 1,
            "behavior_frequency": {"UPnP discovery scan": 2},
            "unique_tactics": 1,
            "tactic_frequency": {"Reconnaissance": 2},
            "technique_frequency": {"T1595": 2},
        },
        "interpretation": {
            "primary_behavior": "UPnP discovery scan",
            "secondary_behaviors": [],
            "dominant_tactic": "Reconnaissance",
            "dominant_technique": "T1595",
            "burst_activity": False,
            "multi_sensor": False,
            "confidence_hint": "medium",
        },
        "event_ids": ["id-1", "id-2"],
    }

    engine = GPTCorrelationEngine()
    result = engine.correlate_window(summary)
    print(result)

if __name__ == "__main__":
    main()
