from AI_MITRE.AI.correlation.attack_window_summary import summarize_attack_window

# giả lập window thật của bạn
WINDOW = {
    "window_start": "2025-12-11T12:27:26.725000+00:00",
    "window_end": "2025-12-11T12:27:28.727000+00:00",
    "actor_ip": "192.168.101.100",
    "target_ip": "100.100.100.100",
    "sensors": ["snort_dmz"],
    "behaviors": [
        "Network discovery",
        "Network discovery",
        "Suspicious network activity",
        "Network discovery",
        "Suspicious network activity",
        "Network discovery",
        "Network discovery",
        "Suspicious network activity",
        "Network discovery"
    ],
    "event_count": 9
}

def main():
    summary = summarize_attack_window(WINDOW)
    print(summary)

if __name__ == "__main__":
    main()
