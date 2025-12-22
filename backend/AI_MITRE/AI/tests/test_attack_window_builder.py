from elasticsearch import Elasticsearch
from AI_MITRE.AI.schema.snort_event_normalizer import normalize_snort_event
from AI_MITRE.AI.correlation.attack_window_builder import build_attack_windows


ES_URL = "http://localhost:9200"
INDEX = "snort-alert-*"

es = Elasticsearch(ES_URL)

QUERY = {
    "size": 20,
    "sort": [{"@timestamp": {"order": "asc"}}],
    "_source": [
        "@timestamp",
        "source",
        "snort.msg",
        "snort.class",
        "snort.action",
        "snort.rule",
        "snort.src_ap",
        "snort.dst_ap",
        "snort.proto",
        "snort.dir"
    ],
    "query": {
        "bool": {
            "filter": [
                {"regexp": {"snort.rule.keyword": "1:[0-9]+:[0-9]+"}}
            ],
            "must_not": [
                {"term": {"snort.class": "none"}}
            ]
        }
    }
}

def main():
    res = es.search(index=INDEX, body=QUERY)
    hits = res["hits"]["hits"]

    events = [normalize_snort_event(h["_source"]) for h in hits]

    windows = build_attack_windows(events, window_seconds=180)

    print(f"\nBuilt {len(windows)} attack windows\n")

    for i, w in enumerate(windows, start=1):
        print("=" * 70)
        print(f"WINDOW #{i}")
        print({
            "window_start": w["window_start"],
            "window_end": w["window_end"],
            "actor_ip": w["actor_ip"],
            "target_ip": w["target_ip"],
            "sensors": w["sensors"],
            "behaviors": w["behaviors"],
            "event_count": len(w["events"])
        })

if __name__ == "__main__":
    main()
