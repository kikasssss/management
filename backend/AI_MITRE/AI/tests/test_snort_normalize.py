from elasticsearch import Elasticsearch
from AI_MITRE.AI.schema.snort_event_normalizer import normalize_snort_event

ES_URL = "http://localhost:9200"
INDEX = "snort-alert-*"

es = Elasticsearch(ES_URL)

QUERY = {
    "size": 5,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "_source": [
        "@timestamp",
        "source",
        "host.name",
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
                {
                    "regexp": {
                        "snort.rule.keyword": "1:[0-9]+:[0-9]+"
                    }
                }
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

    print(f"\nFetched {len(hits)} snort attack events\n")

    for i, h in enumerate(hits, start=1):
        raw = h["_source"]
        event = normalize_snort_event(raw)

        print("=" * 60)
        print(f"EVENT #{i}")
        print(event)

if __name__ == "__main__":
    main()
