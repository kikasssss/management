import os
import config
from pymongo import MongoClient
from AI_MITRE.AI.engines.gpt_correlation_engine import GPTCorrelationEngine
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
from services.correlation_service import run_correlation_pipeline
from AI_MITRE.AI.schema.snort_event_normalizer import normalize_snort_event
client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
openai_client = OpenAIResponsesClient(
    api_key=os.getenv("OPENAI_API_KEY"),
    model="gpt-5-mini",
)
raw_logs = [
    {
        "@timestamp": "2025-12-11T12:27:25.724Z",
        "source": "snort_dmz",
        "snort": {
            "src_ap": "192.168.114.1:55521",
            "dst_ap": "239.255.255.250:1900",
            "proto": "UDP",
            "msg": "INDICATOR-SCAN UPnP service discover attempt",
            "class": "Detection of a Network Scan",
            "rule": "1:2024366:3",
            "action": "alert",
        },
    },
    {
        "@timestamp": "2025-12-11T12:27:30.000Z",
        "source": "snort_dmz",
        "snort": {
            "src_ap": "192.168.114.1:55521",
            "dst_ap": "239.255.255.250:1900",
            "proto": "UDP",
            "msg": "INDICATOR-SCAN UPnP service discover attempt",
            "class": "Detection of a Network Scan",
            "rule": "1:2024366:3",
            "action": "alert",
        },
    },
]

normalized_events = [
    normalize_snort_event(log)
    for log in raw_logs
]

engine = GPTCorrelationEngine(client=openai_client)
results = run_correlation_pipeline(
    events=normalized_events,
    correlation_collection=db.correlation_results,
    enable_ai=True,
    gpt_engine=engine,
)
print(results)
