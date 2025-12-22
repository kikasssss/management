# AI_MITRE/preprocessing/normalize_elastic.py

from datetime import datetime


def to_transport(proto):
    if not proto:
        return "unknown"
    p = str(proto).lower()
    if p in ("tcp", "udp", "icmp"):
        return p
    if p in ("arp", "ethernet", "eth"):
        return "arp"
    return "unknown"


def guess_service(proto, dst_port, msg):
    proto = str(proto).lower() if proto else ""
    msg = str(msg).lower() if msg else ""

    try:
        dst_port = int(dst_port)
    except Exception:
        dst_port = None

    if proto == "icmp":
        return "icmp"
    if "arp" in msg or proto == "arp":
        return "arp"
    if dst_port == 53 or "dns" in msg:
        return "dns"
    if dst_port in (80, 8080) or "http" in msg:
        return "http"
    if dst_port == 443 or "https" in msg:
        return "https"
    if dst_port == 22 or "ssh" in msg:
        return "ssh"

    return "unknown"


def parse_timestamp(ts):
    if not ts:
        return 0.0
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def split_ip_port(value):
    if value and ":" in value:
        ip, port = value.rsplit(":", 1)
        try:
            return ip, int(port)
        except Exception:
            return ip, 0
    return None, 0


# =========================
# MAIN NORMALIZE FUNCTION
# =========================

def normalize_elastic_log(doc: dict) -> dict:
    src = doc.get("_source", doc)
    snort = src.get("snort", {})

    proto = snort.get("proto")
    msg = snort.get("msg")
    direction = str(snort.get("dir", "")).upper()
    pkt_len = int(snort.get("pkt_len", 0) or 0)

    src_ip, src_port = split_ip_port(snort.get("src_ap"))
    dst_ip, dst_port = split_ip_port(snort.get("dst_ap"))

    source_bytes = pkt_len if direction == "C2S" else 0
    destination_bytes = pkt_len if direction == "S2C" else 0
    source_packets = 1 if direction == "C2S" else 0
    destination_packets = 1 if direction == "S2C" else 0

    features = {
        # ===== Network =====
        "network.state": "unknown",
        "network.history": "unknown",
        "network.transport": to_transport(proto),
        "network.service": guess_service(proto, dst_port, msg),

        # ===== Ports =====
        "source.port": src_port,
        "destination.port": dst_port,

        # ===== Traffic =====
        "source.bytes": source_bytes,
        "destination.bytes": destination_bytes,
        "source.packets": source_packets,
        "destination.packets": destination_packets,

        # ===== Time =====
        "event.duration": 0,
        "@timestamp": parse_timestamp(src.get("@timestamp"))
    }

    return features
