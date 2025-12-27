"""
snort_event_normalizer.py

Chuyển log Snort 3 (Elastic JSON) → Security Event có ngữ nghĩa
Phục vụ AI correlation & phát hiện Lateral Movement
"""

from typing import Dict, Any, Optional, Tuple


# =========================
# Behavior hint mapping
# =========================

PORT_BEHAVIOR_MAP = {
    445: "SMB access attempt",
    3389: "RDP connection attempt",
    22: "SSH login attempt",
    21: "FTP access attempt",
    5985: "WinRM access attempt",
    1900: "UPnP discovery scan",
}

CLASS_BEHAVIOR_MAP = {
    "Detection of a Network Scan": "Network reconnaissance",
    "attempted-admin": "Privilege escalation attempt",
    "successful-admin": "Privilege escalation success",
    "attempted-user": "Credential misuse attempt",
    "trojan-activity": "Possible C2 or malware activity",
    "web-application-attack": "Initial access attempt",
    "Misc activity": "Network discovery",
}


# =========================
# Helper functions
# =========================

def parse_ap(value: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    if not value or ":" not in value:
        return None, None
    ip, port = value.rsplit(":", 1)
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


def infer_behavior(snort: Dict[str, Any], dst_port: Optional[int]) -> str:
    snort_class = snort.get("class")

    if snort_class in CLASS_BEHAVIOR_MAP:
        return CLASS_BEHAVIOR_MAP[snort_class]

    if dst_port in PORT_BEHAVIOR_MAP:
        return PORT_BEHAVIOR_MAP[dst_port]

    return "Unclassified detection"


def is_lateral_candidate(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int]
) -> bool:
    if not src_ip or not dst_ip:
        return False

    private = lambda ip: (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.")
    )

    return (
        private(src_ip)
        and private(dst_ip)
        and dst_port in (445, 3389, 22, 5985)
    )


def parse_rule_id(rule: Optional[str]) -> Dict[str, Optional[int]]:
    if not rule or ":" not in rule:
        return {"gid": None, "sid": None, "rev": None}

    try:
        gid, sid, rev = rule.split(":")
        return {
            "gid": int(gid),
            "sid": int(sid),
            "rev": int(rev),
        }
    except ValueError:
        return {"gid": None, "sid": None, "rev": None}


# =========================
# Core normalizer
# =========================

def normalize_snort_event(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Chuẩn hoá 1 log Snort (từ Elastic) → event semantic
    """

    snort = log.get("snort", {})

    # ===== ID (QUAN TRỌNG NHẤT) =====
    elastic_id = log.get("_id") or log.get("elastic_id")

    src_ip, src_port = parse_ap(snort.get("src_ap"))
    dst_ip, dst_port = parse_ap(snort.get("dst_ap"))

    rule_info = parse_rule_id(snort.get("rule"))

    behavior = infer_behavior(snort, dst_port)
    lateral_candidate = is_lateral_candidate(src_ip, dst_ip, dst_port)

    event = {
        # ===== Identity =====
        "elastic_id": elastic_id,
        "source_product": "snort3",

        # ===== Time =====
        "timestamp": log.get("@timestamp"),

        # ===== Sensor =====
        "sensor_id": log.get("source") or log.get("host", {}).get("name"),

        # ===== Actor / Target =====
        "actor": {
            "ip": src_ip,
            "port": src_port,
            "role": "source",
        },
        "target": {
            "ip": dst_ip,
            "port": dst_port,
            "protocol": snort.get("proto"),
            "direction": snort.get("dir"),
        },

        # ===== Semantic layer =====
        "behavior": behavior,

        # ===== Classification (Snort context) =====
        "classification": {
            "snort_class": snort.get("class"),
            "action": snort.get("action"),
            "gid": rule_info["gid"],
            "sid": rule_info["sid"],
            "rev": rule_info["rev"],
            "is_detection_rule": rule_info["gid"] == 1,
            "lateral_movement_candidate": lateral_candidate,
        },

        # ===== Rule context =====
        "rule": {
            "id": snort.get("rule"),
            "message": snort.get("msg"),
        },

        # ===== Placeholder for MITRE enrichment =====
        "mitre": None,
    }

    return event
