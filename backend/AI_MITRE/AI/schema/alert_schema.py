# backend/AI/schema/alert_schema.py

from typing import List, Dict, Any
from datetime import datetime


class AlertSchema:
    """
    Schema chuẩn cho 1 alert gửi lên GPT
    """

    REQUIRED_FIELDS = [
        "alert_id",
        "timestamp",
        "sensor",
        "product",
        "alert",
        "network"
    ]

    @staticmethod
    def validate(alert: Dict[str, Any]) -> bool:
        """
        Validate alert có đủ field bắt buộc không
        """
        for field in AlertSchema.REQUIRED_FIELDS:
            if field not in alert:
                raise ValueError(f"Missing required field: {field}")
        return True

    @staticmethod
    def example() -> Dict[str, Any]:
        """
        Example alert – dùng cho test / documentation
        """
        return {
            "alert_id": "snort-1000001-2025-01-01T10:12:00Z",
            "timestamp": "2025-01-01T10:12:00Z",
            "sensor": "sensor-01",
            "product": "snort",

            "alert": {
                "name": "SQL Injection Attempt",
                "severity": "High",
                "action": "blocked",
                "category": "web-application-attack"
            },

            "network": {
                "src_ip": "1.2.3.4",
                "src_port": 44444,
                "dst_ip": "10.0.0.5",
                "dst_port": 80,
                "protocol": "tcp"
            },

            "rule": {
                "sid": 1000001,
                "priority": 1
            }
        }
