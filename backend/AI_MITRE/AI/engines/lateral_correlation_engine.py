"""
lateral_correlation_engine.py

Build actor-centric lateral movement context
from session-level attack window summaries.

This layer:
- DOES NOT call GPT
- DOES NOT depend on MITRE correctness
- Preserves IDS rule messages for reasoning
"""

from typing import List, Dict, Any
from collections import defaultdict


class LateralCorrelationEngine:
    def __init__(
        self,
        *,
        min_targets: int = 2,
    ) -> None:
        """
        Args:
            min_targets: minimum distinct targets
                         required to consider lateral movement
        """
        self.min_targets = min_targets

    def build_lateral_context(
        self,
        results: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Build lateral movement candidates from run_from_mongo results.

        Args:
            results: output["results"] from run_from_mongo API

        Returns:
            List of lateral context objects (actor-centric)
        """

        # =========================
        # 1. Group summaries by actor_ip
        # =========================
        actor_sessions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for item in results:
            summary = item.get("summary")
            if not summary:
                continue

            actor_ip = summary.get("actor_ip")
            if not actor_ip:
                continue

            actor_sessions[actor_ip].append(summary)

        # =========================
        # 2. Build lateral contexts
        # =========================
        lateral_contexts: List[Dict[str, Any]] = []

        for actor_ip, sessions in actor_sessions.items():
            if len(sessions) < self.min_targets:
                continue

            # sort sessions by time
            sessions = sorted(
                sessions,
                key=lambda s: s["time"]["start"]
            )

            targets = {s["target_ip"] for s in sessions}
            if len(targets) < self.min_targets:
                continue

            lateral_contexts.append({
                "actor_ip": actor_ip,

                "time_range": {
                    "start": sessions[0]["time"]["start"],
                    "end": sessions[-1]["time"]["end"],
                },

                "targets": list(targets),

                # ===== session details (AI-ready) =====
                "sessions": [
                    {
                        "target_ip": s["target_ip"],

                        # behavior signals
                        "primary_behavior": s["interpretation"]["primary_behavior"],
                        "confidence_hint": s["interpretation"]["confidence_hint"],

                        # stats
                        "event_count": s["statistics"]["event_count"],

                        # timing
                        "time": s["time"],

                        # KEEP messages (most important)
                        "message_frequency": s.get("evidence", {}).get(
                            "message_frequency", {}
                        ),

                        # MITRE (supporting only)
                        "dominant_tactic": s["interpretation"].get("dominant_tactic"),
                        "dominant_technique": s["interpretation"].get("dominant_technique"),
                    }
                    for s in sessions
                ]
            })

        return lateral_contexts
