# AI_MITRE/Catboost/inference/engine.py

from typing import Dict, Any, Optional

from AI_MITRE.Catboost.inference.tactic_predictor import TacticPredictor
from AI_MITRE.Catboost.inference.technique_predictor import TechniquePredictor
from AI_MITRE.Catboost.inference.combine_rule import combine_tactic_technique


class MitreEngine:
    """
    Realtime MITRE Engine:
      Elastic log (dict) -> tactic -> technique(probs) -> combine_rule -> result dict
    """

    def __init__(
        self,
        min_tactic_conf: float = 0.0,
        min_technique_conf: float = 0.0,
        min_final_conf: float = 0.0,
        drop_if_low_conf: bool = False,
    ):
        # Load models once
        self.tactic_predictor = TacticPredictor()
        self.technique_predictor = TechniquePredictor()

        # Thresholds (tuỳ chọn)
        self.min_tactic_conf = float(min_tactic_conf)
        self.min_technique_conf = float(min_technique_conf)
        self.min_final_conf = float(min_final_conf)

        # Nếu True và confidence < threshold -> trả None (không show)
        self.drop_if_low_conf = bool(drop_if_low_conf)

    def process_log(self, elastic_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process 1 log Elastic và trả kết quả MITRE.
        Return None nếu drop_if_low_conf=True và không đạt ngưỡng.
        """

        # 1) Predict tactic
        tactic, tactic_conf = self.tactic_predictor.predict(elastic_log)

        # 2) Predict technique (full probs)
        tech_result = self.technique_predictor.predict(elastic_log)
        technique_raw = tech_result["technique"]
        tech_conf = float(tech_result["confidence"])
        probs = tech_result["probs"]
        labels = tech_result["labels"]

        # 3) Combine (MITRE rule-based)
        final_tech = combine_tactic_technique(
            tactic=tactic,
            technique_probs=probs,
            technique_labels=labels,
        )

        explain = ""
        if final_tech is None:
            final_tech = technique_raw
            explain = "No MITRE mapping for tactic or no valid technique in mapping; fallback to top technique model output."
        else:
            explain = "Technique selected from MITRE-valid set for predicted tactic (rule-based filtering + max probability)."

        # 4) Final confidence (gợi ý: min của 2 model)
        final_conf = float(min(tactic_conf, tech_conf))

        # 5) Optional threshold logic
        if self.drop_if_low_conf:
            if tactic_conf < self.min_tactic_conf:
                return None
            if tech_conf < self.min_technique_conf:
                return None
            if final_conf < self.min_final_conf:
                return None

        # 6) Return result JSON for backend/dashboard
        return {
            "tactic": tactic,
            "technique": final_tech,
            "confidence": final_conf,
            "tactic_confidence": float(tactic_conf),
            "technique_confidence": float(tech_conf),
            "technique_raw": technique_raw,
            "explain": explain,
        }


# -------------------------
# LOCAL TEST
# -------------------------
if __name__ == "__main__":
    sample_log = {
        "@timestamp": "2025-01-06T08:30:50.630Z",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 34567,
        "dst_port": 80,
        "proto": "TCP",
        "pkt_len": 512,
        "dir": "C2S",
        "msg": "ET DOS Possible NTP DDoS"
    }

    engine = MitreEngine(
        min_final_conf=0.3,      # tuỳ chọn
        drop_if_low_conf=False,  # đổi True nếu muốn “không đủ tự tin thì không show”
    )

    result = engine.process_log(sample_log)
    print("✅ Engine result:", result)
