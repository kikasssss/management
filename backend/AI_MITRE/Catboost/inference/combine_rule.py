# AI_MITRE/Catboost/inference/combine_rule.py

import json
from typing import List, Optional

# --------------------------------------------------
# LOAD MAPPING ONCE (khi backend start)
# --------------------------------------------------

_MAPPING_PATH = "AI_MITRE/Catboost/config/mapping_tactic_technique.json"

with open(_MAPPING_PATH, "r", encoding="utf-8") as f:
    TACTIC_TECHNIQUE_MAPPING = json.load(f)


# --------------------------------------------------
# RULE-BASED COMBINE
# --------------------------------------------------

def combine_tactic_technique(
    tactic: str,
    technique_probs: List[float],
    technique_labels: List[str],
) -> Optional[str]:
    """
    Combine tactic + technique theo MITRE rule-based (REALTIME)

    Params:
        tactic            : predicted tactic (string)
        technique_probs   : list probability từ model technique
        technique_labels  : list technique ID (thứ tự khớp với probs)

    Return:
        final technique (string) hoặc None
    """

    # 1️⃣ Lấy technique hợp lệ theo tactic
    valid_techniques = TACTIC_TECHNIQUE_MAPPING.get(tactic)

    # Không có mapping → fallback
    if not valid_techniques:
        return None

    # 2️⃣ Lấy index của technique hợp lệ
    valid_indices = [
        i
        for i, tech in enumerate(technique_labels)
        if tech in valid_techniques
    ]

    if not valid_indices:
        return None

    # 3️⃣ Chọn technique hợp lệ có xác suất cao nhất
    best_idx = max(
        valid_indices,
        key=lambda idx: technique_probs[idx]
    )

    return technique_labels[best_idx]
if __name__ == "__main__":
    tactic = "Reconnaissance"

    technique_labels = ["T1595", "T1592", "T1059", "T1041"]
    technique_probs  = [0.54, 0.12, 0.08, 0.26]

    final = combine_tactic_technique(
        tactic,
        technique_probs,
        technique_labels
    )

    print("✅ Final technique:", final)
