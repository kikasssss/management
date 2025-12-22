# AI_MITRE/Catboost/inference/tactic_predictor.py

import joblib
from catboost import CatBoostClassifier, Pool

from AI_MITRE.Catboost.preprocessing.normalize_elastic import normalize_elastic_log


class TacticPredictor:
    """
    Realtime MITRE Tactic Predictor (CatBoost)
    - Input: raw Elastic log (dict)
    - Output: (tactic_name, confidence)
    """

    def __init__(
        self,
        model_path: str = "AI_MITRE/Catboost/models/catboost_tactic_model.cbm",
        encoder_path: str = "AI_MITRE/Catboost/models/label_encoder_tactic.pkl",
    ):
        # Load CatBoost model
        self.model = CatBoostClassifier()
        self.model.load_model(model_path)

        # Load label encoder (sklearn)
        self.label_encoder = joblib.load(encoder_path)

        # Feature schema đã được lưu trong model
        self.feature_names = self.model.feature_names_

        # Categorical features (theo tên, không dùng index)
        cat_indices = self.model.get_cat_feature_indices()
        self.cat_features = [
            self.feature_names[i]
            for i in cat_indices
            if i < len(self.feature_names)
        ]

    # --------------------------------------------------
    # INTERNAL: chuẩn hoá feature theo schema model
    # --------------------------------------------------
    def _build_feature_row(self, features: dict):
        """
        Build feature row đúng thứ tự + đúng kiểu cho CatBoost
        """
        row = []

        for fname in self.feature_names:
            val = features.get(fname)

            # Feature categorical
            if fname in self.cat_features:
                if val is None or val == "" or str(val).lower() in ("nan", "none"):
                    row.append("unknown")
                else:
                    row.append(str(val))

            # Feature numeric
            else:
                try:
                    row.append(float(val))
                except Exception:
                    row.append(0.0)

        return row

    # --------------------------------------------------
    # PUBLIC: predict tactic
    # --------------------------------------------------
    def predict(self, elastic_log: dict):
        """
        Predict MITRE tactic từ 1 log Elastic (Snort)
        """
        # 1️⃣ Normalize raw log → feature dict
        features = normalize_elastic_log(elastic_log)

        # 2️⃣ Build feature row đúng schema
        row = self._build_feature_row(features)

        # 3️⃣ Tạo Pool cho CatBoost (QUAN TRỌNG)
        pool = Pool(
            data=[row],
            feature_names=self.feature_names,
            cat_features=self.cat_features,
        )

        # 4️⃣ Predict
        pred_id = int(self.model.predict(pool)[0])
        tactic = self.label_encoder.inverse_transform([pred_id])[0]

        # 5️⃣ Confidence
        try:
            probs = self.model.predict_proba(pool)[0]
            confidence = float(max(probs))
        except Exception:
            confidence = 0.0

        return tactic, confidence


# --------------------------------------------------
# LOCAL TEST
# --------------------------------------------------
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

    predictor = TacticPredictor()
    tactic, conf = predictor.predict(sample_log)

    print("✅ Tactic:", tactic)
    print("✅ Confidence:", conf)
