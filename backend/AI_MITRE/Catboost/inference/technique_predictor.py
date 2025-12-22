# AI_MITRE/Catboost/inference/technique_predictor.py

import joblib
from catboost import CatBoostClassifier, Pool

from AI_MITRE.Catboost.preprocessing.normalize_elastic import normalize_elastic_log


class TechniquePredictor:
    """
    Realtime MITRE Technique Predictor (CatBoost)
    - Input: raw Elastic log (dict)
    - Output:
        - technique_name
        - confidence
        - full probability vector
        - technique labels (order-safe)
    """

    def __init__(
        self,
        model_path: str = "AI_MITRE/Catboost/models/catboost_technique_model.cbm",
        encoder_path: str = "AI_MITRE/Catboost/models/label_encoder_technique.pkl",
    ):
        # Load CatBoost model
        self.model = CatBoostClassifier()
        self.model.load_model(model_path)

        # Load label encoder (sklearn)
        self.label_encoder = joblib.load(encoder_path)

        # Feature schema đã được lưu trong model
        self.feature_names = self.model.feature_names_

        # Categorical features (theo tên)
        cat_indices = self.model.get_cat_feature_indices()
        self.cat_features = [
            self.feature_names[i]
            for i in cat_indices
            if i < len(self.feature_names)
        ]

        # Technique label order (RẤT QUAN TRỌNG cho combine)
        self.technique_labels = list(self.label_encoder.classes_)

    # --------------------------------------------------
    # INTERNAL: build feature row đúng schema
    # --------------------------------------------------
    def _build_feature_row(self, features: dict):
        row = []

        for fname in self.feature_names:
            val = features.get(fname)

            # Categorical feature
            if fname in self.cat_features:
                if val is None or val == "" or str(val).lower() in ("nan", "none"):
                    row.append("unknown")
                else:
                    row.append(str(val))
            else:
                # Numeric feature
                try:
                    row.append(float(val))
                except Exception:
                    row.append(0.0)

        return row

    # --------------------------------------------------
    # PUBLIC: predict technique
    # --------------------------------------------------
    def predict(self, elastic_log: dict):
        """
        Predict MITRE technique từ 1 log Elastic
        """
        # 1️⃣ Normalize raw log
        features = normalize_elastic_log(elastic_log)

        # 2️⃣ Build feature row
        row = self._build_feature_row(features)

        # 3️⃣ Create Pool (QUAN TRỌNG)
        pool = Pool(
            data=[row],
            feature_names=self.feature_names,
            cat_features=self.cat_features,
        )

        # 4️⃣ Predict class id
        pred_id = int(self.model.predict(pool)[0])
        technique = self.label_encoder.inverse_transform([pred_id])[0]

        # 5️⃣ Predict probability vector
        try:
            probs = self.model.predict_proba(pool)[0]
            confidence = float(max(probs))
            prob_vector = probs.tolist()
        except Exception:
            confidence = 0.0
            prob_vector = []

        return {
            "technique": technique,
            "confidence": confidence,
            "probs": prob_vector,
            "labels": self.technique_labels,
        }


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

    predictor = TechniquePredictor()
    result = predictor.predict(sample_log)

    print("✅ Technique:", result["technique"])
    print("✅ Confidence:", result["confidence"])
    print("✅ #Techniques:", len(result["labels"]))
