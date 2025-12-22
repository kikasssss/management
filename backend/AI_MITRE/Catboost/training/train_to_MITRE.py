#gán nhãn MITRE cho log elastich
# file: infer_mitre_from_snort.py
import argparse
import pandas as pd
import numpy as np
import ipaddress
import hashlib
from datetime import datetime, timezone
import joblib
from catboost import CatBoostClassifier

# ---------- Helpers ----------
def parse_snort_timestamp(ts_snort: str):
    """Parse Snort timestamps into ISO and epoch strings."""
    if pd.isna(ts_snort):
        return None, None
    ts = str(ts_snort).strip()

    # ISO (2024-11-05T10:00:00.646Z)
    if "T" in ts and "Z" in ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            iso = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            return iso, str(dt.timestamp())
        except Exception:
            pass

    # Snort-style MM/DD-HH:MM:SS.micro
    if "-" in ts and len(ts) >= 15:
        try:
            now_year = datetime.now(timezone.utc).year
            month = int(ts[0:2])
            day = int(ts[3:5])
            time_part = ts.split("-", 1)[1]
            dt = datetime.strptime(f"{now_year}-{month:02d}-{day:02d} {time_part}", "%Y-%m-%d %H:%M:%S.%f")
            dt = dt.replace(tzinfo=timezone.utc)
            iso = dt.isoformat().replace("+00:00", "Z")
            return iso, str(dt.timestamp())
        except Exception:
            return None, None

    # epoch numeric
    try:
        f = float(ts)
        dt = datetime.fromtimestamp(f, tz=timezone.utc)
        iso = dt.isoformat().replace("+00:00", "Z")
        return iso, str(f)
    except Exception:
        return None, None


def to_transport(proto):
    if not isinstance(proto, str):
        return "unknown"
    p = proto.lower()
    if p in ("tcp", "udp", "icmp"):
        return p
    if p in ("eth", "ethernet", "arp"):
        return "arp"
    return "unknown"


def guess_service(proto, dport, msg):
    proto_l = str(proto).lower() if proto else ""
    msg_l = str(msg).lower() if msg else ""
    try:
        dport = int(dport)
    except Exception:
        dport = None
    if proto_l == "icmp":
        return "icmp"
    if "arp" in msg_l or proto_l in ("arp", "eth", "ethernet"):
        return "arp"
    if dport == 53 or "dns" in msg_l:
        return "dns"
    if dport in (80, 8080) or "http" in msg_l:
        return "http"
    if dport == 443 or "https" in msg_l:
        return "https"
    if dport == 22 or "ssh" in msg_l:
        return "ssh"
    return "unknown"


def short_event_id(row):
    s = f"{row.get('timestamp','')}|{row.get('src_ip','')}|{row.get('src_port',0)}|{row.get('dst_ip','')}|{row.get('dst_port',0)}|{row.get('proto','')}"
    return hashlib.md5(s.encode()).hexdigest()[:20]


# ---------- Normalize Snort log ----------
def normalize_snort_df(snort_df: pd.DataFrame) -> pd.DataFrame:
    expected = ["timestamp","pkt_num","src_ip","dst_ip","src_port","dst_port","proto","pkt_len","pkt_gen","rule","action","dir","source","msg","class"]
    for c in expected:
        if c not in snort_df.columns:
            snort_df[c] = np.nan

    iso_list, epoch_list = [], []
    for ts in snort_df["timestamp"].astype(str).fillna(""):
        iso, epoch = parse_snort_timestamp(ts)
        iso_list.append(iso)
        epoch_list.append(epoch)
    snort_df["event.created"] = iso_list
    snort_df["@timestamp"] = epoch_list

    out = pd.DataFrame(index=snort_df.index)
    out["network.state"] = "unknown"
    out["network.history"] = "unknown"
    out["network.transport"] = snort_df["proto"].fillna("unknown").astype(str).apply(to_transport)
    out["network.service"] = [
        guess_service(p, d, m) for p, d, m in zip(snort_df["proto"], snort_df["dst_port"], snort_df["msg"])
    ]

    out["source.port"] = pd.to_numeric(snort_df["src_port"], errors="coerce").fillna(0).astype(int)
    out["destination.port"] = pd.to_numeric(snort_df["dst_port"], errors="coerce").fillna(0).astype(int)
    out["event.duration"] = np.nan

    pkt_len = pd.to_numeric(snort_df["pkt_len"], errors="coerce").fillna(0)
    dir_up = snort_df["dir"].astype(str).str.upper().fillna("UNK")
    out["source.bytes"] = np.where(dir_up == "C2S", pkt_len, np.where(dir_up == "S2C", 0, pkt_len))
    out["destination.bytes"] = np.where(dir_up == "S2C", pkt_len, np.where(dir_up == "C2S", 0, 0))
    out["source.packets"] = np.where(dir_up == "C2S", 1, 0)
    out["destination.packets"] = np.where(dir_up == "S2C", 1, 0)

    out["@timestamp"] = snort_df["@timestamp"]
    out["event.id"] = [short_event_id(r) for _, r in snort_df.iterrows()]

    return out


# ---------- Predict MITRE ----------
def predict_mitre(snort_file, model_path, label_encoder_path, out_file):
    df_snort = pd.read_csv(snort_file, low_memory=False)
    print(f"✅ Loaded Snort file: {len(df_snort)} rows")

    # Normalize Snort schema
    X = normalize_snort_df(df_snort)
    print("✅ Normalized to model features. Shape:", X.shape)

    features = [
        "network.state","network.history","network.transport","network.service",
        "source.port","destination.port","event.duration",
        "source.bytes","destination.bytes","source.packets","destination.packets",
        "@timestamp"
    ]
    Xf = X[features].copy()

    # Load model & encoder
    model = CatBoostClassifier()
    model.load_model(model_path)
    le = joblib.load(label_encoder_path)
    print("✅ Loaded model and label encoder.")

    # Determine categorical columns from model
    cat_indices = model.get_cat_feature_indices()
    feature_names = list(Xf.columns)
    cat_cols = [feature_names[i] for i in cat_indices if i < len(feature_names)]
    print(f"📋 Model categorical features: {cat_cols}")

    # Clean and cast values
    for col in cat_cols:
        if col in Xf.columns:
            Xf[col] = (
                Xf[col]
                .astype(str)
                .replace(["nan","NaN","None","0.0","0","NaT"], "unknown")
            )

    # Numeric columns
    for col in Xf.columns:
        if col not in cat_cols:
            Xf[col] = pd.to_numeric(Xf[col], errors="coerce").fillna(0)

    print("🔧 Data types ready for CatBoost:")
    print(Xf.dtypes)
    print("\nSample preview:\n", Xf.head(3))

    # --- Predict ---
    preds_raw = model.predict(Xf)
    try:
        preds_ids = preds_raw.astype(int).ravel()
    except Exception:
        preds_ids = preds_raw.ravel().astype(str)

    try:
        pred_labels = le.inverse_transform(preds_ids)
    except Exception:
        pred_labels = preds_ids

    try:
        proba = model.predict_proba(Xf)
        confidences = proba.max(axis=1)
    except Exception:
        confidences = np.ones(len(Xf)) * np.nan

    out = df_snort.copy()
    out["pred.threat.tactic.name"] = pred_labels
    out["pred.threat.tactic.conf"] = confidences

    out.to_csv(out_file, index=False)
    print(f"\n✅ Wrote output with predictions: {out_file} ({len(out)} rows)")


# ---------- CLI ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Infer MITRE tactic from Snort logs using CatBoost model")
    parser.add_argument("--in", dest="snort_in", required=True, help="Input Snort CSV (timestamp,pkt_num,src_ip,...)")
    parser.add_argument("--model", dest="model", default="catboost_threat_model.cbm", help="CatBoost model for tactic")
    parser.add_argument("--encoder", dest="encoder", default="label_encoder_tactic.pkl", help="LabelEncoder .pkl")
    parser.add_argument("--out", dest="out", default="snort_with_mitre.csv", help="Output CSV with predictions")
    args = parser.parse_args()

    predict_mitre(args.snort_in, args.model, args.encoder, args.out)
