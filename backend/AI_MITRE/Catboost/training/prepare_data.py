#phân loại dữ liệu từ data để train
import os
import pandas as pd
import numpy as np

# ========= 1) Cấu hình =========
DATA_DIR = "data"                             # thư mục chứa các file csv nguồn
OUTPUT_FILE = "combined_logs_minimal.csv"     # file gộp đầu ra

# Các cột GỐC cần lấy từ dữ liệu
SOURCE_COLS = [
    "conn_state", "duration", "history",
    "src_port_zeek", "dest_port_zeek",
    "orig_bytes", "resp_bytes",
    "orig_pkts", "resp_pkts",
    "proto", "service",
    "ts",
    "label_tactic", "label_technique"
]

# Mapping sang schema TRAIN (ECS-like)
RENAME_DICT = {
    "conn_state": "network.state",
    "duration": "event.duration",
    "history": "network.history",
    "src_port_zeek": "source.port",
    "dest_port_zeek": "destination.port",
    "orig_bytes": "source.bytes",
    "resp_bytes": "destination.bytes",
    "orig_pkts": "source.packets",
    "resp_pkts": "destination.packets",
    "proto": "network.transport",
    "service": "network.service",
    "ts": "@timestamp",
    "label_tactic": "threat.tactic.name",
    "label_technique": "threat.technique.name"
}

# Thứ tự cột đích tối giản để train
DEST_COL_ORDER = [
    "network.state", "network.history",
    "network.transport", "network.service",
    "source.port", "destination.port",
    "event.duration",
    "source.bytes", "destination.bytes",
    "source.packets", "destination.packets",
    "@timestamp",
    "threat.tactic.name", "threat.technique.name"
]

# ========= 2) Đọc & gộp =========
csv_files = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR) if f.endswith(".csv")]

dfs = []
for path in csv_files:
    try:
        df = pd.read_csv(path, low_memory=False)

        # Thêm cột thiếu để đồng bộ schema
        for col in SOURCE_COLS:
            if col not in df.columns:
                df[col] = np.nan

        # Giữ đúng thứ tự cột gốc
        df = df[SOURCE_COLS]
        dfs.append(df)
        print(f"✅ Loaded: {path} ({df.shape[0]} rows)")
    except Exception as e:
        print(f"⚠️ Error reading {path}: {e}")

if not dfs:
    raise SystemExit("❌ Không tìm thấy CSV hợp lệ trong thư mục 'data'.")

df_all = pd.concat(dfs, ignore_index=True)
print(f"\n📊 Tổng cộng {df_all.shape[0]} dòng, {df_all.shape[1]} cột (trước chuẩn hóa)")

# ========= 3) Ép kiểu nhẹ để nhất quán =========
# Cổng, bytes, packets, duration → numeric
num_cols = ["duration", "src_port_zeek", "dest_port_zeek",
            "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
for c in num_cols:
    if c in df_all.columns:
        df_all[c] = pd.to_numeric(df_all[c], errors="coerce")

# ========= 4) Đổi tên cột sang schema TRAIN =========
df_all.rename(columns=RENAME_DICT, inplace=True)

# ========= 5) Xử lý trùng cột / rỗng =========
df_all = df_all.loc[:, ~df_all.columns.duplicated()]
df_all.dropna(how="all", inplace=True)

# ========= 6) Thêm cột thiếu (nếu cần) và sắp xếp lại thứ tự =========
for col in DEST_COL_ORDER:
    if col not in df_all.columns:
        df_all[col] = np.nan
df_all = df_all[DEST_COL_ORDER]

# ========= 7) (Tuỳ chọn) thêm đặc trưng thời gian =========
# Nếu timestamp là ISO như 2024-11-05T10:00:00.646Z, có thể tạo giờ/ngày
USE_TIME_FEATURES = False  # đặt True nếu muốn thêm 'hour', 'weekday', 'is_weekend'

if USE_TIME_FEATURES and "@timestamp" in df_all.columns:
    ts = pd.to_datetime(df_all["@timestamp"], errors="coerce", utc=True)
    df_all["hour"] = ts.dt.hour
    df_all["weekday"] = ts.dt.weekday
    df_all["is_weekend"] = df_all["weekday"].isin([5, 6]).astype(int)
    print("🕒 Đã thêm các đặc trưng thời gian: hour, weekday, is_weekend")

# ========= 8) Ghi file =========
df_all.to_csv(OUTPUT_FILE, index=False)
print(f"\n✅ Đã lưu file tối giản cho train AI MITRE: {OUTPUT_FILE}")
print("📊 Shape:", df_all.shape)
