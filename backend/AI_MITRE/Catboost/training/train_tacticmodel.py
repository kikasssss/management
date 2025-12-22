import pandas as pd
import joblib
from catboost import CatBoostClassifier, Pool
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score

# ---- 1. Đọc dữ liệu gộp ----
df = pd.read_csv("combined_logs_minimal.csv", low_memory=False)
print(f"✅ Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")

# ---- 2. Xác định nhãn cần học ----
# Bạn có thể đổi giữa 'threat.tactic.name' và 'threat.technique.name'
target = "threat.tactic.name"

# Loại bỏ những hàng không có nhãn (label trống hoặc 'none')
df = df[df[target].notna() & (df[target].astype(str).str.lower() != "none")]
print(f"📊 Labeled samples: {len(df)}")

if df.empty:
    raise SystemExit("❌ Không có dữ liệu có nhãn hợp lệ để train!")

# ---- 3. Chuẩn bị dữ liệu ----
# Chỉ loại bỏ nhãn tactic/technique khỏi features
X = df.drop(columns=["threat.tactic.name", "threat.technique.name"], errors="ignore")
y = df[target].astype(str)

# ---- 4. Điền giá trị thiếu ----
X = X.fillna("unknown")

# ---- 5. Xác định các cột dạng categorical ----
cat_features = [col for col in X.columns if X[col].dtype == "object"]

# ---- 6. Chuyển tất cả cột object thành string ----
for col in cat_features:
    X[col] = X[col].astype(str)

# ---- 7. Encode nhãn ----
le = LabelEncoder()
y_enc = le.fit_transform(y)

# ---- 8. Tách train/test ----
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)

# ---- 9. Tạo CatBoost Pool ----
train_pool = Pool(X_train, y_train, cat_features=cat_features)
test_pool = Pool(X_test, y_test, cat_features=cat_features)

# ---- 10. Huấn luyện ----
model = CatBoostClassifier(
    iterations=600,
    depth=8,
    learning_rate=0.08,
    loss_function="MultiClass",
    eval_metric="TotalF1",
    random_seed=42,
    early_stopping_rounds=50,
    verbose=100
)

model.fit(train_pool, eval_set=test_pool)

# ---- 11. Đánh giá ----
y_pred = model.predict(X_test)
y_pred = y_pred.astype(int).ravel()

print("\n📈 F1-macro:", f1_score(y_test, y_pred, average="macro"))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ---- 12. Lưu mô hình và encoder ----
model.save_model("catboost_threat_model.cbm")
joblib.dump(le, "label_encoder_tactic.pkl")

print("\n✅ Đã lưu mô hình: catboost_threat_model.cbm")
print("✅ Đã lưu encoder: label_encoder_tactic.pkl")
