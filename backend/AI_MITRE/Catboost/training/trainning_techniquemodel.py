# train_technique_model.py
import pandas as pd
import joblib
from catboost import CatBoostClassifier, Pool
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score

# ---- 1. Load data ----
df = pd.read_csv("combined_logs_minimal.csv", low_memory=False)
print(f"Loaded dataset: {df.shape}")

# ---- 2. Target = technique ----
target = "threat.technique.name"

df = df[df[target].notna() & (df[target].astype(str).str.lower() != "none")]
if df.empty:
    raise SystemExit("No technique labels found")

# ---- 3. Tách tập ----
X = df.drop(columns=["threat.tactic.name", "threat.technique.name"])
y = df[target].astype(str)

# ---- 4. Xử lý missing ----
numeric_cols = X.select_dtypes(include=["number"]).columns
categorical_cols = X.select_dtypes(exclude=["number"]).columns

# numeric → 0
for col in numeric_cols:
    X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

# categorical → "unknown"
for col in categorical_cols:
    X[col] = X[col].astype(str).fillna("unknown")

# ---- 5. Encode nhãn ----
le = LabelEncoder()
y_enc = le.fit_transform(y)

# ---- 6. Train-test split ----
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)

# ---- 7. CatBoost Pool ----
train_pool = Pool(X_train, y_train, cat_features=list(categorical_cols))
test_pool = Pool(X_test, y_test, cat_features=list(categorical_cols))

# ---- 8. Train CatBoost ----
model = CatBoostClassifier(
    iterations=900,
    depth=8,
    learning_rate=0.06,
    loss_function="MultiClass",
    auto_class_weights="Balanced",   # ← THÊM DÒNG NÀY
    eval_metric="TotalF1",
    random_seed=42,
    early_stopping_rounds=70,
)

model.fit(train_pool, eval_set=test_pool)

# ---- 9. Evaluate ----
y_pred = model.predict(X_test).astype(int).ravel()
print("F1 macro:", f1_score(y_test, y_pred, average="macro"))

print(classification_report(y_test, y_pred, target_names=le.classes_))

# ---- 10. Save ----
model.save_model("catboost_technique_model.cbm")
joblib.dump(le, "label_encoder_technique.pkl")

print("\nSaved model & encoder")
