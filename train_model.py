import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
import joblib


# ─────────────────────────────────────────
#  Load & preprocess
# ─────────────────────────────────────────

def load_data(path='Phishing URL dataset/features_v2.csv'):
    df = pd.read_csv(path)

    # clip کردن outlier ها با مرز 99th percentile
    clip_cols = ['url_length', 'hostname_length', 'num_subdomains',
                 'num_dots', 'num_hyphens', 'url_entropy',
                 'path_length', 'num_special_chars', 'digit_ratio']

    for col in clip_cols:
        upper = df[col].quantile(0.99)
        df[col] = df[col].clip(upper=upper)

    X = df.drop(columns=['label'])
    y = df['label']
    return X, y


# ─────────────────────────────────────────
#  Train & evaluate a single model
# ─────────────────────────────────────────

def evaluate(model_name, y_test, y_pred):
    print(f"\n{'='*50}")
    print(f"  {model_name}")
    print(f"{'='*50}")
    print(f"  Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision : {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall    : {recall_score(y_test, y_pred):.4f}")
    print(f"  F1 Score  : {f1_score(y_test, y_pred):.4f}")
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))


# ─────────────────────────────────────────
#  Main
# ─────────────────────────────────────────

if __name__ == '__main__':

    # 1 — Load data
    print("Loading data...")
    X, y = load_data()
    print(f"Shape: {X.shape}")

    # 2 — Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain size: {len(X_train):,}  |  Test size: {len(X_test):,}")
    print(f"Label distribution (train):\n{y_train.value_counts(normalize=True).round(3)}")

    # 3 — Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # 4 — Logistic Regression
    print("\nTraining Logistic Regression...")
    lr = LogisticRegression(max_iter=500, random_state=42)
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    evaluate("Logistic Regression", y_test, y_pred_lr)

    # 5 — Random Forest
    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    y_pred_rf = rf.predict(X_test_scaled)
    evaluate("Random Forest", y_test, y_pred_rf)

    # 6 — Save models + scaler
    joblib.dump(lr,     'lr_phishing_model.pkl')
    joblib.dump(rf,     'rf_phishing_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    print("\nModels and scaler saved:")
    print("  lr_phishing_model.pkl")
    print("  rf_phishing_model.pkl")
    print("  scaler.pkl")

    # 7 — Compare
    print(f"\n{'='*50}")
    print("  Model Comparison")
    print(f"{'='*50}")
    print(f"  {'Model':<25} {'F1':>6}  {'Recall':>8}  {'Precision':>10}")
    print(f"  {'-'*50}")
    print(f"  {'Logistic Regression':<25} {f1_score(y_test, y_pred_lr):.4f}  {recall_score(y_test, y_pred_lr):.6f}  {precision_score(y_test, y_pred_lr):.8f}")
    print(f"  {'Random Forest':<25} {f1_score(y_test, y_pred_rf):.4f}  {recall_score(y_test, y_pred_rf):.6f}  {precision_score(y_test, y_pred_rf):.8f}")
