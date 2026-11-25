"""
Train the PhishGuard phishing URL model.

Usage (from the project folder):
    python ml_service/train_model.py --data ml_service/data/phishing_site_urls.csv

Supported dataset formats (CSV):
  * Kaggle "Phishing Site URLs"       columns: URL, Label   (good / bad)
  * Kaggle "Malicious URLs dataset"   columns: url, type    (benign / phishing / defacement / malware)
  * Any CSV with a url column and a label column (0/1, legitimate/phishing, good/bad ...)

The script trains three models, compares them on a held-out test set,
keeps the best one (by F1 score) and saves it as a new version:
    ml_service/models/phishguard_v<N>.joblib
    ml_service/models/phishguard_v<N>.json   (metrics + details for the report)
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES, extract_features  # noqa: E402

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

URL_COLUMNS = ("url", "urls", "domain", "link")
LABEL_COLUMNS = ("label", "type", "class", "status", "result", "phishing", "target")
PHISHING_VALUES = {"bad", "phishing", "malicious", "1", "phish", "defacement", "malware", "spam", "yes", "true"}
LEGIT_VALUES = {"good", "benign", "legitimate", "0", "safe", "-1", "no", "false"}


def load_dataset(path, phishing_only_types=False):
    df = pd.read_csv(path, low_memory=False)
    cols = {c.lower().strip(): c for c in df.columns}
    url_col = next((cols[c] for c in URL_COLUMNS if c in cols), None)
    label_col = next((cols[c] for c in LABEL_COLUMNS if c in cols), None)
    if not url_col or not label_col:
        raise SystemExit(f"Could not find url / label columns in {list(df.columns)}")

    df = df[[url_col, label_col]].dropna()
    df.columns = ["url", "label"]
    labels = df["label"].astype(str).str.strip().str.lower()

    if phishing_only_types:
        # for the "malicious URLs" dataset: keep only benign vs phishing rows
        keep = labels.isin({"benign", "phishing"})
        df, labels = df[keep], labels[keep]

    y = labels.map(lambda v: 1 if v in PHISHING_VALUES else (0 if v in LEGIT_VALUES else None))
    df = df.assign(y=y).dropna(subset=["y"])
    df["y"] = df["y"].astype(int)
    df["url"] = df["url"].astype(str)
    df = df.drop_duplicates(subset=["url"])
    return df


def next_version():
    os.makedirs(MODELS_DIR, exist_ok=True)
    nums = []
    for f in os.listdir(MODELS_DIR):
        if f.startswith("phishguard_v") and f.endswith(".joblib"):
            try:
                nums.append(int(f[len("phishguard_v"):-len(".joblib")]))
            except ValueError:
                pass
    return max(nums, default=0) + 1


def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    return {
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    ap = argparse.ArgumentParser(description="Train the PhishGuard URL model")
    ap.add_argument("--data", required=True, help="path to the CSV dataset")
    ap.add_argument("--max-rows", type=int, default=200000,
                    help="use at most this many rows (keeps training fast on a laptop)")
    ap.add_argument("--phishing-only", action="store_true",
                    help="for the Malicious URLs dataset: use only benign and phishing rows")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print(f"Loading {args.data} ...")
    df = load_dataset(args.data, args.phishing_only)
    if len(df) > args.max_rows:
        df = df.sample(args.max_rows, random_state=args.seed)
    print(f"Rows used: {len(df)}  (phishing: {int(df.y.sum())}, legitimate: {int((df.y == 0).sum())})")
    if df.y.nunique() < 2:
        raise SystemExit("The dataset needs both phishing and legitimate URLs.")

    print("Extracting URL features ...")
    t0 = time.time()
    X = np.array([extract_features(u) for u in df["url"]], dtype=float)
    y = df["y"].values
    print(f"  {X.shape[1]} features in {time.time() - t0:.1f}s")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y)

    candidates = {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Random Forest": RandomForestClassifier(
            n_estimators=150, max_depth=30, min_samples_leaf=3, n_jobs=-1,
            class_weight="balanced", random_state=args.seed),
        "Gradient Boosting": GradientBoostingClassifier(random_state=args.seed),
    }

    results = {}
    best_name, best_model, best_f1 = None, None, -1
    for name, model in candidates.items():
        t0 = time.time()
        model.fit(X_train, y_train)
        metrics = evaluate(model, X_test, y_test)
        metrics["train_seconds"] = round(time.time() - t0, 1)
        results[name] = metrics
        print(f"  {name:20s} acc={metrics['accuracy']:.4f}  prec={metrics['precision']:.4f}  "
              f"rec={metrics['recall']:.4f}  f1={metrics['f1']:.4f}  auc={metrics['roc_auc']:.4f}")
        if metrics["f1"] > best_f1:
            best_name, best_model, best_f1 = name, model, metrics["f1"]

    version = f"v{next_version()}"
    importances = None
    if hasattr(best_model, "feature_importances_"):
        pairs = sorted(zip(FEATURE_NAMES, best_model.feature_importances_), key=lambda p: -p[1])
        importances = [{"feature": f, "importance": round(float(i), 4)} for f, i in pairs[:15]]

    meta = {
        "version": version,
        "algorithm": best_name,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": os.path.basename(args.data),
        "rows": int(len(df)),
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "features": FEATURE_NAMES,
        "metrics": results[best_name],
        "all_models": results,
        "top_features": importances,
    }
    model_path = os.path.join(MODELS_DIR, f"phishguard_{version}.joblib")
    joblib.dump({"model": best_model, "features": FEATURE_NAMES, "version": version}, model_path, compress=3)
    with open(os.path.join(MODELS_DIR, f"phishguard_{version}.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nBest model: {best_name} (F1 = {best_f1:.4f})")
    print(f"Saved as {version}: {model_path}")
    print("Restart the ML service to load the new version.")


if __name__ == "__main__":
    main()
