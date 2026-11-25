"""
PhishGuard Machine Learning Service.

A small separate Flask service that loads the trained model and answers
prediction requests from the main web application.

Run:   python ml_service/service.py          (listens on http://127.0.0.1:5001)

Endpoints
  GET  /health            -> service status and loaded version
  GET  /models            -> all trained model versions with their metrics
  POST /predict  {"url"}  -> {"phishing_probability", "label", "model_version"}

By default the newest version in ml_service/models/ is loaded.
Set MODEL_VERSION=v2 (for example) to load a specific version.
"""
import json
import os
import sys

import joblib
import numpy as np
from flask import Flask, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import FEATURE_NAMES, extract_features  # noqa: E402

MODELS_DIR = os.path.join(HERE, "models")

app = Flask(__name__)
_state = {"model": None, "version": None, "meta": None, "error": None}


def list_versions():
    out = []
    if not os.path.isdir(MODELS_DIR):
        return out
    for f in os.listdir(MODELS_DIR):
        if f.startswith("phishguard_v") and f.endswith(".json"):
            try:
                with open(os.path.join(MODELS_DIR, f)) as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                continue
    out.sort(key=lambda m: int(m["version"][1:]))
    return out


def load_model():
    wanted = os.getenv("MODEL_VERSION", "").strip()
    versions = list_versions()
    if not versions:
        _state["error"] = "No trained model found. Run ml_service/train_model.py first."
        return
    meta = next((m for m in versions if m["version"] == wanted), None) if wanted else versions[-1]
    if meta is None:
        _state["error"] = f"Model version {wanted} not found."
        return
    bundle = joblib.load(os.path.join(MODELS_DIR, f"phishguard_{meta['version']}.joblib"))
    if bundle.get("features") != FEATURE_NAMES:
        _state["error"] = "Model was trained with different features. Please retrain it."
        return
    _state.update(model=bundle["model"], version=meta["version"], meta=meta, error=None)
    print(f"Loaded model {meta['version']} ({meta['algorithm']}, F1={meta['metrics']['f1']})")


@app.get("/health")
def health():
    return jsonify({
        "status": "ok" if _state["model"] is not None else "no_model",
        "model_version": _state["version"],
        "error": _state["error"],
    })


@app.get("/models")
def models():
    return jsonify({"active": _state["version"], "versions": list_versions()})


@app.post("/predict")
def predict():
    if _state["model"] is None:
        return jsonify({"error": _state["error"] or "model not loaded"}), 503
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    if not url:
        return jsonify({"error": "url is required"}), 400
    x = np.array([extract_features(url)], dtype=float)
    proba = float(_state["model"].predict_proba(x)[0, 1])
    return jsonify({
        "phishing_probability": round(proba, 4),
        "label": "phishing" if proba >= 0.5 else "legitimate",
        "model_version": _state["version"],
        "algorithm": _state["meta"]["algorithm"],
    })


load_model()

if __name__ == "__main__":
    port = int(os.getenv("ML_PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=False)
