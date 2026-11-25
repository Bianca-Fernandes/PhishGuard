"""
Module: Machine Learning Detection (client side)

Asks the separate ML service for a prediction. If the service is not
running the scan still works, and the ML signal is marked unavailable.
"""
import requests
from flask import current_app

from .signals import Signal


def predict(url: str):
    """Returns (probability or None, model_version or None, Signal)."""
    base = current_app.config["ML_SERVICE_URL"].rstrip("/")
    try:
        r = requests.post(f"{base}/predict", json={"url": url},
                          timeout=current_app.config["ML_TIMEOUT"])
        if r.status_code != 200:
            raise RuntimeError(r.json().get("error", f"HTTP {r.status_code}"))
        data = r.json()
    except Exception as exc:  # service down, timeout, no model ...
        current_app.logger.warning("ML service unavailable: %s", exc)
        return None, None, Signal("ml", "Machine learning model", "unavailable", 0,
                                  "The ML service could not be reached, so this check was skipped.")

    p = float(data["phishing_probability"])
    version = data.get("model_version")
    pct = round(p * 100)
    if p >= 0.8:
        sig = Signal("ml", "Machine learning model", "danger", 0,
                     f"The trained model ({version}) thinks this URL looks like phishing ({pct}% likely).")
    elif p >= 0.5:
        sig = Signal("ml", "Machine learning model", "warning", 0,
                     f"The model ({version}) finds this URL somewhat similar to phishing links ({pct}%).")
    else:
        sig = Signal("ml", "Machine learning model", "ok", 0,
                     f"The model ({version}) finds this URL similar to normal links ({pct}% phishing).")
    return p, version, sig


def model_info():
    base = current_app.config["ML_SERVICE_URL"].rstrip("/")
    try:
        r = requests.get(f"{base}/models", timeout=current_app.config["ML_TIMEOUT"])
        return r.json()
    except Exception:
        return None
