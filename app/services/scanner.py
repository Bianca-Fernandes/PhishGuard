"""
Scan process (runs every step one by one):
  1. Clean and validate the URL
  2. Collect signals: URL checks, ML model, threat information, domain information
  3. Risk engine combines the signals
  4. Save the scan, signals and result in MySQL
"""
import time
from concurrent.futures import ThreadPoolExecutor

from flask import copy_current_request_context, current_app

from .. import db
from . import domain_intel, ml_client, threat_intel, url_checks
from .risk_engine import assess
from .validator import clean_url


def run_scan(raw_url: str, user_id=None) -> int:
    """Run a full scan and return the new scan id. Raises ValidationError for bad input."""
    started = time.time()
    u = clean_url(raw_url)

    # Step 2a: URL checks (fast, no network)
    signals = url_checks.check_url(u)
    u_score = url_checks.url_score(signals)

    # Step 2b-d: the network checks run at the same time to save waiting
    @copy_current_request_context
    def ml_job():
        return ml_client.predict(u.normalized)

    @copy_current_request_context
    def domain_job():
        if current_app.config["ENABLE_DOMAIN_INTEL"]:
            return domain_intel.check_domain(u)
        return []

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_ml = pool.submit(ml_job)
        f_domain = pool.submit(domain_job)
        threat_hit, threat_signals = threat_intel.check_threats(u)  # uses DB, keep on main thread
        ml_prob, model_version, ml_signal = f_ml.result()
        domain_signals = f_domain.result()

    signals += [ml_signal] + threat_signals + domain_signals
    d_score = domain_intel.domain_score(domain_signals)

    # Step 3: risk engine
    result = assess(signals, u_score, ml_prob, d_score, threat_hit,
                    domain_checked=current_app.config["ENABLE_DOMAIN_INTEL"])

    # Step 4: save everything in one transaction
    duration = int((time.time() - started) * 1000)
    try:
        scan_id = db.execute(
            "INSERT INTO scans (user_id, original_url, normalized_url, domain, model_version, duration_ms) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, u.original.strip()[:2048], u.normalized[:2048], u.host[:255], model_version, duration),
            commit=False)
        for s in signals:
            db.execute(
                "INSERT INTO scan_signals (scan_id, source, name, status, points, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (scan_id, s.source, s.name[:100], s.status, s.points, s.detail[:500]), commit=False)
        db.execute(
            "INSERT INTO risk_results (scan_id, risk_score, risk_level, url_score, ml_probability, "
            "domain_score, threat_hit, summary) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (scan_id, result.score, result.level, result.url_score, result.ml_probability,
             result.domain_score, int(result.threat_hit), result.summary), commit=False)
        if model_version:
            _register_model_version(model_version)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return scan_id


def _register_model_version(version):
    """Copy model metrics from the ML service into model_versions the first time we see a version."""
    if db.query_one("SELECT id FROM model_versions WHERE version = %s", (version,)):
        return
    info = ml_client.model_info() or {}
    meta = next((m for m in info.get("versions", []) if m.get("version") == version), None)
    if not meta:
        db.execute("INSERT INTO model_versions (version, algorithm) VALUES (%s, %s)",
                   (version, "unknown"), commit=False)
        return
    m = meta.get("metrics", {})
    trained = (meta.get("trained_at") or "").replace("T", " ")[:19] or None
    db.execute(
        "INSERT INTO model_versions (version, algorithm, accuracy, precision_score, recall_score, "
        "f1_score, dataset_name, trained_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (version, meta.get("algorithm", "unknown"), m.get("accuracy"), m.get("precision"),
         m.get("recall"), m.get("f1"), meta.get("dataset"), trained), commit=False)
