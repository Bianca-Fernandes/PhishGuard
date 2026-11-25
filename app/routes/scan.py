"""
Routes for scanning, results, scan history and phishing reports.
"""
from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)

from .. import db
from ..security import client_ip, login_required, rate_limited
from ..services.risk_engine import SUMMARIES, TIPS
from ..services.scanner import run_scan
from ..services.validator import ValidationError, clean_url

bp = Blueprint("scan", __name__)

SOURCE_TITLES = {
    "url": "URL checks",
    "ml": "Machine learning",
    "threat": "Threat intelligence",
    "domain": "Domain intelligence",
}
CHANNELS = [("email", "Email"), ("sms", "SMS"), ("whatsapp", "WhatsApp"),
            ("social_media", "Social media"), ("website", "Website"), ("other", "Other")]


def _scan_limit_hit():
    who = session.get("user_id") or client_ip()
    return rate_limited(f"scan:{who}", limit=20, window_seconds=60)


@bp.route("/")
def index():
    recent = []
    if session.get("user_id"):
        recent = db.query_all(
            "SELECT s.id, s.normalized_url, s.created_at, r.risk_level, r.risk_score "
            "FROM scans s JOIN risk_results r ON r.scan_id = s.id "
            "WHERE s.user_id = %s ORDER BY s.id DESC LIMIT 5", (session["user_id"],))
    return render_template("index.html", recent=recent, url=request.args.get("url", ""))


@bp.route("/scan", methods=["POST"])
def scan():
    raw = request.form.get("url", "")
    if _scan_limit_hit():
        flash("You are scanning too fast. Please wait a minute.", "warning")
        return redirect(url_for("scan.index"))
    try:
        scan_id = run_scan(raw, session.get("user_id"))
    except ValidationError as e:
        flash(str(e), "danger")
        return render_template("index.html", recent=[], url=raw), 400
    if not session.get("user_id"):
        guest = session.get("guest_scans", [])
        guest.append(scan_id)
        session["guest_scans"] = guest[-20:]
    return redirect(url_for("scan.result", scan_id=scan_id))


def _load_scan(scan_id):
    scan = db.query_one(
        "SELECT s.*, r.risk_score, r.risk_level, r.url_score, r.ml_probability, "
        "r.domain_score, r.threat_hit, r.summary FROM scans s "
        "JOIN risk_results r ON r.scan_id = s.id WHERE s.id = %s", (scan_id,))
    if not scan:
        abort(404)
    uid, role = session.get("user_id"), session.get("role")
    allowed = (
        role == "admin"
        or (uid and scan["user_id"] == uid)
        or (scan["user_id"] is None and scan_id in session.get("guest_scans", []))
    )
    if not allowed:
        abort(403 if uid else 404)
    return scan


@bp.route("/result/<int:scan_id>")
def result(scan_id):
    scan = _load_scan(scan_id)
    signals = db.query_all("SELECT * FROM scan_signals WHERE scan_id = %s ORDER BY id", (scan_id,))
    groups = {k: [s for s in signals if s["source"] == k] for k in SOURCE_TITLES}
    order = {"danger": 0, "warning": 1}
    reasons = sorted([s for s in signals if s["status"] in ("danger", "warning")],
                     key=lambda s: (s["source"] != "threat", order[s["status"]], -s["points"]))[:5]
    return render_template(
        "result.html", scan=scan, groups=groups, titles=SOURCE_TITLES, reasons=reasons,
        tips=TIPS[scan["risk_level"]], level_class=scan["risk_level"].lower().replace(" ", "-"))


@bp.route("/history")
@login_required
def history():
    level = request.args.get("level", "")
    q = request.args.get("q", "").strip()[:100]
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = 15

    where = ["s.user_id = %s"]
    params = [session["user_id"]]
    if level in SUMMARIES:
        where.append("r.risk_level = %s")
        params.append(level)
    if q:
        where.append("s.normalized_url LIKE %s")
        params.append("%" + q.replace("%", r"\%").replace("_", r"\_") + "%")
    where_sql = " AND ".join(where)

    total = db.query_one(
        f"SELECT COUNT(*) AS n FROM scans s JOIN risk_results r ON r.scan_id = s.id WHERE {where_sql}",
        tuple(params))["n"]
    rows = db.query_all(
        "SELECT s.id, s.normalized_url, s.domain, s.created_at, s.model_version, "
        "r.risk_level, r.risk_score FROM scans s JOIN risk_results r ON r.scan_id = s.id "
        f"WHERE {where_sql} ORDER BY s.id DESC LIMIT %s OFFSET %s",
        tuple(params + [per_page, (page - 1) * per_page]))
    pages = max((total + per_page - 1) // per_page, 1)
    return render_template("history.html", rows=rows, level=level, q=q, page=page,
                           pages=pages, total=total, levels=list(SUMMARIES))


@bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    db.execute("DELETE FROM scans WHERE id = %s AND user_id = %s", (scan_id, session["user_id"]))
    flash("Scan removed from your history.", "info")
    return redirect(url_for("scan.history"))


@bp.route("/report", methods=["GET", "POST"])
def report():
    form = {"url": request.args.get("url", ""), "source_channel": "other", "description": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("url", "source_channel", "description")}
        if rate_limited(f"report:{session.get('user_id') or client_ip()}", 10, 3600):
            flash("Too many reports from you in the last hour. Please try again later.", "warning")
            return render_template("report.html", form=form, channels=CHANNELS), 429
        try:
            u = clean_url(form["url"])
        except ValidationError as e:
            flash(str(e), "danger")
            return render_template("report.html", form=form, channels=CHANNELS), 400
        channel = form["source_channel"] if form["source_channel"] in dict(CHANNELS) else "other"
        db.execute(
            "INSERT INTO phishing_reports (user_id, url, domain, source_channel, description) "
            "VALUES (%s, %s, %s, %s, %s)",
            (session.get("user_id"), u.normalized[:2048], u.host[:255], channel,
             form["description"][:1000] or None))
        flash("Thank you! Your report was sent to our team for review.", "success")
        return redirect(url_for("scan.report"))
    return render_template("report.html", form=form, channels=CHANNELS)


# ---------------------------------------------------------------- JSON API
@bp.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON endpoint used by the scan page (and future browser extension)."""
    data = request.get_json(silent=True) or {}
    if _scan_limit_hit():
        return jsonify({"error": "Too many requests"}), 429
    try:
        scan_id = run_scan(str(data.get("url", "")), session.get("user_id"))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    if not session.get("user_id"):
        guest = session.get("guest_scans", [])
        guest.append(scan_id)
        session["guest_scans"] = guest[-20:]
    r = db.query_one("SELECT risk_score, risk_level, summary FROM risk_results WHERE scan_id = %s", (scan_id,))
    return jsonify({"scan_id": scan_id, "result_url": url_for("scan.result", scan_id=scan_id), **r})
