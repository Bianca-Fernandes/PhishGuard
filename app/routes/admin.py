"""
Admin panel: dashboard, phishing reports, blocklist, model versions and users.
"""
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from .. import db
from ..security import admin_required, client_ip
from ..services import ml_client
from ..services.validator import ValidationError, clean_url

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    totals = db.query_one(
        "SELECT (SELECT COUNT(*) FROM scans) AS scans, "
        "(SELECT COUNT(*) FROM users) AS users, "
        "(SELECT COUNT(*) FROM phishing_reports WHERE status = 'pending') AS pending, "
        "(SELECT COUNT(*) FROM blocklist) AS blocked, "
        "(SELECT COUNT(*) FROM scans WHERE created_at >= NOW() - INTERVAL 1 DAY) AS today")
    by_level = db.query_all(
        "SELECT risk_level, COUNT(*) AS n FROM risk_results GROUP BY risk_level")
    counts = {r["risk_level"]: r["n"] for r in by_level}
    levels = ["Very Low", "Low", "Medium", "High", "Critical"]
    level_counts = [(lv, counts.get(lv, 0)) for lv in levels]
    max_count = max([c for _, c in level_counts] + [1])

    top_domains = db.query_all(
        "SELECT s.domain, COUNT(*) AS n, MAX(r.risk_score) AS max_score FROM scans s "
        "JOIN risk_results r ON r.scan_id = s.id WHERE r.risk_level IN ('High','Critical') "
        "GROUP BY s.domain ORDER BY n DESC LIMIT 8")
    recent = db.query_all(
        "SELECT s.id, s.normalized_url, s.created_at, r.risk_level, r.risk_score, u.email "
        "FROM scans s JOIN risk_results r ON r.scan_id = s.id "
        "LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id DESC LIMIT 10")
    ml = ml_client.model_info()
    return render_template("admin/dashboard.html", totals=totals, level_counts=level_counts,
                           max_count=max_count, top_domains=top_domains, recent=recent, ml=ml)


# ---------------------------------------------------------------- reports
@bp.route("/reports")
@admin_required
def reports():
    status = request.args.get("status", "pending")
    if status not in ("pending", "confirmed", "rejected", "all"):
        status = "pending"
    sql = ("SELECT p.*, u.email AS reporter, a.email AS reviewer FROM phishing_reports p "
           "LEFT JOIN users u ON u.id = p.user_id LEFT JOIN users a ON a.id = p.reviewed_by ")
    params = ()
    if status != "all":
        sql += "WHERE p.status = %s "
        params = (status,)
    rows = db.query_all(sql + "ORDER BY p.id DESC LIMIT 200", params)
    return render_template("admin/reports.html", rows=rows, status=status)


@bp.route("/reports/<int:report_id>/<action>", methods=["POST"])
@admin_required
def review_report(report_id, action):
    if action not in ("confirm", "reject"):
        abort(404)
    rep = db.query_one("SELECT * FROM phishing_reports WHERE id = %s", (report_id,))
    if not rep:
        abort(404)
    new_status = "confirmed" if action == "confirm" else "rejected"
    db.execute("UPDATE phishing_reports SET status = %s, reviewed_by = %s, reviewed_at = NOW() "
               "WHERE id = %s", (new_status, session["user_id"], report_id), commit=False)
    if new_status == "confirmed" and not db.query_one("SELECT id FROM blocklist WHERE domain = %s", (rep["domain"],)):
        db.execute("INSERT INTO blocklist (domain, report_id, added_by) VALUES (%s, %s, %s)",
                   (rep["domain"], report_id, session["user_id"]), commit=False)
    db.commit()
    db.audit(f"report_{new_status}", rep["url"], session["user_id"], client_ip())
    msg = f"Report #{report_id} confirmed and '{rep['domain']}' added to the blocklist." \
        if new_status == "confirmed" else f"Report #{report_id} rejected."
    flash(msg, "success")
    return redirect(url_for("admin.reports", status=request.args.get("back", "pending")))


# -------------------------------------------------------------- blocklist
@bp.route("/blocklist", methods=["GET", "POST"])
@admin_required
def blocklist():
    if request.method == "POST":
        try:
            u = clean_url(request.form.get("domain", ""))
        except ValidationError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin.blocklist"))
        if db.query_one("SELECT id FROM blocklist WHERE domain = %s", (u.host,)):
            flash(f"'{u.host}' is already blocked.", "info")
        else:
            db.execute("INSERT INTO blocklist (domain, added_by) VALUES (%s, %s)", (u.host, session["user_id"]))
            db.audit("blocklist_add", u.host, session["user_id"], client_ip())
            flash(f"'{u.host}' added to the blocklist.", "success")
        return redirect(url_for("admin.blocklist"))
    rows = db.query_all("SELECT b.*, u.email AS added_by_email FROM blocklist b "
                        "LEFT JOIN users u ON u.id = b.added_by ORDER BY b.id DESC")
    return render_template("admin/blocklist.html", rows=rows)


@bp.route("/blocklist/<int:item_id>/delete", methods=["POST"])
@admin_required
def blocklist_delete(item_id):
    row = db.query_one("SELECT domain FROM blocklist WHERE id = %s", (item_id,))
    if row:
        db.execute("DELETE FROM blocklist WHERE id = %s", (item_id,))
        db.audit("blocklist_remove", row["domain"], session["user_id"], client_ip())
        flash(f"'{row['domain']}' removed from the blocklist.", "info")
    return redirect(url_for("admin.blocklist"))


# ----------------------------------------------------------------- models
@bp.route("/models")
@admin_required
def models():
    info = ml_client.model_info()
    registered = db.query_all(
        "SELECT m.*, (SELECT COUNT(*) FROM scans s WHERE s.model_version = m.version) AS scans_used "
        "FROM model_versions m ORDER BY m.id DESC")
    return render_template("admin/models.html", info=info, registered=registered)


# ------------------------------------------------------------------ users
@bp.route("/users")
@admin_required
def users():
    rows = db.query_all(
        "SELECT u.id, u.full_name, u.email, u.role, u.is_active, u.created_at, u.last_login, "
        "(SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scans "
        "FROM users u ORDER BY u.id")
    return render_template("admin/users.html", rows=rows)


@bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot disable your own account.", "warning")
        return redirect(url_for("admin.users"))
    db.execute("UPDATE users SET is_active = 1 - is_active WHERE id = %s", (user_id,))
    db.audit("user_toggled", str(user_id), session["user_id"], client_ip())
    flash("User status updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/audit")
@admin_required
def audit():
    rows = db.query_all("SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON u.id = a.user_id "
                        "ORDER BY a.id DESC LIMIT 200")
    return render_template("admin/audit.html", rows=rows)
