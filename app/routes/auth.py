"""
Module: Login & User Management
Registration, login, logout and profile. Passwords are stored as hashes.
"""
import re

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .. import db
from ..security import client_ip, login_required, rate_limited

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)


def password_problems(pw: str) -> list[str]:
    problems = []
    if len(pw) < 8:
        problems.append("at least 8 characters")
    if not re.search(r"[A-Z]", pw):
        problems.append("one capital letter")
    if not re.search(r"[a-z]", pw):
        problems.append("one small letter")
    if not re.search(r"\d", pw):
        problems.append("one number")
    return problems


def _safe_next(target):
    # only allow redirects inside our own site (no open redirect)
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("scan.index")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("scan.index"))
    form = {"full_name": "", "email": ""}
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"full_name": full_name, "email": email}

        errors = []
        if not 2 <= len(full_name) <= 100:
            errors.append("Please enter your full name.")
        if not EMAIL_RE.match(email) or len(email) > 150:
            errors.append("Please enter a valid email address.")
        problems = password_problems(password)
        if problems:
            errors.append("Password needs " + ", ".join(problems) + ".")
        if password != confirm:
            errors.append("The two passwords do not match.")
        if not errors and db.query_one("SELECT id FROM users WHERE email = %s", (email,)):
            errors.append("An account with this email already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            uid = db.execute(
                "INSERT INTO users (full_name, email, password_hash) VALUES (%s, %s, %s)",
                (full_name, email, generate_password_hash(password)))
            db.audit("register", email, uid, client_ip())
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("scan.index"))
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if rate_limited(f"login:{client_ip()}", limit=10, window_seconds=300):
            flash("Too many login attempts. Please wait 5 minutes and try again.", "danger")
            return render_template("auth/login.html", email=email), 429

        user = db.query_one("SELECT * FROM users WHERE email = %s", (email,))
        # same message for wrong email and wrong password (no user enumeration)
        if not user or not check_password_hash(user["password_hash"], password):
            db.audit("login_failed", email, user["id"] if user else None, client_ip())
            flash("Wrong email or password.", "danger")
        elif not user["is_active"]:
            flash("This account has been disabled. Please contact the admin.", "danger")
        else:
            guest_scans = session.get("guest_scans", [])
            session.clear()   # new session id after login (prevents session fixation)
            session.permanent = True
            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            session["role"] = user["role"]
            # attach scans done before login to this account
            for sid in guest_scans[-20:]:
                db.execute("UPDATE scans SET user_id = %s WHERE id = %s AND user_id IS NULL",
                           (user["id"], sid), commit=False)
            db.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user["id"],))
            db.audit("login", None, user["id"], client_ip())
            flash(f"Welcome back, {user['full_name'].split()[0]}!", "success")
            return redirect(_safe_next(request.args.get("next")))
    return render_template("auth/login.html", email=email)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("scan.index"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = session["user_id"]
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        user = db.query_one("SELECT password_hash FROM users WHERE id = %s", (uid,))
        problems = password_problems(new)
        if not check_password_hash(user["password_hash"], current):
            flash("Your current password is wrong.", "danger")
        elif problems:
            flash("New password needs " + ", ".join(problems) + ".", "danger")
        elif new != confirm:
            flash("The two new passwords do not match.", "danger")
        else:
            db.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                       (generate_password_hash(new), uid))
            db.audit("password_changed", None, uid, client_ip())
            flash("Password changed.", "success")
        return redirect(url_for("auth.profile"))

    user = db.query_one("SELECT full_name, email, role, created_at, last_login FROM users WHERE id = %s", (uid,))
    stats = db.query_one(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN r.risk_level IN ('High','Critical') THEN 1 ELSE 0 END) AS risky "
        "FROM scans s JOIN risk_results r ON r.scan_id = s.id WHERE s.user_id = %s", (uid,))
    reports = db.query_one("SELECT COUNT(*) AS n FROM phishing_reports WHERE user_id = %s", (uid,))
    return render_template("auth/profile.html", user=user, stats=stats, report_count=reports["n"])
