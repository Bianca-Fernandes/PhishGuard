"""
Security helpers: CSRF protection, login checks and simple rate limiting.
"""
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, flash, redirect, request, session, url_for


# ------------------------------------------------------------------ CSRF
def get_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def verify_csrf():
    """Every POST form must send back the token stored in the session."""
    if request.method != "POST":
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not expected or not secrets.compare_digest(sent, expected):
        abort(400, description="Invalid or missing form token. Please reload the page and try again.")


# --------------------------------------------------------- access control
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------- rate limiting
_hits = defaultdict(deque)


def rate_limited(key, limit, window_seconds):
    """Return True if this key has made more than `limit` calls in the window."""
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > window_seconds:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def client_ip():
    # X-Forwarded-For is not trusted because any client can fake it.
    return request.remote_addr or ""
