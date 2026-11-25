"""
PhishGuard - Phishing Attacks Detection System
Flask application factory.
"""
from flask import Flask, render_template, session

from . import db
from .config import Config
from .security import get_csrf_token, verify_csrf


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    if app.config["SECRET_KEY"] == "change-this-secret-key" and not app.config.get("TESTING"):
        app.logger.warning("SECRET_KEY is the default value. Set a long random SECRET_KEY in .env")

    db.init_app(app)

    from .routes.admin import bp as admin_bp
    from .routes.auth import bp as auth_bp
    from .routes.pages import bp as pages_bp
    from .routes.scan import bp as scan_bp
    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)

    app.before_request(verify_csrf)

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": get_csrf_token,
            "current_user": {
                "id": session.get("user_id"),
                "name": session.get("user_name"),
                "role": session.get("role"),
            },
        }

    @app.template_filter("pct")
    def pct(value):
        return "-" if value is None else f"{float(value) * 100:.0f}%"

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        return resp

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, title="Bad request",
                               message=getattr(e, "description", "")), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, title="Access denied",
                               message="You do not have permission to open this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, title="Page not found",
                               message="The page you are looking for does not exist."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500, title="Something went wrong",
                               message="Please try again in a moment."), 500

    return app
