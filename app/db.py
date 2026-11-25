"""
Database helper for MySQL.

Every query uses parameters (%s) so user input is never joined into SQL
text. This protects against SQL injection.
"""
import mysql.connector
from flask import current_app, g


def get_db():
    """Open one MySQL connection per request and reuse it."""
    if "db" not in g:
        cfg = current_app.config
        g.db = mysql.connector.connect(
            host=cfg["DB_HOST"],
            port=cfg["DB_PORT"],
            user=cfg["DB_USER"],
            password=cfg["DB_PASSWORD"],
            database=cfg["DB_NAME"],
            autocommit=False,
        )
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            if exc is not None:
                db.rollback()
        finally:
            db.close()


def query_all(sql, params=()):
    cur = get_db().cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        cur.close()


def query_one(sql, params=()):
    cur = get_db().cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        row = cur.fetchone()
        cur.fetchall()  # clear any remaining rows
        return row
    finally:
        cur.close()


def execute(sql, params=(), commit=True):
    """Run INSERT / UPDATE / DELETE. Returns the new row id for inserts."""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(sql, params)
        if commit:
            db.commit()
        return cur.lastrowid
    finally:
        cur.close()


def commit():
    get_db().commit()


def rollback():
    get_db().rollback()


def audit(action, detail=None, user_id=None, ip=None):
    """Write an entry to the audit log. Never breaks the main request."""
    try:
        execute(
            "INSERT INTO audit_log (user_id, action, detail, ip_address) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, action, (detail or "")[:500], ip),
        )
    except Exception:  # pragma: no cover - logging must not crash the app
        current_app.logger.exception("audit log failed")


def init_app(app):
    app.teardown_appcontext(close_db)
