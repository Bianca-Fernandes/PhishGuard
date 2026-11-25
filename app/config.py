"""
Application settings.
All secrets (database password, API keys, secret key) are read from
environment variables / the .env file and are never written in the code.
"""
import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _bool(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")

    # --- MySQL ---
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "phishguard")

    # --- Machine learning service ---
    ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://127.0.0.1:5001")
    ML_TIMEOUT = float(os.getenv("ML_TIMEOUT", "5"))

    # --- Threat intelligence (all optional) ---
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    OPENPHISH_FEED_URL = os.getenv(
        "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
    ENABLE_OPENPHISH = _bool("ENABLE_OPENPHISH", "true")

    # --- Domain intelligence ---
    ENABLE_DOMAIN_INTEL = _bool("ENABLE_DOMAIN_INTEL", "true")
    NETWORK_TIMEOUT = float(os.getenv("NETWORK_TIMEOUT", "5"))

    # --- Session cookie security ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", "false")  # true when on HTTPS
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 4  # 4 hours

    TESTING = False
