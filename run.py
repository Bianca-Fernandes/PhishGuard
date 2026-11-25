"""
Start the PhishGuard web application.
    python run.py        ->  http://127.0.0.1:5000
Start the ML service in a second terminal first:
    python ml_service/service.py
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=debug)
