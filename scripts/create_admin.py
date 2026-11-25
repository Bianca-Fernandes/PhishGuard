"""
Create an admin account (or turn an existing user into an admin).

    python scripts/create_admin.py
"""
import getpass
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from werkzeug.security import generate_password_hash  # noqa: E402

from app import create_app, db  # noqa: E402
from app.routes.auth import EMAIL_RE, password_problems  # noqa: E402


def main():
    app = create_app()
    with app.app_context():
        name = os.getenv("ADMIN_NAME") or input("Admin full name: ").strip()
        email = (os.getenv("ADMIN_EMAIL") or input("Admin email: ")).strip().lower()
        if not EMAIL_RE.match(email):
            sys.exit("That email address is not valid.")

        existing = db.query_one("SELECT id FROM users WHERE email = %s", (email,))
        if existing:
            db.execute("UPDATE users SET role = 'admin', is_active = 1 WHERE id = %s", (existing["id"],))
            print(f"{email} is now an admin.")
            return

        password = os.getenv("ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
        problems = password_problems(password)
        if problems:
            sys.exit("Password needs " + ", ".join(problems) + ".")
        db.execute("INSERT INTO users (full_name, email, password_hash, role) VALUES (%s, %s, %s, 'admin')",
                   (name or "Administrator", email, generate_password_hash(password)))
        print(f"Admin account created for {email}.")


if __name__ == "__main__":
    main()
