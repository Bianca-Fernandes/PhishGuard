# PhishGuard – Phishing Attacks Detection System

BCA Vth Semester Major Project · School of Computer Applications, JECRC University, Jaipur
Bianca Rosy Fernandes (24BCAN0001) · Muskan Raj (24BCAN0303) · Guide: Ms. Mona

PhishGuard is a full-stack web application. A user pastes a suspicious link, and the system checks it in four ways (URL structure, a machine learning model, threat lists, domain details), combines the results into one of five risk levels, and explains the reasons with safety tips.

---

## 1. Setup on Windows (first time)

You need **Python 3.10+**, **MySQL 8** (with MySQL Workbench) and **Git**.

```bat
:: 1. open the project folder in VS Code, then open a terminal (Ctrl + `)
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

:: 2. settings
copy .env.example .env
```

Open `.env` and set `DB_PASSWORD` to your MySQL root password, and set `SECRET_KEY` to a long random value:

```bat
python -c "import secrets; print(secrets.token_hex(32))"
```

**3. Create the database.** Open MySQL Workbench → File → Open SQL Script → `database/schema.sql` → run it (lightning icon). This creates the `phishguard` database and all 8 tables.

**4. Get a dataset and train the model.** Download one of these and put the CSV in `ml_service/data/`:

| Dataset | Where | Columns |
|---|---|---|
| Phishing Site URLs (≈550k URLs) | Kaggle, search "phishing site urls" | `URL`, `Label` (good/bad) |
| Malicious URLs dataset (≈650k URLs) | Kaggle, search "malicious urls dataset" | `url`, `type` → add `--phishing-only` |
| Malicious URL data (≈420k URLs) | github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs → `data/data.csv` | `url`, `label` (good/bad) |

```bat
python ml_service\train_model.py --data ml_service\data\phishing_site_urls.csv
```

This takes about a minute. It trains Logistic Regression, Random Forest and Gradient Boosting, prints the accuracy of each, and saves the best one as `ml_service/models/phishguard_v1.joblib` (+ a `.json` file with all metrics, useful for the report). Running it again creates `v2`, `v3` …

**5. Create the admin account.**

```bat
python scripts\create_admin.py
```

## 2. Running the project

Two programs run together, so use two terminals (or double-click the two `.bat` files):

```bat
:: terminal 1 – ML service (port 5001)
venv\Scripts\activate
python ml_service\service.py

:: terminal 2 – website (port 5000)
venv\Scripts\activate
python run.py
```

Open **http://127.0.0.1:5000**. Log in with the admin account to see the **Admin** menu.

If the ML service is not running, scans still work. The ML check is shown as "unavailable" and its weight is shared between the other checks.

## 3. Running the tests

```bat
python -m pytest -v
```

60 automated tests cover URL validation, the URL rules, look-alike brand detection, ML feature extraction, the risk engine, SSRF protection and the domain checks (with fake RDAP/DNS/TLS answers, so no internet is needed).

---

## 4. Project structure

```
PhishGuard/
├── run.py                       start the website
├── requirements.txt
├── .env.example                 settings template (copy to .env)
├── database/schema.sql          MySQL tables
├── app/
│   ├── __init__.py              Flask app factory, security headers, error pages
│   ├── config.py                reads settings from .env
│   ├── db.py                    MySQL connection + helpers (parameterised queries)
│   ├── security.py              CSRF tokens, login/admin checks, rate limiting
│   ├── routes/
│   │   ├── auth.py              register, login, logout, profile
│   │   ├── scan.py              scan, result, history, report phishing, JSON API
│   │   ├── admin.py             dashboard, reports, blocklist, models, users, audit log
│   │   └── pages.py             awareness, about
│   ├── services/
│   │   ├── validator.py         URL Input & Validation
│   │   ├── url_checks.py        URL Checks (15 rules)
│   │   ├── ml_client.py         talks to the ML service
│   │   ├── threat_intel.py      blocklist, OpenPhish, Google Safe Browsing
│   │   ├── domain_intel.py      RDAP, DNS, TLS + SSRF protection
│   │   ├── risk_engine.py       combines everything into 5 risk levels
│   │   └── scanner.py           runs the whole scan process and saves it
│   ├── templates/               HTML pages (Jinja2)
│   └── static/                  CSS and JavaScript
├── ml_service/
│   ├── service.py               separate Flask service: /predict, /models, /health
│   ├── features.py              35 URL features (same code for training and predicting)
│   ├── train_model.py           trains, compares and versions the model
│   ├── data/                    put your dataset CSV here
│   └── models/                  trained versions are saved here
├── scripts/create_admin.py
└── tests/                       pytest tests
```

## 5. How the modules map to the synopsis

| Synopsis module | Where it is |
|---|---|
| Login & User Management | `routes/auth.py`, `security.py`, admin → Users |
| URL Input & Validation | `services/validator.py` |
| URL Checks | `services/url_checks.py` |
| Machine Learning Detection | `ml_service/` (separate service with versions) + `services/ml_client.py` |
| Threat Intelligence | `services/threat_intel.py` |
| Domain Intelligence | `services/domain_intel.py` |
| Risk Engine | `services/risk_engine.py` |
| Result & Safety Tips | `templates/result.html`, tips in `risk_engine.py` |
| Scan History | `/history`, tables `scans`, `scan_signals`, `risk_results` |
| Awareness & Report Phishing | `/awareness`, `/report`, admin → Reports |

## 6. How the risk score works

1. **Weighted average** of the parts that are available: URL checks 35%, ML probability 40%, domain checks 25%.
2. **Safety floors** so one strong warning is never hidden by the average:
   - found on a threat list or the PhishGuard blocklist → at least 90 (Critical)
   - ML probability ≥ 90% → at least 60 (High)
   - URL checks score ≥ 60 → at least 60 (High)
   - a "danger" signal **and** ML ≥ 75% (two checks agree) → at least 60 (High)
   - any single "danger" signal → at least 40 (Medium)
3. **Levels:** Very Low 0–19 · Low 20–39 · Medium 40–59 · High 60–79 · Critical 80–100. "Very Low" never says "safe".

## 7. Security features

- Passwords hashed (Werkzeug PBKDF2/scrypt), never stored in plain text
- Secrets only in `.env`, which is in `.gitignore`
- CSRF token on every form, parameterised SQL everywhere (no SQL injection)
- Role-based access: users only see their own scans; admin pages need the admin role
- Session ID renewed at login, HttpOnly and SameSite cookies, 4-hour session lifetime
- Login rate limit (10 attempts / 5 min) and scan rate limit (20 / min)
- Same error for wrong email or wrong password (no account guessing)
- **SSRF protection:** before connecting to a site for the TLS/DNS checks, its address is resolved and private, loopback and cloud-metadata addresses (e.g. 192.168.x.x, 127.0.0.1, 169.254.169.254) are refused
- Content-Security-Policy, X-Frame-Options and nosniff headers; all page output auto-escaped by Jinja2
- Audit log of logins, failed logins, report reviews and blocklist changes

## 8. Optional: Google Safe Browsing

Get a free API key from the Google Cloud Console (enable "Safe Browsing API") and put it in `.env` as `GOOGLE_SAFE_BROWSING_KEY`. Without a key this check is simply skipped.

## 9. Future scope

Email (.eml) checking, QR code checking, a browser extension using the `/api/scan` endpoint, retraining the model automatically from confirmed reports, and page-content analysis in a sandbox.
