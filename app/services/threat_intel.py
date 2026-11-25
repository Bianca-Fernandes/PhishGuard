"""
Module: Threat Intelligence

Checks the link against lists of known bad websites:
  1. PhishGuard's own blocklist (reports confirmed by an admin)
  2. OpenPhish community feed (free, no key, refreshed every 30 minutes)
  3. Google Safe Browsing (optional, needs a free API key in .env)

If an outside service is not reachable it is skipped and marked unavailable.
"""
import threading
import time

import requests
from flask import current_app

from .. import db
from .signals import Signal
from .validator import CleanURL

_feed = {"urls": set(), "hosts": set(), "loaded_at": 0.0, "ok": False}
_feed_lock = threading.Lock()
FEED_TTL = 30 * 60


def _openphish():
    cfg = current_app.config
    with _feed_lock:
        if time.time() - _feed["loaded_at"] > FEED_TTL:
            try:
                r = requests.get(cfg["OPENPHISH_FEED_URL"], timeout=cfg["NETWORK_TIMEOUT"])
                r.raise_for_status()
                urls = {line.strip().lower().rstrip("/") for line in r.text.splitlines() if line.strip()}
                hosts = set()
                for line in urls:
                    h = line.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
                    hosts.add(h)
                _feed.update(urls=urls, hosts=hosts, ok=True)
            except Exception as exc:
                current_app.logger.warning("OpenPhish feed failed: %s", exc)
                _feed["ok"] = bool(_feed["urls"])  # keep old copy if we had one
            _feed["loaded_at"] = time.time()
        return dict(_feed)


def _google_safe_browsing(url):
    key = current_app.config["GOOGLE_SAFE_BROWSING_KEY"]
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
        json=body, timeout=current_app.config["NETWORK_TIMEOUT"])
    r.raise_for_status()
    return r.json().get("matches", [])


def check_threats(u: CleanURL):
    """Returns (threat_hit: bool, list[Signal])."""
    signals = []
    hit = False

    # 1. Local blocklist
    try:
        row = db.query_one("SELECT domain FROM blocklist WHERE domain IN (%s, %s)",
                           (u.host, u.registered_domain))
    except Exception:
        row = None
    if row:
        hit = True
        signals.append(Signal("threat", "PhishGuard blocklist", "danger", 0,
                              f"'{row['domain']}' was reported by users and confirmed as phishing by our team."))
    else:
        signals.append(Signal("threat", "PhishGuard blocklist", "ok", 0,
                              "Not found in PhishGuard's confirmed phishing reports."))

    # 2. OpenPhish
    if current_app.config["ENABLE_OPENPHISH"]:
        feed = _openphish()
        if not feed["ok"]:
            signals.append(Signal("threat", "OpenPhish feed", "unavailable", 0,
                                  "The OpenPhish list could not be downloaded right now."))
        else:
            key = u.normalized.lower().rstrip("/")
            if key in feed["urls"]:
                hit = True
                signals.append(Signal("threat", "OpenPhish feed", "danger", 0,
                                      "This exact link is on the OpenPhish list of active phishing sites."))
            elif u.host in feed["hosts"]:
                hit = True
                signals.append(Signal("threat", "OpenPhish feed", "danger", 0,
                                      f"The website '{u.host}' is on the OpenPhish list of active phishing sites."))
            else:
                signals.append(Signal("threat", "OpenPhish feed", "ok", 0,
                                      f"Not found among {len(feed['urls'])} active phishing links."))

    # 3. Google Safe Browsing
    if current_app.config["GOOGLE_SAFE_BROWSING_KEY"]:
        try:
            matches = _google_safe_browsing(u.normalized)
            if matches:
                hit = True
                kinds = sorted({m.get("threatType", "").replace("_", " ").lower() for m in matches})
                signals.append(Signal("threat", "Google Safe Browsing", "danger", 0,
                                      "Google lists this link as dangerous (" + ", ".join(kinds) + ")."))
            else:
                signals.append(Signal("threat", "Google Safe Browsing", "ok", 0,
                                      "Not on Google's list of dangerous sites."))
        except Exception as exc:
            current_app.logger.warning("Safe Browsing failed: %s", exc)
            signals.append(Signal("threat", "Google Safe Browsing", "unavailable", 0,
                                  "Google Safe Browsing could not be reached."))
    return hit, signals
