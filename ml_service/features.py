"""
URL feature extraction for the phishing model.

The SAME function is used when training the model and when predicting,
so the model always sees features in the same form.

Important: many public phishing datasets store URLs without "http://"
and some store them with it. To stop the model from learning
"has http:// = phishing" by accident, the scheme and a leading "www."
are removed before features are calculated.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

SUSPICIOUS_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "security", "banking", "confirm", "password", "wallet",
    "webscr", "ebayisapi", "suspend", "unlock", "billing", "invoice", "kyc",
    "reward", "bonus", "free", "gift", "lucky", "prize", "otp", "recover",
)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country",
    "work", "loan", "men", "kim", "review", "party", "racing", "date", "science",
    "stream", "download", "cam", "rest", "fit", "buzz", "monster", "cyou", "icu",
    "sbs", "cfd", "quest", "support", "live", "online", "site", "info",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy", "s.id", "t.ly",
    "v.gd", "bitly.com", "lnkd.in", "shorte.st", "adf.ly", "qr.ae", "trib.al",
}

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_at", "num_question", "num_equals", "num_ampersand",
    "num_percent", "num_tilde", "num_digits", "num_params",
    "digit_ratio", "letter_ratio", "special_ratio",
    "num_subdomains", "host_has_digits", "host_hyphens",
    "is_ip", "has_port", "is_punycode", "is_shortener",
    "suspicious_tld", "suspicious_word_count", "path_depth",
    "has_double_slash_in_path", "host_entropy", "url_entropy",
    "longest_token", "has_php_or_html", "tld_length",
]


def _strip(url: str) -> str:
    url = (url or "").strip().lower()
    url = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", url)
    url = re.sub(r"^www\d?\.", "", url)
    return url


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        # also catch hex / decimal tricks like 0x7f000001
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def extract_features(url: str) -> list[float]:
    s = _strip(url)
    try:
        parts = urlsplit("http://" + s)
        host = (parts.hostname or "")
        path = parts.path or ""
        query = parts.query or ""
        try:
            has_port = 1 if parts.port else 0
        except ValueError:
            has_port = 1
    except ValueError:
        host, path, query, has_port = s.split("/")[0], "", "", 0

    n = max(len(s), 1)
    digits = sum(ch.isdigit() for ch in s)
    letters = sum(ch.isalpha() for ch in s)
    special = n - digits - letters
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if labels else ""
    is_ip = _is_ip(host)
    tokens = [t for t in re.split(r"[/\.\-_?=&]", s) if t]

    feats = {
        "url_length": len(s),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": s.count("."),
        "num_hyphens": s.count("-"),
        "num_underscores": s.count("_"),
        "num_slashes": s.count("/"),
        "num_at": s.count("@"),
        "num_question": s.count("?"),
        "num_equals": s.count("="),
        "num_ampersand": s.count("&"),
        "num_percent": s.count("%"),
        "num_tilde": s.count("~"),
        "num_digits": digits,
        "num_params": len([q for q in query.split("&") if q]),
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "special_ratio": special / n,
        "num_subdomains": 0 if is_ip else max(len(labels) - 2, 0),
        "host_has_digits": int(any(ch.isdigit() for ch in host)) if not is_ip else 0,
        "host_hyphens": host.count("-"),
        "is_ip": int(is_ip),
        "has_port": has_port,
        "is_punycode": int("xn--" in host),
        "is_shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "suspicious_word_count": sum(w in s for w in SUSPICIOUS_WORDS),
        "path_depth": len([p for p in path.split("/") if p]),
        "has_double_slash_in_path": int("//" in path),
        "host_entropy": _entropy(host),
        "url_entropy": _entropy(s),
        "longest_token": max((len(t) for t in tokens), default=0),
        "has_php_or_html": int(bool(re.search(r"\.(php|html?|asp|aspx|jsp)\b", path))),
        "tld_length": len(tld),
    }
    return [float(feats[name]) for name in FEATURE_NAMES]
