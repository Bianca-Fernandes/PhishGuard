"""
Module: URL Checks

Rule-based checks on the URL text itself. Each rule gives points and a
reason in simple words so the user can learn what to look for.
No network request is made here.
"""
import re

from .signals import Signal
from .validator import CleanURL

# keep these in step with ml_service/features.py
SUSPICIOUS_WORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "banking", "confirm", "password", "wallet", "suspend", "unlock",
    "billing", "kyc", "reward", "prize", "otp", "recover",
)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country",
    "work", "loan", "men", "kim", "review", "party", "racing", "date", "cam",
    "rest", "buzz", "monster", "cyou", "icu", "sbs", "cfd", "quest",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy", "s.id", "t.ly",
    "v.gd", "bitly.com", "shorte.st", "adf.ly",
}

# brand -> its real registered domains
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au",
               "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es", "amazon.ae", "amazon.com.br",
               "amazonaws.com"},
    "google": {"google.com", "google.co.in", "youtube.com", "gmail.com", "googleusercontent.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfcbank.bank.in"},
    "icici": {"icicibank.com", "icici.bank.in"},
    "axisbank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com", "dhl.de"},
}


LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})


def _unconfuse(token: str) -> str:
    """amaz0n -> amazon, rnicrosoft -> microsoft, paypa1 -> paypal"""
    return token.translate(LOOKALIKE).replace("rn", "m").replace("vv", "w")


def _one_edit_away(a: str, b: str) -> bool:
    """True if a and b differ by one added, removed or changed letter (gooogle, paypai)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    return any(a == b[:i] + b[i + 1:] for i in range(len(b)))


def check_url(u: CleanURL) -> list[Signal]:
    s: list[Signal] = []
    full = u.normalized.lower()
    host = u.host

    # 1. IP address instead of a name
    if u.is_ip:
        s.append(Signal("url", "IP address used", "danger", 25,
                        "The link uses a number (IP address) instead of a website name. "
                        "Real companies almost never do this."))

    # 2. HTTPS
    if u.scheme == "http" and not u.scheme_added:
        s.append(Signal("url", "No HTTPS", "warning", 8,
                        "The link is not encrypted (http://). Never enter passwords on such a page."))

    # 3. Length
    if len(full) > 100:
        s.append(Signal("url", "Very long URL", "warning", 10,
                        f"The URL is {len(full)} characters long. Long links are often used to hide the real website."))
    elif len(full) > 75:
        s.append(Signal("url", "Long URL", "info", 5,
                        f"The URL is {len(full)} characters long."))

    # 4. @ symbol
    if "@" in u.original and "@" in (u.original.split("?")[0]):
        s.append(Signal("url", "@ symbol in URL", "danger", 20,
                        "Everything before an @ in a link is ignored by the browser. "
                        "Attackers use it to make a link look like a trusted site."))

    # 5. Sub-domains
    dots = host.count(".")
    if not u.is_ip and dots >= 4:
        s.append(Signal("url", "Too many sub-domains", "warning", 12,
                        f"The website name has {dots + 1} parts ({host}). "
                        "Extra parts are used to push the real domain out of sight."))
    elif not u.is_ip and dots == 3:
        s.append(Signal("url", "Several sub-domains", "info", 5,
                        f"The website name has {dots + 1} parts."))

    # 6. Hyphens in the domain
    if not u.is_ip and u.registered_domain.count("-") >= 2:
        s.append(Signal("url", "Many hyphens in domain", "warning", 8,
                        f"'{u.registered_domain}' has several hyphens, a common trick in fake domains."))
    elif not u.is_ip and "-" in u.registered_domain:
        s.append(Signal("url", "Hyphen in domain", "info", 3,
                        f"'{u.registered_domain}' contains a hyphen."))

    # 7. Suspicious words
    found = [w for w in SUSPICIOUS_WORDS if w in full]
    if found:
        pts = min(5 * len(found), 15)
        s.append(Signal("url", "Suspicious words", "warning", pts,
                        "The link contains words often used in phishing: " + ", ".join(found[:6]) + "."))

    # 8. Brand name in the wrong place
    reg = u.registered_domain
    host_tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    path_tokens = set(re.split(r"[^a-z0-9]+", (u.path + "?" + u.query).lower()))
    for brand, real_domains in BRANDS.items():
        in_host = any(t == brand or t.startswith(brand) for t in host_tokens)
        in_path = brand in path_tokens
        if in_host and reg not in real_domains:
            s.append(Signal("url", "Brand name misuse", "danger", 25,
                            f"The website name contains '{brand}', but the real website is '{reg}', "
                            f"which is not an official {brand} domain."))
            break
        if in_path and reg not in real_domains:
            s.append(Signal("url", "Brand name in link path", "warning", 10,
                            f"The link mentions '{brand}' after the website name, but the real website "
                            f"is '{reg}'. Check that you are on the official {brand} site."))
            break
    else:
        # 8b. Look-alike spelling of a brand (amaz0n, paypai, rnicrosoft)
        for t in host_tokens:
            fixed = _unconfuse(t)
            for brand, real_domains in BRANDS.items():
                if reg in real_domains or len(brand) < 5:
                    continue
                if (fixed != t and (fixed == brand or fixed.startswith(brand))) or (len(brand) >= 6 and _one_edit_away(t, brand)):
                    s.append(Signal("url", "Look-alike brand name", "danger", 25,
                                    f"'{t}' looks like '{brand}' but is spelled differently. "
                                    "This is a common trick to copy a famous brand."))
                    break
            else:
                continue
            break

    # 9. Punycode / look-alike letters
    if "xn--" in host:
        s.append(Signal("url", "Look-alike characters", "danger", 18,
                        f"The website name uses special letters ({u.host_unicode}) that can look like "
                        "normal English letters. This is used to copy real brand names."))

    # 10. Risky TLD
    if u.suffix and u.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        s.append(Signal("url", "Risky domain ending", "warning", 10,
                        f"Domains ending in .{u.suffix} are cheap or free and are used a lot for phishing."))

    # 11. Shortener
    if host in SHORTENERS or reg in SHORTENERS:
        s.append(Signal("url", "Shortened link", "warning", 10,
                        "This is a short link. It hides the real website you will be sent to."))

    # 12. Unusual port
    if u.port:
        s.append(Signal("url", "Unusual port", "warning", 10,
                        f"The link uses port {u.port}. Normal websites do not need this."))

    # 13. Redirect tricks
    if "//" in u.path or re.search(r"[?&](url|redirect|next|goto|dest|target)=https?", full):
        s.append(Signal("url", "Hidden redirect", "warning", 8,
                        "The link contains another link inside it, which can send you somewhere else."))

    # 14. Many digits in the domain
    digits = sum(ch.isdigit() for ch in reg)
    if not u.is_ip and digits >= 4:
        s.append(Signal("url", "Many numbers in domain", "info", 5,
                        f"'{reg}' contains a lot of numbers."))

    # 15. Heavy encoding
    if full.count("%") >= 5:
        s.append(Signal("url", "Encoded characters", "info", 5,
                        "The link has many encoded characters (%xx), which can hide its real content."))

    if not s:
        s.append(Signal("url", "URL structure", "ok", 0,
                        "No suspicious patterns were found in the URL text."))
    return s


def url_score(signals: list[Signal]) -> int:
    return min(sum(x.points for x in signals if x.source == "url"), 100)
