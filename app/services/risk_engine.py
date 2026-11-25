"""
Module: Risk Engine

Combines all signals into one risk score (0-100) and one of five levels:
    Very Low  (0-19)   Low (20-39)   Medium (40-59)   High (60-79)   Critical (80-100)

How the score is made
  1. Weighted average of the three scores that are available:
        URL checks   35%     ML probability  40%     Domain checks  25%
     If a part is unavailable (e.g. ML service down), its weight is shared
     between the others.
  2. Safety floors, so one very strong warning is never hidden by the average:
        * listed on a threat list ............ at least 90  (Critical)
        * ML probability >= 0.90 ............. at least 60  (High)
        * URL checks score >= 60 ............. at least 60  (High)
        * any single "danger" signal ......... at least 40  (Medium)
        * a "danger" URL/domain signal AND
          ML probability >= 0.75 ............. at least 60  (High)
  3. The result is a risk, never a guarantee. Even "Very Low" tells the
     user to stay careful.
"""
from dataclasses import dataclass, field

WEIGHTS = {"url": 0.35, "ml": 0.40, "domain": 0.25}

LEVELS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Very Low"),
]

SUMMARIES = {
    "Critical": "This link is very likely a phishing or dangerous website. Do not open it and do not enter any details.",
    "High": "This link shows strong signs of phishing. Avoid it unless you can confirm it is real through another way.",
    "Medium": "This link has some warning signs. Be careful and do not enter passwords, OTPs or bank details.",
    "Low": "Only small warning signs were found. It is probably fine, but still check the website before logging in.",
    "Very Low": "No strong warning signs were found. This is not a guarantee: stay alert before sharing personal details.",
}

TIPS = {
    "Critical": [
        "Do not click the link or enter any information on that page.",
        "If you already entered a password, change it now and turn on two-factor authentication.",
        "If you shared bank or card details, call your bank immediately and block the card.",
        "In India, report financial fraud at cybercrime.gov.in or call the helpline 1930.",
        "Use the 'Report Phishing' page so other PhishGuard users are protected.",
    ],
    "High": [
        "Do not log in or make any payment through this link.",
        "Open the official website by typing its address yourself or using the official app.",
        "Contact the company using the phone number on their official website, not the one in the message.",
        "Report the message as spam/phishing in your email, SMS or WhatsApp app.",
    ],
    "Medium": [
        "Check the website name letter by letter before typing anything.",
        "Never share OTPs, PINs or CVV numbers. No real bank or company asks for them.",
        "If the message creates panic or urgency (\"account blocked today\"), treat it as suspicious.",
        "When unsure, go to the official website directly instead of using the link.",
    ],
    "Low": [
        "Make sure the address bar shows the website you expect before logging in.",
        "Be careful with links that come from unknown senders.",
        "Keep your browser and phone updated.",
    ],
    "Very Low": [
        "No tool can promise a link is 100% safe. Phishing sites appear every minute.",
        "Still check the address bar before entering passwords or payment details.",
        "Turn on two-factor authentication for important accounts.",
    ],
}


@dataclass
class RiskResult:
    score: int
    level: str
    summary: str
    tips: list = field(default_factory=list)
    url_score: int | None = None
    ml_probability: float | None = None
    domain_score: int | None = None
    threat_hit: bool = False
    reasons: list = field(default_factory=list)   # top reasons shown first


def level_for(score: int) -> str:
    for minimum, name in LEVELS:
        if score >= minimum:
            return name
    return "Very Low"


def assess(signals, url_score, ml_probability, domain_score, threat_hit, domain_checked=True):
    parts = {"url": url_score}
    if ml_probability is not None:
        parts["ml"] = ml_probability * 100
    if domain_checked and domain_score is not None:
        parts["domain"] = domain_score

    total_weight = sum(WEIGHTS[k] for k in parts)
    score = sum(WEIGHTS[k] * v for k, v in parts.items()) / total_weight

    has_danger = any(s.status == "danger" for s in signals if s.source in ("url", "domain"))
    if has_danger:
        score = max(score, 40)
        if ml_probability is not None and ml_probability >= 0.75:
            score = max(score, 60)   # two independent checks agree
    if url_score >= 60:
        score = max(score, 60)
    if ml_probability is not None and ml_probability >= 0.90:
        score = max(score, 60)
    if threat_hit:
        score = max(score, 90)

    score = int(round(min(score, 100)))
    level = level_for(score)

    # most important reasons first: threat hits, then by points
    order = {"danger": 0, "warning": 1, "info": 2, "ok": 3, "unavailable": 4}
    reasons = sorted(
        (s for s in signals if s.status in ("danger", "warning")),
        key=lambda s: (s.source != "threat", order[s.status], -s.points),
    )[:5]

    return RiskResult(
        score=score,
        level=level,
        summary=SUMMARIES[level],
        tips=TIPS[level],
        url_score=url_score,
        ml_probability=ml_probability,
        domain_score=domain_score if domain_checked else None,
        threat_hit=threat_hit,
        reasons=reasons,
    )
