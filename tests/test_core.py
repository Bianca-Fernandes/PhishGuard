"""
Unit tests for the parts that do not need MySQL or the internet.
Run:  python -m pytest -v
"""
import pytest

from app.services.domain_intel import is_public_ip
from app.services.risk_engine import assess, level_for
from app.services.signals import Signal
from app.services.url_checks import check_url, url_score
from app.services.validator import ValidationError, clean_url
from features import FEATURE_NAMES, extract_features


# ------------------------------------------------------------ validation
class TestValidator:
    def test_adds_scheme(self):
        u = clean_url("example.com/login")
        assert u.normalized == "http://example.com/login"
        assert u.scheme_added

    def test_lowercases_host_and_drops_fragment(self):
        u = clean_url("  HTTPS://Example.COM/Path?a=1#top  ")
        assert u.normalized == "https://example.com/Path?a=1"

    def test_registered_domain(self):
        u = clean_url("https://login.paypal.com.secure-check.co.uk/a")
        assert u.registered_domain == "secure-check.co.uk"
        assert u.subdomain == "login.paypal.com"

    def test_defanged(self):
        assert clean_url("hxxp://evil[.]com/x").normalized == "http://evil.com/x"

    @pytest.mark.parametrize("bad", [
        "", "   ", "javascript:alert(1)", "ftp://files.example.com", "data:text/html,hi",
        "file:///etc/passwd", "http://", "notaurl", "http://exa!mple.com", "http://ex\\ample.com",
    ])
    def test_rejects(self, bad):
        with pytest.raises(ValidationError):
            clean_url(bad)

    def test_too_long(self):
        with pytest.raises(ValidationError):
            clean_url("http://a.com/" + "x" * 3000)

    def test_ip_host(self):
        u = clean_url("http://192.168.1.10/admin")
        assert u.is_ip and u.registered_domain == "192.168.1.10"

    def test_punycode(self):
        u = clean_url("http://аpple.com")  # first letter is Cyrillic
        assert u.host.startswith("xn--")

    def test_port_kept(self):
        assert clean_url("http://example.com:8080/").port == 8080
        assert clean_url("https://example.com:443/").port is None


# ------------------------------------------------------------ URL checks
def names(signals):
    return {s.name for s in signals}


class TestUrlChecks:
    def test_clean_url_is_quiet(self):
        sig = check_url(clean_url("https://www.wikipedia.org/"))
        assert url_score(sig) == 0

    def test_ip_address(self):
        assert "IP address used" in names(check_url(clean_url("http://45.12.8.9/login")))

    def test_brand_misuse(self):
        sig = check_url(clean_url("http://paypal-secure-login.xyz/verify"))
        assert "Brand name misuse" in names(sig)
        assert url_score(sig) >= 40

    def test_real_brand_not_flagged(self):
        assert "Brand name misuse" not in names(check_url(clean_url("https://www.paypal.com/signin")))

    def test_no_false_brand_inside_word(self):
        assert "Brand name misuse" not in names(check_url(clean_url("https://pineapple-recipes.com/")))

    def test_at_symbol(self):
        assert "@ symbol in URL" in names(check_url(clean_url("http://google.com@evil.tk/")))

    def test_shortener(self):
        assert "Shortened link" in names(check_url(clean_url("https://bit.ly/3abc")))

    def test_score_capped(self):
        sig = check_url(clean_url(
            "http://paypal.com.login.verify-account.secure-update.tk:8080//signin?redirect=http://x.com&a=%20%20%20%20%20"))
        assert url_score(sig) == 100


# --------------------------------------------------------- ML features
class TestFeatures:
    def test_length_matches_names(self):
        assert len(extract_features("http://example.com")) == len(FEATURE_NAMES)

    def test_scheme_and_www_ignored(self):
        a = extract_features("https://www.example.com/a")
        b = extract_features("example.com/a")
        assert a == b

    def test_ip_feature(self):
        f = dict(zip(FEATURE_NAMES, extract_features("http://10.0.0.1/x")))
        assert f["is_ip"] == 1

    def test_handles_garbage(self):
        assert len(extract_features("::::[[]]")) == len(FEATURE_NAMES)


# ---------------------------------------------------------- risk engine
class TestRiskEngine:
    def test_levels(self):
        assert level_for(0) == "Very Low"
        assert level_for(25) == "Low"
        assert level_for(45) == "Medium"
        assert level_for(65) == "High"
        assert level_for(85) == "Critical"

    def test_threat_hit_is_critical(self):
        r = assess([], url_score=0, ml_probability=0.05, domain_score=0, threat_hit=True)
        assert r.level == "Critical" and r.score >= 90

    def test_ml_unavailable_reweights(self):
        r = assess([], url_score=50, ml_probability=None, domain_score=50, threat_hit=False)
        assert r.score == 50

    def test_high_ml_floor(self):
        r = assess([], url_score=0, ml_probability=0.95, domain_score=0, threat_hit=False)
        assert r.level == "High"

    def test_danger_floor(self):
        s = [Signal("url", "IP address used", "danger", 25, "x")]
        r = assess(s, url_score=25, ml_probability=0.1, domain_score=0, threat_hit=False)
        assert r.score >= 40

    def test_clean_is_very_low_never_safe(self):
        r = assess([], url_score=0, ml_probability=0.02, domain_score=0, threat_hit=False)
        assert r.level == "Very Low"
        assert "not a guarantee" in r.summary


# ------------------------------------------------------------ SSRF guard
@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.0.5", False),
    ("169.254.169.254", False), ("::1", False), ("0.0.0.0", False), ("::ffff:127.0.0.1", False),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_spaces_from_wrapped_messages_removed():
    assert clean_url("http://exa mple.com/lo gin").normalized == "http://example.com/login"


@pytest.mark.parametrize("url", ["http://amaz0n-prize.top/", "http://paypai.com/login",
                                 "http://rnicrosoft-support.com/", "http://faceb00k-login.net/"])
def test_lookalike_brands(url):
    assert "Look-alike brand name" in names(check_url(clean_url(url)))


@pytest.mark.parametrize("url", ["https://www.amazon.in/", "https://www.netflix.com/", "https://applied-maths.org/",
                                 "https://www.goodreads.com/", "https://www.google.co.in/search?q=x"])
def test_no_lookalike_false_alarm(url):
    sig = names(check_url(clean_url(url)))
    assert "Look-alike brand name" not in sig and "Brand name misuse" not in sig


def test_danger_plus_ml_is_high():
    s = [Signal("url", "Look-alike brand name", "danger", 25, "x")]
    assert assess(s, url_score=40, ml_probability=0.8, domain_score=0, threat_hit=False).level == "High"
