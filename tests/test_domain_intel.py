"""Domain intelligence tests with RDAP, DNS and TLS replaced by fake answers."""
from datetime import datetime, timedelta, timezone

import dns.resolver
import pytest

from app import create_app
from app.config import Config
from app.services import domain_intel as di
from app.services.validator import clean_url


class TestConfig(Config):
    TESTING = True


class FakeAnswer(list):
    pass


class FakeResolver:
    records = {}

    def __init__(self):
        self.lifetime = 1

    def resolve(self, name, rtype):
        key = (name, rtype)
        if key in self.records:
            val = self.records[key]
            if isinstance(val, Exception):
                raise val
            return FakeAnswer(type("R", (), {"to_text": lambda self, v=v: v})() for v in val)
        if name in ("example.com", "google.com"):
            return FakeAnswer([type("R", (), {"to_text": lambda self: "93.184.215.14"})()])
        raise dns.resolver.NXDOMAIN()


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(di.dns.resolver, "Resolver", FakeResolver)
    monkeypatch.setattr(di, "_dns_health", {"ok": None, "checked": 0.0})
    monkeypatch.setattr(di, "resolve_public", lambda host, port=443: ["93.184.215.14"])
    a = create_app(TestConfig)
    with a.app_context():
        yield a


def now_minus(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def by_name(signals):
    return {s.name: s for s in signals}


def test_new_domain_is_flagged(app, monkeypatch):
    FakeResolver.records = {("new-bank-login.com", "A"): ["93.184.215.14"],
                            ("new-bank-login.com", "MX"): dns.resolver.NoAnswer()}
    monkeypatch.setattr(di, "_rdap", lambda d, t: {"created": now_minus(5), "registrar": "Cheap Names"})
    monkeypatch.setattr(di, "_tls_info", lambda h, ip, p, t: {
        "issuer": "Let's Encrypt", "not_before": datetime.now(timezone.utc) - timedelta(days=2),
        "not_after": datetime.now(timezone.utc) + timedelta(days=88)})
    s = by_name(di.check_domain(clean_url("https://new-bank-login.com/")))
    assert s["Domain age"].status == "danger" and s["Domain age"].points == 25
    assert s["DNS records"].status == "ok"
    assert s["Mail server"].status == "info"
    assert s["TLS certificate"].status == "info"  # brand-new certificate


def test_old_domain_is_ok(app, monkeypatch):
    FakeResolver.records = {("www.old-company.com", "A"): ["93.184.215.14"],
                            ("old-company.com", "MX"): ["mx1"]}
    monkeypatch.setattr(di, "_rdap", lambda d, t: {"created": now_minus(4000)})
    monkeypatch.setattr(di, "_tls_info", lambda h, ip, p, t: {
        "issuer": "DigiCert", "not_before": datetime.now(timezone.utc) - timedelta(days=60),
        "not_after": datetime.now(timezone.utc) + timedelta(days=200)})
    sig = di.check_domain(clean_url("https://www.old-company.com/"))
    assert di.domain_score(sig) == 0
    assert all(x.status == "ok" for x in sig)


def test_dns_pointing_inside_is_blocked(app, monkeypatch):
    FakeResolver.records = {("sneaky.example.org", "A"): ["10.0.0.5"]}
    monkeypatch.setattr(di, "_rdap", lambda d, t: {"created": now_minus(900)})
    called = []
    monkeypatch.setattr(di, "_tls_info", lambda *a: called.append(1))
    s = by_name(di.check_domain(clean_url("http://sneaky.example.org/")))
    assert s["Internal address"].status == "danger"
    assert not called  # never connected


def test_broken_dns_is_not_blamed_on_site(app, monkeypatch):
    class DeadResolver(FakeResolver):
        def resolve(self, name, rtype):
            raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(di.dns.resolver, "Resolver", DeadResolver)
    monkeypatch.setattr(di, "_rdap", lambda d, t: (_ for _ in ()).throw(OSError("offline")))
    sig = di.check_domain(clean_url("https://www.google.com/"))
    assert di.domain_score(sig) == 0
    assert {x.status for x in sig} == {"unavailable"}


def test_nonexistent_domain(app, monkeypatch):
    FakeResolver.records = {}
    monkeypatch.setattr(di, "_rdap", lambda d, t: {"not_found": True})
    s = by_name(di.check_domain(clean_url("http://no-such-site-abc123.com/")))
    assert s["DNS records"].points == 15
    assert s["Domain registration"].points == 15
