"""
Module: Domain Intelligence

Collects details about the website's domain:
  * Registration date from RDAP (the modern replacement for WHOIS)
  * DNS records (A / MX)
  * TLS certificate (issuer, validity, expiry)

SSRF protection: before PhishGuard connects to any website, the name is
resolved and the connection is refused if it points to a private,
loopback or other internal address. This stops someone using the scanner
to reach machines inside our own network.
"""
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import requests
from flask import current_app

from .signals import Signal
from .validator import CleanURL


class BlockedAddress(Exception):
    pass


_dns_health = {"ok": None, "checked": 0.0}


def dns_is_working(resolver) -> bool:
    """Resolve well-known names first. If even these fail, our own internet or DNS
    is broken, so a 'does not exist' answer about the scanned site cannot be trusted."""
    if time.time() - _dns_health["checked"] < 300 and _dns_health["ok"] is not None:
        return _dns_health["ok"]
    ok = False
    for canary in ("example.com", "google.com"):
        try:
            resolver.resolve(canary, "A")
            ok = True
            break
        except Exception:
            continue
    _dns_health.update(ok=ok, checked=time.time())
    return ok


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified or
                (addr.version == 6 and addr.ipv4_mapped and not is_public_ip(str(addr.ipv4_mapped))))


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve a host name and make sure every address is public."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise BlockedAddress("no address")
    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedAddress(ip)
    return ips


# ----------------------------------------------------------------- RDAP
def _rdap(domain, timeout):
    r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                     headers={"Accept": "application/rdap+json"})
    if r.status_code == 404:
        return {"not_found": True}
    r.raise_for_status()
    data = r.json()
    info = {}
    for ev in data.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action == "registration":
            info["created"] = date
        elif action == "expiration":
            info["expires"] = date
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    info["registrar"] = item[3]
    return info


def _parse_date(text):
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ------------------------------------------------------------------ TLS
def _tls_info(host, ip, port, timeout):
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName", "unknown"),
        "not_before": not_before,
        "not_after": not_after,
    }


def check_domain(u: CleanURL) -> list[Signal]:
    timeout = current_app.config["NETWORK_TIMEOUT"]
    signals: list[Signal] = []
    now = datetime.now(timezone.utc)

    # ---------- SSRF guard
    if u.is_ip:
        if not is_public_ip(u.host):
            signals.append(Signal("domain", "Internal address", "danger", 20,
                                  "The link points to a private / internal network address. "
                                  "PhishGuard did not connect to it."))
            return signals
    elif u.host == "localhost":
        signals.append(Signal("domain", "Internal address", "danger", 20,
                              "The link points to this computer (localhost). PhishGuard did not connect to it."))
        return signals

    # ---------- RDAP (domain age)
    if not u.is_ip:
        try:
            info = _rdap(u.registered_domain, timeout)
            created = _parse_date(info.get("created"))
            if info.get("not_found"):
                signals.append(Signal("domain", "Domain registration", "warning", 15,
                                      f"No registration record was found for '{u.registered_domain}'."))
            elif created:
                age = (now - created).days
                when = created.strftime("%d %b %Y")
                reg = f" through {info['registrar']}" if info.get("registrar") else ""
                if age < 30:
                    signals.append(Signal("domain", "Domain age", "danger", 25,
                                          f"The domain was registered only {age} days ago ({when}){reg}. "
                                          "Most phishing sites are very new."))
                elif age < 180:
                    signals.append(Signal("domain", "Domain age", "warning", 12,
                                          f"The domain is fairly new: registered {age} days ago ({when}){reg}."))
                elif age < 365:
                    signals.append(Signal("domain", "Domain age", "info", 4,
                                          f"The domain was registered {age} days ago ({when}){reg}."))
                else:
                    years = age // 365
                    signals.append(Signal("domain", "Domain age", "ok", 0,
                                          f"The domain has existed for about {years} year{'s' if years != 1 else ''} "
                                          f"(since {when}){reg}."))
            else:
                signals.append(Signal("domain", "Domain age", "unavailable", 0,
                                      "The registry did not share the registration date."))
        except Exception as exc:
            current_app.logger.info("RDAP failed for %s: %s", u.registered_domain, exc)
            signals.append(Signal("domain", "Domain age", "unavailable", 0,
                                  "Registration details (RDAP) could not be fetched right now."))

    # ---------- DNS
    ips = []
    if u.is_ip:
        ips = [u.host]
    else:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        if not dns_is_working(resolver):
            signals.append(Signal("domain", "DNS records", "unavailable", 0,
                                  "DNS lookups are not working from the server right now, so this check was skipped."))
            return signals
        try:
            answer = resolver.resolve(u.host, "A")
            ips = [a.to_text() for a in answer]
            private = [ip for ip in ips if not is_public_ip(ip)]
            if private:
                signals.append(Signal("domain", "Internal address", "danger", 20,
                                      "This name points to a private / internal address. "
                                      "PhishGuard did not connect to it."))
                return signals
            signals.append(Signal("domain", "DNS records", "ok", 0,
                                  f"The website name points to {len(ips)} server address(es): {', '.join(ips[:3])}."))
        except dns.resolver.NXDOMAIN:
            signals.append(Signal("domain", "DNS records", "warning", 15,
                                  f"'{u.host}' does not exist in DNS. The site may be taken down already, or the link is fake."))
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            signals.append(Signal("domain", "DNS records", "warning", 8,
                                  f"'{u.host}' has no web server address."))
        except (dns.exception.Timeout, Exception):
            signals.append(Signal("domain", "DNS records", "unavailable", 0,
                                  "DNS lookup did not answer in time."))

        if not u.is_ip:
            try:
                resolver.resolve(u.registered_domain, "MX")
                signals.append(Signal("domain", "Mail server", "ok", 0,
                                      "The domain has e-mail servers set up, like most real businesses."))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                signals.append(Signal("domain", "Mail server", "info", 3,
                                      "The domain has no e-mail servers set up."))
            except Exception:
                pass

    # ---------- TLS certificate
    if ips:
        port = u.port or 443
        try:
            if not u.is_ip:
                resolve_public(u.host, port)  # double check with the system resolver
            cert = _tls_info(u.host, ips[0], port, timeout)
            days_left = (cert["not_after"] - now).days
            cert_age = (now - cert["not_before"]).days
            if days_left < 0:
                signals.append(Signal("domain", "TLS certificate", "danger", 15,
                                      "The website's security certificate has expired."))
            else:
                detail = (f"Valid certificate issued by {cert['issuer']}, "
                          f"expires in {days_left} days.")
                if cert_age <= 7:
                    signals.append(Signal("domain", "TLS certificate", "info", 4,
                                          detail + f" It was created only {cert_age} day(s) ago."))
                else:
                    signals.append(Signal("domain", "TLS certificate", "ok", 0, detail))
        except BlockedAddress:
            signals.append(Signal("domain", "Internal address", "danger", 20,
                                  "This name points to an internal address. PhishGuard did not connect to it."))
        except ssl.SSLCertVerificationError as exc:
            reason = getattr(exc, "verify_message", "") or "certificate could not be verified"
            signals.append(Signal("domain", "TLS certificate", "danger", 15,
                                  f"The security certificate is not valid for this site ({reason})."))
        except (socket.timeout, ConnectionRefusedError, OSError):
            pts = 6 if u.scheme == "https" else 4
            signals.append(Signal("domain", "TLS certificate", "warning", pts,
                                  "The site does not offer a secure (HTTPS) connection."))
    return signals


def domain_score(signals: list[Signal]) -> int:
    return min(sum(x.points for x in signals if x.source == "domain"), 100)
