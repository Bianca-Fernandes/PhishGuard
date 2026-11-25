"""
Module: URL Input & Validation

Cleans the URL the user pasted and accepts only proper HTTP / HTTPS links.
"""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import tldextract

# Use the public suffix list that ships with tldextract (no internet needed)
_extract = tldextract.TLDExtract(suffix_list_urls=())

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")


class ValidationError(ValueError):
    pass


@dataclass
class CleanURL:
    original: str
    normalized: str
    scheme: str
    host: str            # e.g. login.paypal.com.evil.tk  (ASCII / punycode form)
    host_unicode: str    # how the host looks to a person
    registered_domain: str   # e.g. evil.tk
    subdomain: str
    suffix: str
    port: int | None
    path: str
    query: str
    is_ip: bool
    scheme_added: bool   # True if the user did not type http:// or https://


def _defang(text: str) -> str:
    """Undo common 'defanged' forms people share, e.g. hxxp://site[.]com"""
    text = re.sub(r"^hxxp", "http", text, flags=re.I)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return text


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def clean_url(raw: str) -> CleanURL:
    if raw is None:
        raise ValidationError("Please enter a URL.")

    original = raw
    url = raw.strip()
    # remove spaces, tabs and line breaks pasted from messages
    url = re.sub(r"\s+", "", url)
    url = _defang(url)

    if not url:
        raise ValidationError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError("This URL is too long to check (maximum 2048 characters).")

    scheme_added = False
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValidationError("Only http:// and https:// links can be checked.")
    elif re.match(r"^(javascript|data|vbscript|file|mailto|ftp|about|blob|tel|sms|intent):", url, re.I):
        raise ValidationError("Only http:// and https:// links can be checked.")
    else:
        # user typed "example.com/login" without http:// - add it
        url = "http://" + url
        scheme_added = True

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValidationError("This does not look like a valid URL.")

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError("Only http:// and https:// links can be checked.")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise ValidationError("The URL has no website name in it.")

    is_ip = _is_ip(host)

    # Convert international (unicode) names to punycode and back
    host_unicode = host
    if not is_ip:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValidationError("The website name contains characters that are not allowed.")
        try:
            host_unicode = ascii_host.encode("ascii").decode("idna")
        except UnicodeError:
            host_unicode = ascii_host
        host = ascii_host
        if not re.fullmatch(r"[a-z0-9.\-]+", host) or ".." in host:
            raise ValidationError("The website name contains characters that are not allowed.")
        if "." not in host and host != "localhost":
            raise ValidationError("Please enter a full website address, for example example.com")

    ext = _extract(host)
    if is_ip:
        registered = host
    else:
        registered = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
        registered = registered or host

    netloc = host if not is_ip or ":" not in host else f"[{host}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    else:
        port = None
    path = parts.path or "/"
    # the fragment (#...) is never sent to a server, so it is dropped
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))

    return CleanURL(
        original=original,
        normalized=normalized,
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        registered_domain=registered,
        subdomain="" if is_ip else ext.subdomain,
        suffix="" if is_ip else ext.suffix,
        port=port,
        path=path,
        query=parts.query,
        is_ip=is_ip,
        scheme_added=scheme_added,
    )
