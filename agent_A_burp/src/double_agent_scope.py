# -*- coding: utf-8 -*-
"""Destination consistency checks, compatible with CPython and Jython 2.7."""
try:
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit


def origin(url):
    parsed = urlsplit(str(url or ""))
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or parsed.fragment or
            any(ord(char) <= 32 for char in str(url))):
        raise ValueError("Target must be an unambiguous HTTP(S) URL without userinfo")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port < 1 or port > 65535:
        raise ValueError("Invalid target port")
    return parsed.scheme, parsed.hostname.lower(), port


def validate_destination(url, host, port, https, authorities=()):
    """The checked URL, physical service and virtual authority must agree."""
    expected = origin(url)
    scheme = "https" if https else "http"
    host = str(host or "").strip()
    if any(char in host for char in ("/", "@", "?", "#", "\\")):
        raise ValueError("Invalid target host")
    netloc = "[%s]" % host if ":" in host and not host.startswith("[") else host
    actual = origin("%s://%s:%d/" % (scheme, netloc, int(port)))
    if actual != expected:
        raise ValueError("Checked URL does not match the destination service")
    for authority in authorities:
        authority = str(authority or "").strip()
        if not authority or any(char in authority for char in ("/", "@", "?", "#", "\\")):
            raise ValueError("Invalid request authority")
        if origin("%s://%s/" % (scheme, authority)) != expected:
            raise ValueError("Request authority does not match the checked destination")


def validate_raw_destination(url, host, port, https, raw):
    header_block = str(raw).replace("\r\n", "\n").split("\n\n", 1)[0]
    lines = header_block.splitlines()
    parts = lines[0].split() if lines else []
    if len(parts) != 3:
        raise ValueError("Invalid HTTP request line")
    for line in lines[1:]:
        name = line.split(":", 1)[0]
        if ":" not in line or not name or name != name.strip() or any(char.isspace() for char in name):
            raise ValueError("Ambiguous HTTP header")
    authorities = [line.split(":", 1)[1].strip() for line in lines[1:]
                   if line.lower().startswith("host:")]
    if len(authorities) != 1:
        raise ValueError("Exactly one Host header is required")
    validate_destination(url, host, port, https, authorities)
    if parts[1].lower().startswith(("http://", "https://")):
        if origin(parts[1]) != origin(url):
            raise ValueError("Absolute request target does not match the checked URL")
    elif not parts[1].startswith("/") or parts[1].startswith("//"):
        raise ValueError("Invalid origin-form request target")
    validate_request_path(url, parts[1])


def validate_request_path(url, target):
    expected, actual = urlsplit(str(url)), urlsplit(str(target))
    if actual.fragment or ((actual.path or "/"), actual.query) != ((expected.path or "/"), expected.query):
        raise ValueError("Request path does not match the exact scope-check URL")
