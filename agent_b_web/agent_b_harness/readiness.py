"""Passive access evidence. No target requests, credentials, or model decisions."""
from __future__ import annotations

import re
import urllib.parse


SIGNED_IN = "I’m signed in through Burp"
PUBLIC_APP = "The app doesn’t need a login"
STOP = "Stop"


class ReadinessBlocked(RuntimeError):
    pass


def app_origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ReadinessBlocked("Choose an HTTP(S) app target in Burp first.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}:{port}"


def login_response(response: dict) -> bool:
    headers = response.get("response_headers", response.get("headers", [])) or []
    for header in headers:
        key, _, value = str(header).partition(":")
        if key.lower().strip() == "location" and re.search(r"login|sign[-_]?in|/auth", value, re.I):
            return True
    body = str(response.get("response_preview", response.get("body", "")))[:8000]
    return bool(re.search(r'<input\b[^>]*\btype\s*=\s*[\"\']?password\b', body, re.I))


def captured_access(client, target: str) -> dict:
    """Return only booleans and history indices; discard all HTTP material.

    A cookie plus 200 is ambiguous. Authentication evidence requires an earlier
    credential-free 401 on the same exact URL followed by a credentialed 2xx.
    This is historical evidence, never a claim of a fresh authentication check.
    """
    wanted = app_origin(target)
    scope = client.get("/api/agent/scope?" + urllib.parse.urlencode({"url": target}))
    if not isinstance(scope, dict) or (scope.get("scope_guard") or {}).get("in_scope") is not True:
        raise ReadinessBlocked("Burp has not confirmed that the app URL is in scope.")
    query = {"regex": re.escape(urllib.parse.urlsplit(target).hostname), "count": 1}
    base = "/api/agent/history/http/regex?"
    try:
        first = client.get(base + urllib.parse.urlencode(query))
        total = int(first.get("total_matches", 0))
        query.update(count=80, offset=max(0, total - 80), include="headers,previews", preview_limit=8000)
        history = client.get(base + urllib.parse.urlencode(query)) if total else {"items": []}
    except Exception:
        return {"access": False, "authenticated": False, "source": "history_unavailable"}
    observations = []
    for item in history.get("items", []):
        try:
            url = str(item.get("url", ""))
            if app_origin(url) != wanted or not item.get("has_response") or item.get("method") not in {"GET", "HEAD"}:
                continue
            path = urllib.parse.urlsplit(url).path
            if re.search(r"(?:login|sign[-_]?in|logout)|\.(?:js|css|png|jpg|ico|svg|woff2?)$", path, re.I):
                continue
            status = int(item.get("status_code", 0))
            credentialed = any(str(h).split(":", 1)[0].lower().strip() in {"cookie", "authorization"}
                               for h in item.get("request_headers", []) or [])
            observations.append((int(item["history_index"]), url, status, credentialed, login_response(item)))
        except (ValueError, TypeError, KeyError):
            continue
    observations.sort(reverse=True)
    if not observations:
        return {"access": False, "authenticated": False, "source": "burp_history"}
    latest = observations[0]
    if latest[2] in {401, 403} or latest[4] or not 200 <= latest[2] < 300:
        return {"access": False, "authenticated": False, "source": "burp_history", "history_index": latest[0]}
    exact_scope = client.get("/api/agent/scope?" + urllib.parse.urlencode({"url": latest[1]}))
    if not isinstance(exact_scope, dict) or (exact_scope.get("scope_guard") or {}).get("in_scope") is not True:
        return {"access": False, "authenticated": False, "source": "burp_history"}
    authenticated = latest[3] and any(
        older[1] == latest[1] and older[2] == 401 and not older[3] and not older[4]
        for older in observations[1:]
    )
    return {"access": True, "authenticated": bool(authenticated), "source": "burp_history", "history_index": latest[0]}
