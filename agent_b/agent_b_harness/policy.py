from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any


GET_PREFIXES = (
    "/api/health", "/api/docs", "/api/findings", "/api/report", "/api/coverage",
    "/api/agent/queue", "/api/agent/preflight", "/api/agent/scope",
    "/api/agent/project-profile", "/api/agent/knowledge", "/api/agent/fixtures",
    "/api/agent/confirmations", "/api/agent/attack-surface", "/api/agent/auth/latest",
    "/api/agent/prompt",
    "/api/agent/burp/", "/api/agent/browseros/", "/api/agent/history/", "/api/agent/scanner/",
)

POST_PATTERNS = (
    r"^/api/findings(?:/[^/]+/(?:triage|poc-repeater))?$",
    r"^/api/findings/triage$",
    r"^/api/agent/queue/(?:finding|automated-testing|risk-hunt|full-app-assessment|try-harder)$",
    r"^/api/agent/queue/[^/]+/(?:claim|release|result|heartbeat|repeater)$",
    r"^/api/agent/queue/[^/]+/campaign/step$",
    r"^/api/agent/results/[^/]+/amend$",
    r"^/api/agent/(?:project-profile|knowledge|fixtures|confirmations|attack-surface)(?:/[^?]+)?$",
    r"^/api/agent/burp/action(?:/dry-run)?$",
    r"^/api/agent/(?:request|request/http2|mcp/call)$",
    r"^/api/agent/scanner/(?:full-app|active)$",
)


def path_only(path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/api/") or ".." in parsed.path:
        raise ValueError("Only Double Agent /api/ paths are accepted")
    return parsed.path


def allow_get(path: str) -> None:
    value = path_only(path)
    if not any(value.startswith(prefix) for prefix in GET_PREFIXES):
        raise ValueError(f"GET path is outside the Agent B contract: {value}")


def allow_post(path: str, body: dict[str, Any]) -> None:
    value = path_only(path)
    if value.endswith("/curl"):
        raise ValueError(
            "The queue /curl endpoint is GET-only. Use double_agent_get to read it, "
            "POST /api/agent/request to execute the returned request through Burp, "
            "then POST the outcome to the queue /result endpoint."
        )
    if not any(re.match(pattern, value) for pattern in POST_PATTERNS):
        raise ValueError(f"POST path is outside the Agent B contract: {value}")
    if value == "/api/findings":
        status = str(body.get("agent_status", "valid")).lower()
        if status == "valid":
            required = {
                "deduplication_key": 8,
                "request_data": 20,
                "response_data": 10,
            }
            missing = [key for key, size in required.items() if len(str(body.get(key, "")).strip()) < size]
            if missing:
                raise ValueError("A valid finding needs exact evidence: " + ", ".join(missing))
    if value.endswith("/result") and str(body.get("outcome", "")).lower().replace("_", "-") in {"confirmed", "not-vulnerable"}:
        evidence = body.get("evidence", [])
        valid = [item for item in evidence if isinstance(item, dict) and len(str(item.get("request", ""))) >= 10
                 and len(str(item.get("response_snippet", item.get("response", "")))) >= 5]
        if len(valid) < 2 or len(str(body.get("reproduction", ""))) < 20:
            raise ValueError("A conclusive queue result needs at least two evidence entries and reproducible steps")


def signature(name: str, arguments: dict[str, Any]) -> str:
    raw = json.dumps([name, arguments], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def compact(value: Any, limit: int = 9000) -> Any:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(raw) <= limit:
        return value
    return {"truncated": True, "characters": len(raw), "preview": raw[:limit]}
