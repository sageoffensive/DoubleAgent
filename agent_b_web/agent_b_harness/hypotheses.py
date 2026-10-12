"""Durable research state. Entries are observations, never authorization."""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
import urllib.parse
from typing import Any

from .store import Store, redact_text, redact_checkpoint_value


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def route(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use an absolute HTTP(S) route without credentials")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def bounded(value: Any, limit: int = 2000) -> Any:
    if isinstance(value, dict):
        return {str(k)[:100]: bounded(v, limit) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [bounded(v, limit) for v in value[:20]]
    if isinstance(value, str):
        return redact_text(value)[:limit]
    return value


class Registry:
    def __init__(self, store: Store, engagement: str, target: str, queue: str):
        self.store = store
        self.scope = fingerprint(json.dumps([engagement, route(target), queue]))

    def all(self) -> list[dict[str, Any]]:
        return self.store.hypotheses(self.scope)

    def get(self, ident: str) -> dict[str, Any]:
        return next((item for item in self.all() if item["id"] == ident), {})

    def save(self, item: dict[str, Any]) -> dict[str, Any]:
        item["updated"] = time.time()
        self.store.save_hypothesis(self.scope, item)
        return self.get(item["id"])

    def propose(self, family: str, url: str, mechanism: str, parameter: str = "", actor: str = "current actor") -> dict[str, Any]:
        values = [family, route(url), parameter, actor, mechanism]
        if not family.strip() or len(mechanism.strip()) < 10:
            raise ValueError("A family and a concrete mechanism (at least 10 characters) are required")
        normalized = [re.sub(r"\s+", " ", str(v).strip().lower()) for v in values]
        identity = fingerprint(json.dumps(normalized))
        existing = next((item for item in self.all() if item["identity"] == identity), None)
        if existing:
            return existing
        if len(self.all()) >= 500:
            raise ValueError("Registry capacity reached; continue an existing hypothesis")
        return self.save({"id": "hyp_" + uuid.uuid4().hex[:16], "identity": identity,
                          "family": family[:100], "route": route(url), "parameter": parameter[:200],
                          "actor": actor[:100], "mechanism": mechanism[:1200], "status": "proposed",
                          "note": "", "observations": [], "revisions": [], "created": time.time()})

    def update(self, ident: str, status: str, note: str, new_information: str = "", *, reviewed: bool = False) -> dict[str, Any]:
        item = self.get(ident)
        if not item:
            raise ValueError("Unknown hypothesis in this engagement/target/queue")
        if status not in {"testing", "supported", "refuted", "blocked", "inconclusive"}:
            raise ValueError("Unsupported hypothesis status")
        if status == "supported" and not reviewed:
            raise ValueError("Only the evidence reviewer can mark a hypothesis supported")
        if item["status"] == "supported" and status != "testing" and not reviewed:
            raise ValueError("Reopen a supported hypothesis with new information before revising it")
        terminal = {"supported", "refuted", "blocked", "inconclusive"}
        if item["status"] in terminal and status == "testing":
            if len(new_information.strip()) < 20 or new_information.strip() == item.get("new_information"):
                raise ValueError("Reopening requires distinct new evidence or a changed mechanism (at least 20 characters)")
            item["new_information"] = new_information[:1200]
            # Never mix an earlier attempt's evidence into a reopened attempt.
            item["observations"] = []
        if len(note.strip()) < 10:
            raise ValueError("Record a concrete outcome or blocker")
        item["revisions"] = (item["revisions"] + [{"status": item["status"], "note": item["note"], "at": time.time()}])[-20:]
        item.update(status=status, note=note[:1200])
        return self.save(item)

    def capture(self, ident: str, run: str, request: str, result: dict[str, Any], purpose: str) -> dict[str, Any]:
        item = self.get(ident)
        if not item or item["status"] not in {"proposed", "testing"}:
            raise ValueError("Select an open hypothesis before testing; reopen terminal ideas with new information")
        headers = result.get("headers", [])
        response = str(result.get("body", ""))
        observation = {
            "id": "ev_" + uuid.uuid4().hex[:16], "run_id": run,
            "hypothesis_id": ident, "captured_at": time.time(),
            "request_digest": fingerprint(request.replace("\r\n", "\n").strip()),
            "request": redact_text(request)[:6000], "request_truncated": len(request) > 6000,
            "status_code": int(result.get("status_code", 0)),
            "url": redact_text(str(result.get("url", "")))[:2000],
            "headers": bounded(headers, 1000), "headers_truncated": len(headers) > 20,
            "response_snippet": redact_text(response)[:6000], "response_truncated": len(response) > 6000,
            "purpose": redact_text(purpose)[:500],
        }
        # Additional field-name redaction applies before returning or persisting.
        observation = redact_checkpoint_value(observation)
        item["observations"] = (item["observations"] + [observation])[-24:]
        item["status"] = "testing"
        self.save(item)
        return observation

    def summary(self, active: str = "", offset: int = 0) -> dict[str, Any]:
        items = self.all()
        # Keep the active item plus recent results; counts make sampling explicit.
        ordered = sorted(items, key=lambda item: item["id"] != active)
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        page = ordered[offset:offset + 20]
        return {"active_id": active, "total": len(items), "shown": len(page), "offset": offset,
                "next_offset": offset + len(page) if offset + len(page) < len(items) else None,
                "hypotheses": [{k: bounded(item.get(k), 350) for k in ("id", "family", "route", "parameter", "actor", "mechanism", "status", "note")}
                               | {"evidence_ids": [e["id"] for e in item["observations"]]}
                               for item in page]}


REGISTRY_TOOL = {"type": "function", "function": {
    "name": "hypothesis_registry",
    "description": "Read or manage durable hypotheses. Reuse the same family/route/parameter/actor/mechanism; record blockers and disproved ideas. Only the reviewer can confirm support. Selecting an idea grants no traffic authorization. Reopen terminal ideas only with new evidence or a changed mechanism.",
    "parameters": {"type": "object", "properties": {
        "action": {"type": "string", "enum": ["list", "propose", "select", "update", "reopen"]},
        "offset": {"type": "integer", "minimum": 0},
        "id": {"type": "string"}, "family": {"type": "string"}, "url": {"type": "string"},
        "parameter": {"type": "string"}, "actor": {"type": "string"}, "mechanism": {"type": "string"},
        "status": {"type": "string", "enum": ["refuted", "blocked", "inconclusive"]},
        "note": {"type": "string"}, "new_information": {"type": "string"}},
        "required": ["action"], "additionalProperties": False}}}
