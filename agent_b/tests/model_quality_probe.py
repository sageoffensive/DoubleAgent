"""Live CyberStrike probe for the Full App planning/tool contract.

This uses a synthetic, authorized example.test application and never sends target
traffic. It evaluates whether the model follows the harness plan and typed tools.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from agent_b_harness import config
from agent_b_harness.clients import Model
from agent_b_harness.engine import Engine, SYSTEM, TOOLS, build_full_assessment_plan
from agent_b_harness.discovery import surface_fingerprint
from agent_b_harness.store import Store


ALLOWED = {
    "refresh_assessment_state", "run_application_discovery", "next_assessment_test", "complete_assessment_test",
    "check_scope", "send_burp_request", "burp_action",
    "update_campaign_step", "record_attack_surface_route", "coverage_overwatch",
    "review_attack_surface", "run_full_app_scanner", "scanner_status", "record_finding",
    "record_knowledge", "submit_active_queue_result", "ask_user", "finish",
}


class ProbeDoubleAgent:
    """Synthetic Double Agent transport; no network traffic leaves the model API."""

    def __init__(self):
        self.surface: list[dict] = []
        self.findings: list[dict] = []

    def get(self, path: str) -> dict:
        if path.startswith("/api/agent/scope?"):
            return {"authoritative": True, "scope_guard": {"in_scope": True}}
        if path.startswith("/api/agent/auth/latest?"):
            return {"recommended_auth": {"raw_header_lines": ["Cookie: session=synthetic"]}}
        if path.startswith("/api/agent/history/http/regex"):
            return {"matches": 6, "path": path}
        if path == "/api/agent/queue/41":
            return {"id": 41, "status": "claimed", "campaign_type": "full_app_assessment"}
        if path.startswith("/api/agent/attack-surface/review"):
            return {"ready_to_complete": False, "blockers": [{"code": "planned_tests_remaining"}]}
        if path == "/api/agent/attack-surface":
            return {"attack_surface": {"entries": list(self.surface)}}
        if path.startswith("/api/coverage/parameters"):
            return {"meaningful_tested": []}
        if path.startswith("/api/coverage?"):
            return {"tested": [], "untested": []}
        if path == "/api/findings?limit=500":
            return {"findings": list(self.findings)}
        return {"status": "ok", "path": path, "findings": [], "tested": [], "meaningful_tested": []}

    def post(self, path: str, body: dict) -> dict:
        if path == "/api/agent/request":
            request = str(body.get("request", ""))
            first_line = request.splitlines()[0] if request else "GET / HTTP/1.1"
            target = first_line.split(" ", 2)[1] if " " in first_line else "/"
            url = "https://example.test" + target
            response_body = "<a href='/api/users/1'>Users</a><a href='/search?q=book'>Search</a><a href='/continue?next=/'>Continue</a><a href='/download?file=manual.pdf'>Download</a>"
            if "/api/users/2" in url:
                response_body = '{"id":2,"email":"other-user@example.test"}'
            elif "next=https" in url:
                return {"status_code": 302, "headers": ["Location: https://outside.example/"], "body": "", "url": url}
            elif "../" in url or "%2e%2e" in url.lower():
                response_body = "safe file not found"
            return {"status_code": 200, "headers": ["Content-Type: application/json"], "body": response_body, "url": url}
        if path == "/api/findings":
            finding = {**body, "id": "daf_probe_1"}
            self.findings.append(finding)
            return {"status": "created", "id": "daf_probe_1", "poc_repeater": {"created": True}}
        if path == "/api/agent/attack-surface":
            incoming = body.get("entries", []) or ([body.get("entry")] if body.get("entry") else [])
            by_key = {(item.get("method"), item.get("url")): item for item in self.surface}
            for item in incoming:
                by_key[(item.get("method"), item.get("url"))] = dict(item)
            self.surface = list(by_key.values())
            return {"status": "updated", "accepted": incoming, "rejected": []}
        if path == "/api/agent/knowledge":
            return {"status": "updated"}
        if path.endswith("/campaign/step"):
            return {"status": "updated"}
        if path == "/api/agent/scanner/full-app":
            return {"status": "launched", "launched": 4}
        if path == "/api/agent/queue/41/result":
            return {"status": "completed", "outcome": body.get("outcome")}
        return {"status": "ok", "path": path}


def legacy_tool_result(name: str, args: dict, plan: dict) -> dict:
    """Fallback for deliberately hallucinated read aliases."""
    if name in {"assessment_snapshot", "parameter_coverage_snapshot", "coverage_snapshot", "attack_surface_snapshot"}:
        return {"queue": {"id": 41, "status": "claimed"}, "plan": plan, "review": {"ready_to_complete": False}}
    if name == "send_burp_request":
        url = str(args.get("url", ""))
        body = "normal response"
        if "/api/users/2" in url:
            body = '{"id":2,"email":"other-user@example.test"}'
        elif "next=https" in url:
            return {"status_code": 302, "headers": ["Location: https://outside.example/"], "body": "", "url": url}
        elif "../" in url or "%2e%2e" in url.lower():
            body = "safe file not found"
        return {"status_code": 200, "headers": ["Content-Type: application/json"], "body": body, "url": url}
    if name == "record_attack_surface_route":
        return {"status": "updated", "accepted": [{"url": args.get("url")}], "rejected": []}
    if name == "update_campaign_step":
        return {"status": "updated", "key": args.get("key"), "step_status": args.get("status")}
    if name == "record_finding":
        return {"status": "created", "id": "daf_probe_1", "poc_repeater": {"created": True}}
    if name == "record_knowledge":
        return {"status": "updated"}
    if name == "run_full_app_scanner":
        return {"status": "launched", "launched": 4}
    if name == "scanner_status":
        return {"all_terminal": True, "scanner_findings": [], "unvalidated_count": 0}
    if name in {"coverage_overwatch", "review_attack_surface"}:
        return {"ready_to_complete": False, "blockers": [{"code": "more_routes_required"}]}
    return {"error": "unknown simulated tool"}


def main() -> None:
    cfg = config.load()
    if not cfg.model_api_key:
        raise SystemExit("Model API key is unavailable")
    inventory = {
        "coverage": {"tested": [
            {"method": "POST", "host": "example.test", "path": "/login", "url_example": "https://example.test/login"},
            {"method": "GET", "host": "example.test", "path": "/api/users/1", "url_example": "https://example.test/api/users/1"},
            {"method": "GET", "host": "example.test", "path": "/search", "url_example": "https://example.test/search?q=book"},
            {"method": "GET", "host": "example.test", "path": "/continue", "url_example": "https://example.test/continue?next=/"},
            {"method": "GET", "host": "example.test", "path": "/download", "url_example": "https://example.test/download?file=manual.pdf"},
        ]},
        "parameters": {"meaningful_tested": [
            {"method": "POST", "host": "example.test", "path": "/login", "parameter": "username", "type": "body"},
            {"method": "POST", "host": "example.test", "path": "/login", "parameter": "password", "type": "body"},
            {"method": "GET", "host": "example.test", "path": "/api/users/1", "parameter": "id", "type": "path"},
            {"method": "GET", "host": "example.test", "path": "/search", "parameter": "q", "type": "query"},
            {"method": "GET", "host": "example.test", "path": "/continue", "parameter": "next", "type": "query"},
            {"method": "GET", "host": "example.test", "path": "/download", "parameter": "file", "type": "query"},
        ]},
        "findings": {"findings": []},
        "attack_surface": {"attack_surface": {"entries": []}},
        "capabilities": {"effective_actions": [
            {"action": "history.http.search", "available": True, "transport": "double_agent_api", "classification": "read_only"},
            {"action": "scanner.active.start", "available": True, "transport": "double_agent_api", "classification": "active"},
            {"action": "request.send.http2", "available": True, "transport": "double_agent_api", "classification": "active"},
            {"action": "crawl.start", "available": False, "reason": "not exposed"},
        ]},
    }
    plan = build_full_assessment_plan(inventory)
    plan["scope_gate"] = {"ready": True, "blockers": [], "checked_routes": []}
    queue = {
        "id": 41, "status": "claimed", "campaign_type": "full_app_assessment",
        "summary": "Synthetic Full App quality probe", "harness_assessment_plan": plan,
        "campaign_state": {"steps": [
            {"key": key, "status": "pending"} for key in
            ("surface_discovery", "generate_hypotheses", "security_baseline", "active_testing", "burp_active_scan", "scanner_validation", "ai_coverage_overwatch", "overwatch_review", "write_back")
        ]},
    }
    tools = [tool for tool in TOOLS if tool.get("function", {}).get("name") in ALLOWED]
    temporary = tempfile.TemporaryDirectory()
    engine = Engine(Store(Path(temporary.name) / "probe.sqlite3"))
    engine.queue_fetch_mode = True
    engine.active_queue = "41"
    engine.assessment_inventory = inventory
    engine.assessment_plan = plan
    client = ProbeDoubleAgent()
    engine.assessment_discovery = {
        "status": "pending", "passes": 0, "stable_passes": 0, "required_stable_passes": 2,
        "fingerprint": surface_fingerprint(plan), "technologies": [], "plan_finalized": False, "blockers": [],
    }
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            "Trusted harness runtime event: Full App queue #41 is already claimed. The deterministic plan below is authoritative. "
            "Use only the named typed tools; never construct API paths. Call run_application_discovery until its two stable passes finalize the "
            "application model and ranked plan, then call next_assessment_test and work only the returned track with baseline, focused mutation, and negative control. "
            "Close it with complete_assessment_test and repeat. Final submission is impossible while any track remains.\n\n" +
            json.dumps(queue, ensure_ascii=False)
        )},
    ]
    model = Model(cfg.model_url, cfg.model_api_key, cfg.model, min(cfg.request_timeout, 180), min(cfg.max_output_tokens, 4096))
    print(json.dumps({"plan_version": plan["version"], "families": len(plan["attack_families"]), "test_tracks": len(plan["planned_tests"]), "tools": sorted(ALLOWED)}))
    max_steps = max(1, int(os.environ.get("PROBE_STEPS", "18")))
    for step in range(1, max_steps + 1):
        message = model.complete(messages, tools, tool_choice="required")
        calls = message.get("tool_calls") or []
        if not calls:
            print(json.dumps({"step": step, "error": "no_tool", "content": str(message.get("content", ""))[:500]}))
            break
        messages.append(message)
        for call in calls:
            function = call.get("function", {})
            name = str(function.get("name", ""))
            try:
                args = json.loads(function.get("arguments", "{}") or "{}")
            except ValueError:
                args = {"_invalid": str(function.get("arguments", ""))[:500]}
            print(json.dumps({"step": step, "tool": name, "args": args}, ensure_ascii=False))
            try:
                result, _ = engine._tool(client, name, args)
            except Exception as exc:
                result = legacy_tool_result(name, args, plan)
                result["probe_exception"] = str(exc)[:500]
            if name == "run_application_discovery":
                print(json.dumps({"step": step, "discovery_result": {
                    "ok": result.get("ok"), "error": result.get("error"),
                    "plan_finalized": result.get("plan_finalized"),
                    "passes": (result.get("discovery") or {}).get("passes"),
                    "stable_passes": (result.get("discovery") or {}).get("stable_passes"),
                    "route_count": (result.get("discovery") or {}).get("route_count"),
                }}, ensure_ascii=False))
            messages.append({"role": "tool", "tool_call_id": call.get("id", f"probe-{step}"), "content": json.dumps(result, ensure_ascii=False)})
        if any(str(call.get("function", {}).get("name")) == "finish" for call in calls):
            break
    print(json.dumps({"final_discovery": engine.assessment_discovery, "final_progress": engine._assessment_progress_summary()}, ensure_ascii=False))
    temporary.cleanup()


if __name__ == "__main__":
    main()
