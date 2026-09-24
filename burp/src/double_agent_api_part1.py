# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk1(object):
    """HTTP handler that exposes findings and a work queue for AI Agent to consume.

    Endpoints are available only on the loopback-bound local server:
      GET  /api/health                          -> {status, version, queue_size}
      GET  /api/findings                        -> list of findings (summary)
      GET  /api/findings/<id>                   -> full finding detail
      GET  /api/agent/queue                   -> list of queue items (summary)
      GET  /api/agent/queue/<id>              -> full queue item with all findings
      POST /api/agent/queue/<id>/claim        -> mark item as claimed
      POST /api/agent/queue/<id>/release      -> release a claimed item back to pending
      POST /api/agent/queue/<id>/result       -> store tested outcome and evidence
      POST /api/agent/queue/automated-testing -> queue automated active testing
      POST /api/findings                      -> create agent-discovered findings
    """

    def __init__(self, extender, *args, **kwargs):
        self.extender = extender
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def _send_json(self, status, payload):
        try:
            body = json.dumps(payload, ensure_ascii=True)
            if isinstance(body, TEXT_TYPE):
                body = body.encode("utf-8")
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
            max_body = int(getattr(self.extender, "MAX_AGENT_API_BODY_BYTES", 10 * 1024 * 1024))
            if content_length > max_body:
                raise Exception("Request body exceeds %d byte limit" % max_body)
            data = self.rfile.read(content_length)
            text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
            if not text.strip():
                return {}
            return json.loads(text)
        except Exception as e:
            raise Exception("Invalid JSON body: %s" % str(e))

    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass

    def _apply_rate_limit(self, method):
        delay = 0.0
        with self.extender.agent_api_rate_lock:
            now = time.time()
            elapsed = now - self.extender.agent_api_last_request
            if elapsed < self.extender.agent_api_min_interval:
                delay = self.extender.agent_api_min_interval - elapsed
            self.extender.agent_api_last_request = now + delay
        if delay > 0:
            time.sleep(delay)

    def do_GET(self):
        try:
            self._apply_rate_limit("GET")

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
                    "version": getattr(self.extender, "VERSION", "3.0"),
                    "queue_size": total,
                    "queue_pending": pending,
                    "docs": "/api/docs"
                })
                return

            # Public: self-describing API docs so any AI Agent session can onboard
            if path == "/api/docs":
                docs = self._build_docs()
                if self._bool_query_value(query, "compact", "false"):
                    compact_endpoints = []
                    for item in docs.get("endpoints", []):
                        compact_item = {
                            "method": item.get("method"),
                            "path": item.get("path"),
                            "description": item.get("description", "")
                        }
                        # Write endpoints must be usable without downloading
                        # the much larger operating manual.
                        if item.get("body") is not None:
                            compact_item["body"] = item.get("body")
                        if item.get("returns") is not None and item.get("method") != "GET":
                            compact_item["returns"] = item.get("returns")
                        compact_endpoints.append(compact_item)
                    self._send_json(200, {
                        "name": docs.get("name", "Double Agent API"),
                        "version": docs.get("version", getattr(self.extender, "VERSION", "3.0")),
                        "endpoints": compact_endpoints,
                        "write_schemas_included": True,
                        "full_docs": "/api/docs",
                    })
                else:
                    self._send_json(200, docs)
                return

            if path == "/api/agent/prompt":
                url = "http://%s:%d" % (
                    self.extender.agent_server_host,
                    self.extender.agent_server_port,
                )
                self._send_json(200, {
                    "status": "ok",
                    "agent": "Agent B",
                    "prompt": self.extender._build_agent_burp_expert_prompt(url),
                    "browseros_enabled": bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)),
                    "source": "double_agent",
                    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
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
                    registry = getattr(self.extender, "collaborator_payload_registry", {}) or {}
                    registry[payload] = {
                        "payload": payload,
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "double_agent_api",
                        "interaction_count": 0,
                        "interactions": []
                    }
                    self.extender.collaborator_payload_registry = registry
                    self._send_json(200, {
                        "payload": payload,
                        "location": str(self.extender.collaborator.getCollaboratorServerLocation()),
                        "burp_visibility": {
                            "verified_via": "Burp Collaborator extension client context",
                            "evidence_surface": "Double Agent > Findings > Finding Details after validation",
                            "native_collaborator_tab": "Legacy Extender contexts do not guarantee registration in Burp's built-in Collaborator tab"
                        }
                    })
                    self.extender.stdout.println("[AGENT API] Generated collaborator payload: %s" % payload)
                except Exception as e:
                    self.extender.stdout.println("[COLLABORATOR] generatePayload error: %s" % str(e))
                    self._send_json(500, {"error": "Failed to generate collaborator payload", "message": str(e)})
                return

            if path == "/api/agent/auth/latest":
                self._handle_get_latest_auth(query)
                return
            if path == "/api/agent/project-profile":
                self._handle_get_project_profile(query)
                return
            if path == "/api/agent/knowledge":
                self._handle_get_knowledge(query)
                return
            if path == "/api/agent/attack-surface":
                self._handle_get_attack_surface(query)
                return
            if path == "/api/agent/attack-surface/review":
                self._handle_get_attack_surface_review(query)
                return
            if path == "/api/agent/fixtures":
                self._handle_list_fixtures(query)
                return
            if path == "/api/agent/confirmations":
                self._handle_list_confirmations(query)
                return
            if path == "/api/agent/preflight":
                self._handle_agent_preflight(query)
                return
            if path == "/api/agent/browseros/readiness":
                self._handle_browseros_readiness(query)
                return
            if path == "/api/agent/scope":
                self._handle_get_burp_scope(query)
                return
            if path == "/api/agent/mcp/capabilities":
                self._handle_mcp_capabilities(query)
                return
            if path == "/api/agent/burp/capabilities":
                self._handle_burp_capabilities(query)
                return
            if path == "/api/agent/burp/skill":
                self._handle_burp_skill(query)
                return
            if path == "/api/agent/burp/workspace":
                self._handle_burp_workspace(query)
                return
            if path == "/api/agent/history/http/regex":
                self._handle_proxy_http_history_regex(query)
                return
            if self._dispatch_scanner_get(path, query):
                return
            if path == "/api/coverage/parameters":
                self._handle_get_parameter_coverage(query)
                return

            # Route
            if path == "/api/findings" and method == "GET":
                self._handle_list_findings(query)
            elif path.startswith("/api/findings/"):
                fid = path[len("/api/findings/"):]
                self._handle_get_finding(fid, query)
            elif path == "/api/agent/queue":
                self._handle_list_queue(query)
            elif path.startswith("/api/agent/queue/") and path.endswith("/curl"):
                qid = path[len("/api/agent/queue/"):-len("/curl")]
                self._handle_get_queue_curl(qid, query)
            elif path.startswith("/api/agent/queue/"):
                qid = path[len("/api/agent/queue/"):]
                self._handle_get_queue_item(qid)
            elif path == "/api/report":
                self._handle_get_report(query)
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
            self._apply_rate_limit("POST")

            path = self.path
            method = "POST"

            # Route
            if path == "/api/findings":
                self._handle_create_finding()
            elif path == "/api/agent/queue/finding":
                self._handle_queue_finding()
            elif path in ("/api/agent/queue/automated-testing", "/api/agent/queue/risk-hunt"):
                self._handle_queue_risk_hunt()
            elif path == "/api/agent/queue/full-app-assessment":
                self._handle_queue_campaign("full_app_assessment")
            elif path == "/api/agent/queue/try-harder":
                self._handle_queue_try_harder()
            elif path == "/api/agent/queue/clear":
                self._handle_clear_queue()
            elif path == "/api/agent/project-profile":
                self._handle_update_project_profile()
            elif path == "/api/agent/project-profile/import-notes":
                self._handle_import_project_profile_from_notes()
            elif path == "/api/agent/knowledge":
                self._handle_update_knowledge()
            elif path == "/api/agent/attack-surface":
                self._handle_update_attack_surface()
            elif path == "/api/agent/attack-surface/overwatch":
                self._handle_ai_coverage_overwatch()
            elif path == "/api/agent/attack-surface/review":
                self._handle_run_attack_surface_review()
            elif path == "/api/agent/fixtures/import-notes":
                self._handle_import_fixtures_from_notes()
            elif path == "/api/agent/fixtures":
                self._handle_upsert_fixture()
            elif path == "/api/agent/confirmations":
                self._handle_create_confirmation()
            elif path.startswith("/api/agent/queue/") and path.endswith("/claim"):
                qid = path[len("/api/agent/queue/"):-len("/claim")]
                self._handle_claim_queue(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/release"):
                qid = path[len("/api/agent/queue/"):-len("/release")]
                self._handle_release_queue(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/result"):
                qid = path[len("/api/agent/queue/"):-len("/result")]
                self._handle_queue_result(qid)
            elif path.startswith("/api/agent/results/") and path.endswith("/amend"):
                qid = path[len("/api/agent/results/"):-len("/amend")]
                self._handle_amend_completed_result(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/repeater"):
                qid = path[len("/api/agent/queue/"):-len("/repeater")]
                self._handle_send_queue_to_repeater(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/heartbeat"):
                qid = path[len("/api/agent/queue/"):-len("/heartbeat")]
                self._handle_queue_heartbeat(qid)
            elif path.startswith("/api/agent/queue/") and path.endswith("/campaign/step"):
                qid = path[len("/api/agent/queue/"):-len("/campaign/step")]
                self._handle_campaign_step(qid)
            elif path == "/api/findings/triage":
                self._handle_bulk_triage_findings()
            elif path.startswith("/api/findings/") and path.endswith("/poc-repeater"):
                fid = path[len("/api/findings/"):-len("/poc-repeater")]
                self._handle_finding_poc_repeater(fid)
            elif path.startswith("/api/findings/") and path.endswith("/triage"):
                fid = path[len("/api/findings/"):-len("/triage")]
                self._handle_triage_finding(fid)
            elif path == "/api/agent/request":
                self._handle_agent_request()
            elif path == "/api/agent/request/http2":
                self._handle_agent_request_http2()
            elif path == "/api/agent/mcp/call":
                self._handle_mcp_call()
            elif path == "/api/agent/burp/action/dry-run":
                self._handle_burp_action(execute=False)
            elif path == "/api/agent/burp/action":
                self._handle_burp_action(execute=True)
            elif self._dispatch_scanner_post(path):
                pass
            elif path == "/api/agent/campaign/crawl-audit":
                self._handle_queue_campaign("crawl_audit")
            elif path == "/api/agent/campaign/authz-matrix":
                self._handle_queue_campaign("authz_matrix")
            elif path == "/api/agent/campaign/race":
                self._handle_queue_campaign("race")
            elif path == "/api/agent/campaign/browser-dom":
                self._handle_queue_campaign("browser_dom")
            elif path == "/api/agent/campaign/parser-protocol":
                self._handle_queue_campaign("parser_protocol")
            elif path == "/api/agent/campaign/full-app-assessment":
                self._handle_queue_campaign("full_app_assessment")
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
