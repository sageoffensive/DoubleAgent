# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk3(object):
    def _enqueueTryHarder(self, user_context="", focus="", browser_verify=False, requested_by="ui", minimum_coverage_percent=50.0):
        """Queue a stronger autonomous web app pentest item."""
        if self.agent_server is None:
            self.stdout.println("[AGENT] Server not running, starting now...")
            if not self.start_agent_server():
                self.stderr.println("[AGENT] Failed to start server; cannot enqueue Try Harder")
                return None

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        browseros_enabled = bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False))
        browser_verify = bool(browser_verify) and browseros_enabled
        context_text = self._try_harder_context_text(user_context=user_context, focus=focus)
        target_finding_ids = self._automated_testing_finding_ids()
        try:
            api_view = AgentAPIHandler.__new__(AgentAPIHandler)
            api_view.extender = self
            coverage_baseline = api_view._coverage_totals_snapshot()
        except Exception:
            coverage_baseline = {
                "available": False,
                "endpoints": 0,
                "covered": 0,
                "untested": 0,
                "coverage_percent": 0.0,
                "measured_at": now
            }
        try:
            requested_floor = max(20.0, min(90.0, float(minimum_coverage_percent or 50.0)))
        except Exception:
            requested_floor = 50.0
        baseline_percent = float(coverage_baseline.get("coverage_percent", 0.0) or 0.0)
        required_coverage_percent = max(requested_floor, min(80.0, baseline_percent + 20.0))
        with self.agent_queue_lock:
            qid = self.agent_queue_next_id
            self.agent_queue_next_id += 1
            queue_item = {
                "id": qid,
                "status": "pending",
                "created_at": now,
                "claimed_at": None,
                "completed_at": None,
                "finding_ids": target_finding_ids,
                "summary": "Try Harder: autonomous web app pentest for new bugs",
                "assessment": "",
                "test_results": [],
                "notes": [],
                "user_context": context_text,
                "source": "risk_hunt",
                "mode": "try_harder",
                "browser_verify": bool(browser_verify),
                "persistent_agent_goal": {
                    "required": True,
                    "explicitly_authorized_by_user_action": True,
                    "authorization": "The user explicitly selected Try Harder, which requests a persistent agent goal for this queue item.",
                    "tool": "create_goal",
                    "check_tool": "get_goal",
                    "complete_tool": "update_goal",
                    "objective": "Complete Double Agent Try Harder queue #%d: expand Burp discovery to the required coverage and continue bounded high-value testing until one previously undiscovered High/Critical finding is confirmed, or Double Agent accepts an evidence-backed bounded/Gated negative result." % qid,
                    "create_when": "Immediately after claiming this Try Harder queue item and before preflight/discovery/testing. First call get_goal and reuse the matching active goal if one exists; otherwise call create_goal exactly once without a token budget.",
                    "keep_active_when": "Keep the persistent goal active while the Double Agent queue item is pending/claimed or while /result is rejected as incomplete.",
                    "complete_when": "Call update_goal(status=complete) only after POST /api/agent/queue/%d/result succeeds and the queue item is terminal." % qid,
                    "result_acknowledgement": "Include persistent_goal={created:true,status:'active',objective:'...'} in the Double Agent /result body. If create_goal is genuinely unavailable, include tool_unavailable=true and an exact reason."
                },
                "campaign_state": {
                    "status": "pending",
                    "steps": build_campaign_steps("try_harder"),
                    "request_budget": 200,
                    "requests_used": 0,
                    "updated_at": now
                },
                "risk_hunt": {
                    "objective": "Run a broad autonomous web app pentest and find one previously undiscovered High or Critical vulnerability using available security/web/browser skills and tools.",
                    "mode": "try_harder",
                    "requested_by": requested_by,
                    "outstanding_finding_count": len(target_finding_ids),
                    "target_new_high_or_critical_findings": 1,
                    "success_definition": "One agent-generated, valid High or Critical finding created during this queue item whose root cause and impact were not already present in findings, completed results, reviewed Scanner issues, or assessment knowledge.",
                    "discovery_contract": {
                        "required": True,
                        "coverage_baseline": coverage_baseline,
                        "minimum_coverage_percent": required_coverage_percent,
                        "minimum_pages_or_routes_browsed": 20,
                        "required_methods": ([
                            "native Burp crawl/audit when advertised by /api/agent/burp/capabilities",
                            "visible BrowserOS browsing through Burp for authenticated and client-rendered routes",
                            "Proxy history, Site Map, JavaScript/API route, and parameter coverage diff"
                        ] if browseros_enabled else [
                            "native Burp crawl/audit when advertised by /api/agent/burp/capabilities",
                            "Proxy history, Site Map, JavaScript/API route extraction, Scanner, and parameter coverage diff"
                        ]),
                        "completion": "Before a no-finding result, complete or explicitly Gate every Try Harder campaign step and raise dynamic endpoint coverage to the required percentage. Persist visited/tested URLs in campaign step artifacts so in-progress coverage is measurable."
                    },
                    "minimum_goals": 6,
                    "minimum_completed_or_blocked_goals": 5,
                    "minimum_new_discovery_goals": 6,
                    "minimum_completed_or_gated_new_discovery_goals": 5,
                    "maximum_new_discovery_goals": 10,
                    "required_goal_categories": ["new_discovery"],
                    "stop_conditions": [
                        "1 previously undiscovered High/Critical finding confirmed and posted",
                        "10 new_discovery goals tested or Gated",
                        "all remaining high-risk leads are blocked by scope, missing fixtures, approval, safety, or absent evidence",
                        "request/time budget reached with tested controls and clear remaining blockers"
                    ],
                    "required_context": [
                        "/api/agent/burp/skill",
                        "/api/agent/burp/capabilities",
                        "/api/agent/burp/workspace",
                        "/api/agent/scope",
                        "/api/agent/preflight",
                        "/api/agent/project-profile",
                        "/api/agent/knowledge",
                        "/api/agent/fixtures",
                        "/api/agent/confirmations",
                        "/api/findings",
                        "/api/coverage",
                        "/api/coverage/parameters",
                        "/api/report",
                        "/api/agent/history/http/regex"
                    ],
                    "write_back": "POST /api/findings with queue_id for confirmed new High/Critical vulnerabilities where found; Try Harder-created findings are stored with a (TH) title prefix; POST /api/agent/knowledge for useful target knowledge; POST /result with categorized risk_hunt_goals and Gated blockers.",
                    "completion": "Stop immediately after one previously undiscovered High/Critical finding is confirmed and posted. Otherwise finish rather than loop after the bounded negative-result contract is met: at least 6 goals, 6 new_discovery goals, and 5 completed or Gated new_discovery outcomes."
                }
            }
            self.agent_queue.append(queue_item)
            self.selected_agent_queue_index = len(self.agent_queue) - 1

        self.save_agent_queue()
        self.log_to_console("[AGENT] Queued Try Harder autonomous pentest as work item #%d (%d Agent A finding(s) linked)" % (qid, len(target_finding_ids)))
        self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
            self.agent_server_host, self.agent_server_port, qid))
        self._ui_dirty = True
        self.refreshUI()
        self._focus_agent_tab()
        return qid

    def _queueRiskHunt(self, event=None):
        """Queue automated active testing from the Agent AI tab."""
        try:
            self._enqueueRiskHunt(requested_by="ui")
        except Exception as e:
            self.stderr.println("[AGENT] Automated testing queue error: %s" % self._safe_ascii_text(e))

    def _queueFullAppAssessment(self, event=None):
        """Queue visible application-wide discovery and deterministic overwatch."""
        try:
            result = self._askAgentContext(
                title="Full App Assessment",
                info_text=("Queue BrowserOS discovery through Burp, map the wider application surface, and actively test prioritized gaps." if self.AGENT_BROWSEROS_ENABLED else "Map the application from Burp history, Site Map, available crawl/Scanner actions, and actively test prioritized gaps."),
                placeholder_text=(
                    "Optional context: seed page, available roles, important workflows, safe state changes, "
                    "or areas to prioritize. BrowserOS follows the Enable BrowserOS checkbox in the Agent AI tab."
                ),
                submit_label="Queue Full Assessment",
            )
            if result is None:
                return
            self._enqueueRiskCampaign(
                campaign_type="full_app_assessment",
                user_context=result.get("context", ""),
                focus="Discover and assess meaningful application surface beyond requests already selected by Agent A.",
                browser_verify=bool(self.AGENT_BROWSEROS_ENABLED),
                requested_by="ui",
                options={
                    "request_budget": 120,
                    "minimum_routes": 20,
                    "minimum_browser_routes": 10 if self.AGENT_BROWSEROS_ENABLED else 0,
                    "required_stable_passes": 2,
                    "stable_max_new_routes": 0,
                    "stable_max_new_parameters": 0,
                },
            )
        except Exception as e:
            self.stderr.println("[AGENT] Full App Assessment queue error: %s" % self._safe_ascii_text(e))

    def _queueTryHarder(self, event=None):
        """Queue a stronger autonomous web app pentest from the Agent AI tab."""
        try:
            result = self._askAgentContext(
                title="Try Harder - Autonomous Pentest",
                info_text="Queue Agent B to go beyond validation and hunt for new scoped web app bugs.",
                placeholder_text=(
                    "Optional focus, for example: 'Prioritize account takeover and IDOR', "
                    "'Ignore static-only findings unless they lead to API exposure', "
                    "'Focus on trading/account update workflows'. Leave blank for broad autonomous testing."
                )
            )
            if result is None:
                return
            self._enqueueTryHarder(
                user_context=result.get("context", ""),
                focus="Broad autonomous web app pentest; prioritize new-discovery goals over linked validation.",
                browser_verify=result.get("browser_verify", False),
                requested_by="ui"
            )
        except Exception as e:
            self.stderr.println("[AGENT] Try Harder queue error: %s" % self._safe_ascii_text(e))

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

                    flow_state = self._infer_flow_step_state(
                        idx + 1, method, url, request_data, response_data, status_code)
                    flow_requests.append({
                        "step": idx + 1,
                        "method": method,
                        "url": url,
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "status_code": status_code,
                        "flow_state": flow_state,
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
                flow_state_summary = [step.get("flow_state", {}) for step in flow_requests]

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
                    "flow_state_summary": flow_state_summary,
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

            # Create handler factory that captures extender reference
            def handler_factory(*args, **kwargs):
                return AgentAPIHandler(self, *args, **kwargs)

            server = ThreadedAgentHTTPServer((self.agent_server_host, int(self.agent_server_port)), handler_factory)
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
        self._cancel_jev_review()
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
            try:
                with self.portswigger_mcp_lock:
                    session = self.portswigger_mcp_session
                    self.portswigger_mcp_session = None
                    if session and session.get("stream") is not None:
                        session.get("stream").close()
            except Exception:
                pass
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

    def _build_agent_burp_expert_prompt(self, url):
        """Build the concise Agent B activation contract.

        Detailed Burp operating knowledge lives in the burpsuite-operator skill
        and the self-describing API. Keeping this prompt short leaves context
        for the actual assessment and avoids hard-coding volatile MCP schemas.
        """
        browseros_enabled = bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False))
        browser_rule = (
            "- BrowserOS is enabled by the operator. For browser_verify=true, use it through Burp and verify the exact URL with /api/agent/browseros/readiness.\n"
            if browseros_enabled else
            ""
        )
        browser_endpoint = (
            "Browser readiness: GET /api/agent/browseros/readiness?url=<exact-url>\n"
            if browseros_enabled else ""
        )
        return (
            "=== DOUBLE AGENT B - EXPERT BURP SUITE OPERATOR ===\n"
            "Base URL: " + url + "\n"
            "Authentication: none; this API is loopback-only.\n\n"
            "ROLE\n"
            "You are Agent B, the active-testing Burp Suite operator. Burp is the assessment workspace and the only scope authority. Operate it deliberately: inventory first, choose a real capability, baseline before mutation, compare a safe control, preserve notes/receipts, and write results back.\n\n"
            "EXPERTISE\n"
            "Fetch GET /api/agent/burp/skill and follow combined_markdown as $burpsuite-operator for this assessment. The API-delivered skill is complete; no agent skill folder or global installation is required. If that endpoint fails, use GET /api/agent/burp/capabilities, GET /api/agent/burp/workspace, and GET /api/docs as the minimum operating contract. Never invent a Burp or MCP action.\n\n"
            "STARTUP - RUN ONCE\n"
            "1. curl -s " + url + "/api/health && curl -s '" + url + "/api/docs?compact=true'\n"
            "2. curl -s " + url + "/api/agent/burp/skill | jq -r .combined_markdown  # read and follow before continuing\n"
            "3. curl -s '" + url + "/api/agent/burp/capabilities?refresh=true'\n"
            "4. curl -s '" + url + "/api/agent/burp/workspace?compact=true'\n"
            "5. curl -s '" + url + "/api/agent/scope?summary=true'\n"
            "6. curl -s " + url + "/api/agent/preflight\n"
            "7. Read paged findings, current-engagement knowledge/fixtures, confirmations, the queue index, and summary coverage. Stale engagement state is excluded by default and must not be reused implicitly.\n"
            "8. Report readiness and wait for q or a queued work item. q means fetch and continue the Burp queue; it never means quit.\n\n"
            "BURP OPERATING LOOP\n"
            "1. Treat the queue list as an index. Read detail_endpoint before claiming, then inspect full next_action, completion thresholds, protocol_profile, fixtures, scope_guard, safety_gate, browser_verify, and request budget.\n"
            "2. Search Proxy/Site Map history and prior coverage. Recover current auth through /api/agent/auth/latest before asking the user for credentials.\n"
            "3. Check the exact candidate URL with /api/agent/scope?url=<encoded-url>. Never use scope files or project notes to authorize traffic.\n"
            "4. Select an available semantic action from /api/agent/burp/capabilities. Dry-run unfamiliar/gated actions with POST /api/agent/burp/action/dry-run.\n"
            "5. Execute through POST /api/agent/burp/action with note='Agent: queue #<id> - <purpose> - <expected result>'. Use the advertised Double Agent fallback when the semantic action is unavailable. Prefer semantic actions over raw /api/agent/mcp/call.\n"
            "6. Establish a baseline before mutations. Change one meaningful variable at a time, compare a safe/expected-deny control, and stop at a defensible vulnerable/safe/inconclusive/Gated signal.\n"
            "7. Persist the semantic action receipt ID, exact request, status, response snippet/state, auth source, control comparison, and Burp history reference.\n"
            "8. Before any finding becomes valid, ensure Burp contains exactly one editable tab named 'Finding <daf_id>' with the exact confirmed request. POST /api/findings and /result create/deduplicate it automatically from request_data/poc_request; repair failures through POST /api/findings/<daf_id>/poc-repeater.\n"
            "9. POST the queue /result; POST confirmed new vulnerabilities to /api/findings; POST durable observations and tested controls to /api/agent/knowledge; verify new findings through /api/report.\n\n"
            "NON-NEGOTIABLE RULES\n"
            "- When a claimed item has mode=try_harder and persistent_agent_goal.required=true, the user's Try Harder action explicitly requests a persistent goal. Call get_goal then create_goal exactly once if needed before testing. Keep it active until Double Agent accepts /result, then call update_goal(status=complete). risk_hunt_goals do not replace it.\n"
            "- Every target curl MUST use -x http://127.0.0.1:8080 and X-Eternals-Agent-Note. Local Double Agent API calls are direct. Use generated queue curl when next_action recommends curl_proxy.\n"
            + browser_rule +
            "- Finding id is the immutable daf_... value. Supply deduplication_key on create. Recipe updates require that immutable ID plus expected_version; never use list position as identity.\n"
            "- Agent B must leave one PoC Repeater tab for every valid finding. A valid transition without an exact replayable request/tab is incomplete and will be rejected. Do not create duplicate tabs for the same finding/request.\n"
            "- HTTP/2-sensitive or pseudo-header-sensitive work uses request.send.http2 or /api/agent/request/http2; never downgrade it to HTTP/1.1 curl.\n"
            "- Prefer Repeater for editable baseline plus focused variants. Prefer direct send for one bounded probe. Use Intruder only with a concrete insertion point and bounded plan.\n"
            "- Delegate high-signal commodity insertion checks to an advertised native Scanner action or POST /api/agent/scanner/active. Poll the job and manually validate impact. Scanner output is a lead, not a finding.\n"
            "- Treat crawl.start as unavailable unless capabilities explicitly advertise it. A crawl campaign queue item does not create a missing native tool.\n"
            "- Ask before state-changing/destructive actions when the safety gate requires confirmation. Never guess actors, objects, tenants, MFA, OTP, or credentials.\n"
            "- Confirmed means a reproducible request plus response/state evidence and a relevant control. Use inconclusive for ambiguity and Gated for missing scope, fixture, approval, or capability.\n"
            "- Monitor /api/findings during long sessions and keep Agent Status, Priority, Severity, and rationale current through /api/findings/triage.\n\n"
            "KEY ENDPOINTS\n"
            "Burp skill: GET /api/agent/burp/skill\n"
            "Capabilities: GET /api/agent/burp/capabilities\n"
            "Workspace: GET /api/agent/burp/workspace\n"
            "Dry-run/execute: POST /api/agent/burp/action/dry-run and /api/agent/burp/action\n"
            "Scope: GET /api/agent/scope?url=<exact-url>\n"
            "History: GET /api/agent/history/http/regex?regex=<pattern>&count=50\n"
            + browser_endpoint +
            "Attack surface: GET/POST /api/agent/attack-surface; GET/POST /api/agent/attack-surface/review\n"
            "Scanner: POST /api/agent/scanner/active; GET /api/agent/scanner/jobs/<id>\n"
            "HTTP/2 fallback: POST /api/agent/request/http2\n"
            "Queue: GET /api/agent/queue; POST /api/agent/queue/<id>/claim; POST /api/agent/queue/<id>/result\n"
            "Finding PoC tab: POST /api/findings/<daf_id>/poc-repeater\n"
            "Full schemas and current rules: GET /api/docs\n"
        )
