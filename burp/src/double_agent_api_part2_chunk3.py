# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk2Chunk3(object):
    def _handle_queue_finding(self):
        """Queue one existing finding by immutable public ID."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "body must be an object"})
            return
        finding_ref = str(body.get("finding_id", body.get("id", "")) or "").strip()
        if not finding_ref:
            self._send_json(400, {"error": "finding_id is required"})
            return
        finding_idx = self.extender._finding_index_by_reference(finding_ref)
        if finding_idx is None:
            self._send_json(404, {"error": "finding not found", "finding_id": finding_ref})
            return
        with self.extender.findings_lock_ui:
            if finding_idx < 0 or finding_idx >= len(self.extender.findings_list):
                self._send_json(404, {"error": "finding not found", "finding_id": finding_ref})
                return
            finding = dict(self.extender.findings_list[finding_idx])
            stable_id = self.extender._ensure_finding_stable_id(
                self.extender.findings_list[finding_idx])

        with self.extender.agent_queue_lock:
            for existing in self.extender.agent_queue:
                if finding_idx in list(existing.get("finding_ids", []) or []) and \
                        existing.get("status") not in ("completed", "failed", "cancelled"):
                    self._send_json(409, {
                        "error": "finding already queued",
                        "finding_id": stable_id,
                        "queue_id": existing.get("id"),
                        "status": existing.get("status"),
                    })
                    return
            qid = self.extender.agent_queue_next_id
            self.extender.agent_queue_next_id += 1
            queue_item = {
                "id": qid,
                "status": "pending",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "claimed_at": None,
                "completed_at": None,
                "finding_ids": [finding_idx],
                "summary": self._limit_text(finding.get("title", ""), 240),
                "assessment": "",
                "test_results": [],
                "notes": [],
                "user_context": self._limit_text(body.get("context", body.get("user_context", "")), 4000),
                "source": "findings",
                "browser_verify": self._coerce_bool(body.get("browser_verify", False), False),
                "url": finding.get("url", ""),
                "request_data": finding.get("request_data"),
                "response_data": finding.get("response_data"),
            }
            self.extender.agent_queue.append(queue_item)
            self.extender.selected_agent_queue_index = len(self.extender.agent_queue) - 1

        self.extender.save_agent_queue()
        self.extender._ui_dirty = True
        self.extender.log_to_console("[AGENT] Queued finding %s as work item #%d" % (stable_id, qid))
        self._send_json(201, {
            "status": "queued",
            "id": qid,
            "source": "findings",
            "finding_id": stable_id,
            "detail_endpoint": "/api/agent/queue/%d" % qid,
        })

    def _handle_queue_risk_hunt(self):
        """Queue automated active testing from API."""
        try:
            body = self._read_body()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        context = self._limit_text(body.get("context", body.get("user_context", "")), 4000)
        focus = self._limit_text(body.get("focus", ""), 2000)
        browser_verify = bool(body.get("browser_verify", False))
        qid = self.extender._enqueueRiskHunt(
            user_context=context,
            focus=focus,
            browser_verify=browser_verify,
            requested_by="api"
        )
        if qid is None:
            self._send_json(500, {"error": "failed to queue automated testing"})
            return
        self._send_json(201, {
            "status": "queued",
            "id": qid,
            "source": "risk_hunt",
            "message": "Automated testing queued. Agent should claim it, verify every outstanding Agent A finding, update each finding or mark it Gated, and return risk_hunt_goals. One umbrella linked_validation goal is acceptable when it accounts for the full list."
        })

    def _handle_queue_campaign(self, campaign_type):
        """Queue a focused campaign work item for Agent B."""
        try:
            body = self._read_body()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        context = self._limit_text(body.get("context", body.get("user_context", "")), 4000)
        focus = self._limit_text(body.get("focus", ""), 2000)
        browser_verify = self._coerce_bool(body.get("browser_verify", False), False)
        browseros_enabled = bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False))
        if campaign_type in ("browser_dom", "full_app_assessment"):
            browser_verify = browseros_enabled
        else:
            browser_verify = bool(browser_verify) and browseros_enabled
        options = {}
        for key in ("concurrency", "repeats", "request_budget", "scan_profile", "seed_url", "host", "path", "queue_id", "finding_id",
                    "minimum_routes", "minimum_browser_routes", "required_stable_passes", "stable_max_new_routes", "stable_max_new_parameters", "expected_roles"):
            if key in body:
                options[key] = body.get(key)
        qid = self.extender._enqueueRiskCampaign(
            campaign_type=campaign_type,
            user_context=context,
            focus=focus,
            browser_verify=browser_verify,
            requested_by="api",
            options=options
        )
        if qid is None:
            self._send_json(500, {"error": "failed to queue campaign"})
            return
        surface_seed = {}
        if campaign_type == "full_app_assessment":
            surface_seed = self._seed_attack_surface_from_burp(queue_id=qid)
            self.extender.save_agent_queue()
        self._send_json(201, {
            "status": "queued",
            "id": qid,
            "source": "risk_hunt",
            "mode": "campaign_%s" % campaign_type,
            "campaign_type": campaign_type,
            "browser_verify": bool(browser_verify),
            "attack_surface_seed": surface_seed,
            "message": "Campaign queued. Agent B should claim /api/agent/queue/%d, follow the campaign contract, and write results through /api/agent/queue/%d/result." % (qid, qid)
        })

    def _handle_queue_try_harder(self):
        """Queue a stronger autonomous web app pentest from API."""
        try:
            body = self._read_body()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        context = self._limit_text(body.get("context", body.get("user_context", "")), 4000)
        focus = self._limit_text(body.get("focus", ""), 2000)
        browser_verify = bool(body.get("browser_verify", False)) and bool(
            getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False))
        try:
            minimum_coverage_percent = max(20.0, min(90.0, float(body.get("minimum_coverage_percent", 50) or 50)))
        except Exception:
            minimum_coverage_percent = 50.0
        qid = self.extender._enqueueTryHarder(
            user_context=context,
            focus=focus,
            browser_verify=browser_verify,
            requested_by="api",
            minimum_coverage_percent=minimum_coverage_percent
        )
        if qid is None:
            self._send_json(500, {"error": "failed to queue try-harder autonomous pentest"})
            return
        queued_item = self._get_queue_item_snapshot(qid) or {}
        self._send_json(201, {
            "status": "queued",
            "id": qid,
            "source": "risk_hunt",
            "mode": "try_harder",
            "minimum_coverage_percent": minimum_coverage_percent,
            "persistent_agent_goal": queued_item.get("persistent_agent_goal", {}),
            "message": "Try Harder queued. Agent should claim it, complete campaign_state discovery steps, use the operator-enabled Burp discovery methods, persist observed/tested URLs as step artifacts, and meet risk_hunt.discovery_contract coverage before a no-finding result. The success target is one previously undiscovered High or Critical vulnerability."
        })

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
        # Attach full findings detail. Immutable IDs are canonical externally;
        # retain numeric positions only as deprecated compatibility metadata.
        findings_full = self._queue_findings_full(item)
        item["findings"] = findings_full
        item["legacy_numeric_finding_ids"] = [finding.get("legacy_numeric_id") for finding in findings_full
                                              if finding.get("legacy_numeric_id") is not None]
        item["finding_stable_ids"] = [finding.get("stable_id", "") for finding in findings_full if finding.get("stable_id")]
        item["finding_ids"] = list(item["finding_stable_ids"])
        item["next_action"] = self._queue_operational_metadata(item, findings_full)
        if item["next_action"].get("recommended_transport") == "curl_proxy":
            status, curl_payload = self._build_queue_curl_payload(item, findings_full, refresh_auth=False)
            if status == 200 and curl_payload.get("commands"):
                item["target_curl"] = curl_payload.get("commands", [])[0]
        # Add reminder so agent doesn't forget about API docs during long sessions.
        if item.get("source") == "risk_hunt" and str(item.get("mode", "") or "") == "try_harder":
            item["_note_for_agent"] = "TRY HARDER: go beyond validation. Build a threat model, use available security/web/browser skills, and try to find one previously undiscovered High or Critical vulnerability. Create at least 6 category=new_discovery goals for the bounded negative-result path, safely test or Gate at least 5, and stop immediately after the single qualifying finding is confirmed and posted, or after 10 tested/Gated new-discovery goals."
        elif item.get("source") == "risk_hunt" and str(item.get("mode", "") or "").startswith("campaign_"):
            if bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
                discovery_tools = "Burp MCP and BrowserOS as instructed"
            else:
                discovery_tools = "the advertised Burp-native actions and history"
            item["_note_for_agent"] = "Campaign work item: follow user_context and next_action.attack_campaign. Use %s, re-check /api/coverage and /api/coverage/parameters where relevant, and write evidence-backed results through /result." % discovery_tools
        elif item.get("source") == "risk_hunt":
            item["_note_for_agent"] = "Automated Testing: verify every linked Agent A finding. One category=linked_validation umbrella goal is acceptable if every linked finding is updated or marked Gated. Target traffic must use Burp proxy."
        elif not item.get("next_action", {}).get("safe_to_auto_test", False):
            item["_note_for_agent"] = "Do not call /curl yet. next_action.safe_to_auto_test=false; resolve missing fixtures/confirmations or get user approval for scope/safety gates before target replay."
        else:
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

    def _local_http_probe(self, url, method="GET", payload=None, timeout_sec=2, request_headers=None):
        started = time.time()
        body = None
        headers = dict(request_headers or {})
        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"
        request = urllib2.Request(url, body, headers)
        if method and str(method).upper() != "GET":
            request.get_method = lambda: str(method).upper()
        response = None
        try:
            response = urllib2.urlopen(request, timeout=max(1, int(timeout_sec)))
            raw = response.read()
            text = raw.decode("utf-8", "replace") if hasattr(raw, "decode") else str(raw)
            parsed = None
            try:
                parsed = json.loads(text) if text else {}
            except Exception:
                parsed = None
            response_headers = {}
            try:
                for name, value in response.info().items():
                    response_headers[str(name).lower()] = str(value)
            except Exception:
                pass
            return {
                "ok": 200 <= int(response.getcode()) < 300,
                "http_status": int(response.getcode()),
                "duration_ms": int((time.time() - started) * 1000),
                "response_headers": response_headers,
                "json": parsed,
                "body_preview": self._limit_text(text, 500),
            }
        except urllib2.HTTPError as e:
            try:
                raw = e.read()
                text = raw.decode("utf-8", "replace") if hasattr(raw, "decode") else str(raw)
            except Exception:
                text = ""
            return {
                "ok": False,
                "http_status": int(getattr(e, "code", 0) or 0),
                "duration_ms": int((time.time() - started) * 1000),
                "error": self._safe_ascii_text(e, 300),
                "body_preview": self._limit_text(text, 500),
            }
        except Exception as e:
            return {
                "ok": False,
                "http_status": 0,
                "duration_ms": int((time.time() - started) * 1000),
                "error": self._safe_ascii_text(e, 300),
            }
        finally:
            try:
                if response is not None:
                    response.close()
            except Exception:
                pass

    def _proxy_history_exact_url(self, target_url, limit=20):
        indices = []
        try:
            history = self.extender.callbacks.getProxyHistory() or []
            for index in range(len(history) - 1, -1, -1):
                try:
                    observed = str(self.extender.helpers.analyzeRequest(history[index]).getUrl() or "")
                    if observed == str(target_url or ""):
                        indices.append(index)
                        if len(indices) >= limit:
                            break
                except Exception:
                    continue
        except Exception:
            pass
        return sorted(indices)

    def _handle_browseros_readiness(self, query):
        if not bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
            self._send_json(409, {
                "status": "disabled",
                "ready": False,
                "browseros_enabled": False,
                "diagnostic": "BrowserOS is disabled in Double Agent. Enable it in the Agent AI tab before using browser automation.",
                "recovery_actions": []
            })
            return
        target_url = self._query_value(query, "url", "")
        process_listener = self._check_tcp_listener("127.0.0.1", 9000, 500)
        cdp = self._local_http_probe("http://127.0.0.1:9100/json/version", timeout_sec=2)
        initialize = self._local_http_probe(
            "http://127.0.0.1:9000/mcp", "POST", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "double-agent-readiness", "version": self.extender.VERSION}}
            }, timeout_sec=3, request_headers={"Accept": "application/json, text/event-stream"})
        tools_list = {"ok": False, "skipped": True, "reason": "initialize_failed"}
        if initialize.get("ok") and not (initialize.get("json") or {}).get("error"):
            session_id = (initialize.get("response_headers", {}) or {}).get("mcp-session-id", "")
            mcp_headers = {"Accept": "application/json, text/event-stream"}
            if session_id:
                mcp_headers["Mcp-Session-Id"] = session_id
            initialized = self._local_http_probe(
                "http://127.0.0.1:9000/mcp", "POST", {
                    "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
                }, timeout_sec=2, request_headers=mcp_headers)
            tools_list = self._local_http_probe(
                "http://127.0.0.1:9000/mcp", "POST", {
                    "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
                }, timeout_sec=3, request_headers=mcp_headers)
            tools_list["session_id_present"] = bool(session_id)
            tools_list["initialized_notification"] = initialized
        tool_names = []
        try:
            tool_names = [str(tool.get("name")) for tool in
                          ((tools_list.get("json") or {}).get("result", {}) or {}).get("tools", [])
                          if isinstance(tool, dict) and tool.get("name")]
        except Exception:
            tool_names = []
        initialize_ready = bool(initialize.get("ok") and not (initialize.get("json") or {}).get("error"))
        tools_ready = bool(tools_list.get("ok") and not (tools_list.get("json") or {}).get("error") and tool_names)
        failure_stage = ""
        if not process_listener.get("reachable"):
            failure_stage = "process_listener"
        elif not cdp.get("ok"):
            failure_stage = "cdp"
        elif not initialize_ready:
            failure_stage = "mcp_initialize"
        elif not tools_ready:
            failure_stage = "mcp_tools_list"

        history_indices = self._proxy_history_exact_url(target_url) if target_url else []
        scope_guard = self._scope_guard_for_url(target_url) if target_url else {}
        proxy_verified = bool(history_indices) if target_url else True
        scope_allowed = scope_guard.get("in_scope") is True if target_url else True
        if target_url and not scope_allowed and not failure_stage:
            failure_stage = "burp_scope"
        elif target_url and not proxy_verified and not failure_stage:
            failure_stage = "burp_proxy_history_verification"
        ready = bool(process_listener.get("reachable") and cdp.get("ok") and tools_ready and scope_allowed and proxy_verified)
        status = "ready" if ready else ("degraded" if process_listener.get("reachable") or cdp.get("ok") else "unavailable")
        payload = {
            "status": status,
            "ready": ready,
            "failure_stage": failure_stage,
            "diagnostic": "BrowserOS is ready for this URL." if ready else (
                "BrowserOS process/MCP is not running." if failure_stage == "process_listener" else
                "BrowserOS CDP is unavailable." if failure_stage == "cdp" else
                "BrowserOS MCP initialize failed." if failure_stage == "mcp_initialize" else
                "BrowserOS MCP tools/list failed or returned no tools." if failure_stage == "mcp_tools_list" else
                "The exact URL is outside Burp scope." if failure_stage == "burp_scope" else
                "The exact URL has not yet been observed in Burp Proxy history."
            ),
            "process_alive": bool(process_listener.get("reachable")),
            "process_listener": process_listener,
            "cdp": cdp,
            "mcp": {
                "ready": tools_ready,
                "initialize": initialize,
                "tools_list": tools_list,
                "tool_names": tool_names,
                "failure_stage": failure_stage,
            },
            "proxy_verification": {
                "required": bool(target_url),
                "url": target_url,
                "scope_guard": scope_guard,
                "observed": proxy_verified,
                "history_indices": history_indices,
                "guidance": "Navigate the exact Burp-authorized URL in visible BrowserOS, then call this endpoint again. Browser discovery does not count until observed=true."
            },
            "recovery_actions": [
                "Relaunch BrowserOS without restarting the agent session.",
                "Include --proxy-server=http://127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100.",
                "If MCP remains unavailable but CDP is healthy, use visible computer control as a documented fallback and require proxy_verification.observed=true.",
            ],
            "recovery_contract": {
                "automatable_in_current_agent_session": bool(cdp.get("ok")),
                "human_action_required": not bool(cdp.get("ok")),
                "gated_exit_allowed": True,
                "gated_outcome": "gated",
                "blocker_code": "browseros_unavailable" if not ready else ""
            }
        }
        self._send_json(200 if ready else 503, payload)

    def _browseros_claim_preflight(self):
        if not bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
            return {
                "status": "disabled",
                "available": False,
                "browseros_enabled": False,
                "completion_impact": "none; BrowserOS requirements are omitted while disabled",
                "gated_exit_allowed": True
            }
        mcp_listener = self._check_tcp_listener("127.0.0.1", 9000, 250)
        cdp_listener = self._check_tcp_listener("127.0.0.1", 9100, 250)
        available = bool(mcp_listener.get("reachable") or cdp_listener.get("reachable"))
        return {
            "status": "available" if available else "unavailable",
            "available": available,
            "mcp_listener": mcp_listener,
            "cdp_listener": cdp_listener,
            "completion_impact": "browser thresholds can be attempted" if available else "browser-required thresholds are currently unsatisfiable; recover BrowserOS now or submit outcome=gated with exact browser blocker evidence",
            "readiness_endpoint": "/api/agent/browseros/readiness?url=<encoded-exact-url>",
            "gated_exit_allowed": True
        }

    def _handle_agent_preflight(self, query):
        host_filter = self._query_value(query, "host", "").lower()
        scope_url = self._query_value(query, "url", "")
        include_auth = bool(host_filter)
        with self.extender.agent_queue_lock:
            pending = sum(1 for q in self.extender.agent_queue if q.get("status") == "pending")
            claimed = sum(1 for q in self.extender.agent_queue if q.get("status") == "claimed")
            total = len(self.extender.agent_queue)
        profile = getattr(self.extender, "project_profile", {}) or {}
        if not self.extender._engagement_bound_record_is_current(profile):
            profile = {}
        current_fixtures = [item for item in (getattr(self.extender, "test_fixtures", []) or [])
                            if self.extender._engagement_bound_record_is_current(item)]
        current_confirmations = [item for item in (getattr(self.extender, "human_confirmations", []) or [])
                                 if self.extender._engagement_bound_record_is_current(item)]
        knowledge_entries = ((getattr(self.extender, "assessment_knowledge", {}) or {}).get("entries", []) or [])
        current_knowledge = [item for item in knowledge_entries
                             if self.extender._engagement_bound_record_is_current(item)]
        checks = {
            "api": {"reachable": True, "version": getattr(self.extender, "VERSION", "3.0")},
            "burp_proxy_listener": self._check_tcp_listener("127.0.0.1", 8080),
            "portswigger_mcp": self._portswigger_mcp_status(),
            "workspace_files": {
                "findings.md": self._workspace_file_status("findings.md", 300)
            },
            "burp_scope": {
                "source": "burp_suite",
                "authoritative": True,
                "candidate": self._scope_guard_for_url(scope_url) if scope_url else {},
                "inventory": self._burp_scope_snapshot(100)
            },
            "project_profile": {
                "allowed_state_changes": list(profile.get("allowed_state_changes", []) or []),
                "auth_schemes_hosts": sorted(list((profile.get("auth_schemes", {}) or {}).keys())),
                "updated_at": profile.get("updated_at", "")
            },
            "queue": {"total": total, "pending": pending, "claimed": claimed},
            "fixtures": {"counts": self._fixture_counts(), "total": len(current_fixtures)},
            "confirmations": {"total": len(current_confirmations)},
            "knowledge": {"total": len(current_knowledge)}
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
        if not checks["portswigger_mcp"].get("reachable"):
            warnings.append("PortSwigger/Burp MCP is not reachable at %s; HTTP/2-sensitive work cannot run until the listener is available." % checks["portswigger_mcp"].get("url", "http://127.0.0.1:9876/"))
        elif not checks["portswigger_mcp"].get("protocol_ready"):
            warnings.append("PortSwigger MCP is network-reachable but tools are not discovered, so MCP semantic actions are unavailable. Double Agent callback/API fallbacks such as PoC Repeater creation remain usable. Do not block HTTP/2 work on discovery alone: execution-test /api/agent/request/http2 once before recording a blocker.")
        if not checks["burp_scope"]["inventory"].get("available"):
            warnings.append("Burp Suite scope could not be queried; active testing must wait until Burp scope is available.")
        if scope_url and checks["burp_scope"]["candidate"].get("in_scope") is False:
            warnings.append("Burp Suite reports the supplied exact URL outside scope; do not send target traffic.")
        if include_auth and not checks.get("auth_latest", {}).get("usable"):
            warnings.append("No usable auth material found in Burp history for %s." % host_filter)
        self._send_json(200, {
            "status": "ok" if not warnings else "warn",
            "checks": checks,
            "warnings": warnings,
            "next_steps": [
                "Use /api/agent/scope for Burp Suite's authoritative scope inventory and exact URL checks.",
                "Use /api/agent/project-profile for auth schemes, roles, and allowed state-changing actions; it does not define scope.",
                "Read and update /api/agent/knowledge for durable target notes, risk leads, assumptions, and tested controls.",
                "Check saved test context via /api/agent/fixtures before IDOR, tenant, MFA, OTP, or role-bound testing.",
                "Use /api/agent/confirmations to record human-confirmed OTP/SMS/email receipt evidence.",
                "Use /api/agent/queue/<id>/curl?refresh_auth=true for curl-capable target HTTP requests.",
                "Use /api/agent/request/http2 or PortSwigger MCP send_http2_request for HTTP/2-only or pseudo-header-sensitive tests; do not downgrade those to HTTP/1.1 curl.",
                "Run generated target curl commands as-is; they include -x http://127.0.0.1:8080 and X-Eternals-Agent-Note. Automated Testing has no generated curl; hand-build scoped Burp-proxied requests instead.",
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
                    browseros_preflight = {}
                    if bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)) and (q.get("browser_verify") or str(q.get("campaign_type", "")) in ("full_app_assessment", "browser_dom")):
                        browseros_preflight = self._browseros_claim_preflight()
                        q["browseros_claim_preflight"] = browseros_preflight
                        if not browseros_preflight.get("available"):
                            q.setdefault("runtime_blockers", []).append({
                                "code": "browseros_unavailable",
                                "detail": browseros_preflight.get("completion_impact", "BrowserOS unavailable at claim time"),
                                "observed_at": now_str
                            })
                    if str(q.get("campaign_type", "")) == "full_app_assessment":
                        q["passive_scan_policy"] = self.extender._set_full_app_passive_scan(qid, True)
                    self.extender._ui_dirty = True
                    self.extender._agent_queue_save_pending = True
                    timeout_sec = int(getattr(self.extender, "AGENT_CLAIM_TIMEOUT_SEC", 900))
                    self._send_json(200, {
                        "status": "claimed",
                        "id": qid,
                        "heartbeat_required_within_seconds": timeout_sec,
                        "heartbeat_url": "/api/agent/queue/%d/heartbeat" % qid,
                        "browseros_preflight": browseros_preflight,
                        "passive_scan_policy": q.get("passive_scan_policy", {}),
                        "completion_contract": {
                            "write_back_auto_completed_on_result": True,
                            "overwatch_review_auto_completed_when_review_runs": True,
                            "gated_is_first_class_outcome": True
                        }
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
                    was_claimed = q.get("status") == "claimed"
                    q["status"] = "pending"
                    q["claimed_at"] = None
                    if was_claimed and str(q.get("campaign_type", "")) == "full_app_assessment":
                        q["passive_scan_policy"] = self.extender._set_full_app_passive_scan(qid, False)
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

    def _handle_campaign_step(self, qid):
        try:
            qid = int(qid)
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid campaign step update", "message": str(e)})
            return
        step_ref = body.get("step_id", body.get("step", body.get("key", "")))
        status = str(body.get("status", "completed") or "completed").strip().lower()
        if status not in ("pending", "running", "completed", "blocked", "failed", "skipped"):
            self._send_json(400, {"error": "invalid campaign step status"})
            return
        artifacts = self._limit_list(body.get("artifacts", []), 50)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated = None
        with self.extender.agent_queue_lock:
            for item in self.extender.agent_queue:
                if item.get("id") != qid:
                    continue
                state = item.get("campaign_state", {}) or {}
                steps = state.get("steps", []) or []
                for step in steps:
                    if str(step.get("id")) != str(step_ref) and str(step.get("key")) != str(step_ref):
                        continue
                    step_key = str(step.get("key", "") or "")
                    transition_error = self._full_app_scanner_step_transition_error(
                        item, step_key, status, body, artifacts)
                    if transition_error:
                        transition_error = dict(transition_error)
                        response_status = int(transition_error.pop("status", 409))
                        self._send_json(response_status, transition_error)
                        return
                    step["status"] = status
                    step["updated_at"] = now
                    step["artifacts"] = [self._limit_text(artifact, 2000) if not isinstance(artifact, dict) else artifact for artifact in artifacts]
                    if body.get("note"):
                        step["note"] = self._limit_text(body.get("note"), 2000)
                    try:
                        request_count = max(0, int(body.get("requests_used", 0) or 0))
                    except Exception:
                        request_count = 0
                    state["requests_used"] = int(state.get("requests_used", 0) or 0) + request_count
                    state["updated_at"] = now
                    if str(step.get("key", "")) in ("surface_baseline", "surface_diff"):
                        snapshots = list(state.get("surface_snapshots", []) or [])
                        snapshots.append({
                            "kind": str(step.get("key", "")),
                            "recorded_at": now,
                            "snapshot": self._attack_surface_snapshot(),
                        })
                        state["surface_snapshots"] = snapshots[-50:]
                    pending = [candidate for candidate in steps if candidate.get("required", True) and candidate.get("status") not in ("completed", "blocked", "skipped")]
                    state["status"] = "completed" if not pending else ("running" if status != "pending" else "pending")
                    item["campaign_state"] = state
                    item["last_heartbeat_at"] = now
                    updated = dict(step)
                    self.extender._agent_queue_save_pending = True
                    self.extender._ui_dirty = True
                    break
                break
        if updated is None:
            self._send_json(404, {"error": "campaign or step not found"})
            return
        self.extender.save_agent_queue()
        self._send_json(200, {"status": "updated", "queue_id": qid, "campaign_step": updated})

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
