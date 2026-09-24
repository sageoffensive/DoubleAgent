# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk4Chunk2(object):
    def _portswigger_mcp_rpc(self, method, params=None, timeout_sec=12, retry=True, fresh_session=False):
        with self.extender.portswigger_mcp_lock:
            if fresh_session:
                self._close_portswigger_mcp_session()
            try:
                session = getattr(self.extender, "portswigger_mcp_session", None)
                if not session:
                    session = self._open_portswigger_mcp_session(timeout_sec)
                request_id = int(session.get("next_id", 2))
                session["next_id"] = request_id + 1
                self._mcp_post_json(session.get("session_url"), {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params or {}
                }, timeout_sec)
                # Each protocol phase gets its own timeout budget.  The old
                # shared deadline included SSE connect + initialize + tools
                # POST, causing an otherwise healthy response to be discarded
                # when setup consumed most of the four-second discovery window.
                deadline = time.time() + max(3, int(timeout_sec))
                msg = self._mcp_read_message(session.get("stream"), request_id, deadline)
                session["last_used_at"] = time.time()
                return msg.get("result", {})
            except Exception:
                self._close_portswigger_mcp_session()
                if retry:
                    return self._portswigger_mcp_rpc(
                        method, params, timeout_sec, retry=False, fresh_session=True)
                raise
            finally:
                if fresh_session:
                    self._close_portswigger_mcp_session()

    def _portswigger_mcp_discover_tools(self, force=False, timeout_sec=8):
        cached = getattr(self.extender, "portswigger_mcp_capabilities", {}) or {}
        if cached.get("tools") and not force:
            return cached
        started_at = time.time()
        try:
            result = self._portswigger_mcp_rpc(
                "tools/list", {}, max(3, min(12, int(timeout_sec))), retry=False, fresh_session=True)
            tools = []
            for tool in result.get("tools", []) or []:
                if not isinstance(tool, dict) or not tool.get("name"):
                    continue
                tools.append({
                    "name": str(tool.get("name")),
                    "description": self._limit_text(tool.get("description", ""), 500),
                    "inputSchema": tool.get("inputSchema", tool.get("input_schema", {})) or {},
                    "classification": mcp_tool_policy(
                        tool.get("name", ""),
                        tool.get("description", ""),
                        tool.get("inputSchema", tool.get("input_schema", {})) or {}
                    ).get("classification"),
                    "policy": mcp_tool_policy(
                        tool.get("name", ""),
                        tool.get("description", ""),
                        tool.get("inputSchema", tool.get("input_schema", {})) or {}
                    )
                })
            capabilities = {
                "tools": tools,
                "tool_names": [tool.get("name") for tool in tools],
                "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_success_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_probe_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "discovery_ms": int((time.time() - started_at) * 1000),
                "stale": False,
                "error": "",
                "failure_stage": "",
            }
            self.extender.portswigger_mcp_capabilities = capabilities
            return capabilities
        except Exception as e:
            capabilities = dict(cached)
            capabilities.setdefault("tools", [])
            capabilities.setdefault("tool_names", [tool.get("name") for tool in capabilities.get("tools", []) if isinstance(tool, dict)])
            capabilities["last_probe_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            capabilities["last_probe_ms"] = int((time.time() - started_at) * 1000)
            capabilities["stale"] = bool(capabilities.get("tools"))
            capabilities["error"] = self._safe_ascii_text(e, 500)
            capabilities["failure_stage"] = "tools_list"
            self.extender.portswigger_mcp_capabilities = capabilities
            return capabilities

    def _start_portswigger_capability_refresh(self):
        with self.extender.portswigger_mcp_refresh_lock:
            if bool(getattr(self.extender, "portswigger_mcp_refresh_in_progress", False)):
                return False
            self.extender.portswigger_mcp_refresh_in_progress = True

        def run_refresh():
            try:
                self._portswigger_mcp_discover_tools(force=True, timeout_sec=8)
            finally:
                with self.extender.portswigger_mcp_refresh_lock:
                    self.extender.portswigger_mcp_refresh_in_progress = False

        worker = threading.Thread(target=run_refresh, name="double-agent-mcp-capability-refresh")
        worker.setDaemon(True)
        worker.start()
        return True

    def _portswigger_mcp_call_tool(self, tool_name, arguments, timeout_sec=12):
        capabilities = getattr(self.extender, "portswigger_mcp_capabilities", {}) or {}
        if tool_name != "send_http2_request" and not capabilities.get("tools"):
            capabilities = self._portswigger_mcp_discover_tools(False, min(timeout_sec, 8))
        names = capabilities.get("tool_names", []) or []
        if names and tool_name not in names:
            raise Exception("PortSwigger MCP tool is unavailable: %s" % tool_name)
        return self._portswigger_mcp_rpc("tools/call", {
            "name": tool_name,
            "arguments": arguments or {}
        }, timeout_sec, fresh_session=True)

    def _handle_mcp_capabilities(self, query):
        force = self._bool_query_value(query, "refresh", "false")
        refresh_started = self._start_portswigger_capability_refresh() if force else False
        capabilities = dict(getattr(self.extender, "portswigger_mcp_capabilities", {}) or {})
        status = 200
        self._send_json(status, {
            "status": "ready" if capabilities.get("tools") and not capabilities.get("stale") else ("stale" if capabilities.get("tools") else "degraded"),
            "mcp_url": str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "")),
            "capabilities": capabilities,
            "refresh": {"requested": force, "started": refresh_started,
                        "in_progress": bool(getattr(self.extender, "portswigger_mcp_refresh_in_progress", False))}
        })

    def _mcp_tool_definition(self, capabilities, tool_name):
        for tool in (capabilities or {}).get("tools", []) or []:
            if str(tool.get("name", "")) == str(tool_name or ""):
                return tool
        return {}

    def _burp_fallback_capabilities(self):
        repeater_callback = bool(hasattr(self.extender.callbacks, "sendToRepeater"))
        scanner_callback = bool(hasattr(self.extender.callbacks, "doActiveScan"))
        mcp_status = self._portswigger_mcp_status()
        http2_available = bool(mcp_status.get("reachable"))
        collaborator_available = bool(
            getattr(self.extender, "collaborator", None) is not None or
            hasattr(self.extender.callbacks, "createBurpCollaboratorClient") or
            hasattr(self.extender.callbacks, "createBurpCollaboratorClientContext")
        )
        return [
            {"action": "scope.check", "available": True, "transport": "double_agent_api", "endpoint": "GET /api/agent/scope?url=<exact-url>", "classification": "read_only"},
            {"action": "workspace.read", "available": True, "transport": "double_agent_api", "endpoint": "GET /api/agent/burp/workspace", "classification": "read_only"},
            {"action": "history.http.search", "available": True, "transport": "double_agent_api", "endpoint": "GET /api/agent/history/http/regex", "classification": "read_only"},
            {"action": "repeater.queue.create", "available": repeater_callback, "execution_verified": repeater_callback, "transport": "callbacks.sendToRepeater", "endpoint": "POST /api/agent/queue/<id>/repeater", "classification": "active"},
            {"action": "repeater.finding.create", "available": repeater_callback, "execution_verified": repeater_callback, "transport": "callbacks.sendToRepeater", "endpoint": "POST /api/findings/<daf_id>/poc-repeater", "classification": "active"},
            {"action": "scanner.active.start", "available": scanner_callback, "execution_verified": scanner_callback, "transport": "double_agent_api", "endpoint": "POST /api/agent/scanner/active", "classification": "active", "reason": "" if scanner_callback else "Burp's active-scan callback is unavailable."},
            {"action": "scanner.jobs.list", "available": True, "transport": "double_agent_api", "endpoint": "GET /api/agent/scanner/jobs", "classification": "read_only"},
            {"action": "request.send.http2", "available": http2_available, "execution_verified": bool(mcp_status.get("last_success_at")), "transport": "double_agent_api" if http2_available else "unavailable", "endpoint": "POST /api/agent/request/http2", "classification": "active", "reason": "" if http2_available else "PortSwigger MCP is not reachable; HTTP/2 and pseudo-header-sensitive execution is unavailable."},
            {"action": "collaborator.generate", "available": collaborator_available, "transport": "double_agent_api", "endpoint": "GET /api/agent/collaborator", "classification": "read_only"},
            {"action": "collaborator.poll", "available": bool(self.extender.collaborator is not None), "transport": "double_agent_api", "endpoint": "GET /api/agent/collaborator/interactions", "classification": "read_only"},
            {"action": "crawl.start", "available": False, "transport": "unavailable", "reason": "The connected PortSwigger MCP does not expose crawl/audit start. Queue /api/agent/campaign/crawl-audit only when a native crawl capability is discovered or a human will run the crawl."},
        ]

    def _handle_burp_capabilities(self, query):
        stage = "start"
        try:
            force = self._bool_query_value(query, "refresh", "false")
            stage = "refresh"
            refresh_started = self._start_portswigger_capability_refresh() if force else False
            capabilities = dict(getattr(self.extender, "portswigger_mcp_capabilities", {}) or {})
            stage = "semantic"
            semantic = semantic_burp_capabilities(capabilities.get("tools", []))
            stage = "fallbacks"
            fallbacks = self._burp_fallback_capabilities()
            callback_ready = bool(hasattr(self.extender.callbacks, "sendToRepeater"))
            probe_metadata = {
                "last_success_at": capabilities.get("last_success_at", ""),
                "last_probe_at": capabilities.get("last_probe_at", ""),
                "duration_ms": capabilities.get("last_probe_ms", capabilities.get("discovery_ms")),
                "stale": bool(capabilities.get("stale", False)),
                "failure_stage": capabilities.get("failure_stage", ""),
                "failure_reason": capabilities.get("error", ""),
            }
            for capability in semantic:
                capability["probe"] = dict(probe_metadata)
            effective_actions = []
            for item in semantic:
                effective = dict(item)
                effective["source"] = "portswigger_mcp"
                effective_actions.append(effective)
            for item in fallbacks:
                effective = dict(item)
                effective["source"] = "double_agent_fallback"
                effective_actions.append(effective)
            stage = "response"
            self._send_json(200, {
            "status": "ready" if capabilities.get("tools") and not capabilities.get("stale") else ("stale_with_fallbacks" if capabilities.get("tools") else ("ready_with_fallbacks" if callback_ready else "degraded")),
            "refresh": {"requested": force, "started": refresh_started,
                        "in_progress": bool(getattr(self.extender, "portswigger_mcp_refresh_in_progress", False))},
            "profile": {
                "name": "burpsuite-operator",
                "version": "1.0.0",
                "required_for_agent_b": True,
                "skill_endpoint": "/api/agent/burp/skill",
                "installation_required": False,
                "operating_loop": [
                    "inventory workspace and authoritative scope",
                    "select the smallest appropriate Burp action",
                    "establish a baseline before mutation",
                    "record a Burp-visible note for active work",
                    "compare vulnerable and safe controls",
                    "persist evidence and coverage"
                ]
            },
            "semantic_actions": semantic,
            "double_agent_fallbacks": fallbacks,
            "effective_actions": effective_actions,
            "execution_paths": {
                "portswigger_mcp": {
                    "network_reachable": self._check_tcp_listener("127.0.0.1", 9876, 250).get("reachable", False),
                    "protocol_ready": bool(capabilities.get("tools")),
                    "tools_discovered": bool(capabilities.get("tool_names")),
                    "execution_verified": bool(capabilities.get("last_success_at"))
                },
                "burp_callbacks": {
                    "available": callback_ready,
                    "repeater_create": callback_ready,
                    "execution_verified": callback_ready,
                    "transport": "callbacks.sendToRepeater"
                }
            },
            "raw_mcp": {
                "url": str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "")),
                "tool_names": capabilities.get("tool_names", []),
                "discovered_at": capabilities.get("discovered_at", ""),
                "last_success_at": capabilities.get("last_success_at", ""),
                "last_probe_at": capabilities.get("last_probe_at", ""),
                "probe_duration_ms": capabilities.get("last_probe_ms", capabilities.get("discovery_ms")),
                "stale": bool(capabilities.get("stale", False)),
                "failure_stage": capabilities.get("failure_stage", ""),
                "error": capabilities.get("error", "")
            },
                "guidance": "Choose from effective_actions. MCP discovery state applies only to the PortSwigger MCP path; working Burp callback fallbacks remain available and are reported separately. Never invent a capability."
            })
        except:
            try:
                import sys
                problem = sys.exc_info()[1]
            except:
                problem = "unknown capability error"
            self._send_json(500, {
                "error": "burp_capability_inventory_failed",
                "stage": stage,
                "message": self._safe_ascii_text(problem, 1000)
            })

    def _handle_burp_skill(self, query):
        try:
            extension_dir = self.extender._extension_working_directory()
            skill_dir = os.path.join(extension_dir, "skills", "burpsuite-operator")
            package = build_burpsuite_operator_package(skill_dir)
        except Exception as e:
            self._send_json(503, {
                "error": "burpsuite_operator_skill_unavailable",
                "message": self._safe_ascii_text(e, 500),
                "expected_source": "<extension-directory>/skills/burpsuite-operator",
                "fallback": "Use /api/agent/burp/capabilities, /api/agent/burp/workspace, and /api/docs as the minimum Agent B operating contract."
            })
            return

        browseros_enabled = bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False))
        if not browseros_enabled:
            for item in package.get("documents", []) or []:
                content = unicode_text(item.get("content", u"") or u"")
                item["content"] = u"\n".join([
                    line for line in content.splitlines()
                    if "browseros" not in line.lower()
                ])
            combined = unicode_text(package.get("combined_markdown", u"") or u"")
            package["combined_markdown"] = u"\n".join([
                line for line in combined.splitlines()
                if "browseros" not in line.lower()
            ])
        package["browseros_enabled"] = browseros_enabled

        document = self._query_value(query, "document", "")
        if document:
            selected = None
            for item in package.get("documents", []):
                if item.get("path") == document:
                    selected = item
                    break
            if selected is None:
                self._send_json(404, {
                    "error": "skill_document_not_found",
                    "document": document,
                    "available_documents": package.get("load_order", [])
                })
                return
            self._send_json(200, {
                "status": "ok",
                "name": package.get("name"),
                "version": package.get("version"),
                "content_sha256": package.get("content_sha256"),
                "document": selected,
                "usage": "Treat document.content as Agent B operating instructions for this session. No local skill installation is required."
            })
            return

        package["status"] = "ok"
        package["content_source"] = package.get("source", "")
        package["source"] = "double_agent_api"
        package["usage"] = (
            "Read combined_markdown in load_order and follow it as the $burpsuite-operator skill for this session. "
            "No ~/.codex/skills, ~/.claude/skills, or project agent folder is required."
        )
        package["fetch_command"] = "curl -s http://127.0.0.1:8777/api/agent/burp/skill | jq -r .combined_markdown"
        self._send_json(200, package)

    def _recent_burp_history_summary(self, limit=25):
        try:
            limit = max(1, min(100, int(limit)))
        except Exception:
            limit = 25
        items = []
        try:
            history = self.extender.callbacks.getProxyHistory() or []
            helpers = self.extender.helpers
            for index in range(len(history) - 1, -1, -1):
                if len(items) >= limit:
                    break
                try:
                    entry = history[index]
                    req_info = helpers.analyzeRequest(entry)
                    item = {
                        "history_index": index,
                        "method": str(req_info.getMethod() or ""),
                        "url": str(req_info.getUrl() or ""),
                        "has_response": entry.getResponse() is not None,
                        "comment": self._limit_text(entry.getComment() or "", 300)
                    }
                    if entry.getResponse() is not None:
                        try:
                            item["status_code"] = int(helpers.analyzeResponse(entry.getResponse()).getStatusCode())
                        except Exception:
                            item["status_code"] = None
                    items.append(item)
                except Exception:
                    continue
        except Exception:
            return []
        return items

    def _handle_burp_workspace(self, query):
        compact = self._bool_query_value(query, "compact", "false")
        try:
            history_limit = int(self._query_value(query, "history_limit", "25"))
        except Exception:
            history_limit = 25
        try:
            scope_limit = int(self._query_value(query, "scope_limit", "200"))
        except Exception:
            scope_limit = 200
        with self.extender.agent_queue_lock:
            queue_items = list(self.extender.agent_queue)
        with self.extender.scanner_jobs_lock:
            scanner_jobs = [self._serialize_scanner_job(job_id, job) for job_id, job in self.extender.scanner_jobs.items()]
        findings = list(getattr(self.extender, "findings_list", []) or [])
        with self.extender.attack_surface_lock:
            attack_surface_entries = list((getattr(self.extender, "attack_surface", {}) or {}).get("entries", []) or [])
        self._send_json(200, {
            "status": "ok",
            "engagement": self.extender._active_engagement_context(),
            "compact": compact,
            "scope": self._burp_scope_snapshot(min(scope_limit, 10) if compact else scope_limit),
            "recent_proxy_history": [] if compact else self._recent_burp_history_summary(history_limit),
            "counts": {
                "findings": len(findings),
                "agent_a_findings": len([item for item in findings if str(item.get("agent_validated_by", "A")) != "B"]),
                "queue_pending": len([item for item in queue_items if item.get("status") == "pending"]),
                "queue_claimed": len([item for item in queue_items if item.get("status") == "claimed"]),
                "scanner_jobs": len(scanner_jobs),
                "attack_surface_routes": len(attack_surface_entries)
            },
            "scanner_jobs": [] if compact else scanner_jobs[:25],
            "next": [
                "Read /api/coverage and /api/coverage/parameters for test gaps.",
                "Read /api/findings, /api/agent/knowledge, and /api/agent/attack-surface before active testing.",
                "Use /api/agent/burp/capabilities before choosing a native Burp action."
            ]
        })

    def _mcp_target_url_from_arguments(self, arguments):
        target = extract_mcp_target(arguments)
        return target.get("url", ""), target.get("method", "GET")

    def _mcp_action_policy(self, capabilities, tool_name):
        tool = self._mcp_tool_definition(capabilities, tool_name)
        if tool.get("policy"):
            return tool.get("policy")
        return mcp_tool_policy(
            tool_name,
            tool.get("description", ""),
            tool.get("inputSchema", {})
        )

    def _mcp_action_gate(self, capabilities, tool_name, arguments, confirmed):
        policy = self._mcp_action_policy(capabilities, tool_name)
        classification = policy.get("classification", "destructive")
        tool_definition = self._mcp_tool_definition(capabilities, tool_name)
        schema = tool_definition.get("inputSchema", {}) if isinstance(tool_definition, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []
        missing = [key for key in required if key not in arguments]
        if missing:
            return 400, {
                "error": "mcp_arguments_invalid",
                "tool_name": tool_name,
                "missing_required_arguments": missing,
                "input_schema": schema
            }
        target = extract_mcp_target(arguments)
        target_url = target.get("url", "")
        method = target.get("method", "GET")
        scope_guard = self._scope_guard_for_url(target_url) if target_url else {}
        if target_url and policy.get("executes_target_request"):
            safety_gate = self._safety_gate_for_request(method, target_url)
        elif target_url:
            safety_gate = {
                "safe_to_auto_test": True,
                "requires_confirmation": False,
                "reason": "This Burp workspace action prepares a target-bound item but does not send target traffic."
            }
        else:
            safety_gate = {}

        if policy.get("target_required") and not target_url:
            return 400, {
                "error": "mcp_target_required",
                "tool_name": tool_name,
                "policy": policy,
                "target": target,
                "message": "The target could not be extracted from the MCP arguments, so Burp scope cannot be enforced. Provide targetHostname/service plus path/pseudoHeaders, an exact URL, or a raw request with Host."
            }
        if classification == "destructive" and not confirmed:
            return 409, {
                "error": "mcp_destructive_confirmation_required",
                "tool_name": tool_name,
                "classification": classification,
                "policy": policy
            }
        if target_url and scope_guard.get("in_scope") is False:
            return 403, {"error": "out_of_scope", "scope_guard": scope_guard, "target": target}
        if target_url and (scope_guard.get("requires_confirmation") or safety_gate.get("requires_confirmation")) and not confirmed:
            return 409, {
                "error": "mcp_action_confirmation_required",
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "target": target
            }
        return 200, {
            "tool_name": tool_name,
            "classification": classification,
            "policy": policy,
            "target": target,
            "scope_guard": scope_guard,
            "safety_gate": safety_gate
        }

    def _prepare_burp_action_arguments(self, tool_name, arguments, note):
        prepared = dict(arguments or {})
        note = self._limit_text(note, 250)
        if note and not note.lower().startswith("agent:"):
            note = "Agent: " + note
        if not note:
            return prepared, note

        if tool_name in ("send_http2_request", "create_repeater_tab_http2"):
            headers = dict(prepared.get("headers", {}) or {})
            headers["X-Eternals-Agent-Note"] = note
            prepared["headers"] = headers
        elif tool_name in ("send_http1_request", "create_repeater_tab", "send_to_intruder"):
            content = prepared.get("content", "")
            if content:
                mutation = apply_raw_http_mutation(content, {
                    "label": "Double Agent Burp history note",
                    "type": "set_header",
                    "name": "X-Eternals-Agent-Note",
                    "value": note
                })
                if mutation.get("applied"):
                    prepared["content"] = mutation.get("raw_request", content)
        if tool_name in ("create_repeater_tab", "create_repeater_tab_http2") and not prepared.get("tabName"):
            prepared["tabName"] = self._limit_text(note.replace("Agent: ", "Agent B - ", 1), 80)
        return prepared, note

    def _semantic_tool_for_action(self, capabilities, action):
        for item in semantic_burp_capabilities((capabilities or {}).get("tools", [])):
            if item.get("action") == action and item.get("available"):
                return item.get("tool_name"), item
        return "", {}

    def _burp_action_fallback(self, action):
        for item in self._burp_fallback_capabilities():
            if item.get("action") == action:
                return item
        return {}

    def _handle_burp_action(self, execute=True):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return
        action = str(body.get("action", "") or "").strip()
        arguments = body.get("arguments", {}) or {}
        confirmed = self._coerce_bool(body.get("confirmed", False), False)
        note = str(body.get("note", body.get("comment", "")) or "").strip()
        if not action or not isinstance(arguments, dict):
            self._send_json(400, {"error": "action and object arguments are required"})
            return

        capabilities = self._portswigger_mcp_discover_tools(False)
        tool_name, semantic = self._semantic_tool_for_action(capabilities, action)
        if not tool_name:
            fallback = self._burp_action_fallback(action)
            self._send_json(501, {
                "error": "burp_action_unavailable",
                "action": action,
                "fallback": fallback,
                "available_actions": [item.get("action") for item in semantic_burp_capabilities(capabilities.get("tools", [])) if item.get("available")]
            })
            return

        prepared, normalized_note = self._prepare_burp_action_arguments(tool_name, arguments, note)
        status, plan = self._mcp_action_gate(capabilities, tool_name, prepared, confirmed)
        receipt = {
            "id": "burp_action_" + uuid.uuid4().hex,
            "action": action,
            "tool_name": tool_name,
            "transport": "portswigger_mcp",
            "classification": plan.get("classification", semantic.get("classification", "")),
            "target": plan.get("target", {}),
            "scope_guard": plan.get("scope_guard", {}),
            "safety_gate": plan.get("safety_gate", {}),
            "note": normalized_note,
            "executed": False,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        if status != 200:
            plan["action"] = action
            plan["receipt"] = receipt
            self._send_json(status, plan)
            return
        if plan.get("classification") == "active" and not normalized_note:
            self._send_json(400, {
                "error": "burp_action_note_required",
                "action": action,
                "message": "Active Burp actions require note='Agent: <work item> - <purpose> - <expected result>' so the operation remains auditable.",
                "receipt": receipt
            })
            return
        if not execute:
            receipt["status"] = "ready"
            self._send_json(200, {"status": "ready", "receipt": receipt, "arguments": prepared})
            return
        try:
            result = self._portswigger_mcp_call_tool(tool_name, prepared)
            receipt["executed"] = True
            receipt["status"] = "ok"
            receipt["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._send_json(200, {"status": "ok", "receipt": receipt, "result": result})
        except Exception as e:
            receipt["status"] = "failed"
            receipt["error"] = self._safe_ascii_text(e, 1000)
            self._send_json(503, {"error": "burp_action_failed", "receipt": receipt})

    def _handle_mcp_call(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return
        tool_name = str(body.get("tool_name", body.get("name", "")) or "").strip()
        arguments = body.get("arguments", {}) or {}
        if not tool_name or not isinstance(arguments, dict):
            self._send_json(400, {"error": "tool_name and object arguments are required"})
            return
        capabilities = self._portswigger_mcp_discover_tools(False)
        if tool_name not in (capabilities.get("tool_names", []) or []):
            self._send_json(404, {
                "error": "mcp_tool_unavailable",
                "tool_name": tool_name,
                "available_tools": capabilities.get("tool_names", [])
            })
            return
        confirmed = self._coerce_bool(body.get("confirmed", False), False)
        status, plan = self._mcp_action_gate(capabilities, tool_name, arguments, confirmed)
        if status != 200:
            self._send_json(status, plan)
            return
        try:
            result = self._portswigger_mcp_call_tool(tool_name, arguments)
            self._send_json(200, {
                "status": "ok",
                "tool_name": tool_name,
                "classification": plan.get("classification"),
                "policy": plan.get("policy"),
                "target": plan.get("target"),
                "scope_guard": plan.get("scope_guard"),
                "safety_gate": plan.get("safety_gate"),
                "result": result
            })
        except Exception as e:
            self._send_json(503, {"error": "mcp_tool_call_failed", "message": self._safe_ascii_text(e, 1000)})

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

        comment = self._limit_text(body.get("comment", body.get("note", "")), 250)
        clean_headers = {}
        for name, value in headers.items():
            name_s = str(name or "").strip()
            if not name_s:
                continue
            if name_s.lower() == "x-eternals-agent-note":
                header_note = str(value or "").strip()
                if header_note:
                    if comment and comment != header_note:
                        comment = self._limit_text(comment + " | " + header_note, 250)
                    else:
                        comment = self._limit_text(header_note, 250)
                continue
            clean_headers[name_s] = str(value or "")
        headers = clean_headers

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

        method = str(pseudo_headers.get(":method", pseudo_headers.get("method", body.get("method", "GET"))) or "GET").upper()
        path = str(pseudo_headers.get(":path", pseudo_headers.get("path", body.get("path", "/"))) or "/")
        if path.lower().startswith("http://") or path.lower().startswith("https://"):
            try:
                parsed_path_url = urlparse.urlparse(path)
                path = (parsed_path_url.path or "/") + (("?" + parsed_path_url.query) if parsed_path_url.query else "")
            except Exception:
                path = "/"
        if not path.startswith("/"):
            path = "/" + path
        scheme = str(pseudo_headers.get(":scheme", pseudo_headers.get("scheme", "https" if uses_https else "http")) or ("https" if uses_https else "http")).lower()
        netloc = target_host
        if (scheme == "https" and target_port != 443) or (scheme == "http" and target_port != 80):
            netloc = "%s:%d" % (target_host, target_port)
        target_url = "%s://%s%s" % (scheme, netloc, path)
        scope_guard = self._scope_guard_for_url(target_url)
        safety_gate = self._safety_gate_for_request(method, target_url)
        confirmed = self._coerce_bool(body.get("confirmed", False), False)
        if scope_guard.get("in_scope") is False:
            self._send_json(403, {
                "error": "out_of_scope",
                "scope_guard": scope_guard,
                "url": target_url,
                "message": "HTTP/2 MCP request refused because target is outside scope."
            })
            return
        if scope_guard.get("requires_confirmation") and not confirmed:
            self._send_json(409, {
                "error": "scope_confirmation_required",
                "scope_guard": scope_guard,
                "url": target_url,
                "message": "Confirm scope before sending this HTTP/2 MCP request."
            })
            return
        if safety_gate.get("requires_confirmation") and not confirmed:
            self._send_json(409, {
                "error": "safety_confirmation_required",
                "safety_gate": safety_gate,
                "url": target_url,
                "message": "Confirm this state-changing/sensitive HTTP/2 request before sending."
            })
            return

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
                "url": target_url,
                "method": method,
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "comment": comment,
                "result": result,
                "note": "HTTP/2 execution is delegated to the PortSwigger MCP extension on port 9876."
            })
        except Exception as e:
            self._send_json(503, {
                "error": "portswigger mcp http2 request failed",
                "message": self._safe_ascii_text(e, 1000),
                "mcp_url": str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "")),
                "attempted_fresh_session": True,
                "reconnect_retry_attempted": True,
                "fallback": "Use the PortSwigger MCP tool send_http2_request directly, or use POST /api/agent/request for HTTP/1.1 fallback when protocol fidelity is not required."
            })

    def _strip_agent_note_header_from_raw_request(self, raw_request):
        """Strip X-Eternals-Agent-Note from a raw request and return it as comment text."""
        if not raw_request:
            return raw_request, ""
        try:
            text = raw_request
            header_block = text
            rest = ""
            for separator in ("\r\n\r\n", "\n\n", "\r\r"):
                idx = text.find(separator)
                if idx >= 0:
                    header_block = text[:idx]
                    rest = text[idx:]
                    break

            clean_lines = []
            notes = []
            for line in header_block.splitlines(True):
                header_line = line.strip("\r\n")
                if header_line.lower().startswith("x-eternals-agent-note:"):
                    notes.append(header_line.split(":", 1)[1].strip())
                    continue
                clean_lines.append(line)

            if not notes:
                return raw_request, ""
            return "".join(clean_lines) + rest, " | ".join(notes)
        except Exception:
            return raw_request, ""

    def _handle_agent_request(self):
        """Fire an HTTP request through Burp's HTTP stack and return the response as JSON."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return

        host = str(body.get("host", "")).strip()
        port = body.get("port", 443)
        use_https = self._coerce_bool(body.get("https", True), True)
        raw_request = body.get("request", "")
        comment = self._limit_text(body.get("comment", body.get("note", "")), 250)
        raw_request, header_note = self._strip_agent_note_header_from_raw_request(raw_request)
        if header_note:
            if comment and comment != header_note:
                comment = self._limit_text(comment + " | " + header_note, 250)
            else:
                comment = self._limit_text(header_note, 250)

        if not host or not raw_request:
            self._send_json(400, {"error": "host and request are required"})
            return

        try:
            port = int(port)
        except:
            self._send_json(400, {"error": "port must be an integer"})
            return

        parsed_request = self._split_raw_http_request(raw_request)
        method = str(parsed_request.get("method", "GET") or "GET").upper()
        target = str(parsed_request.get("target", "/") or "/")
        if target.lower().startswith("http://") or target.lower().startswith("https://"):
            target_url = target
        else:
            if not target.startswith("/"):
                target = "/" + target
            scheme = "https" if use_https else "http"
            netloc = host if port in (443 if use_https else 80, 0) else "%s:%d" % (host, port)
            target_url = "%s://%s%s" % (scheme, netloc, target)
        scope_guard = self._scope_guard_for_url(target_url)
        safety_gate = self._safety_gate_for_request(method, target_url)
        confirmed = self._coerce_bool(body.get("confirmed", False), False)
        if scope_guard.get("in_scope") is False:
            self._send_json(403, {"error": "out_of_scope", "scope_guard": scope_guard, "url": target_url})
            return
        if (scope_guard.get("requires_confirmation") or safety_gate.get("requires_confirmation")) and not confirmed:
            self._send_json(409, {
                "error": "request_confirmation_required",
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "url": target_url
            })
            return

        try:
            helpers = self.extender.helpers
            # Burp requires a complete HTTP/1 message. Local models sometimes omit
            # the final empty line when reconstructing a request from generated curl.
            # Canonicalise line endings and add the header terminator when missing.
            raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")
            if "\n\n" not in raw_request:
                raw_request += "\n\n"
            raw_request = raw_request.replace("\n", "\r\n")
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
                "url": target_url,
                "method": method,
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "comment": comment,
                "comment_set": bool(object_comment_set or history_comment_set),
                "comment_set_on_response_object": bool(object_comment_set),
                "comment_set_on_proxy_history": bool(history_comment_set)
            })
        except Exception as e:
            self.extender.stderr.println("[AGENT API] agent/request error: %s" % str(e))
            self._send_json(500, {"error": "request failed", "message": str(e)})
