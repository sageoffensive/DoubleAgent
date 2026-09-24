# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk3Chunk2(object):
    def _serialize_scanner_job(self, job_id, job):
        queue_item = job.get("queue_item", None)
        burp_status = "unknown"
        percentage_complete = None
        num_requests = None
        num_errors = None
        num_insertion_points = None
        if queue_item is not None:
            try:
                burp_status = str(queue_item.getStatus())
            except Exception:
                burp_status = str(job.get("status", "unknown") or "unknown")
            try:
                percentage_complete = int(queue_item.getPercentageComplete())
            except Exception:
                percentage_complete = None
            try:
                num_requests = int(queue_item.getNumRequests())
            except Exception:
                num_requests = None
            try:
                num_errors = int(queue_item.getNumErrors())
            except Exception:
                num_errors = None
            try:
                num_insertion_points = int(queue_item.getNumInsertionPoints())
            except Exception:
                num_insertion_points = None
        return {
            "id": job_id,
            "status": job.get("status", "queued"),
            "burp_status": burp_status,
            "percentage_complete": percentage_complete,
            "num_requests": num_requests,
            "num_errors": num_errors,
            "num_insertion_points": num_insertion_points,
            "created_at": job.get("created_at", ""),
            "updated_at": job.get("updated_at", ""),
            "url": job.get("url", ""),
            "method": job.get("method", ""),
            "host": job.get("host", ""),
            "port": job.get("port", 0),
            "https": bool(job.get("https", True)),
            "scan_type": job.get("scan_type", ""),
            "focus": job.get("focus", ""),
            "insertion_point_offsets": job.get("insertion_point_offsets", []),
            "source": job.get("source", ""),
            "queue_id": job.get("queue_id", ""),
            "finding_id": job.get("finding_id", ""),
            "candidate_label": job.get("candidate_label", ""),
            "scope_guard": job.get("scope_guard", {}),
            "safety_gate": job.get("safety_gate", {}),
            "warnings": job.get("warnings", []),
            "scanner_findings": self._scanner_job_findings(job)
        }

    def _handle_list_scanner_jobs(self):
        jobs = []
        with self.extender.scanner_jobs_lock:
            for job_id in sorted(self.extender.scanner_jobs.keys()):
                jobs.append(self._serialize_scanner_job(job_id, self.extender.scanner_jobs[job_id]))
        self._send_json(200, {"jobs": jobs, "count": len(jobs)})

    def _handle_get_scanner_job(self, jid):
        try:
            job_id = int(jid)
        except:
            self._send_json(400, {"error": "invalid scanner job id"})
            return
        with self.extender.scanner_jobs_lock:
            job = self.extender.scanner_jobs.get(job_id)
        if job is None:
            self._send_json(404, {"error": "scanner job not found"})
            return
        self._send_json(200, {"scanner_job": self._serialize_scanner_job(job_id, job)})

    def _handle_cancel_scanner_job(self, jid):
        try:
            job_id = int(jid)
        except:
            self._send_json(400, {"error": "invalid scanner job id"})
            return
        with self.extender.scanner_jobs_lock:
            job = self.extender.scanner_jobs.get(job_id)
        if job is None:
            self._send_json(404, {"error": "scanner job not found"})
            return
        try:
            queue_item = job.get("queue_item", None)
            if queue_item is not None:
                queue_item.cancel()
            job["status"] = "cancelled"
            job["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            self._send_json(500, {"error": "cancel failed", "message": self._safe_ascii_text(e, 500)})
            return
        self._send_json(200, {"status": "cancelled", "scanner_job": self._serialize_scanner_job(job_id, job)})

    def _handle_start_burp_active_scan(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return
        if not isinstance(body, dict):
            body = {}

        candidate, source, warnings = self._scanner_candidate_from_body(body)
        if candidate is None:
            self._send_json(400, {"error": "no scanner target", "warnings": warnings})
            return

        refresh_auth = self._coerce_bool(body.get("refresh_auth", True), True)
        built = self._raw_repeater_request(candidate, refresh_auth=refresh_auth, note="")
        warnings.extend(built.get("warnings", []))
        if not built.get("ok"):
            self._send_json(400, {"error": "could not build scanner request", "warnings": warnings})
            return

        url = built.get("url", "")
        host = built.get("host", "")
        try:
            port = int(built.get("port", 443) or 443)
        except:
            port = 443
        use_https = bool(built.get("https", True))
        parsed = self._split_raw_http_request(built.get("raw_request", ""))
        method = str(parsed.get("method", "GET") or "GET").upper()
        scope_guard = self._scope_guard_for_url(url)
        safety_gate = self._safety_gate_for_request(method, url)

        if scope_guard.get("in_scope") is False:
            self._send_json(403, {
                "error": "out_of_scope",
                "scope_guard": scope_guard,
                "message": "Burp Scanner delegation refused because target is outside scope."
            })
            return
        if scope_guard.get("requires_confirmation") and not self._coerce_bool(body.get("confirmed", False), False):
            self._send_json(409, {
                "error": "scope_confirmation_required",
                "scope_guard": scope_guard,
                "message": "Confirm scope before delegating this request to Burp Scanner."
            })
            return
        if safety_gate.get("requires_confirmation") and not self._coerce_bool(body.get("confirmed", False), False):
            self._send_json(409, {
                "error": "safety_confirmation_required",
                "safety_gate": safety_gate,
                "message": "Confirm this state-changing/sensitive request before delegating it to Burp Scanner."
            })
            return

        scan_type = self._limit_text(body.get("scan_type", body.get("focus", "focused")), 80)
        focus = self._limit_text(body.get("focus", scan_type), 500)
        queue_id = body.get("queue_id", body.get("agent_queue_id", ""))
        finding_id = body.get("finding_id", body.get("id", ""))
        request_bytes = self.extender.helpers.stringToBytes(built.get("raw_request", ""))
        insertion_point_offsets = []
        for pair in body.get("insertion_point_offsets", []) or []:
            try:
                start = int(pair[0])
                end = int(pair[1])
                if start >= 0 and end > start and end <= len(request_bytes):
                    insertion_point_offsets.append([start, end])
            except Exception:
                continue
        if body.get("insertion_point_offsets") and not insertion_point_offsets:
            warnings.append("no valid insertion_point_offsets were supplied; using Burp automatic insertion points")

        try:
            if insertion_point_offsets:
                scanner_queue_item = self.extender.callbacks.doActiveScan(
                    host, port, use_https, request_bytes, insertion_point_offsets)
            else:
                scanner_queue_item = self.extender.callbacks.doActiveScan(host, port, use_https, request_bytes)
        except Exception as e:
            self._send_json(503, {
                "error": "burp_active_scan_failed",
                "message": self._safe_ascii_text(e, 1000),
                "guidance": "Use the Burp MCP native scanner action if available, or send the request to Repeater for manual validation."
            })
            return

        with self.extender.findings_lock_ui:
            finding_start_index = len(self.extender.findings_list)
        with self.extender.scanner_jobs_lock:
            job_id = self.extender.scanner_job_next_id
            self.extender.scanner_job_next_id += 1
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            job = {
                "id": job_id,
                "status": "queued",
                "queue_item": scanner_queue_item,
                "created_at": now,
                "updated_at": now,
                "url": url,
                "method": method,
                "host": host,
                "port": port,
                "https": use_https,
                "scan_type": scan_type,
                "focus": focus,
                "insertion_point_offsets": insertion_point_offsets,
                "source": source,
                "queue_id": queue_id,
                "finding_id": finding_id,
                "candidate_label": candidate.get("label", ""),
                "finding_start_index": finding_start_index,
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "warnings": warnings
            }
            self.extender.scanner_jobs[job_id] = job

        try:
            self.extender.stdout.println("[SCANNER API] Started Burp active scan job #%d type=%s url=%s" % (
                job_id, scan_type, self._safe_ascii_text(url, 180)))
        except Exception:
            pass
        self._send_json(201, {
            "status": "queued",
            "scanner_job": self._serialize_scanner_job(job_id, job),
            "guidance": "Poll /api/agent/scanner/jobs/%d. Burp Scanner issues are ingested into /api/findings as '(Burp Scanner)' findings; Agent B should validate reportable impact before finalizing." % job_id
        })

    def _normalize_fixture_requirement(self, value):
        req = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "second_user": "needs_second_account",
            "needs_second_user": "needs_second_account",
            "needs_other_user": "needs_second_account",
            "needs_second_account_number": "needs_account_number_pair",
            "second_account_number": "needs_account_number_pair",
            "needs_two_tenants": "needs_tenant_pair",
            "needs_cross_tenant": "needs_tenant_pair",
            "needs_object_pair": "needs_object_id_pair",
            "needs_foreign_object": "needs_object_id_pair",
            "needs_mfa": "needs_pre_mfa_session",
            "needs_pre_mfa_authid": "needs_pre_mfa_session",
            "needs_post_mfa_authid": "needs_post_mfa_session",
            "needs_otp": "needs_live_otp",
            "needs_sms": "needs_live_otp",
            "needs_email": "needs_human_confirmation"
        }
        return aliases.get(req, req)

    def _fixture_requirements_from_recipe(self, recipe):
        if not isinstance(recipe, dict):
            recipe = {}
        requirements = []

        raw = recipe.get("fixture_requirements", recipe.get("required_fixtures", []))
        if isinstance(raw, basestring):
            raw = [r.strip() for r in raw.split(",")]
        if isinstance(raw, list):
            for item in raw:
                req = self._normalize_fixture_requirement(item)
                if req and req not in requirements:
                    requirements.append(req)

        bool_map = [
            ("needs_second_user", "needs_second_account"),
            ("requires_second_user", "needs_second_account"),
            ("needs_second_account", "needs_second_account"),
            ("needs_second_account_number", "needs_account_number_pair"),
            ("needs_object_id_pair", "needs_object_id_pair"),
            ("needs_tenant_pair", "needs_tenant_pair"),
            ("needs_live_otp", "needs_live_otp"),
            ("needs_pre_mfa_session", "needs_pre_mfa_session"),
            ("needs_post_mfa_session", "needs_post_mfa_session"),
            ("needs_revoked_session", "needs_revoked_session"),
            ("needs_human_confirmation", "needs_human_confirmation")
        ]
        for key, req in bool_map:
            if bool(recipe.get(key, False)) and req not in requirements:
                requirements.append(req)

        text = ("%s %s %s %s" % (
            recipe.get("hypothesis", ""),
            recipe.get("active_test_type", ""),
            recipe.get("mutation_hint", ""),
            recipe.get("safety_notes", "")
        )).lower()
        if ("idor" in text or "cross-user" in text or "other user" in text) and "needs_second_account" not in requirements:
            requirements.append("needs_second_account")
        if ("tenant" in text or "accountnumber" in text or "account number" in text) and "needs_account_number_pair" not in requirements:
            requirements.append("needs_account_number_pair")
        if ("otp" in text or "sms" in text or "email received" in text or "mfa" in text) and "needs_human_confirmation" not in requirements:
            requirements.append("needs_human_confirmation")
        return requirements

    def _fixture_status_for_requirements(self, requirements):
        fixtures = [item for item in (getattr(self.extender, "test_fixtures", []) or [])
                    if self.extender._engagement_bound_record_is_current(item)]
        confirmations = [item for item in (getattr(self.extender, "human_confirmations", []) or [])
                         if self.extender._engagement_bound_record_is_current(item)]
        accounts = [f for f in fixtures if f.get("kind") == "account"]
        sessions = [f for f in fixtures if f.get("kind") == "session"]
        objects = [f for f in fixtures if f.get("kind") == "object"]
        tenants = [f for f in fixtures if f.get("kind") == "tenant"]

        def labels(items):
            return [str(i.get("label", "") or i.get("id", "")) for i in items if i.get("label") or i.get("id")]

        def distinct_values(items, key):
            values = []
            for item in items:
                value = str(item.get(key, "") or "").strip()
                if value and value not in values:
                    values.append(value)
            return values

        details = {}
        missing = []
        available = []
        for req in requirements or []:
            req = self._normalize_fixture_requirement(req)
            ok = False
            detail = {}
            if req == "needs_second_account":
                scoped_accounts = [a for a in accounts if str(a.get("consent_scope", "") or "").strip()]
                ok = len(labels(scoped_accounts or accounts)) >= 2
                detail = {"accounts": labels(accounts), "consented_accounts": labels(scoped_accounts)}
            elif req == "needs_account_number_pair":
                values = distinct_values(accounts, "account_number")
                ok = len(values) >= 2
                detail = {"account_numbers": values, "accounts": labels(accounts)}
            elif req == "needs_tenant_pair":
                values = distinct_values(accounts + tenants, "tenant")
                ok = len(values) >= 2
                detail = {"tenants": values, "tenant_fixtures": labels(tenants)}
            elif req == "needs_object_id_pair":
                object_labels = labels(objects)
                has_owned_foreign = False
                for obj in objects:
                    owned = obj.get("owned_object_ids", obj.get("object_ids", []))
                    foreign = obj.get("foreign_object_ids", [])
                    has_owned_foreign = has_owned_foreign or bool(owned and foreign)
                ok = has_owned_foreign or len(object_labels) >= 2
                detail = {"objects": object_labels}
            elif req == "needs_pre_mfa_session":
                matches = [s for s in sessions if str(s.get("session_state", "")).lower() in ("pre_mfa", "pre-mfa")]
                ok = len(matches) > 0
                detail = {"sessions": labels(matches)}
            elif req == "needs_post_mfa_session":
                matches = [s for s in sessions if str(s.get("session_state", "")).lower() in ("post_mfa", "post-mfa", "fresh")]
                ok = len(matches) > 0
                detail = {"sessions": labels(matches)}
            elif req == "needs_revoked_session":
                matches = [s for s in sessions if str(s.get("session_state", "")).lower() == "revoked"]
                ok = len(matches) > 0
                detail = {"sessions": labels(matches)}
            elif req == "needs_live_otp":
                matches = [c for c in confirmations if str(c.get("kind", "")).lower() in ("otp", "sms", "email", "push")]
                ok = len(matches) > 0
                detail = {"confirmation_count": len(matches)}
            elif req == "needs_human_confirmation":
                ok = len(confirmations) > 0
                detail = {"confirmation_count": len(confirmations)}
            else:
                detail = {"note": "unknown requirement; agent should ask user for this fixture"}

            details[req] = detail
            if ok:
                available.append(req)
            else:
                missing.append(req)

        return {
            "required": requirements or [],
            "available": available,
            "missing": missing,
            "blocked": bool(missing),
            "details": details,
            "guidance": "If blocked=true, do not run speculative active tests. Submit outcome=blocked-by-missing-fixture or ask the user to add the missing fixture."
        }

    def _automated_testing_fixture_status(self, findings_full):
        per_finding = []
        all_required = []
        ready_count = 0
        blocked_count = 0
        for finding in findings_full or []:
            if not isinstance(finding, dict):
                continue
            recipe = finding.get("active_test_recipe", {}) or {}
            requirements = self._fixture_requirements_from_recipe(recipe)
            status = self._fixture_status_for_requirements(requirements)
            for req in status.get("required", []) or []:
                if req not in all_required:
                    all_required.append(req)
            if status.get("blocked"):
                blocked_count += 1
            else:
                ready_count += 1
            per_finding.append({
                "id": finding.get("id", ""),
                "title": self._limit_text(finding.get("title", ""), 200),
                "agent_status_display": finding.get("agent_status_display", ""),
                "required": status.get("required", []),
                "available": status.get("available", []),
                "missing": status.get("missing", []),
                "blocked": bool(status.get("blocked", False)),
                "guidance": "Block this finding/goal only if missing is non-empty; do not block unrelated automated testing goals."
            })
        return {
            "required": all_required,
            "available": [],
            "missing": [],
            "blocked": False,
            "mode": "per_finding",
            "ready_findings": ready_count,
            "blocked_findings": blocked_count,
            "per_finding": per_finding,
            "guidance": "Automated Testing is not globally blocked by one missing fixture. Validate ready Agent A findings and mark only fixture-dependent goals as blocked."
        }

    def _attack_campaign_for_queue(self, item, findings_full, active_recipe, fixture_status):
        source = str(item.get("source", "") or "")
        campaign_type = "focused_validation"
        if source == "flow_analysis":
            campaign_type = "multi_step_flow"
        elif source == "risk_hunt":
            campaign_type = "automated_testing"
        elif active_recipe:
            campaign_type = active_recipe.get("active_test_type", "focused_validation") or "focused_validation"
        steps = []
        steps.append({"step": 1, "action": "Rehydrate context", "detail": "Read project_profile, test context, confirmations, findings, coverage, and completed queue results before active testing."})
        if fixture_status.get("required"):
            steps.append({"step": len(steps) + 1, "action": "Verify test context", "detail": "Check next_action.fixture_status; if blocked, submit blocked-by-missing-fixture with missing=%s." % ", ".join(fixture_status.get("missing", []))})
        if source == "risk_hunt":
            mode = str(item.get("mode", "") or "")
            if mode.startswith("campaign_"):
                campaign_type = item.get("campaign_type", mode.replace("campaign_", "", 1))
                steps.append({"step": len(steps) + 1, "action": "Campaign setup", "detail": "Follow the %s campaign contract in user_context. Read /api/coverage and /api/coverage/parameters before choosing targets." % campaign_type})
                if campaign_type == "full_app_assessment":
                    if bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
                        steps.append({"step": len(steps) + 1, "action": "Visible application exploration", "detail": "Use visible BrowserOS through Burp to cover public, authenticated, role-dependent, client-rendered, and high-value workflows without unapproved state changes."})
                    else:
                        steps.append({"step": len(steps) + 1, "action": "Application exploration", "detail": "Use Burp Proxy history, Site Map, JavaScript/API extraction, Repeater, Scanner, and any advertised native crawl capability. BrowserOS is disabled by the operator."})
                    steps.append({"step": len(steps) + 1, "action": "Attack-surface inventory", "detail": "POST scoped observed routes and their parameters, roles, states, workflows, protocols, discovery sources, and test status to /api/agent/attack-surface."})
                    steps.append({"step": len(steps) + 1, "action": "Discovery overwatch", "detail": "Repeat surface_diff snapshots until saturation, then POST /api/agent/attack-surface/review with this queue_id and resolve or Gate every blocker before /result."})
                elif campaign_type == "crawl_audit":
                    steps.append({"step": len(steps) + 1, "action": "Burp MCP crawl/audit", "detail": "Use native Burp MCP crawl/audit actions for in-scope seed URLs or focused paths, then compare new sitemap entries against endpoint and parameter coverage."})
                    steps.append({"step": len(steps) + 1, "action": "Delegate scanner leads", "detail": "For high-signal insertion points discovered during crawl/audit, prefer native Burp MCP scanner control or /api/agent/scanner/active, then validate any scanner issue manually."})
                elif campaign_type == "authz_matrix":
                    steps.append({"step": len(steps) + 1, "action": "Build authz matrix", "detail": "Use /api/agent/fixtures to map roles, tenants, sessions, and object IDs; Gate the work if fixture pairs are missing."})
                    steps.append({"step": len(steps) + 1, "action": "Replay A/B controls", "detail": "Replay safe requests across allowed/denied actor-object combinations and record an allow/deny matrix with exact evidence."})
                elif campaign_type == "race":
                    steps.append({"step": len(steps) + 1, "action": "Baseline and safety", "detail": "Only race explicitly safe or approved endpoints. Establish a single-request baseline and stop if the safety gate requires confirmation."})
                    steps.append({"step": len(steps) + 1, "action": "Bounded concurrency", "detail": "Use Burp MCP/Turbo Intruder or equivalent parallel runner with small concurrency/repeats; stop after a clear signal or bounded negative result."})
                elif campaign_type == "browser_dom":
                    steps.append({"step": len(steps) + 1, "action": "BrowserOS proof", "detail": "Use BrowserOS through Burp for DOM XSS, postMessage, client-side authz, service worker/cache, console logs, dialogs, screenshots, and visible session state."})
                    steps.append({"step": len(steps) + 1, "action": "DOM controls", "detail": "Include benign controls and browser-visible proof; do not rely on HTTP response text alone for DOM/browser-state issues."})
                elif campaign_type == "parser_protocol":
                    steps.append({"step": len(steps) + 1, "action": "Surface inventory", "detail": "Identify GraphQL, WebSocket, multipart upload/parser, JWT/OAuth/SAML/XML/XXE, and HTTP/2-sensitive surfaces from history and coverage."})
                    steps.append({"step": len(steps) + 1, "action": "Protocol-fidelity tests", "detail": "Use Burp MCP and /api/agent/request/http2 where protocol fidelity matters; do not downgrade HTTP/2-sensitive tests to HTTP/1.1 curl."})
                steps.append({"step": len(steps) + 1, "action": "Write back", "detail": "POST confirmed vulnerabilities to /api/findings and POST /result with risk_hunt_goals covering tested, not-vulnerable, and Gated campaign leads."})
            elif mode == "try_harder":
                steps.append({"step": len(steps) + 1, "action": "Threat model", "detail": "Use /api/coverage, /api/findings, /api/report, /api/agent/knowledge, project profile, and Burp history regex to identify highest-risk unknowns."})
                steps.append({"step": len(steps) + 1, "action": "Coverage baseline", "detail": "Read risk_hunt.discovery_contract and campaign_state. Record current /api/coverage and /api/coverage/parameters before discovery."})
                if bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
                    steps.append({"step": len(steps) + 1, "action": "Spider and browse", "detail": "Use native Burp crawl/audit when advertised, plus visible BrowserOS through Burp for at least 20 meaningful public/authenticated/client routes. Persist absolute visited URLs through /campaign/step artifacts."})
                else:
                    steps.append({"step": len(steps) + 1, "action": "Discover routes", "detail": "Use Burp Proxy history, Site Map, JavaScript/API extraction, Scanner, and any advertised native crawl capability. Persist absolute observed/tested URLs through /campaign/step artifacts."})
                steps.append({"step": len(steps) + 1, "action": "Coverage diff", "detail": "Re-run endpoint and parameter coverage. A no-finding result cannot complete below discovery_contract.minimum_coverage_percent unless spider_browse and coverage_diff are both Gated with exact evidence."})
                steps.append({"step": len(steps) + 1, "action": "Generate new-discovery goals", "detail": "Create fresh category=new_discovery goals targeting one previously undiscovered High or Critical vulnerability, with endpoint/flow, actor/context needs, safe test plan, expected signal, and stop condition."})
                steps.append({"step": len(steps) + 1, "action": "Test or Gate goals", "detail": "Execute scoped goals through Burp proxy, stop immediately after one new High/Critical finding is confirmed and posted, or after 10 tested/Gated new-discovery goals, and mark exact blockers as Gated."})
                steps.append({"step": len(steps) + 1, "action": "Write findings and knowledge", "detail": "For each confirmed new vulnerability, POST /api/findings with queue_id set, verify it appears in /api/report, and POST useful observations to /api/agent/knowledge."})
            else:
                steps.append({"step": len(steps) + 1, "action": "Verify Agent A findings", "detail": "Actively test linked findings whose Agent Status is still marked (A) or (B triage); use finding_updates in /result so they become Agent B validated."})
                steps.append({"step": len(steps) + 1, "action": "Account for blockers", "detail": "Use Gated status for linked findings that need missing fixtures, approval, object IDs, account pairs, MFA/OOB proof, or scope changes."})
                steps.append({"step": len(steps) + 1, "action": "Close verification", "detail": "POST queue result with risk_hunt_goals. One completed category=linked_validation umbrella goal is acceptable if every linked finding is updated or Gated."})
        elif source == "flow_analysis":
            for state in item.get("flow_state_summary", [])[:8]:
                if isinstance(state, dict):
                    steps.append({
                        "step": len(steps) + 1,
                        "action": "Map flow step %s" % state.get("step", ""),
                        "detail": "actor=%s state_changing=%s replayability=%s object_ids=%d" % (
                            state.get("actor_session_hint", ""),
                            state.get("state_changing", ""),
                            state.get("replayability", ""),
                            len(state.get("object_ids", []) or []))
                    })
        else:
            steps.append({"step": len(steps) + 1, "action": "Baseline", "detail": active_recipe.get("baseline_request", "Replay baseline request with refreshed auth and record status/shape.") if isinstance(active_recipe, dict) else "Replay baseline request with refreshed auth and record status/shape."})
            steps.append({"step": len(steps) + 1, "action": "Mutation", "detail": active_recipe.get("mutation_hint", "Apply the smallest safe evidence-backed mutation.") if isinstance(active_recipe, dict) else "Apply the smallest safe evidence-backed mutation."})
            steps.append({"step": len(steps) + 1, "action": "Control", "detail": "Run a negative/control request where feasible: own object, original ID, second account, or expected-deny path."})
            steps.append({"step": len(steps) + 1, "action": "Impact confirmation", "detail": active_recipe.get("expected_vulnerable_signal", "Confirm downstream security impact with exact response evidence.") if isinstance(active_recipe, dict) else "Confirm downstream security impact with exact response evidence."})
        return {
            "campaign_type": campaign_type,
            "hypothesis": active_recipe.get("hypothesis", item.get("summary", "")) if isinstance(active_recipe, dict) else item.get("summary", ""),
            "actor_requirements": fixture_status.get("required", []),
            "steps": steps,
            "stop_conditions": [
                "scope_guard.in_scope is false",
                "safety_gate.requires_confirmation is true and user has not approved",
                "fixture_status.blocked is true",
                "baseline cannot be reproduced after auth/latest recovery"
            ]
        }

    def _queue_operational_metadata(self, item, findings_full=None):
        candidates = self._queue_target_candidates(item, findings_full)
        qid = item.get("id", 0)
        source = str(item.get("source", "") or "")
        browseros_enabled = bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False))
        browser_verify = bool(item.get("browser_verify", False)) and browseros_enabled
        active_recipe = {}
        for finding in findings_full or []:
            if isinstance(finding, dict) and finding.get("active_test_recipe"):
                active_recipe = finding.get("active_test_recipe", {})
                break
        if not active_recipe and isinstance(item.get("active_test_recipe", {}), dict):
            active_recipe = item.get("active_test_recipe", {})
        fixture_requirements = self._fixture_requirements_from_recipe(active_recipe)
        if source == "risk_hunt":
            fixture_status = self._automated_testing_fixture_status(findings_full or [])
        else:
            fixture_status = self._fixture_status_for_requirements(fixture_requirements)
        attack_campaign = self._attack_campaign_for_queue(item, findings_full or [], active_recipe, fixture_status)
        protocol_profile = self._queue_protocol_profile(item, candidates, active_recipe)

        if source == "risk_hunt" and str(item.get("mode", "") or "") == "try_harder":
            transport = "autonomous_hunt"
            discovery = ("advertised native Burp crawl plus visible BrowserOS browsing through Burp" if browseros_enabled else "Burp Proxy history, Site Map, JavaScript/API extraction, Scanner, and any advertised native crawl capability")
            instruction = "TRY HARDER: immediately after claim, follow persistent_agent_goal: call get_goal and create_goal exactly once when no matching active goal exists. Keep it active until Double Agent accepts /result. Then follow campaign_state.steps in order. Before a no-finding result, use %s, persist observed/tested absolute URLs through /campaign/step artifacts, and meet risk_hunt.discovery_contract.minimum_coverage_percent. Prioritize one previously undiscovered High/Critical finding. Hand-build only scoped target requests through Burp Proxy with X-Eternals-Agent-Note: Agent: queue #%s - <purpose> - <expected result>." % (discovery, qid)
        elif source == "risk_hunt" and str(item.get("mode", "") or "").startswith("campaign_"):
            transport = "autonomous_hunt"
            instruction = "Campaign %s has no generated replay curl. Follow the campaign contract in user_context, use available Burp and protocol tools, and hand-build only scoped target requests through Burp Proxy with X-Eternals-Agent-Note: Agent: queue #%s - <test purpose> - <expected result>. Confirmed vulnerabilities must be created with POST /api/findings; coverage and tested controls must be written back through /result and /api/agent/knowledge." % (item.get("campaign_type", str(item.get("mode", ""))[9:]), qid)
            if browser_verify:
                instruction += " This campaign has browser_verify=true: use BrowserOS MCP, not target curl, for browser actions. If BrowserOS MCP tools are missing, call GET /api/docs and follow browseros_mcp_setup: kill old BrowserOS instances, relaunch BrowserOS through Burp proxy with remote debugging on 9100, register claude mcp add --transport http browseros http://127.0.0.1:9000/mcp --scope user, then re-check tools. If registration succeeds but tools still are not visible, try a fresh Claude Code session; if a fresh session still lacks callable tools but http://127.0.0.1:9000/mcp is healthy and tools/list returns BrowserOS tools, use browseros_mcp_setup.direct_jsonrpc_fallback local MCP control calls."
        elif source == "risk_hunt":
            transport = "autonomous_hunt"
            instruction = "Automated Testing has no generated replay curl. Validate linked Agent A findings first, generate goals from project context, coverage gaps, Burp history, knowledge, and current findings, then hand-build only scoped target requests through Burp Proxy with X-Eternals-Agent-Note: Agent: queue #%s - <test purpose> - <expected result>. Confirmed new vulnerabilities must be created with POST /api/findings and verified in GET /api/report." % qid
            if browser_verify:
                instruction += " browser_verify=true: when browser state is required, use BrowserOS MCP through Burp. If BrowserOS MCP tools are missing, call GET /api/docs and follow browseros_mcp_setup, including direct_jsonrpc_fallback when the MCP endpoint is healthy but tools are not callable, before asking the user how to proceed."
        elif browser_verify:
            transport = "browseros"
            instruction = "Use BrowserOS MCP only; BrowserOS must be launched through Burp proxy. Do not use target-application curl. Check /api/agent/browseros/readiness?url=<exact-scoped-url>. On macOS and Kali/Linux include --proxy-server=http://127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100. Browser discovery does not count until readiness proxy_verification.observed=true. If MCP is unavailable but CDP is healthy, visible computer control is allowed only with that Burp-history proof."
        elif candidates and protocol_profile.get("requires_portswigger_mcp"):
            transport = "portswigger_mcp_http2"
            instruction = "This item is protocol-sensitive (%s). Do not use generated curl or downgrade to HTTP/1.1. Use POST /api/agent/request/http2, preserving pseudoHeaders and request body. If MCP discovery timed out but port 9876 is reachable, make one actual endpoint attempt; it opens a fresh session and retries one reconnect. Block only if execution fails. Respect scope_guard and safety_gate." % "; ".join(protocol_profile.get("reasons", []))
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

        if transport == "autonomous_hunt":
            safe_to_auto_test = False
        else:
            safe_to_auto_test = (
                transport in ("curl_proxy", "portswigger_mcp_http2") and
                scope_guard.get("in_scope") is not False and
                not scope_guard.get("requires_confirmation", False) and
                not safety_gate.get("requires_confirmation", False) and
                not fixture_status.get("blocked", False)
            )

        campaign_state = item.get("campaign_state", {}) or {}
        next_campaign_step = {}
        for step in campaign_state.get("steps", []) or []:
            if step.get("status") in ("pending", "running"):
                next_campaign_step = step
                break

        return {
            "recommended_transport": transport,
            "must_proxy": transport in ("curl_proxy", "browseros", "autonomous_hunt", "portswigger_mcp_http2"),
            "curl_endpoint": "/api/agent/queue/%s/curl?refresh_auth=true" % qid if transport == "curl_proxy" else "",
            "http2_endpoint": "/api/agent/request/http2" if transport == "portswigger_mcp_http2" else "",
            "portswigger_mcp_tool": "send_http2_request" if transport == "portswigger_mcp_http2" else "",
            "protocol_profile": protocol_profile,
            "request_candidates": len(candidates),
            "requires_auth_refresh": "call auth/latest automatically via curl endpoint before replay",
            "scope_guard": scope_guard,
            "safety_gate": safety_gate,
            "fixture_status": fixture_status,
            "attack_campaign": attack_campaign,
            "campaign_state": campaign_state,
            "persistent_agent_goal": item.get("persistent_agent_goal", {}) or {},
            "next_campaign_step": next_campaign_step,
            "campaign_step_update_endpoint": "/api/agent/queue/%s/campaign/step" % qid if campaign_state else "",
            "browseros_enabled": browseros_enabled,
            "browseros_mcp_setup_hint": "If BrowserOS MCP tools are missing, GET /api/docs and follow browseros_mcp_setup. Expected MCP endpoint: http://127.0.0.1:9000/mcp." if browseros_enabled and (browser_verify or transport == "browseros" or (source == "risk_hunt" and str(item.get("mode", "") or "") == "try_harder")) else "",
            "autonomous_hunt_requires_per_request_scope_checks": bool(transport == "autonomous_hunt"),
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
                    item = copy.deepcopy(q)
                    if not bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)):
                        item["browser_verify"] = False
                        item.pop("browseros_claim_preflight", None)
                        item["runtime_blockers"] = [
                            blocker for blocker in item.get("runtime_blockers", []) or []
                            if str(blocker.get("code", "")) != "browseros_unavailable"
                        ]
                        context = str(item.get("user_context", "") or "")
                        context_lines = [line for line in context.splitlines() if "browseros" not in line.lower()]
                        context = "\n".join(context_lines)
                        context = re.sub(
                            r'("minimum_browser_routes"\s*:\s*)\d+',
                            r'\g<1>0',
                            context,
                        )
                        item["user_context"] = context.strip()
                        campaign_options = dict(item.get("campaign_options", {}) or {})
                        campaign_options["minimum_browser_routes"] = 0
                        item["campaign_options"] = campaign_options
                        risk = dict(item.get("risk_hunt", {}) or {})
                        contract = dict(risk.get("discovery_contract", {}) or {})
                        contract["required_methods"] = [
                            method for method in contract.get("required_methods", []) or []
                            if "browseros" not in str(method).lower()
                        ]
                        risk["discovery_contract"] = contract
                        item["risk_hunt"] = risk
                        goal = dict(item.get("persistent_agent_goal", {}) or {})
                        goal["objective"] = str(goal.get("objective", "")).replace("Burp/BrowserOS discovery", "Burp-native discovery")
                        item["persistent_agent_goal"] = goal
                        campaign = dict(item.get("campaign_state", {}) or {})
                        campaign["steps"] = [dict(step) for step in campaign.get("steps", []) or []]
                        for step in campaign["steps"]:
                            step["title"] = str(step.get("title", "")).replace("BrowserOS, ", "").replace("BrowserOS", "browser automation")
                        item["campaign_state"] = campaign
                    return item
        return None

    def _queue_findings_full(self, item):
        findings_full = []
        with self.extender.findings_lock_ui:
            stable_refs = set([str(value) for value in item.get("finding_stable_ids", []) or [] if value])
            if stable_refs:
                for idx, finding in enumerate(self.extender.findings_list):
                    if str(finding.get("stable_id", "") or "") in stable_refs:
                        findings_full.append(self._serialize_finding(idx, finding, include_full=True))
                return findings_full
            for fid in item.get("finding_ids", []):
                if 0 <= fid < len(self.extender.findings_list):
                    f = self.extender.findings_list[fid]
                    findings_full.append(self._serialize_finding(fid, f, include_full=True))
        return findings_full

    def _build_queue_curl_payload(self, item, findings_full, refresh_auth=True, step_filter=""):
        if bool(item.get("browser_verify", False)):
            return 409, {
                "error": "browser verification item",
                "message": "This work item has browser_verify=true. Use BrowserOS MCP through Burp proxy, not target curl. If BrowserOS MCP tools are missing, GET /api/docs and follow browseros_mcp_setup. If the MCP endpoint is healthy but tools are not callable, use browseros_mcp_setup.direct_jsonrpc_fallback local MCP control calls."
            }
        if str(item.get("source", "") or "") == "risk_hunt":
            qid = item.get("id", 0)
            return 409, {
                "error": "no_replayable_curl_for_automated_testing",
                "message": "Automated Testing has no single replayable curl. Hand-build only scoped target requests through Burp Proxy.",
                "proxy_required": "http://127.0.0.1:8080",
                "required_header": "X-Eternals-Agent-Note: Agent: queue #%s - <test purpose> - <expected result>" % qid,
                "guidance": "Use /api/coverage, /api/findings, /api/report, /api/agent/knowledge, project profile, test context, completed queue results, and /api/agent/history/http/regex metadata to choose scoped requests. Every target request must use the Burp proxy and the note header so new passive findings can be linked back to this queue."
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
        next_action = self._queue_operational_metadata(item, findings_full)
        fixture_status = next_action.get("fixture_status", {}) or {}
        scope_guard = next_action.get("scope_guard", {}) or {}
        safety_gate = next_action.get("safety_gate", {}) or {}
        if next_action.get("recommended_transport") == "portswigger_mcp_http2":
            return 409, {
                "error": "protocol_sensitive_item_requires_portswigger_mcp",
                "message": "Generated curl is withheld because this work item requires HTTP/2 or pseudo-header fidelity. Use /api/agent/request/http2 or PortSwigger MCP send_http2_request; do not downgrade to HTTP/1.1 curl.",
                "queue_id": qid,
                "http2_endpoint": "/api/agent/request/http2",
                "portswigger_mcp_tool": "send_http2_request",
                "protocol_profile": next_action.get("protocol_profile", {}),
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "guidance": "Build pseudoHeaders and headers from the queue item's request_data. If scope_guard or safety_gate requires confirmation, ask the user before sending."
            }
        blocked_reasons = []
        if fixture_status.get("blocked"):
            blocked_reasons.append("fixture_status.blocked")
        if scope_guard.get("in_scope") is False:
            blocked_reasons.append("scope_guard.in_scope=false")
        if scope_guard.get("requires_confirmation"):
            blocked_reasons.append("scope_guard.requires_confirmation")
        if safety_gate.get("requires_confirmation"):
            blocked_reasons.append("safety_gate.requires_confirmation")
        if not next_action.get("safe_to_auto_test", False):
            blocked_reasons.append("next_action.safe_to_auto_test=false")
        if blocked_reasons:
            return 409, {
                "error": "queue_item_not_safe_for_generated_curl",
                "message": "Generated curl is withheld because this queue item needs missing context or user confirmation before target traffic is replayed.",
                "blocked_reasons": blocked_reasons,
                "fixture_status": fixture_status,
                "scope_guard": scope_guard,
                "safety_gate": safety_gate,
                "safe_to_auto_test": False,
                "guidance": "Resolve missing fixtures/confirmations or explicitly approve the unsafe action, then retry. No runnable curl or live auth material is returned while blocked."
            }
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
            "usage": "Run the generated command as-is for target traffic. Each generated command includes X-Eternals-Agent-Note so Double Agent copies it into the visible Burp Proxy Notes column and strips it upstream. Local Double Agent API calls remain direct and do not use -x."
        }

    def _normalize_queue_outcome(self, value):
        outcome = str(value or "inconclusive").strip().lower().replace("_", "-").replace(" ", "-")
        valid = set(["confirmed", "not-vulnerable", "gated", "blocked-by-missing-fixture", "needs-more-info", "inconclusive", "failed"])
        return outcome if outcome in valid else "inconclusive"
