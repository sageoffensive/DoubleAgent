# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk2Chunk3(object):
    def _try_harder_context_text(self, user_context="", focus=""):
        parts = []
        parts.append("TRY HARDER - AUTONOMOUS WEB APP PENTEST")
        parts.append("")
        parts.append("The user is explicitly asking you to stop doing narrow queue validation and go find bugs yourself.")
        parts.append("Act like a senior web application pentester with access to Burp history, the Double Agent API, and any relevant security/web/browser skills or tools available in your agent environment.")
        parts.append("Use those skills/tools when they fit the target: web app methodology, auth/IDOR/tenant testing, variant analysis, browser testing, protocol-sensitive testing, JS/API recon, and report-quality validation.")
        parts.append("")
        parts.append("Persistent goal - required immediately after claim:")
        parts.append("- The user's Try Harder action explicitly requests a persistent agent goal. Read persistent_agent_goal from the queue item, call get_goal, and call create_goal exactly once with its supplied objective when no matching active goal exists. Do this before preflight, discovery, or testing.")
        parts.append("- Double Agent risk_hunt_goals are testing hypotheses and do not replace the persistent agent goal. Keep the persistent goal active across continuations and rejected /result submissions.")
        parts.append("- Include persistent_goal={created:true,status:'active',objective:'...'} in /result. Call update_goal(status=complete) only after Double Agent accepts /result. If the client genuinely lacks create_goal, report tool_unavailable=true with the exact reason.")
        parts.append("")
        parts.append("Required first phase - get up to speed and threat model:")
        parts.append("- Fetch /api/agent/burp/skill and follow combined_markdown as $burpsuite-operator, then read /api/agent/burp/capabilities, /api/agent/burp/workspace, /api/agent/scope, /api/agent/preflight, /api/agent/project-profile, /api/agent/knowledge, /api/agent/fixtures, /api/agent/confirmations, /api/findings, /api/coverage?in_scope_only=true&limit=500, /api/coverage/parameters?in_scope_only=true&limit=500, and /api/report. No local skill folder is required.")
        parts.append("- Use /api/agent/history/http/regex in metadata mode to map endpoint families, auth/session flows, object identifiers, static JS/API schemas, role/tenant/account boundaries, and high-value state-changing workflows.")
        parts.append("- Produce a short threat model before testing: assets, actors/roles, trust boundaries, sensitive workflows, auth model, likely object/tenant boundaries, exposed client/API surface, and highest-risk unknowns.")
        parts.append("")
        parts.append("Mandatory discovery and coverage phase before any no-finding result:")
        parts.append("- Follow campaign_state.steps in order and POST every transition to /api/agent/queue/<id>/campaign/step. The coverage_baseline, spider_browse, and coverage_diff steps are completion gates, not optional suggestions.")
        parts.append("- Read risk_hunt.discovery_contract for the measured baseline and required dynamic endpoint coverage percentage. A low-coverage result such as 10% is not a defensible negative result.")
        parts.append("- If /api/agent/burp/capabilities advertises native crawl/audit, use it on in-scope seeds and authenticated areas. If it does not, do not invent it; record the missing native capability and continue with BrowserOS discovery.")
        parts.append("- Use visible BrowserOS through Burp to browse/spider at least 20 meaningful pages or client routes across public, authenticated, navigation, form, account, admin/role-dependent, and high-value workflow surfaces that are available and safe. Do not submit state-changing forms without approval.")
        parts.append("- Inspect Proxy history, Site Map, JavaScript/API routes, WebSocket history, and /api/coverage/parameters after browsing. Persist every visited or tested absolute URL in campaign step artifacts so GET /api/coverage can count in-progress work.")
        parts.append("- Re-run /api/coverage and /api/coverage/parameters. Continue discovery and focused tests until the required percentage is met. Only use a Gated discovery outcome when exact blockers such as missing auth/role, unavailable BrowserOS/native crawl, scope, or approval prevent further coverage; include evidence and the areas left unvisited.")
        parts.append("")
        parts.append("Required goal model:")
        parts.append("- Primary target: find and validate one previously undiscovered High or Critical vulnerability.")
        parts.append("- Previously undiscovered means it was not already present as the same root cause and impact in /api/findings, completed queue results, reviewed Scanner issues, or /api/agent/knowledge before this Try Harder item began.")
        parts.append("- You may validate linked Agent A findings, but that does not count as the main success condition unless it uncovers a new High/Critical impact.")
        parts.append("- Create at least 6 total goals before closing this item.")
        parts.append("- At least 6 goals must have category=new_discovery and must be fresh bug-hunting hypotheses not just existing finding validation.")
        parts.append("- At least 5 new_discovery goals must be tested to a defensible conclusion or explicitly marked Gated with the missing fixture/approval/evidence.")
        parts.append("- Stop immediately when one qualifying new High/Critical finding is confirmed and POSTed to /api/findings. Otherwise stop when 10 new_discovery goals have been tested/Gated, or when all remaining high-risk leads are blocked by scope, fixtures, approval, or safety.")
        parts.append("- Do not count static-only recon as a completed new_discovery goal unless it produces a concrete security hypothesis and a tested signal.")
        parts.append("")
        parts.append("High-value areas to hunt:")
        parts.append("1. Auth and session: custom auth headers, cookie/session mixing, JWT/OAuth/Federation issues, token freshness, revoked/expired sessions, MFA/pre-MFA boundaries.")
        parts.append("2. Authorization: IDOR, account_number/client_id/object_id/tenant substitution, function-level auth, role confusion, horizontal and vertical privilege paths.")
        parts.append("3. Business logic: workflow skips, replay, race/retry behavior, approval/order/payment/profile-change edges, server-side state transitions.")
        parts.append("4. API and client surface: JS bundles, proto/schema/GraphQL/OpenAPI hints, hidden endpoints, service routers, dispatcher parameters, method/action fields.")
        parts.append("5. Injection/parsing: SSRF, SQL/NoSQL/template/command/path traversal, XML/XXE, file upload/parser behavior, deserialization or unsafe format handling.")
        parts.append("6. Chaining: combine weaker observations into data access, account takeover, financial impact, admin impact, or durable persistence.")
        parts.append("")
        parts.append("Execution rules:")
        parts.append("- Target traffic must go through Burp Proxy with -x http://127.0.0.1:8080 and X-Eternals-Agent-Note: Agent: queue #<id> - <test purpose> - <expected result>.")
        parts.append("- For this source=risk_hunt item, do not call /curl. Hand-build only scoped, minimal, safe requests.")
        parts.append("- Use Burp Scanner for commodity insertion-point payload breadth when signal is concrete: prefer native Burp MCP scanner control, otherwise POST /api/agent/scanner/active with raw request/queue_id/finding_id, scan_type, and confirmed=true only after safety confirmation. Scanner output is a lead; confirm impact yourself.")
        parts.append("- Prefer semantic POST /api/agent/burp/action calls with dry-run, Agent note, and receipt over raw MCP calls. Never invent a capability; use the advertised fallback or mark the goal Gated.")
        parts.append("- When the hunt points at a broad blind spot, queue or emulate the specific campaign workflow: Burp MCP crawl/audit, parameter-level coverage, authz matrix, race/concurrency, BrowserOS DOM testing, or parser/protocol testing.")
        parts.append("- Use BrowserOS MCP for browser-dependent proof when browser_verify=true or when the bug needs DOM/session/UI state.")
        parts.append("- For HTTP/2-sensitive behavior, use /api/agent/request/http2 or the PortSwigger MCP send_http2_request path.")
        parts.append("- Respect scope, project profile, allowed state changes, and safety gates. Ask before destructive/state-changing actions unless explicitly allowed.")
        parts.append("- If blocked by missing account/session/object/tenant/MFA/OOB/approval, mark the relevant goal and finding as Gated with the exact missing item and next step.")
        parts.append("- Confirmed vulnerabilities must be POSTed immediately to /api/findings with a stable deduplication_key, queue_id, evidence, request/response snippets, agent_status=valid, priority, rationale, and active_test_recipe. Preserve the returned immutable daf_... ID and version. The tool will store Try Harder findings with a (TH) title prefix.")
        parts.append("- Write durable observations, tested controls, assumptions, blockers, and follow-up leads to /api/agent/knowledge.")
        parts.append("")
        parts.append("Completion contract:")
        parts.append("- Submit /result immediately after one previously undiscovered High/Critical finding is confirmed and POSTed, or after a bounded serious attempt: at least 6 goals exist, at least 5 total goals are tested/confirmed/not-vulnerable/Gated, at least 6 goals are category=new_discovery, and at least 5 new_discovery goals are tested or Gated.")
        parts.append("- Do not relabel, duplicate, or inflate an existing issue to hit the target. If no qualifying High/Critical bug is present or safely testable, finish with the tested goals, exact Gated blockers, and the next fixtures/approvals needed.")
        parts.append("- risk_hunt_goals must include category for every goal: linked_validation, new_discovery, variant_analysis, threat_model, or control_check.")
        parts.append("- Include threat_model_summary, new_discovery_summary, controls_tested, gated_findings, confirmed finding IDs, and recommended next goals in assessment/test_results/evidence/notes.")
        if focus:
            parts.append("")
            parts.append("User-requested focus:")
            parts.append(str(focus))
        if user_context:
            parts.append("")
            parts.append("User context:")
            parts.append(str(user_context))
        text = "\n".join(parts)
        if not bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False)):
            text = "\n".join([line for line in text.splitlines() if "browseros" not in line.lower()])
            text = (
                "BrowserOS is disabled by the operator. Do not attempt its setup or use. Discover through Burp Proxy history, Site Map, JavaScript/API extraction, Scanner, Repeater, and any advertised native crawl capability.\n\n"
                + text
            )
        return text

    def _enqueueRiskHunt(self, user_context="", focus="", browser_verify=False, requested_by="ui"):
        """Queue an autonomous, goal-driven assessment item."""
        if self.agent_server is None:
            self.stdout.println("[AGENT] Server not running, starting now...")
            if not self.start_agent_server():
                self.stderr.println("[AGENT] Failed to start server; cannot enqueue automated testing")
                return None

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        context_text = self._risk_hunt_context_text(user_context=user_context, focus=focus)
        target_finding_ids = self._automated_testing_finding_ids()
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
                "summary": "Automated testing: verify current Agent A findings",
                "assessment": "",
                "test_results": [],
                "notes": [],
                "user_context": context_text,
                "source": "risk_hunt",
                "browser_verify": bool(browser_verify),
                "risk_hunt": {
                    "objective": "Actively verify every visible Agent A finding not yet tested by Agent B. Account for each linked finding with finding_updates or a Gated blocker. One umbrella linked_validation goal is acceptable when it covers the whole list.",
                    "requested_by": requested_by,
                    "outstanding_finding_count": len(target_finding_ids),
                    "minimum_goals": 1,
                    "minimum_completed_or_blocked_goals": 1,
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
                        "/api/report"
                    ],
                    "write_back": "POST /result with finding_updates for Agent B validated findings; mark missing-fixture/safety/scope blockers as Gated; POST /api/findings only for new vulnerabilities discovered during verification; GET /api/report confirms markdown output.",
                    "completion": "POST /api/agent/queue/%d/result after every linked finding has been validated, rejected, already covered, or marked Gated. A single completed linked_validation goal is acceptable when it accounts for the full findings list." % qid
                }
            }
            self.agent_queue.append(queue_item)
            self.selected_agent_queue_index = len(self.agent_queue) - 1

        self.save_agent_queue()
        self.log_to_console("[AGENT] Queued automated testing as work item #%d (%d Agent A finding(s) linked)" % (qid, len(target_finding_ids)))
        self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
            self.agent_server_host, self.agent_server_port, qid))
        self._ui_dirty = True
        self.refreshUI()
        self._focus_agent_tab()
        return qid

    def _enqueueDuplicateReview(self, requested_by="ui"):
        """Queue a read-only duplicate-review work item for Agent B. Agent B marks
        genuine same-issue Agent A findings as duplicate using its configured
        model; no target traffic is sent."""
        if self.agent_server is None:
            self.stdout.println("[AGENT] Server not running, starting now...")
            if not self.start_agent_server():
                self.stderr.println("[AGENT] Failed to start server; cannot enqueue duplicate review")
                return None
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_finding_ids = self._automated_testing_finding_ids()
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
                "summary": "Duplicate review: mark same-issue Agent A findings",
                "assessment": "",
                "test_results": [],
                "notes": [],
                "user_context": (
                    "Duplicate review only - do NOT send target traffic or actively test. Compare the linked Agent A findings "
                    "pairwise by #ID (URL, title, CWE, root cause, affected location/parameter, evidence). For each pair that is the "
                    "same underlying issue, keep the stronger/earlier finding canonical and call triage_finding on the other with "
                    "status=duplicate, duplicate_of=<canonical #ID>, duplicate_evidence_match, priority=defer and a rationale. A shared "
                    "CWE or host alone is not a duplicate; do not merge related-but-distinct issues. Call finish when done."
                ),
                "source": "duplicate_review",
                "browser_verify": False,
                "duplicate_review": {
                    "objective": "Mark genuine duplicates among Agent A findings; keep the canonical finding. No active testing.",
                    "requested_by": requested_by,
                    "finding_count": len(target_finding_ids),
                },
            }
            self.agent_queue.append(queue_item)
            self.selected_agent_queue_index = len(self.agent_queue) - 1

        self.save_agent_queue()
        self.log_to_console("[AGENT] Queued duplicate review as work item #%d (%d finding(s) linked)" % (qid, len(target_finding_ids)))
        self.log_to_console("[AGENT] Agent B can pick it up at: http://%s:%d/api/agent/queue/%d" % (
            self.agent_server_host, self.agent_server_port, qid))
        self._ui_dirty = True
        self.refreshUI()
        self._focus_agent_tab()
        return qid

    def _campaign_label(self, campaign_type):
        labels = {
            "full_app_assessment": "Full App Assessment",
            "crawl_audit": "Burp MCP crawl/audit discovery",
            "authz_matrix": "Authorization matrix",
            "race": "Race/concurrency testing",
            "browser_dom": "Browser DOM testing",
            "parser_protocol": "Parser/protocol testing"
        }
        return labels.get(str(campaign_type or ""), str(campaign_type or "campaign").replace("_", " ").title())

    def _campaign_context_text(self, campaign_type, user_context="", focus="", options=None):
        options = options if isinstance(options, dict) else {}
        parts = []
        label = self._campaign_label(campaign_type)
        parts.append("%s campaign for Agent B." % label)
        parts.append("")
        parts.append("Read first:")
        parts.append("- /api/agent/burp/skill (follow combined_markdown; no local skill folder required), /api/agent/burp/capabilities, /api/agent/burp/workspace, /api/agent/scope, /api/agent/preflight, /api/agent/project-profile, /api/agent/knowledge, /api/agent/fixtures, /api/agent/confirmations")
        parts.append("- /api/findings, /api/report, /api/coverage?in_scope_only=true&limit=500, /api/coverage/parameters?in_scope_only=true&limit=500")
        parts.append("- /api/agent/history/http/regex for compact discovery from Burp history before asking the user for more context")
        parts.append("")
        parts.append("Shared execution rules:")
        parts.append("- Prefer semantic POST /api/agent/burp/action with dry-run, Agent note, and receipt for Burp-native work. Use raw PortSwigger MCP only for a discovered capability without a semantic mapping.")
        parts.append("- Target curl traffic must go through Burp Proxy with -x http://127.0.0.1:8080 and X-Eternals-Agent-Note: Agent: queue #<id> - <test purpose> - <expected result>.")
        parts.append("- Respect scope_guard, project_profile, allowed state changes, and safety_gate. Ask before destructive/state-changing actions unless explicitly allowed.")
        parts.append("- Write confirmed vulnerabilities immediately to /api/findings with queue_id, evidence, request/response snippets, agent_status=valid, priority, rationale, and active_test_recipe.")
        parts.append("- Finish with /api/agent/queue/<id>/result using risk_hunt_goals for tested, not-vulnerable, confirmed, and Gated leads; write durable observations to /api/agent/knowledge.")
        parts.append("")

        if campaign_type == "full_app_assessment":
            parts.extend(full_app_campaign_context_lines())
        elif campaign_type == "crawl_audit":
            parts.append("Campaign objective: close discovery gaps that passive sitemap review misses.")
            parts.append("- Use native Burp MCP crawl/audit actions for in-scope seed URLs, focused paths, and authenticated areas when available.")
            parts.append("- After crawl/audit, re-run /api/coverage and /api/coverage/parameters; prioritize new dynamic endpoints and untested parameters with responses.")
            parts.append("- For high-signal XSS/SQLi/SSTI/open-redirect/injection insertion points, prefer native Burp MCP scanner control; fallback to POST /api/agent/scanner/active only after scope/safety checks.")
            parts.append("- Do not treat Burp Scanner output as final. Agent B must validate reportable impact or record it as a lead/Gated blocker.")
        elif campaign_type == "authz_matrix":
            parts.append("Campaign objective: find authorization bypasses that single-user replay misses.")
            parts.append("- Build a role/tenant/session/object matrix from /api/agent/fixtures and project_profile.roles.")
            parts.append("- Require at least two useful actors or actor/object combinations. If fixtures are missing, return blocked-by-missing-fixture with the exact account/session/object/tenant pair needed.")
            parts.append("- Replay safe captured requests across owner, peer, lower-privilege, cross-tenant, pre-MFA/post-MFA, expired/revoked session, and anonymous controls when fixtures exist.")
            parts.append("- Evidence must include the expected deny/allow matrix, actor used, object tested, status code, response snippet, and why the response proves impact.")
        elif campaign_type == "race":
            parts.append("Campaign objective: find race/concurrency flaws that normal sequential testing misses.")
            parts.append("- Use only explicitly safe, in-scope, non-destructive, or user-approved targets. Stop for payment, purchase, password, delete, transfer, invite, upload, or admin flows unless approval exists.")
            parts.append("- Establish a single-request baseline first; then use Burp MCP/Turbo Intruder or an equivalent parallel runner with small bounded concurrency and repeats.")
            parts.append("- Default bounds when not provided: concurrency<=10 and repeats<=30. Stop early after a clear vulnerable or safe signal.")
            parts.append("- Evidence must include baseline, concurrent request count, response distribution, final state, and whether the result is reproducible.")
        elif campaign_type == "browser_dom":
            parts.append("Campaign objective: find browser-only issues that HTTP replay misses.")
            parts.append("- Use BrowserOS through Burp Proxy. Include --proxy-server=http://127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100, then require /api/agent/browseros/readiness proxy_verification.observed=true for the exact URL.")
            parts.append("- Test DOM XSS, reflected-to-DOM flows, postMessage handlers, client-side authz, service worker/cache behavior, local/session storage trust, redirects, CORS-visible behavior, console errors, dialogs, and UI-only state changes.")
            parts.append("- Capture browser-visible proof with URL, state, console/dialog/screenshot notes, and the exact proxied request history reference when possible.")
        elif campaign_type == "parser_protocol":
            parts.append("Campaign objective: cover specialized protocol/parser surfaces that generic web checks miss.")
            parts.append("- Inventory GraphQL, WebSocket, multipart upload, CSV/JSON/XML parser, JWT/OAuth/SAML, webhook, and HTTP/2-sensitive surfaces from Burp history, sitemap, and parameter coverage.")
            parts.append("- Use Burp MCP and protocol-native tooling. For HTTP/2-only or pseudo-header-sensitive behavior, use /api/agent/request/http2 or PortSwigger MCP send_http2_request.")
            parts.append("- For GraphQL, consider introspection, batching, aliasing, method changes, variable tampering, IDOR through object IDs, and authorization differences.")
            parts.append("- For WebSocket, use BrowserOS/manual WebSocket tooling through Burp; native curl is insufficient.")
            parts.append("- For upload/XML/JWT/OAuth/SAML parser behavior, keep payloads safe and bounded; use Collaborator only when OOB proof is needed and allowed.")
        else:
            parts.append("Campaign objective: focused scoped testing requested by the user.")

        if focus:
            parts.append("")
            parts.append("User-requested focus:")
            parts.append(str(focus))
        if options:
            parts.append("")
            parts.append("Campaign options:")
            try:
                parts.append(json.dumps(options, sort_keys=True))
            except Exception:
                parts.append(str(options))
        if user_context:
            parts.append("")
            parts.append("User context:")
            parts.append(str(user_context))
        text = "\n".join(parts)
        if not bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False)):
            text = "\n".join([line for line in text.splitlines() if "browseros" not in line.lower()])
            text = (
                "BrowserOS is disabled by the operator. Do not attempt its setup or use. Use Burp-native discovery and HTTP evidence for this campaign.\n\n"
                + text
            )
        return text

    def _enqueueRiskCampaign(self, campaign_type, user_context="", focus="", browser_verify=False, requested_by="ui", options=None):
        """Queue a focused risk campaign item."""
        if self.agent_server is None:
            self.stdout.println("[AGENT] Server not running, starting now...")
            if not self.start_agent_server():
                self.stderr.println("[AGENT] Failed to start server; cannot enqueue campaign")
                return None

        campaign_type = str(campaign_type or "focused").strip().lower().replace("-", "_").replace(" ", "_")
        if campaign_type not in ("full_app_assessment", "crawl_audit", "authz_matrix", "race", "browser_dom", "parser_protocol"):
            campaign_type = "focused"
        options = options if isinstance(options, dict) else {}
        if campaign_type == "full_app_assessment":
            options = dict(options)
            options.setdefault("minimum_routes", 20)
            options.setdefault("minimum_browser_routes", 10)
            options.setdefault("required_stable_passes", 2)
            options.setdefault("stable_max_new_routes", 0)
            options.setdefault("stable_max_new_parameters", 0)
            if not bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False)):
                options["minimum_browser_routes"] = 0
        try:
            default_budget = 120 if campaign_type == "full_app_assessment" else 40
            request_budget = max(1, min(200, int(options.get("request_budget", default_budget) or default_budget)))
        except Exception:
            request_budget = 40
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        label = self._campaign_label(campaign_type)
        context_text = self._campaign_context_text(campaign_type, user_context=user_context, focus=focus, options=options)
        required_context = [
            "/api/agent/burp/skill",
            "/api/agent/burp/capabilities",
            "/api/agent/burp/workspace",
            "/api/agent/scope",
            "/api/agent/preflight",
            "/api/agent/project-profile",
            "/api/agent/knowledge",
            "/api/agent/attack-surface",
            "/api/agent/attack-surface/review",
            "/api/agent/fixtures",
            "/api/agent/confirmations",
            "/api/findings",
            "/api/coverage",
            "/api/coverage/parameters",
            "/api/report",
            "/api/agent/history/http/regex"
        ]
        browseros_enabled = bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False))
        if campaign_type in ("browser_dom", "full_app_assessment"):
            browser_verify = browseros_enabled
        else:
            browser_verify = bool(browser_verify) and browseros_enabled
        with self.agent_queue_lock:
            qid = self.agent_queue_next_id
            self.agent_queue_next_id += 1
            queue_item = {
                "id": qid,
                "status": "pending",
                "created_at": now,
                "claimed_at": None,
                "completed_at": None,
                "finding_ids": [],
                "summary": "Campaign: %s" % label,
                "assessment": "",
                "test_results": [],
                "notes": [],
                "user_context": context_text,
                "source": "risk_hunt",
                "mode": "campaign_%s" % campaign_type,
                "campaign_type": campaign_type,
                "campaign_options": options,
                "campaign_state": {
                    "status": "pending",
                    "steps": build_campaign_steps(campaign_type, options),
                    "request_budget": request_budget,
                    "requests_used": 0,
                    "surface_snapshots": [],
                    "scanner_campaign": {},
                    "overwatch_review": {},
                    "updated_at": now
                },
                "browser_verify": bool(browser_verify),
                "risk_hunt": {
                    "objective": "Complete the %s campaign, using scope/safety gates and writing evidence-backed findings/results." % label,
                    "requested_by": requested_by,
                    "campaign_type": campaign_type,
                    "minimum_goals": 1,
                    "minimum_completed_or_blocked_goals": 1,
                    "required_context": required_context,
                    "write_back": "POST confirmed vulnerabilities to /api/findings with queue_id; POST /result with risk_hunt_goals and evidence; POST durable observations to /api/agent/knowledge.",
                    "completion": "POST /api/agent/queue/%d/result when the campaign has tested its bounded target set or exact blockers are recorded as Gated." % qid
                }
            }
            self.agent_queue.append(queue_item)
            self.selected_agent_queue_index = len(self.agent_queue) - 1

        self.save_agent_queue()
        self.log_to_console("[AGENT] Queued %s campaign as work item #%d" % (label, qid))
        self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
            self.agent_server_host, self.agent_server_port, qid))
        self._ui_dirty = True
        self.refreshUI()
        self._focus_agent_tab()
        return qid
