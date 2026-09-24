# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk6Chunk3(object):
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
            "- Do not return a finding that matches any known finding or suppressed false-positive fingerprint shown in the context, even if you would use a different title.\n"
            "\n"
            "PASSIVE TRIAGE GATE:\n"
            "- You are the cheap passive scanner and first triage layer. Put real thought into whether the issue is likely valid before returning it.\n"
            "- Response-header hygiene is handled deterministically before this prompt. Do not duplicate those candidates. You may strengthen one only when the captured traffic demonstrates a concrete exploit path.\n"
            "- Return only findings that are either likely valid from passive evidence or worth active verification by the expensive active agent.\n"
            "- For each returned finding set agent_status:\n"
            "  valid = passive evidence is strong enough that active testing should confirm impact, including real low-risk findings when agent_priority=P4.\n"
            "  needs_investigation = plausible and worth one focused active-agent check, but not proven from passive data.\n"
            "  Do not return false positives, zero-risk, or non-actionable noise. Suppress those instead of returning a finding.\n"
            "- For each returned finding set agent_priority: P1/P2 for high-impact likely-valid issues, P3 for focused active checks, P4 for valid low-risk issues.\n"
            "- agent_rationale must explain why this should or should not be sent to the active agent, tied to specific evidence.\n"
            "- For every returned valid or needs_investigation finding, include active_test_recipe. This is the handoff to the expensive active agent, so it must be specific enough to run without re-thinking the plan.\n"
            "\n"
            "ACTIVE TEST RECIPE:\n"
            "- hypothesis: the exact claim the active agent should validate.\n"
            "- why_now: why this is worth active testing based on passive evidence.\n"
            "- active_test_type: one of authorization, authentication, injection, ssrf, xss, csrf, business_logic, token_or_session, focused_validation.\n"
            "- baseline_request: what baseline request/response behavior to confirm first.\n"
            "- mutation_hint: the smallest safe request change to test the hypothesis.\n"
            "- mutations: optional executable request transforms for Repeater. Use operations with types set_header, remove_header, set_query_param, remove_query_param, set_method, replace_body, json_set, or replace_text.\n"
            "- scanner_recommended: true when the finding is a high-signal XSS, SQLi, SSTI, open redirect, or similar insertion-point candidate that should be delegated to Burp Scanner before manual payload breadth.\n"
            "- scanner_focus: optional short focus such as xss, sqli, ssti, open_redirect, or injection.\n"
            "- expected_vulnerable_signal: what response/status/body difference would prove impact.\n"
            "- expected_safe_signal: what response/status/body difference would disprove or weaken it.\n"
            "- max_requests: 1-10 focused requests; keep cheap and bounded.\n"
            "- needs_second_user: true only when authorization/IDOR/account-bound proof needs another identity.\n"
            "- fixture_requirements: exact prerequisites such as needs_second_account, needs_account_number_pair, needs_object_id_pair, needs_tenant_pair, needs_pre_mfa_session, needs_post_mfa_session, needs_revoked_session, needs_live_otp, needs_human_confirmation.\n"
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
            "9. Deterministic CORS, session-cookie, and representative browser-header candidates; keep standalone hardening at P4/Information unless a concrete attack raises impact\n"
            "\n"
            "FALSE POSITIVE SUPPRESSION (do NOT flag):\n"
            "- Bearer/JWT/cookie tokens appearing in Authorization headers, Set-Cookie, or request bodies. "
            "Proxy traffic is visible by design; this is not exposure.\n"
            "- Duplicate missing-header or cookie-attribute findings already supplied in existing_findings_on_host. The deterministic response-hygiene pass owns those facts.\n"
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
            "\"agent_status\":\"valid|needs_investigation\","
            "\"agent_priority\":\"P1|P2|P3|P4|defer\","
            "\"agent_rationale\":\"why this passive finding is worth/not worth active-agent follow-up\","
            "\"active_test_recipe\":{\"hypothesis\":\"claim to validate\","
            "\"why_now\":\"passive evidence reason\","
            "\"active_test_type\":\"authorization|authentication|injection|ssrf|xss|csrf|business_logic|token_or_session|focused_validation\","
            "\"baseline_request\":\"baseline to replay first\","
            "\"mutation_hint\":\"smallest safe mutation\","
            "\"mutations\":[{\"label\":\"peer object probe\",\"operations\":[{\"type\":\"set_query_param\",\"name\":\"id\",\"value\":\"456\"}]}],"
            "\"scanner_recommended\":false,"
            "\"scanner_focus\":\"xss|sqli|ssti|open_redirect|injection|focused\","
            "\"expected_vulnerable_signal\":\"proof signal\","
            "\"expected_safe_signal\":\"safe/negative signal\","
            "\"max_requests\":3,"
            "\"needs_second_user\":false,"
            "\"fixture_requirements\":[],"
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
            auth_model = data.get("host_auth_model", {}) or {}
            if auth_model:
                prompt += "  Learned host auth model: headers=%s cookies=%s\n" % (
                    ", ".join(auth_model.get("headers", [])[:10]),
                    ", ".join(auth_model.get("cookies", [])[:10]))
                prompt += "  Do not treat missing standard Authorization as unauthenticated if this host uses custom auth headers/cookies.\n"

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
            prompt += "\n=== KNOWN FINDINGS ON THIS HOST (do NOT duplicate these, even with different titles) ===\n"
            for f in existing:
                prompt += "  [%s] family=%s location=%s fingerprint=%s status=%s title=%s (%s)\n" % (
                    f.get("severity", ""),
                    f.get("canonical_family", ""),
                    f.get("fingerprint_location", ""),
                    f.get("finding_fingerprint", ""),
                    f.get("agent_status", ""),
                    f.get("title", ""),
                    f.get("url", ""))

        suppressed = data.get("suppressed_fingerprints_on_host", [])
        if suppressed:
            prompt += "\n=== SUPPRESSED FALSE-POSITIVE FINGERPRINTS ON THIS HOST (do NOT return) ===\n"
            for f in suppressed:
                prompt += "  family=%s location=%s fingerprint=%s\n" % (
                    f.get("canonical_family", ""),
                    f.get("fingerprint_location", ""),
                    f.get("finding_fingerprint", ""))

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
