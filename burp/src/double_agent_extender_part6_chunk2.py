# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk6Chunk2(object):
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

            self._ingest_response_hygiene(messageInfo, url, req, res)

            # CORS preflight is deterministically inspected above. It does not
            # need the expensive general-purpose LLM pass.
            method = req.getMethod()
            if method == "OPTIONS":
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [HYGIENE ONLY] OPTIONS request (CORS preflight)" % (source, url_str))
                if task_id is not None:
                    self.updateTask(task_id, "Completed (CORS Preflight Baseline)")
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
                if agent_status == "not_important":
                    agent_status = "false_positive"
                if agent_status not in ("valid", "needs_investigation", "false_positive", "untouched"):
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

                if agent_status == "false_positive":
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
                if not str(issue_title).startswith("(Double Agent)") and not str(issue_title).startswith("(Eternals)"):
                    issue_title = "(Double Agent) " + str(issue_title)

                issue = CustomScanIssue(messageInfo.getHttpService(), req.getUrl(),
                                       [messageInfo], issue_title, full_detail, burp_severity, burp_conf)
                self.callbacks.addScanIssue(issue)
                created += 1
                self.updateStats("findings_created")
                agent_queue_id = None
                try:
                    agent_queue_id = self._queue_id_from_agent_note_text(
                        "%s\n%s" % (str(messageInfo.getComment() or ""), request_data_full or ""))
                except Exception:
                    agent_queue_id = None

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
                                active_test_recipe=active_test_recipe,
                                agent_queue_id=agent_queue_id)
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
        cookie_names = []
        if cookie_header:
            cookie_names = [c.split("=")[0].strip() for c in cookie_header.split(";") if "=" in c]
            auth_signals.append("Cookies: %s" % ", ".join(cookie_names[:8]))
        custom_auth_headers = []
        for header_name in sorted(req_headers_dict.keys()):
            if str(header_name).lower() in ("authorization", "cookie"):
                continue
            if self._looks_like_auth_header_name(header_name):
                custom_auth_headers.append(header_name)
        if custom_auth_headers:
            auth_signals.append("Custom auth-like headers: %s" % ", ".join(custom_auth_headers[:8]))
        host_auth_model = self._record_host_auth_model(url, req_headers_dict, cookie_names)
        if host_auth_model:
            auth_signals.append("Learned host auth model: headers=%s cookies=%s" % (
                ", ".join(host_auth_model.get("headers", [])[:8]),
                ", ".join(host_auth_model.get("cookies", [])[:8])))
        if not auth_header and not cookie_header and not custom_auth_headers:
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
        suppressed_fingerprints_summary = []
        try:
            from java.net import URL as JavaURL
            target_host = str(JavaURL(url).getHost() or "").lower()
            with self.findings_lock_ui:
                for f in self.findings_list:
                    if f.get("fp", False):
                        continue
                    try:
                        fhost = str(JavaURL(f.get("url", "http://x")).getHost() or "").lower()
                    except:
                        fhost = ""
                    if fhost == target_host:
                        existing_findings_summary.append({
                            "title": f.get("title", "")[:120],
                            "severity": f.get("severity", ""),
                            "url": f.get("url", "")[:120],
                            "agent_status": f.get("agent_status", ""),
                            "canonical_family": f.get("canonical_family", ""),
                            "finding_fingerprint": f.get("finding_fingerprint", ""),
                            "fingerprint_location": f.get("fingerprint_location", "")
                        })
                for fp_key in self.fp_suppressed:
                    try:
                        if not (isinstance(fp_key, tuple) and len(fp_key) == 2 and fp_key[0] == "fingerprint"):
                            continue
                        fingerprint = str(fp_key[1])
                        parts = fingerprint.split("|")
                        if len(parts) >= 6 and parts[2] == target_host:
                            suppressed_fingerprints_summary.append({
                                "canonical_family": parts[1],
                                "finding_fingerprint": fingerprint,
                                "fingerprint_location": parts[5]
                            })
                    except:
                        pass
            existing_findings_summary = existing_findings_summary[-10:]  # most recent 10
            suppressed_fingerprints_summary = suppressed_fingerprints_summary[-20:]
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
            "host_auth_model": host_auth_model,
            "request_headers": req_headers_list,
            "request_body": req_body,
            "response_headers": res_headers_list,
            "response_body": res_body,
            "tech_stack": tech_info,
            "neighboring_requests": neighbors,
            "existing_findings_on_host": existing_findings_summary,
            "suppressed_fingerprints_on_host": suppressed_fingerprints_summary
        }

        return data
