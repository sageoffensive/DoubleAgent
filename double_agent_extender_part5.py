# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk5(object):
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

        fixture_requirements = []
        raw_requirements = recipe.get("fixture_requirements", recipe.get("required_fixtures", []))
        if isinstance(raw_requirements, basestring):
            raw_requirements = [r.strip() for r in raw_requirements.split(",")]
        if isinstance(raw_requirements, list):
            for requirement in raw_requirements:
                req = str(requirement or "").strip().lower().replace(" ", "_").replace("-", "_")
                aliases = {
                    "needs_second_user": "needs_second_account",
                    "second_user": "needs_second_account",
                    "needs_second_account_number": "needs_account_number_pair",
                    "second_account_number": "needs_account_number_pair",
                    "needs_otp": "needs_live_otp",
                    "needs_sms": "needs_live_otp",
                    "needs_email": "needs_human_confirmation"
                }
                req = aliases.get(req, req)
                if req and req not in fixture_requirements:
                    fixture_requirements.append(req)
        if needs_second_user and "needs_second_account" not in fixture_requirements:
            fixture_requirements.append("needs_second_account")

        text_for_fixtures = ("%s %s %s %s" % (
            hypothesis, active_test_type, mutation_hint, recipe.get("safety_notes", recipe.get("safety", ""))
        )).lower()
        if ("accountnumber" in text_for_fixtures or "account number" in text_for_fixtures or "tenant" in text_for_fixtures) and "needs_account_number_pair" not in fixture_requirements:
            fixture_requirements.append("needs_account_number_pair")
        if ("otp" in text_for_fixtures or "sms" in text_for_fixtures or "email received" in text_for_fixtures or "mfa" in text_for_fixtures) and "needs_human_confirmation" not in fixture_requirements:
            fixture_requirements.append("needs_human_confirmation")

        safety_notes = self._recipe_text_value(recipe, fallback, ["safety_notes", "safety", "constraints"], 1000)
        if not safety_notes:
            safety_notes = "Respect queue safety_gate and scope_guard. Ask before destructive, payment, password, delete, upload, transfer, order, or admin actions."

        ready_for_active = bool(status in ("valid", "needs_investigation") and str(priority).lower() != "defer")
        default_scanner_recommended = active_test_type in ("xss", "injection")
        scanner_recommended = self._recipe_bool_value(
            recipe, fallback,
            ["scanner_recommended", "burp_scanner_recommended", "delegate_to_scanner", "scanner_delegate"],
            default_scanner_recommended
        )
        scanner_focus = self._recipe_text_value(
            recipe, fallback,
            ["scanner_focus", "burp_scanner_focus", "scanner_profile", "scan_type"],
            120
        )
        if not scanner_focus and scanner_recommended:
            scanner_focus = active_test_type or "focused"

        if not hypothesis and not mutation_hint and not title:
            return {}

        structured_mutations = []
        for source in (recipe, fallback):
            raw_mutations = source.get("mutations", source.get("mutation_recipes", [])) if isinstance(source, dict) else []
            if not isinstance(raw_mutations, list):
                continue
            for mutation in raw_mutations[:5]:
                if isinstance(mutation, dict):
                    structured_mutations.append(mutation)
            if structured_mutations:
                break

        return {
            "hypothesis": hypothesis,
            "why_now": why_now,
            "active_test_type": active_test_type,
            "baseline_request": baseline_request,
            "mutation_hint": mutation_hint,
            "mutations": structured_mutations,
            "scanner_recommended": bool(scanner_recommended),
            "scanner_focus": scanner_focus,
            "expected_vulnerable_signal": expected_vulnerable_signal,
            "expected_safe_signal": expected_safe_signal,
            "max_requests": max_requests,
            "needs_second_user": bool(needs_second_user),
            "fixture_requirements": fixture_requirements,
            "safety_notes": safety_notes,
            "ready_for_active": ready_for_active
        }

    def _classify_agent_candidate_type(self, finding):
        """Coarse active-agent queue quality label.

        This separates reportable candidates from fixture-dependent work,
        theory-only hypotheses, and scanner noise without changing the
        existing agent_status values used elsewhere.
        """
        try:
            if not isinstance(finding, dict):
                finding = {}
            if self._low_signal_noise_finding(finding):
                return "scanner_noise"
            status = str(finding.get("agent_status", "untouched") or "untouched").lower()
            priority = str(finding.get("agent_priority", "") or "").lower()
            if status in ("false_positive", "not_important") or priority == "defer" or bool(finding.get("fp", False)):
                return "scanner_noise"
            recipe = finding.get("active_test_recipe", {}) or {}
            if isinstance(recipe, dict) and recipe.get("fixture_requirements"):
                return "needs_fixture"
            has_evidence = bool(finding.get("request_data") or finding.get("response_data") or finding.get("evidence"))
            ready = bool(isinstance(recipe, dict) and recipe.get("ready_for_active", False))
            if status == "valid" and has_evidence:
                return "reportable_candidate"
            if status == "needs_investigation" and ready and has_evidence:
                return "reportable_candidate"
            if status in ("valid", "needs_investigation"):
                return "theory_only"
            return "theory_only"
        except Exception:
            return "theory_only"

    def _low_signal_noise_finding(self, finding):
        try:
            text = " ".join([
                str(finding.get("title", "") or ""),
                str(finding.get("detail", "") or ""),
                str(finding.get("evidence", "") or ""),
                str(finding.get("url", "") or "")
            ]).lower()
            url = str(finding.get("url", "") or "").lower()
            high_signal = any(term in text for term in [
                "secret", "credential", "api key", "apikey", "password", "private key",
                "source map", ".map", "pii", "token leak", "admin", "authorization bypass",
                "idor", "account takeover", "xss", "sqli", "sql injection", "ssrf", "rce"
            ])
            if high_signal:
                return False
            static_markers = [
                "/_next/static/", "/static/chunks/", "/static/media/", "/assets/",
                "/dist/", ".chunk.js", ".bundle.js", "-manifest.json", "/webpack-runtime",
                "/runtime~main", "module federation", "federation chunk", "remoteentry.js"
            ]
            if any(marker in url or marker in text for marker in static_markers):
                return True
            low_signal_terms = [
                "cookie sent to same-origin static asset",
                "same-origin static asset",
                "module federation chunk",
                "chunk map",
                "build manifest",
                "version metadata",
                "configuration metadata",
                "framework version",
                "webpack runtime"
            ]
            return any(term in text for term in low_signal_terms)
        except Exception:
            return False

    def _agent_validation_marker(self, finding):
        marker = str((finding or {}).get("agent_validated_by", "") or "").strip().upper()
        if marker == "B":
            return "B"
        return "A"

    def _agent_status_marker(self, finding):
        """Display marker: B=Agent B actively tested, B triage=Agent B triaged
        but not yet actively tested, A=Agent A passive only. Kept separate from
        _agent_validation_marker so automated testing still targets B-triaged
        findings (which are not yet actively validated)."""
        if self._agent_validation_marker(finding) == "B":
            return "B"
        # Jev auto-review marks non-exact duplicates among Agent A findings.
        if (finding or {}).get("jev_duplicate"):
            return "jev"
        triaged = str((finding or {}).get("agent_triaged_by", "") or "").strip().lower()
        if triaged in ("b", "agent_b"):
            return "B triage"
        return "A"

    def _agent_status_display(self, finding):
        display_status = self._safe_ascii_text((finding or {}).get("agent_display_status", ""), 100).strip().lower()
        if display_status in ("gated", "blocked", "blocked_by_fixture", "blocked-by-fixture"):
            return "Gated (%s)" % self._agent_status_marker(finding)
        if display_status in ("partially_tested", "partial", "partially-tested"):
            return "Partial (%s)" % self._agent_status_marker(finding)
        status = self._safe_ascii_text((finding or {}).get("agent_status", "untouched"), 100)
        status_l = str(status or "").lower()
        if status_l == "needs_investigation":
            if (finding or {}).get("gate_reason") or (finding or {}).get("gate_detail"):
                display = "Gated"
            else:
                display = "Needs Testing"
        else:
            display = status or "untouched"
        return "%s (%s)" % (display, self._agent_status_marker(finding))

    def _automated_testing_finding_ids(self):
        ids = []
        try:
            with self.findings_lock_ui:
                for idx, finding in enumerate(self.findings_list):
                    if self._agent_validation_marker(finding) == "B":
                        continue
                    if self._finding_hidden_from_normal_view(finding):
                        continue
                    ids.append(idx)
        except Exception:
            pass
        return ids

    def _queue_id_from_agent_note_text(self, text):
        try:
            text = str(text or "")
            for pattern in (r"(?i)\bqueue\s*#?\s*(\d+)\b", r"(?i)\bq\s*#?\s*(\d+)\b"):
                match = re.search(pattern, text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return None

    def _agent_queue_id_for_scanner_issue(self, url):
        """Best-effort link from a Burp Scanner issue URL to a delegated scanner job."""
        try:
            target_host = self._url_host(url)
            target_path = self._normalized_url_path(url)
            if not target_host:
                return None
            matches = []
            with self.scanner_jobs_lock:
                for job_id, job in self.scanner_jobs.items():
                    try:
                        queue_id = job.get("queue_id", "")
                        if queue_id is None or str(queue_id).strip() == "":
                            continue
                        job_host = self._url_host(job.get("url", ""))
                        job_path = self._normalized_url_path(job.get("url", ""))
                        if job_host == target_host and job_path == target_path:
                            matches.append((int(job_id), queue_id))
                    except Exception:
                        continue
            if not matches:
                return None
            matches.sort(reverse=True)
            try:
                return int(matches[0][1])
            except Exception:
                return matches[0][1]
        except Exception:
            return None

    def _agent_queue_mode_for_id(self, queue_id):
        try:
            queue_id = int(queue_id)
        except Exception:
            return ""
        try:
            with self.agent_queue_lock:
                for item in self.agent_queue:
                    try:
                        if int(item.get("id", -1)) == queue_id:
                            return str(item.get("mode", "") or "")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            for item in getattr(self, "completed_agent_results", []) or []:
                try:
                    if int(item.get("id", -1)) == queue_id:
                        return str(item.get("mode", "") or "")
                except Exception:
                    continue
        except Exception:
            pass
        return ""

    def _try_harder_prefixed_title(self, title):
        title = self._safe_ascii_text(title, 500).strip()
        if title.lower().startswith("(th)"):
            return title
        return "(TH) " + title

    def _should_prefix_try_harder_finding(self, agent_queue_id, source):
        source_l = str(source or "").lower()
        if source_l not in ("agent_active", "agent_api", "automated_testing"):
            return False
        return self._agent_queue_mode_for_id(agent_queue_id).lower() == "try_harder"

    def _link_finding_to_agent_queue(self, queue_id, finding_idx, link_kind="agent_generated"):
        try:
            queue_id = int(queue_id)
            finding_idx = int(finding_idx)
        except Exception:
            return False
        with self.findings_lock_ui:
            if finding_idx < 0 or finding_idx >= len(self.findings_list):
                return False
            finding_stable_id = self._ensure_finding_stable_id(self.findings_list[finding_idx])
        linked = False

        def _append_unique(item, field_name):
            values = list(item.get(field_name, []) or [])
            if finding_idx not in values:
                values.append(finding_idx)
            item[field_name] = values

        def _append_link(item):
            ids = list(item.get("finding_ids", []) or [])
            if finding_idx not in ids:
                ids.append(finding_idx)
            item["finding_ids"] = ids
            stable_ids = list(item.get("finding_stable_ids", []) or [])
            if finding_stable_id and finding_stable_id not in stable_ids:
                stable_ids.append(finding_stable_id)
            item["finding_stable_ids"] = stable_ids
            if link_kind == "scanner_seen":
                _append_unique(item, "scanner_findings_seen_during_work")
                stable_field = "scanner_finding_stable_ids"
            elif link_kind == "passive_seen":
                _append_unique(item, "passive_findings_seen_during_work")
                stable_field = "passive_finding_stable_ids"
            else:
                _append_unique(item, "agent_generated_finding_ids")
                stable_field = "agent_generated_finding_stable_ids"
            stable_values = list(item.get(stable_field, []) or [])
            if finding_stable_id and finding_stable_id not in stable_values:
                stable_values.append(finding_stable_id)
            item[stable_field] = stable_values

        with self.agent_queue_lock:
            for item in self.agent_queue:
                try:
                    if int(item.get("id", -1)) == queue_id:
                        _append_link(item)
                        linked = True
                        break
                except Exception:
                    continue
        if linked:
            self._agent_queue_save_pending = True
            return True

        try:
            history = getattr(self, "completed_agent_results", []) or []
            for item in history:
                try:
                    if int(item.get("id", -1)) == queue_id:
                        _append_link(item)
                        linked = True
                        break
                except Exception:
                    continue
        except Exception:
            pass
        if linked:
            self._agent_queue_save_pending = True
        return linked

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
            agent_status_display = self._agent_status_display(f)
            agent_priority = self._safe_ascii_text(f.get("agent_priority", ""), 100)
            agent_rationale = self._safe_ascii_text(f.get("agent_rationale", ""), 2000)
            source = self._safe_ascii_text(f.get("source", "eternals_passive"), 200)

            lines.append("### %d. [%s] %s" % (idx, sev, title))
            lines.append("")
            lines.append("- **Finding ID:** `%s`" % self._ensure_finding_stable_id(f))
            lines.append("- **URL:** `%s`" % url)
            lines.append("- **Confidence:** %s" % conf)
            lines.append("- **Source:** %s" % source)
            if f.get("cwe"):
                lines.append("- **CWE:** %s" % self._safe_ascii_text(f.get("cwe"), 200))
            if f.get("owasp"):
                lines.append("- **OWASP:** %s" % self._safe_ascii_text(f.get("owasp"), 200))
            lines.append("- **Agent Status:** %s%s" % (
                agent_status_display,
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
                if recipe.get("scanner_recommended"):
                    lines.append("- **Burp Scanner Delegation:** recommended (%s)" % self._safe_ascii_text(recipe.get("scanner_focus", "focused"), 120))
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

    def add_finding(self, url, title, severity, confidence, detail="", cwe="", evidence="", remediation="", owasp="", ai_confidence=0, request_data=None, response_data=None, source="eternals_passive", raw_ai_confidence=None, agent_status="untouched", agent_priority="", agent_rationale="", active_test_recipe=None, agent_validated_by=None, agent_queue_id=None, deduplication_key=""):
        new_finding_idx = None
        normalized_agent_status = self._agent_status_value(agent_status)
        if normalized_agent_status == "not_important":
            normalized_agent_status = "false_positive"
        if normalized_agent_status not in ("untouched", "valid", "false_positive", "duplicate", "already_covered", "needs_investigation"):
            normalized_agent_status = "untouched"
        agent_status = normalized_agent_status
        with self.findings_lock_ui:
            fingerprint = self._finding_fingerprint(url, title, cwe, detail, evidence, request_data, source)
            canonical_family = self._canonical_finding_family(title, cwe, detail, evidence)
            fingerprint_location = self._fingerprint_location(url, title, detail, evidence, request_data)
            fp_keys = self._get_fp_keys_for_finding(url, title, source, cwe, detail, evidence, request_data)
            if any(fp_key in self.fp_suppressed for fp_key in fp_keys):
                if self.VERBOSE:
                    self.stdout.println("[FP] Suppressing known FP: %s" % self._safe_ascii_text(str(title)[:100]))
                return {
                    "disposition": "suppressed",
                    "reason": "known_false_positive",
                    "stable_id": "",
                    "title": title,
                    "deduplication_key": str(deduplication_key or ""),
                }
            duplicate = None
            duplicate_reason = ""
            explicit_dedupe_key = str(deduplication_key or "").strip()
            if explicit_dedupe_key:
                for candidate in self.findings_list:
                    if str(candidate.get("deduplication_key", "") or "") == explicit_dedupe_key:
                        duplicate = candidate
                        duplicate_reason = "explicit_deduplication_key"
                        break
            if duplicate is None:
                duplicate, duplicate_reason = self._find_duplicate_finding(url, title, cwe, source, detail, evidence, request_data)
            if duplicate:
                self._merge_duplicate_finding(duplicate, url, title, detail, evidence, duplicate_reason)
                if self.VERBOSE:
                    self.stdout.println("[DEDUP] Merged duplicate finding (%s): %s" % (
                        duplicate_reason, self._safe_ascii_text(str(title)[:100])))
                duplicate_idx = self.findings_list.index(duplicate)
                return {
                    "disposition": "matched",
                    "stable_id": self._ensure_finding_stable_id(duplicate),
                    "legacy_numeric_id": self._ensure_finding_legacy_numeric_id(duplicate, duplicate_idx + 1),
                    "version": int(duplicate.get("version", 1) or 1),
                    "title": duplicate.get("title", title),
                    "active_test_recipe": duplicate.get("active_test_recipe", {}),
                    "match_reason": duplicate_reason,
                    "deduplication_key": explicit_dedupe_key or duplicate.get("deduplication_key", ""),
                }
            if self._should_prefix_try_harder_finding(agent_queue_id, source):
                title = self._try_harder_prefixed_title(title)
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
            validation_marker = str(agent_validated_by or "").strip().upper()
            if validation_marker not in ("A", "B"):
                validation_marker = "B" if str(source or "").lower() in ("agent_active", "agent_api", "automated_testing") else "A"
            finding = {
                "stable_id": "daf_" + uuid.uuid4().hex,
                "version": 1,
                "audit_log": [],
                "deduplication_key": explicit_dedupe_key,
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
                "fp": bool(agent_status == "false_positive"),
                "agent_status": agent_status or "untouched",
                "agent_validated_by": validation_marker,
                "agent_priority": agent_priority or "",
                "agent_rationale": agent_rationale or "",
                "agent_queue_id": agent_queue_id if agent_queue_id is not None else "",
                "active_test_recipe": active_test_recipe,
                "agent_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if agent_status and agent_status != "untouched" else "",
                "request_data": request_data,
                "response_data": response_data,
                "source": source,
                "canonical_family": canonical_family,
                "finding_fingerprint": fingerprint or "",
                "fingerprint_location": fingerprint_location
            }
            self._ensure_finding_legacy_numeric_id(finding)
            finding["agent_candidate_type"] = self._classify_agent_candidate_type(finding)
            if finding["agent_candidate_type"] == "scanner_noise" and finding.get("agent_status") in ("untouched", "needs_investigation", "valid"):
                finding["agent_status"] = "false_positive"
                finding["fp"] = True
                finding["agent_priority"] = "defer"
                finding["agent_rationale"] = "Automatically downgraded as low-signal static/config/version metadata without chained secret, source-map, log, auth, or exploit impact."
                finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._record_finding_audit(finding, "created", {
                "source": source,
                "queue_id": agent_queue_id if agent_queue_id is not None else "",
                "deduplication_key": explicit_dedupe_key,
            }, actor="agent_b" if validation_marker == "B" else "agent_a", bump_version=False)
            new_finding_idx = len(self.findings_list)
            self.findings_list.append(finding)
        if agent_queue_id is not None and new_finding_idx is not None:
            source_l = str(source or "").lower()
            if source_l == "burp_scanner":
                link_kind = "scanner_seen"
            elif source_l in ("agent_active", "agent_api", "automated_testing"):
                link_kind = "agent_generated"
            else:
                link_kind = "passive_seen"
            self._link_finding_to_agent_queue(agent_queue_id, new_finding_idx, link_kind=link_kind)
        self.save_findings()
        self._ui_dirty = True
        return {
            "disposition": "created",
            "stable_id": finding.get("stable_id", ""),
            "legacy_numeric_id": finding.get("legacy_numeric_id"),
            "version": int(finding.get("version", 1) or 1),
            "title": finding.get("title", title),
            "active_test_recipe": finding.get("active_test_recipe", {}),
            "match_reason": "",
            "deduplication_key": explicit_dedupe_key,
        }

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
        if source in ("PROXY", "EXTENDER", "REPEATER", "SCANNER") and not getattr(self, "PROXY_DEDUPE_ENABLED", True):
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
