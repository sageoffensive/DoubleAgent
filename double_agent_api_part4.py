# -*- coding: utf-8 -*-
from double_agent_prelude import *


class _JavaSSEStream(object):
    """Small readline adapter around Java's chunk-aware HTTP input stream."""
    def __init__(self, connection, reader):
        self.connection = connection
        self.reader = reader

    def readline(self):
        line = self.reader.readLine()
        if line is None:
            return None
        return unicode_text(line) + u"\n"

    def close(self):
        try:
            self.reader.close()
        finally:
            try:
                self.connection.disconnect()
            except Exception:
                pass


class AgentAPIChunk4(object):
    def _apply_queue_result_to_findings(self, queue_item, body, outcome, assessment, now):
        updated = []
        update_map = self._finding_update_map_from_result_body(body)
        explicit_only = bool(queue_item.get("source") == "risk_hunt" or body.get("explicit_finding_updates_only", False))
        if explicit_only:
            finding_ids = sorted(update_map.keys())
            if not finding_ids:
                return []
        else:
            finding_ids = queue_item.get("finding_ids", []) or []
        default_status = self._agent_status_for_queue_outcome(outcome)
        default_rationale = self._limit_text(
            body.get("agent_rationale", body.get("finding_rationale", assessment)),
            2000
        )
        if not default_rationale:
            default_rationale = "Agent result (%s) submitted for queue #%s." % (
                outcome, str(queue_item.get("id", "")))

        with self.extender.findings_lock_ui:
            for fid in finding_ids:
                try:
                    idx = int(fid)
                except:
                    continue
                if idx < 0 or idx >= len(self.extender.findings_list):
                    continue
                finding = self.extender.findings_list[idx]
                item_update = update_map.get(idx, {})
                raw_status = item_update.get("agent_status", item_update.get("finding_status", None))
                if raw_status is None:
                    if explicit_only and body.get("agent_status") is None and body.get("finding_status") is None:
                        raw_status = finding.get("agent_status", "untouched")
                    else:
                        raw_status = body.get("agent_status", body.get("finding_status", default_status))
                status = self._normalize_agent_status(raw_status)

                raw_severity = item_update.get("severity", item_update.get("risk", None))
                if raw_severity is None:
                    raw_severity = body.get("severity", body.get("risk", finding.get("severity", "Information")))
                severity = self._normalize_finding_severity(raw_severity, finding.get("severity", "Information"))

                raw_priority = item_update.get("agent_priority", item_update.get("priority", None))
                if raw_priority is None:
                    raw_priority = body.get("agent_priority", body.get("priority", ""))
                priority = self._agent_priority_for_queue_result(outcome, severity, raw_priority or finding.get("agent_priority", ""))

                rationale = self._limit_text(
                    item_update.get("agent_rationale", item_update.get("rationale", default_rationale)),
                    2000
                )
                if not rationale:
                    rationale = default_rationale

                finding["agent_status"] = status
                finding["agent_validated_by"] = "B"
                finding["agent_validated_at"] = now
                finding["agent_priority"] = priority
                finding["severity"] = severity
                finding["agent_rationale"] = rationale
                finding["canonical_family"] = self.extender._canonical_finding_family(
                    finding.get("title", ""), finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""))
                finding["finding_fingerprint"] = self.extender._finding_fingerprint(
                    finding.get("url", ""), finding.get("title", ""), finding.get("cwe", ""),
                    finding.get("detail", ""), finding.get("evidence", ""), finding.get("request_data"),
                    finding.get("source", "")) or ""
                finding["fingerprint_location"] = self.extender._fingerprint_location(
                    finding.get("url", ""), finding.get("title", ""), finding.get("detail", ""),
                    finding.get("evidence", ""), finding.get("request_data"))
                finding["agent_updated_at"] = now

                set_fp = item_update.get("set_fp", body.get("set_fp", None))
                if set_fp is None and status == "false_positive":
                    set_fp = True
                elif set_fp is None and status == "valid":
                    set_fp = False
                if set_fp is not None:
                    finding["fp"] = bool(set_fp)
                    fp_keys = self.extender._get_fp_keys_for_finding(
                        finding.get("url", ""), finding.get("title", ""), finding.get("source", ""),
                        finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""),
                        finding.get("request_data")
                    )
                    if fp_keys:
                        if bool(set_fp):
                            for fp_key in fp_keys:
                                self.extender.fp_suppressed.add(fp_key)
                        else:
                            for fp_key in fp_keys:
                                if fp_key in self.extender.fp_suppressed:
                                    self.extender.fp_suppressed.discard(fp_key)

                gate_detail = item_update.get("gate_detail", item_update.get("blocker", ""))
                gate_reason = item_update.get("gate_reason", "")
                gate_next_step = item_update.get("next_step", item_update.get("gate_next_step", ""))
                if outcome in ("gated", "blocked-by-missing-fixture") and not gate_detail:
                    gate_detail = default_rationale
                    gate_reason = "missing_fixture" if outcome == "blocked-by-missing-fixture" else "blocked"
                if gate_detail or gate_reason:
                    self._apply_gate_to_finding(finding, gate_reason, gate_detail, gate_next_step, now)

                updated.append({
                    "id": self.extender._ensure_finding_stable_id(finding),
                    "legacy_numeric_id": self.extender._ensure_finding_legacy_numeric_id(finding, idx + 1),
                    "severity": finding.get("severity", ""),
                    "status": finding.get("agent_status", ""),
                    "display": self.extender._agent_status_display(finding),
                    "gate_reason": finding.get("gate_reason", ""),
                    "priority": finding.get("agent_priority", ""),
                    "fp": bool(finding.get("fp", False))
                })
        return updated

    def _sanitize_result_items(self, items):
        cleaned = []
        for item in self._limit_list(items, 25):
            if isinstance(item, dict):
                cleaned.append({
                    "title": self._limit_text(item.get("title", item.get("test", "")), 300),
                    "outcome": self._normalize_queue_outcome(item.get("outcome", "")),
                    "detail": self._limit_text(item.get("detail", ""), 1000),
                    "evidence": self._limit_text(item.get("evidence", ""), 2000)
                })
            else:
                cleaned.append({
                    "title": self._limit_text(item, 300),
                    "outcome": "inconclusive",
                    "detail": "",
                    "evidence": ""
                })
        return cleaned

    def _sanitize_evidence_items(self, items):
        cleaned = []
        for item in self._limit_list(items, 25):
            if not isinstance(item, dict):
                cleaned.append({"notes": self._limit_text(item, 2000)})
                continue
            status_code = item.get("status_code", item.get("status", None))
            try:
                status_code = int(status_code) if status_code is not None and status_code != "" else None
            except:
                status_code = None
            cleaned.append({
                "request": self._limit_text(item.get("request", item.get("curl", "")), 6000),
                "status_code": status_code,
                "response_snippet": self._limit_text(item.get("response_snippet", item.get("response", "")), 6000),
                "notes": self._limit_text(item.get("notes", item.get("detail", "")), 2000),
                "auth_source": self._limit_text(item.get("auth_source", item.get("auth", "")), 300),
                "burp_history_ref": self._limit_text(item.get("burp_history_ref", item.get("burp_history_index", "")), 300),
                "hypothesis": self._limit_text(item.get("hypothesis", item.get("test_purpose", "")), 500)
            })
        return cleaned

    def _risk_hunt_goals_from_body(self, body):
        goals = body.get("risk_hunt_goals", body.get("goals", []))
        if not isinstance(goals, list):
            return []
        cleaned = []
        for goal in self._limit_list(goals, 20):
            if isinstance(goal, dict):
                cleaned.append({
                    "id": self._limit_text(goal.get("id", goal.get("name", "")), 120),
                    "category": self._limit_text(goal.get("category", goal.get("type", "")), 80).lower().replace("-", "_").replace(" ", "_"),
                    "hypothesis": self._limit_text(goal.get("hypothesis", goal.get("title", "")), 600),
                    "target": self._limit_text(goal.get("target", goal.get("endpoint", goal.get("flow", ""))), 500),
                    "status": self._limit_text(goal.get("status", goal.get("outcome", "")), 80).lower().replace("_", "-"),
                    "evidence": self._limit_text(goal.get("evidence", ""), 1000),
                    "finding_ids": self._limit_list(goal.get("finding_ids", []), 20) if isinstance(goal.get("finding_ids", []), list) else [],
                    "blocker": self._limit_text(goal.get("blocker", goal.get("blocked_by", "")), 500),
                    "next_step": self._limit_text(goal.get("next_step", ""), 500)
                })
            else:
                cleaned.append({
                    "id": "",
                    "category": "",
                    "hypothesis": self._limit_text(goal, 600),
                    "target": "",
                    "status": "",
                    "evidence": "",
                    "finding_ids": [],
                    "blocker": "",
                    "next_step": ""
                })
        return cleaned

    def _persistent_goal_report_from_body(self, body):
        report = body.get("persistent_goal", {}) if isinstance(body, dict) else {}
        if not isinstance(report, dict):
            report = {}
        return {
            "created": self._coerce_bool(report.get("created", body.get("persistent_goal_created", False)), False),
            "status": self._limit_text(report.get("status", ""), 80).lower().replace("-", "_").replace(" ", "_"),
            "objective": self._limit_text(report.get("objective", ""), 1000),
            "goal_id": self._limit_text(report.get("goal_id", report.get("id", "")), 200),
            "tool_unavailable": self._coerce_bool(report.get("tool_unavailable", False), False),
            "reason": self._limit_text(report.get("reason", report.get("blocker", "")), 1000)
        }

    def _persistent_goal_problem(self, queue_item, body):
        contract = queue_item.get("persistent_agent_goal", {}) or {}
        if not contract.get("required"):
            return ""
        report = self._persistent_goal_report_from_body(body)
        if report.get("tool_unavailable"):
            if len(report.get("reason", "").strip()) >= 20:
                return ""
            return "persistent_agent_goal reports create_goal unavailable but does not include an exact reason"
        if not report.get("created"):
            return "Try Harder requires a persistent agent goal. Call get_goal, then create_goal exactly once if no matching active goal exists, and include persistent_goal.created=true in /result."
        if report.get("status") not in ("active", "in_progress", "created"):
            return "persistent_agent_goal must still be active when /result is submitted; call update_goal(status=complete) only after Double Agent accepts the result"
        if not report.get("objective"):
            return "persistent_agent_goal must include the active goal objective in /result"
        return ""

    def _risk_hunt_completion_problem(self, queue_item, body, risk_hunt_goals):
        if str(queue_item.get("source", "")) != "risk_hunt":
            return ""
        risk_meta = queue_item.get("risk_hunt", {}) or {}
        mode = str(risk_meta.get("mode", queue_item.get("mode", "")) or "").lower()
        # Automated Testing is a verification queue. Every linked finding must
        # receive an explicit Agent B update or an evidence-backed gate before
        # the queue can become terminal. A successful triage write alone is not
        # validation and must never make an empty result acceptable.
        if not mode.startswith("campaign_") and mode != "try_harder":
            linked_ids = []
            for raw_id in queue_item.get("finding_ids", []) or []:
                try:
                    linked_ids.append(int(raw_id))
                except:
                    continue
            if linked_ids:
                accounted = set(self._finding_update_map_from_result_body(body).keys())
                for goal in risk_hunt_goals or []:
                    if not isinstance(goal, dict):
                        continue
                    status = str(goal.get("status", "") or "").lower()
                    evidence = unicode_text(goal.get("blocker", goal.get("evidence", "")) or "").strip()
                    if status not in ("blocked", "gated", "blocked-by-missing-fixture", "needs-more-info", "inconclusive"):
                        continue
                    if len(evidence) < 20:
                        continue
                    for raw_fid in goal.get("finding_ids", []) or []:
                        idx = self.extender._finding_index_by_reference(raw_fid)
                        if idx is not None:
                            accounted.add(idx)
                with self.extender.findings_lock_ui:
                    for idx in linked_ids:
                        if idx < 0 or idx >= len(self.extender.findings_list):
                            continue
                        finding = self.extender.findings_list[idx] or {}
                        if str(finding.get("agent_validated_by", "A") or "A").upper() == "B":
                            accounted.add(idx)
                missing = [idx for idx in linked_ids if idx not in accounted]
                if missing:
                    labels = []
                    with self.extender.findings_lock_ui:
                        for idx in missing[:20]:
                            if 0 <= idx < len(self.extender.findings_list):
                                finding = self.extender.findings_list[idx] or {}
                                labels.append(self.extender._ensure_finding_stable_id(finding) or str(idx + 1))
                            else:
                                labels.append(str(idx + 1))
                    return "Automated Testing has %d linked finding(s) without an explicit Agent B finding_update or evidence-backed gate: %s. The queue remains claimed; validate each finding and retry." % (
                        len(missing), ", ".join(labels))
        if mode.startswith("campaign_") and str(body.get("outcome", "")).lower() != "failed":
            campaign_state = queue_item.get("campaign_state", {}) or {}
            incomplete_steps = [
                step.get("key", step.get("id"))
                for step in campaign_state.get("steps", []) or []
                if (step.get("required", True) and step.get("key") != "write_back" and
                    step.get("status") not in ("completed", "blocked", "skipped"))
            ]
            if incomplete_steps:
                return "campaign has incomplete required steps: %s. Update each through /api/agent/queue/%s/campaign/step before completion." % (
                    ", ".join([str(step) for step in incomplete_steps]), queue_item.get("id", ""))
            if int(campaign_state.get("requests_used", 0) or 0) > int(campaign_state.get("request_budget", 0) or 0):
                return "campaign request budget was exceeded; record the overrun and amend the campaign before completion"
            if mode == "campaign_full_app_assessment":
                scanner_problem = self._full_app_scanner_result_problem(queue_item, body)
                if scanner_problem:
                    return scanner_problem
                if not bool(getattr(self.extender, "PASSIVE_SCANNING_ENABLED", False)):
                    # A claimed Full App campaign owns this temporary policy. If the
                    # UI checkbox or a settings reload turns it off mid-run, restore
                    # the campaign invariant here instead of rejecting an otherwise
                    # complete result forever.
                    self.extender._set_full_app_passive_scan(queue_item.get("id"), True)
                if not bool(getattr(self.extender, "PASSIVE_SCANNING_ENABLED", False)):
                    return "Full App Assessment could not restore Analyze Burp Traffic for Agent A before completion."
                stored_review = campaign_state.get("overwatch_review", {}) or {}
                if not stored_review:
                    return "Full App Assessment requires a recorded deterministic overwatch review. POST /api/agent/attack-surface/review with queue_id=%s after the final surface_diff pass." % queue_item.get("id", "")
                review = self._attack_surface_review_payload(queue_id=queue_item.get("id"))
                if not review.get("ready_to_complete"):
                    reported_blockers = {}
                    for reported in body.get("discovery_blockers", []) or []:
                        if not isinstance(reported, dict):
                            continue
                        code = str(reported.get("code", "") or "").strip()
                        detail = str(reported.get("detail", reported.get("evidence", "")) or "").strip()
                        if code and len(detail) >= 20:
                            reported_blockers[code] = detail
                    unresolved = [
                        blocker for blocker in review.get("blockers", []) or []
                        if isinstance(blocker, dict) and str(blocker.get("code", "")) not in reported_blockers
                    ]
                    gated_outcome = str(body.get("outcome", "") or "").lower() == "gated"
                    if not (gated_outcome and not unresolved and review.get("blockers")):
                        blocker_text = "; ".join([
                            str(blocker.get("detail", blocker.get("code", "discovery blocker")))
                            for blocker in (unresolved or review.get("blockers", []) or [])
                            if isinstance(blocker, dict)
                        ])
                        return "Full App Assessment discovery overwatch rejected completion: %s. Continue visible discovery, update /api/agent/attack-surface, repeat surface_diff, or submit a Gated outcome with discovery_blockers covering every review blocker code and at least 20 characters of exact evidence each." % (blocker_text or "unresolved attack-surface blockers")
                unreconciled = self._full_app_unreconciled_findings(body, risk_hunt_goals)
                if unreconciled:
                    identifiers = ", ".join([
                        "%s (%s)" % (item.get("id", ""), item.get("title", ""))
                        for item in unreconciled[:20]
                    ])
                    return "Full App Assessment has %d live Agent A finding(s) that are not reconciled: %s. Refresh /api/findings and include each in finding_updates or in an evidence-backed Gated risk_hunt_goal. Findings created after the campaign started are included." % (
                        len(unreconciled), identifiers)
        if mode == "try_harder" and risk_hunt_goals:
            try:
                target_high_critical = int(risk_meta.get("target_new_high_or_critical_findings", 1) or 1)
            except:
                target_high_critical = 1
            confirmed_high_critical = 0
            with self.extender.findings_lock:
                for raw_id in queue_item.get("agent_generated_finding_ids", []) or []:
                    try:
                        idx = int(raw_id)
                    except:
                        continue
                    if idx < 0 or idx >= len(self.extender.findings_list):
                        continue
                    finding = self.extender.findings_list[idx] or {}
                    severity = str(finding.get("severity", "") or "").lower()
                    status = self._normalize_agent_status(finding.get("agent_status", ""))
                    if severity in ("critical", "high") and status == "valid":
                        confirmed_high_critical += 1
            if confirmed_high_critical >= target_high_critical:
                return ""
            campaign_state = queue_item.get("campaign_state", {}) or {}
            campaign_steps = campaign_state.get("steps", []) or []
            incomplete_steps = [
                step.get("key", step.get("id"))
                for step in campaign_steps
                if step.get("required", True) and step.get("status") not in ("completed", "blocked")
            ]
            if incomplete_steps:
                return "Try Harder cannot submit a no-finding result with incomplete discovery/testing steps: %s. Spider or visibly browse more of the app through Burp, persist absolute visited/tested URLs in campaign step artifacts, re-run coverage, and update every step through /api/agent/queue/%s/campaign/step." % (
                    ", ".join([str(step) for step in incomplete_steps]), queue_item.get("id", ""))

            discovery_contract = risk_meta.get("discovery_contract", {}) or {}
            if discovery_contract.get("required"):
                current_coverage = self._coverage_totals_snapshot()
                try:
                    minimum_coverage = float(discovery_contract.get("minimum_coverage_percent", 50.0) or 50.0)
                except Exception:
                    minimum_coverage = 50.0
                current_percent = float(current_coverage.get("coverage_percent", 0.0) or 0.0)
                try:
                    minimum_routes = int(discovery_contract.get("minimum_pages_or_routes_browsed", 20) or 20)
                except Exception:
                    minimum_routes = 20
                discovery_steps = dict((str(step.get("key", "")), step) for step in campaign_steps)
                spider_step = discovery_steps.get("spider_browse", {}) or {}
                visited_urls = set()
                spider_evidence_text = []
                for artifact in spider_step.get("artifacts", []) or []:
                    try:
                        artifact_text = json.dumps(artifact) if isinstance(artifact, (dict, list)) else str(artifact or "")
                        spider_evidence_text.append(artifact_text)
                        for match in re.finditer(r'https?://[^\s"\'<>]+', artifact_text):
                            visited_urls.add(match.group(0).rstrip("),.;]"))
                    except Exception:
                        continue
                spider_evidence_text.append(str(spider_step.get("note", "") or ""))
                expected_routes = min(minimum_routes, int(current_coverage.get("endpoints", 0) or 0))
                if (spider_step.get("status") == "completed" and expected_routes > 0 and
                        len(visited_urls) < expected_routes):
                    return "Try Harder spider_browse recorded only %d distinct absolute URLs; record at least %d meaningful visited routes in campaign step artifacts before a no-finding result." % (
                        len(visited_urls), expected_routes)
                if (bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)) and
                        spider_step.get("status") == "completed" and
                        "browseros" not in " ".join(spider_evidence_text).lower()):
                    return "Try Harder spider_browse must include evidence of visible BrowserOS browsing through Burp. Add BrowserOS navigation evidence and absolute visited URLs, or mark the step blocked with the exact BrowserOS/auth/scope blocker."
                if not current_coverage.get("available") or current_percent < minimum_coverage:
                    blocked_with_evidence = True
                    for key in ("spider_browse", "coverage_diff"):
                        step = discovery_steps.get(key, {}) or {}
                        evidence = (step.get("artifacts", []) or [])
                        note = str(step.get("note", "") or "").strip()
                        if step.get("status") != "blocked" or not (evidence or note):
                            blocked_with_evidence = False
                            break
                    gated_discovery_goal = False
                    for goal in risk_hunt_goals:
                        status = str(goal.get("status", "") or "").lower()
                        text = " ".join([
                            str(goal.get("category", "") or ""),
                            str(goal.get("hypothesis", "") or ""),
                            str(goal.get("blocker", "") or ""),
                            str(goal.get("evidence", "") or "")
                        ]).lower()
                        if status in ("blocked", "gated", "blocked-by-missing-fixture") and any(marker in text for marker in ("coverage", "browser", "crawl", "spider", "auth", "role", "scope", "approval")):
                            gated_discovery_goal = True
                            break
                    if not (blocked_with_evidence and gated_discovery_goal):
                        discovery_guidance = ("native Burp crawl when available plus visible BrowserOS browsing through Burp" if bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False)) else "Burp history, Site Map, JavaScript/API extraction, Scanner, and native crawl when available")
                        return "Try Harder coverage is %.1f%%, below the required %.1f%% for a no-finding result. Continue %s, record observed/tested absolute URLs in campaign artifacts, and re-run /api/coverage. If discovery is genuinely impossible, block both spider_browse and coverage_diff with exact evidence and include a Gated discovery goal." % (
                            current_percent, minimum_coverage, discovery_guidance)
        try:
            min_goals = int(risk_meta.get("minimum_goals", 4) or 4)
        except:
            min_goals = 4
        try:
            min_completed = int(risk_meta.get("minimum_completed_or_blocked_goals", 3) or 3)
        except:
            min_completed = 3
        completed_statuses = set([
            "tested", "confirmed", "not-vulnerable", "not vulnerable",
            "blocked", "gated", "blocked-by-missing-fixture", "needs-more-info",
            "inconclusive", "failed"
        ])
        completed = 0
        new_discovery = 0
        completed_new_discovery = 0
        for goal in risk_hunt_goals:
            status = str(goal.get("status", "") or "").lower()
            category = str(goal.get("category", "") or "").lower().replace("-", "_").replace(" ", "_")
            if category in ("new_discovery", "discovery", "solo_hunt", "bug_hunt", "new_bug"):
                new_discovery += 1
                if status in completed_statuses:
                    completed_new_discovery += 1
            if status in completed_statuses:
                completed += 1
        if len(risk_hunt_goals) < min_goals:
            return "automated testing requires risk_hunt_goals with at least %d planned goals before completion; got %d. Use heartbeat while continuing." % (
                min_goals, len(risk_hunt_goals))
        if completed < min_completed:
            return "automated testing requires at least %d goals with tested/confirmed/not-vulnerable/blocked outcomes before completion; got %d. Use heartbeat while continuing." % (
                min_completed, completed)
        if mode == "try_harder":
            try:
                min_new = int(risk_meta.get("minimum_new_discovery_goals", 4) or 4)
            except:
                min_new = 4
            try:
                min_new_done = int(risk_meta.get("minimum_completed_or_gated_new_discovery_goals", 3) or 3)
            except:
                min_new_done = 3
            if new_discovery < min_new:
                return "Try Harder requires at least %d category=new_discovery goals before completion; got %d. Generate fresh bug-hunting goals from coverage/history/knowledge and continue." % (
                    min_new, new_discovery)
            if completed_new_discovery < min_new_done:
                return "Try Harder requires at least %d category=new_discovery goals with tested/confirmed/not-vulnerable/blocked/Gated outcomes before completion; got %d. Continue autonomous testing or mark exact blockers as Gated." % (
                    min_new_done, completed_new_discovery)
        return ""

    def _completion_problem_payload(self, queue_item, body, problem, risk_hunt_goals):
        campaign_state = queue_item.get("campaign_state", {}) or {}
        incomplete_steps = [
            str(step.get("key", step.get("id", "")))
            for step in campaign_state.get("steps", []) or []
            if (step.get("required", True) and step.get("key") != "write_back" and
                step.get("status") not in ("completed", "blocked", "skipped"))
        ]
        review = {}
        blocker_codes = []
        if str(queue_item.get("mode", "")) == "campaign_full_app_assessment":
            review = self._attack_surface_review_payload(queue_id=queue_item.get("id"))
            blocker_codes = [
                str(blocker.get("code", ""))
                for blocker in review.get("blockers", []) or []
                if isinstance(blocker, dict) and blocker.get("code")
            ]
        missing_fields = []
        if not str(body.get("outcome", "") or "").strip():
            missing_fields.append("outcome")
        payload = {
            "error": "risk_hunt_incomplete",
            "message": self._limit_text(problem, 1200),
            "queue_id": queue_item.get("id"),
            "missing_fields": missing_fields,
            "incomplete_steps": incomplete_steps,
            "blocker_codes": blocker_codes,
            "received_goals": len(risk_hunt_goals or []),
            "write_back_auto_completed_on_accept": True,
        }
        if blocker_codes:
            payload["gated_example"] = {
                "outcome": "gated",
                "discovery_blockers": [
                    {"code": code, "detail": "Provide at least 20 characters of exact blocker evidence."}
                    for code in blocker_codes
                ]
            }
        if incomplete_steps:
            payload["next_action"] = "Update only the listed steps. POSTing an accepted result completes write_back automatically."
        elif blocker_codes:
            payload["next_action"] = "Resolve the review blockers or submit outcome=gated with evidence for every blocker code."
        else:
            payload["next_action"] = "Address the message and retry the same result payload."
        return payload

    def _handle_queue_result(self, qid):
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

        outcome_error = self._queue_outcome_error(body)
        if outcome_error:
            self._send_json(400, outcome_error)
            return
        outcome = self._normalize_queue_outcome(body.get("outcome", body.get("status", "inconclusive")))
        evidence_error = self._conclusive_evidence_error(body, outcome)
        if evidence_error:
            self._send_json(409, evidence_error)
            return
        assessment = self._limit_text(body.get("assessment", ""), 4000)
        test_results = self._sanitize_result_items(body.get("test_results", []))
        evidence = self._sanitize_evidence_items(body.get("evidence", []))
        risk_hunt_goals = self._risk_hunt_goals_from_body(body)
        reproduction = self._limit_text(body.get("reproduction", body.get("repro", "")), 4000)
        notes = []
        for note in self._limit_list(body.get("notes", []), 20):
            notes.append({
                "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": self._limit_text(note, 1000)
            })

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        terminal_status = "failed" if outcome == "failed" else "completed"
        completed_item = None
        removed_from_queue = False
        poc_repeater_tabs = []
        collaborator_artifacts = []

        # Preflight valid-finding artifacts before making the queue item
        # terminal. Rejected results remain claimed and can be retried after
        # supplying the exact PoC request.
        queue_snapshot = self._get_queue_item_snapshot(qid)
        if queue_snapshot is not None and queue_snapshot.get("status") not in ("pending", "completed", "failed", "cancelled"):
            persistent_goal_problem = self._persistent_goal_problem(queue_snapshot, body)
            risk_hunt_problem = self._risk_hunt_completion_problem(queue_snapshot, body, risk_hunt_goals)
            if not persistent_goal_problem and not risk_hunt_problem:
                collaborator_artifacts, collaborator_errors = self._ensure_ssrf_collaborator_for_result(
                    queue_snapshot, body, outcome)
                if collaborator_errors:
                    self._send_json(409, {
                        "error": "ssrf_collaborator_evidence_required",
                        "message": "Every SSRF finding Agent B marks valid must have a registered Collaborator attempt plus a confirmed interaction or accepted structured in-band proof.",
                        "queue_id": qid,
                        "failures": collaborator_errors,
                        "next_action": "Generate and inject a payload, poll interactions, then retry with collaborator_evidence; when egress is blocked, also supply ssrf_inband_evidence with internal response markers and a concrete control."
                    })
                    return
                poc_repeater_tabs, poc_errors = self._ensure_valid_finding_pocs_for_result(
                    queue_snapshot, body, outcome)
                if poc_errors:
                    self._send_json(409, {
                        "error": "poc_repeater_required",
                        "message": "Every finding Agent B marks valid must have an editable PoC Repeater tab before /result is accepted.",
                        "queue_id": qid,
                        "failures": poc_errors,
                        "guidance": "POST the exact confirmed request to /api/findings/<daf_id>/poc-repeater, then retry this result."
                    })
                    return
        with self.extender.agent_queue_lock:
            for q_index, q in enumerate(list(self.extender.agent_queue)):
                if q.get("id") == qid:
                    if q.get("status") == "pending":
                        self._send_json(409, {"error": "must claim item before posting result", "status": q.get("status")})
                        return
                    if q.get("status") in ("completed", "failed", "cancelled"):
                        self._send_json(409, {"error": "already terminal", "status": q.get("status")})
                        return
                    persistent_goal_problem = self._persistent_goal_problem(q, body)
                    if persistent_goal_problem:
                        self._send_json(409, {
                            "error": "persistent_agent_goal_required",
                            "message": persistent_goal_problem,
                            "queue_id": qid,
                            "missing_fields": ["persistent_goal"],
                            "next_action": "Keep the persistent goal active, add persistent_goal to the same result payload, and retry."
                        })
                        return
                    risk_hunt_problem = self._risk_hunt_completion_problem(q, body, risk_hunt_goals)
                    if risk_hunt_problem:
                        self._send_json(409, self._completion_problem_payload(
                            q, body, risk_hunt_problem, risk_hunt_goals))
                        return
                    campaign_state = q.get("campaign_state", {}) or {}
                    for step in campaign_state.get("steps", []) or []:
                        if step.get("key") == "write_back":
                            step["status"] = "completed"
                            step["updated_at"] = now
                            step["artifacts"] = [{"result_endpoint": "/api/agent/queue/%s/result" % qid, "outcome": outcome}]
                    if campaign_state:
                        campaign_state["updated_at"] = now
                        q["campaign_state"] = campaign_state
                    q["status"] = terminal_status
                    q["completed_at"] = now
                    q["outcome"] = outcome
                    q["assessment"] = assessment
                    q["test_results"] = test_results
                    q["evidence"] = evidence
                    if risk_hunt_goals:
                        q["risk_hunt_goals"] = risk_hunt_goals
                    if q.get("persistent_agent_goal", {}).get("required"):
                        q["persistent_agent_goal_report"] = self._persistent_goal_report_from_body(body)
                    q["reproduction"] = reproduction
                    if poc_repeater_tabs:
                        q["poc_repeater_tabs"] = poc_repeater_tabs
                    if collaborator_artifacts:
                        q["collaborator_evidence"] = collaborator_artifacts
                    if notes:
                        q.setdefault("notes", []).extend(notes)
                    q["result_updated_at"] = now
                    completed_item = dict(q)
                    history = getattr(self.extender, "completed_agent_results", None)
                    if history is None:
                        history = []
                        self.extender.completed_agent_results = history
                    history.append(completed_item)
                    self.extender.completed_agent_results = history[-500:]
                    try:
                        self.extender.agent_queue.pop(q_index)
                        removed_from_queue = True
                    except:
                        removed_from_queue = False
                    if self.extender.selected_agent_queue_index >= len(self.extender.agent_queue):
                        self.extender.selected_agent_queue_index = len(self.extender.agent_queue) - 1
                    self.extender._ui_dirty = True
                    self.extender._agent_queue_save_pending = True
                    break
        if completed_item is not None:
            if str(completed_item.get("campaign_type", "")) == "full_app_assessment":
                completed_item["passive_scan_policy"] = self.extender._set_full_app_passive_scan(qid, False)
            updated_findings = self._apply_queue_result_to_findings(completed_item, body, outcome, assessment, now)
            gated_findings = self._apply_risk_hunt_goal_gates(completed_item, risk_hunt_goals, now)
            self.extender.save_findings()
            self.extender.save_agent_queue()
            self.extender._ui_dirty = True
            self.extender.stdout.println("[AGENT API] Stored result for queue #%d: %s; updated %d finding(s); queue_removed=%s" % (
                qid, outcome, len(updated_findings), str(bool(removed_from_queue)).lower()))
            warnings = []
            if completed_item.get("source") == "risk_hunt" and not updated_findings:
                warnings.append("Automated Testing result stored without finding_updates; linked findings were intentionally preserved.")
            try:
                linked_finding_ids = [int(fid) + 1 for fid in (completed_item.get("finding_ids", []) or [])]
            except Exception:
                linked_finding_ids = []
            try:
                generated_finding_ids = [int(fid) + 1 for fid in (completed_item.get("agent_generated_finding_ids", []) or [])]
            except Exception:
                generated_finding_ids = []
            try:
                scanner_seen_ids = [int(fid) + 1 for fid in (completed_item.get("scanner_findings_seen_during_work", []) or [])]
            except Exception:
                scanner_seen_ids = []
            try:
                passive_seen_ids = [int(fid) + 1 for fid in (completed_item.get("passive_findings_seen_during_work", []) or [])]
            except Exception:
                passive_seen_ids = []
            self._send_json(200, {
                "status": terminal_status,
                "id": qid,
                "outcome": outcome,
                "queue_removed": bool(removed_from_queue),
                "updated_findings": updated_findings,
                "gated_findings": gated_findings,
                "linked_finding_ids": linked_finding_ids,
                "agent_generated_finding_ids": generated_finding_ids,
                "scanner_findings_seen_during_work": scanner_seen_ids,
                "passive_findings_seen_during_work": passive_seen_ids,
                "poc_repeater_tabs": poc_repeater_tabs,
                "collaborator_evidence": collaborator_artifacts,
                "persistent_goal_next_action": "Double Agent accepted the Try Harder result. Call update_goal(status=complete) now." if completed_item.get("persistent_agent_goal", {}).get("required") else "",
                "warnings": warnings
            })
            return
        self._send_json(404, {"error": "not found"})

    def _handle_amend_completed_result(self, qid):
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
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        completed_snapshot = None
        with self.extender.agent_queue_lock:
            for item in list(getattr(self.extender, "completed_agent_results", []) or []):
                if int(item.get("id", -1)) == qid:
                    completed_snapshot = dict(item)
                    break
        if completed_snapshot is None:
            self._send_json(404, {"error": "completed result not found"})
            return
        amended_outcome = self._normalize_queue_outcome(
            body.get("outcome", completed_snapshot.get("outcome", "inconclusive")))
        collaborator_artifacts, collaborator_errors = self._ensure_ssrf_collaborator_for_result(
            completed_snapshot, body, amended_outcome)
        if collaborator_errors:
            self._send_json(409, {
                "error": "ssrf_collaborator_evidence_required",
                "message": "Every SSRF finding Agent B marks valid must have a registered Collaborator attempt plus a confirmed interaction or accepted structured in-band proof.",
                "failures": collaborator_errors
            })
            return
        poc_repeater_tabs, poc_errors = self._ensure_valid_finding_pocs_for_result(
            completed_snapshot, body, amended_outcome)
        if poc_errors:
            self._send_json(409, {
                "error": "poc_repeater_required",
                "message": "Every finding Agent B marks valid must have an editable PoC Repeater tab before an amendment is accepted.",
                "failures": poc_errors
            })
            return
        amended = None
        with self.extender.agent_queue_lock:
            history = list(getattr(self.extender, "completed_agent_results", []) or [])
            for idx, item in enumerate(history):
                if int(item.get("id", -1)) != qid:
                    continue
                amendment = {
                    "at": now,
                    "outcome": body.get("outcome", ""),
                    "assessment": self._limit_text(body.get("assessment", ""), 4000),
                    "test_results": self._sanitize_result_items(body.get("test_results", [])),
                    "evidence": self._sanitize_evidence_items(body.get("evidence", [])),
                    "notes": [self._limit_text(n, 1000) for n in self._limit_list(body.get("notes", []), 20)]
                }
                item.setdefault("amendments", []).append(amendment)
                if body.get("outcome"):
                    item["outcome"] = self._normalize_queue_outcome(body.get("outcome"))
                if body.get("assessment"):
                    previous = item.get("assessment", "")
                    item["assessment"] = (previous + "\n\nAMENDMENT %s:\n%s" % (now, amendment["assessment"])).strip() if previous else amendment["assessment"]
                if amendment["test_results"]:
                    item.setdefault("test_results", []).extend(amendment["test_results"])
                if amendment["evidence"]:
                    item.setdefault("evidence", []).extend(amendment["evidence"])
                if amendment["notes"]:
                    for note in amendment["notes"]:
                        item.setdefault("notes", []).append({"at": now, "note": note})
                item["result_updated_at"] = now
                history[idx] = item
                amended = dict(item)
                break
            self.extender.completed_agent_results = history[-500:]
        if amended is None:
            self._send_json(404, {"error": "completed result not found"})
            return
        outcome = self._normalize_queue_outcome(body.get("outcome", amended.get("outcome", "inconclusive")))
        updated_findings = self._apply_queue_result_to_findings(amended, body, outcome, amended.get("assessment", ""), now)
        self.extender.save_findings()
        self.extender.save_agent_queue()
        self.extender._ui_dirty = True
        self._send_json(200, {
            "status": "amended",
            "id": qid,
            "outcome": amended.get("outcome", ""),
            "updated_findings": updated_findings,
            "poc_repeater_tabs": poc_repeater_tabs,
            "amendments": len(amended.get("amendments", []))
        })

    def _handle_clear_queue(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        mode = str(body.get("mode", "completed") or "completed").strip().lower()
        if mode not in ("completed", "all"):
            self._send_json(400, {"error": "mode must be completed or all"})
            return

        with self.extender.agent_queue_lock:
            before = len(self.extender.agent_queue)
            if mode == "all":
                self.extender.agent_queue = []
                self.extender.agent_queue_next_id = 0
                self.extender.selected_agent_queue_index = -1
            else:
                self.extender.agent_queue = [
                    q for q in self.extender.agent_queue
                    if q.get("status") not in ("completed", "failed", "cancelled")
                ]
                if self.extender.selected_agent_queue_index >= len(self.extender.agent_queue):
                    self.extender.selected_agent_queue_index = len(self.extender.agent_queue) - 1
            removed = before - len(self.extender.agent_queue)

        self.extender.save_agent_queue()
        self.extender._ui_dirty = True
        self.extender.stdout.println("[AGENT API] Cleared queue mode=%s removed=%d remaining=%d" % (
            mode, removed, len(self.extender.agent_queue)))
        self._send_json(200, {
            "status": "ok",
            "mode": mode,
            "removed": removed,
            "remaining": len(self.extender.agent_queue)
        })

    def _coerce_bool(self, value, default=False):
        if value is None:
            return bool(default)
        try:
            if isinstance(value, bool):
                return value
        except Exception:
            pass
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        return bool(default)

    def _read_sse_event(self, stream, deadline):
        event_name = u""
        data_lines = []
        while time.time() < deadline:
            line = stream.readline()
            if line is None:
                continue
            if hasattr(line, "decode"):
                try:
                    line = line.decode("utf-8", "replace")
                except Exception:
                    line = unicode_text(line)
            line = unicode_text(line).rstrip(u"\r\n")
            if line == u"":
                if event_name or data_lines:
                    return event_name, u"\n".join(data_lines)
                continue
            if line.startswith(u"event:"):
                event_name = line[len(u"event:"):].strip()
            elif line.startswith(u"data:"):
                data_lines.append(line[len(u"data:"):].strip())
        raise Exception("timeout waiting for MCP SSE event")

    def _mcp_post_json(self, url, payload, timeout_sec):
        # Use Java's native HTTP decoder rather than Jython's urllib2 stack.
        # The latter connects successfully but stalls before exposing the
        # first chunk of PortSwigger's SSE response on recent Burp/JRE builds.
        from java.net import URL, Proxy
        from java.lang import String as JavaString
        body = JavaString(unicode_text(json.dumps(payload))).getBytes("UTF-8")
        conn = URL(str(url)).openConnection(Proxy.NO_PROXY)
        conn.setConnectTimeout(max(3, int(timeout_sec)) * 1000)
        conn.setReadTimeout(max(3, int(timeout_sec)) * 1000)
        conn.setRequestMethod("POST")
        # PortSwigger's legacy SSE transport validates this media type
        # literally and rejects the otherwise-valid charset parameter.
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json, text/plain")
        conn.setDoOutput(True)
        conn.setFixedLengthStreamingMode(len(body))
        output = conn.getOutputStream()
        try:
            output.write(body)
            output.flush()
        finally:
            try:
                output.close()
            except Exception:
                pass
        try:
            status = int(conn.getResponseCode())
            if status < 200 or status >= 300:
                raise Exception("MCP POST returned HTTP %s" % status)
            # The JSON-RPC result arrives on the SSE stream.  Do not wait for
            # or decode the acknowledgement body.
            return status
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

    def _mcp_read_message(self, stream, expected_id, deadline):
        while time.time() < deadline:
            event_name, data = self._read_sse_event(stream, deadline)
            if event_name != "message" or not data:
                continue
            msg = json.loads(data)
            if msg.get("id") == expected_id:
                if msg.get("error"):
                    raise Exception("MCP error: %s" % self._safe_ascii_text(msg.get("error"), 1000))
                return msg
        raise Exception("timeout waiting for MCP response id=%s" % expected_id)

    def _close_portswigger_mcp_session(self):
        session = getattr(self.extender, "portswigger_mcp_session", None)
        self.extender.portswigger_mcp_session = None
        if session:
            try:
                stream = session.get("stream")
                if stream is not None:
                    stream.close()
            except Exception:
                pass

    def _open_portswigger_mcp_session(self, timeout_sec=12):
        base_url = str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "http://127.0.0.1:9876/") or "").strip()
        if not base_url:
            base_url = "http://127.0.0.1:9876/"
        if not base_url.endswith("/"):
            base_url += "/"
        stream = None
        stage = "sse_connect"
        try:
            from java.net import URL, Proxy
            from java.io import BufferedReader, InputStreamReader
            timeout_sec = max(3, int(timeout_sec))
            conn = URL(base_url).openConnection(Proxy.NO_PROXY)
            conn.setConnectTimeout(timeout_sec * 1000)
            conn.setReadTimeout(timeout_sec * 1000)
            conn.setRequestMethod("GET")
            conn.setRequestProperty("Accept", "text/event-stream")
            conn.setRequestProperty("Cache-Control", "no-cache")
            status = int(conn.getResponseCode())
            if status < 200 or status >= 300:
                raise Exception("MCP SSE returned HTTP %s" % status)
            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
            stream = _JavaSSEStream(conn, reader)
            endpoint = ""
            stage = "sse_endpoint"
            endpoint_deadline = time.time() + timeout_sec
            while time.time() < endpoint_deadline:
                event_name, data = self._read_sse_event(stream, endpoint_deadline)
                if event_name == "endpoint" and data:
                    endpoint = data.strip()
                    break
            if not endpoint:
                raise Exception("MCP server did not return a session endpoint")

            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                session_url = endpoint
            elif endpoint.startswith("?"):
                session_url = base_url + endpoint
            else:
                session_url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
            init_id = 1
            stage = "initialize_post"
            self._mcp_post_json(session_url, {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                    "clientInfo": {"name": "double-agent", "version": str(getattr(self.extender, "VERSION", "3.0"))}
                }
            }, timeout_sec)
            stage = "initialize_response"
            self._mcp_read_message(stream, init_id, time.time() + timeout_sec)
            stage = "initialized_notification"
            self._mcp_post_json(session_url, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }, timeout_sec)
            session = {
                "stream": stream,
                "session_url": session_url,
                "next_id": 2,
                "opened_at": time.time(),
                "last_used_at": time.time()
            }
            stream = None
            self.extender.portswigger_mcp_session = session
            return session
        except Exception as e:
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
            raise Exception("MCP session %s failed: %s" % (
                stage, self._safe_ascii_text(e, 500)))
