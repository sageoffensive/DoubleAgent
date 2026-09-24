# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk3Chunk3(object):
    def _queue_outcome_error(self, body):
        allowed = ["confirmed", "not-vulnerable", "gated", "blocked-by-missing-fixture", "needs-more-info", "inconclusive", "failed"]
        if not isinstance(body, dict) or not str(body.get("outcome", "") or "").strip():
            return {
                "error": "outcome_required",
                "message": "A queue result requires an explicit outcome.",
                "missing_fields": ["outcome"],
                "allowed_outcomes": allowed,
                "gated_example": {"outcome": "gated", "discovery_blockers": [{"code": "browser_unavailable", "detail": "BrowserOS MCP and CDP were unavailable during preflight."}]}
            }
        normalized = str(body.get("outcome", "") or "").strip().lower().replace("_", "-").replace(" ", "-")
        if normalized not in allowed:
            return {
                "error": "invalid_outcome",
                "message": "Unsupported queue result outcome: %s" % normalized,
                "invalid_fields": ["outcome"],
                "allowed_outcomes": allowed
            }
        return None

    def _conclusive_evidence_error(self, body, outcome):
        if outcome not in ("confirmed", "not-vulnerable"):
            return None
        reproduction = str(body.get("reproduction", body.get("repro", "")) or "").strip()
        evidence = body.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = []
        valid = []
        seen_requests = set()
        for item in evidence:
            if not isinstance(item, dict):
                continue
            request = str(item.get("request", "") or "").strip()
            snippet = str(item.get("response_snippet", item.get("response", "")) or "").strip()
            try:
                status_code = int(item.get("status_code", 0))
            except:
                status_code = 0
            if len(request) >= 10 and len(snippet) >= 5 and 100 <= status_code <= 599 and request not in seen_requests:
                seen_requests.add(request)
                valid.append(item)
        missing = []
        if len(valid) < 2:
            missing.append("at least two distinct evidence entries with request, HTTP status_code, and response_snippet")
        if len(reproduction) < 20:
            missing.append("reproduction steps")
        if missing:
            return {
                "error": "conclusive_evidence_required",
                "message": "A confirmed or not-vulnerable result requires fresh baseline and mutation/control evidence.",
                "missing": missing,
                "valid_evidence_entries": len(valid),
                "next_action": "Execute the baseline and mutation/control through Burp, then retry /result with structured evidence and reproduction."
            }
        return None

    def _agent_status_for_queue_outcome(self, outcome):
        if outcome == "confirmed":
            return "valid"
        if outcome == "not-vulnerable":
            return "false_positive"
        if outcome in ("gated", "blocked-by-missing-fixture", "needs-more-info", "inconclusive", "failed"):
            return "needs_investigation"
        return "needs_investigation"

    def _agent_priority_for_queue_result(self, outcome, severity, fallback):
        fallback = str(fallback or "")
        if outcome == "not-vulnerable":
            return "defer"
        if fallback:
            return self._normalize_agent_priority(fallback)
        if outcome == "confirmed":
            sev = self._normalize_finding_severity(severity, "Information")
            if sev == "Critical":
                return "P1"
            if sev == "High":
                return "P2"
            if sev == "Medium":
                return "P3"
            if sev in ("Low", "Information"):
                return "P4"
        return "P3"

    def _gate_reason_from_text(self, text):
        text_l = str(text or "").lower()
        if any(term in text_l for term in ("fixture", "second account", "account_number", "account number", "object id", "tenant")):
            return "missing_fixture"
        if any(term in text_l for term in ("otp", "mfa", "sms", "email", "oob", "human confirmation")):
            return "needs_human_confirmation"
        if any(term in text_l for term in ("approval", "approve", "destructive", "state-changing", "state changing", "safety")):
            return "needs_approval"
        if any(term in text_l for term in ("scope", "out of scope", "out-of-scope")):
            return "scope_blocked"
        return "blocked"

    def _missing_from_gate_text(self, text):
        text_l = str(text or "").lower()
        missing = []
        checks = [
            ("distinct_account_number_pair", ("account_number", "account number")),
            ("second_account", ("second account", "second user", "other user")),
            ("object_id_pair", ("object id", "object_id")),
            ("tenant_pair", ("tenant",)),
            ("mfa_or_otp_confirmation", ("otp", "mfa", "2fa")),
            ("email_or_sms_confirmation", ("email", "sms", "oob")),
            ("user_approval", ("approval", "approve", "state-changing", "state changing", "destructive")),
        ]
        for label, terms in checks:
            if any(term in text_l for term in terms) and label not in missing:
                missing.append(label)
        return missing

    def _apply_gate_to_finding(self, finding, reason, detail, next_step, now, display_status="gated"):
        finding["agent_status"] = "needs_investigation"
        finding["agent_display_status"] = display_status
        finding["gate_reason"] = self._limit_text(reason or self._gate_reason_from_text(detail), 120)
        finding["gate_detail"] = self._limit_text(detail, 1000)
        finding["gate_missing"] = self._missing_from_gate_text("%s %s" % (detail or "", next_step or ""))
        finding["gate_next_step"] = self._limit_text(next_step, 500)
        finding["agent_validated_by"] = "B"
        finding["agent_validated_at"] = now
        finding["agent_updated_at"] = now
        if not finding.get("agent_rationale"):
            finding["agent_rationale"] = self._limit_text(detail or "Active testing was gated by missing context or approval.", 2000)

    def _apply_risk_hunt_goal_gates(self, queue_item, risk_hunt_goals, now):
        gated = []
        if not risk_hunt_goals:
            return gated
        with self.extender.findings_lock_ui:
            for goal in risk_hunt_goals:
                if not isinstance(goal, dict):
                    continue
                status = str(goal.get("status", "") or "").lower()
                blocker = self._limit_text(goal.get("blocker", ""), 1000)
                next_step = self._limit_text(goal.get("next_step", ""), 500)
                if status not in ("blocked", "gated", "blocked-by-missing-fixture", "needs-more-info", "inconclusive") and not blocker:
                    continue
                display_status = "gated" if blocker or status in ("blocked", "gated", "blocked-by-missing-fixture", "needs-more-info") else "partially_tested"
                reason = self._gate_reason_from_text("%s %s" % (blocker, next_step))
                for raw_fid in goal.get("finding_ids", []) or []:
                    idx = self.extender._finding_index_by_reference_unlocked(raw_fid)
                    if idx is None:
                        continue
                    if idx < 0 or idx >= len(self.extender.findings_list):
                        continue
                    finding = self.extender.findings_list[idx]
                    if finding.get("agent_status") in ("valid", "false_positive"):
                        continue
                    detail = blocker or goal.get("evidence", "") or "Automated testing reached this goal but could not safely complete validation."
                    self._apply_gate_to_finding(finding, reason, detail, next_step, now, display_status=display_status)
                    gated.append({
                        "id": self.extender._ensure_finding_stable_id(finding),
                        "legacy_numeric_id": self.extender._ensure_finding_legacy_numeric_id(finding, idx + 1),
                        "display": self.extender._agent_status_display(finding),
                        "gate_reason": finding.get("gate_reason", ""),
                        "gate_missing": finding.get("gate_missing", [])
                    })
        return gated

    def _finding_update_map_from_result_body(self, body):
        mapped = {}
        raw_updates = body.get("finding_updates", body.get("updated_findings", []))
        if isinstance(raw_updates, dict):
            normalized_updates = []
            for raw_id, update in raw_updates.items():
                if isinstance(update, dict):
                    item = dict(update)
                    item.setdefault("id", raw_id)
                    normalized_updates.append(item)
            raw_updates = normalized_updates
        for item in self._limit_list(raw_updates, 100):
            if not isinstance(item, dict):
                continue
            fid = self.extender._finding_index_by_reference(item.get("stable_id", item.get("id", item.get("finding_id", ""))))
            if fid is not None and fid >= 0:
                mapped[fid] = item
        return mapped

    def _ensure_valid_finding_pocs_for_result(self, queue_item, body, outcome):
        """Ensure every finding this result will mark valid has one PoC tab."""
        artifacts = []
        errors = []
        update_map = self._finding_update_map_from_result_body(body)
        explicit_only = bool(queue_item.get("source") == "risk_hunt" or body.get("explicit_finding_updates_only", False))
        finding_ids = sorted(update_map.keys()) if explicit_only else list(queue_item.get("finding_ids", []) or [])
        default_status = self._agent_status_for_queue_outcome(outcome)
        for fid in finding_ids:
            try:
                idx = int(fid)
            except Exception:
                continue
            with self.extender.findings_lock_ui:
                if idx < 0 or idx >= len(self.extender.findings_list):
                    continue
                stable_id = self.extender._ensure_finding_stable_id(self.extender.findings_list[idx])
            item_update = update_map.get(idx, {}) or {}
            raw_status = item_update.get("agent_status", item_update.get("finding_status", None))
            if raw_status is None:
                raw_status = body.get("agent_status", body.get("finding_status", default_status))
            if self._normalize_agent_status(raw_status) != "valid":
                continue
            result = self._ensure_finding_poc_repeater(
                stable_id,
                raw_request=item_update.get(
                    "poc_request",
                    item_update.get("request", item_update.get("request_data", ""))),
                queue_id=queue_item.get("id", None)
            )
            if result.get("ok"):
                artifacts.append(result)
            else:
                errors.append(result)
        return artifacts, errors

    def _ensure_ssrf_collaborator_for_result(self, queue_item, body, outcome):
        artifacts = []
        errors = []
        update_map = self._finding_update_map_from_result_body(body)
        default_status = self._agent_status_for_queue_outcome(outcome)
        finding_ids = set(queue_item.get("finding_ids", []) or [])
        finding_ids.update(update_map.keys())
        for fid in finding_ids:
            try:
                idx = int(fid)
            except Exception:
                continue
            with self.extender.findings_lock_ui:
                if idx < 0 or idx >= len(self.extender.findings_list):
                    continue
                finding = dict(self.extender.findings_list[idx])
                stable_id = self.extender._ensure_finding_stable_id(self.extender.findings_list[idx])
            item_update = update_map.get(idx, {}) or {}
            raw_status = item_update.get("agent_status", item_update.get("finding_status", None))
            if raw_status is None:
                raw_status = body.get("agent_status", body.get("finding_status", default_status))
            if self._normalize_agent_status(raw_status) != "valid" or not self._is_ssrf_finding(finding):
                continue
            evidence_body = dict(body)
            if item_update.get("collaborator_evidence") is not None:
                evidence_body["collaborator_evidence"] = item_update.get("collaborator_evidence")
            result = self._collaborator_evidence_for_finding(finding, evidence_body)
            if not result.get("ok"):
                errors.append(result)
                continue
            artifact = result.get("artifact", {}) or {}
            if artifact:
                artifact["finding_id"] = stable_id
                artifacts.append(artifact)
                self._store_collaborator_artifact(stable_id, result)
        return artifacts, errors

    def _full_app_unreconciled_findings(self, body, risk_hunt_goals):
        """Return live Agent A findings omitted from a Full App result payload."""
        with self.extender.findings_lock_ui:
            candidates = []
            for idx, finding in enumerate(self.extender.findings_list):
                if self.extender._agent_validation_marker(finding) == "B":
                    continue
                if self.extender._finding_hidden_from_normal_view(finding):
                    continue
                candidates.append({
                    "index": idx,
                    "id": self.extender._ensure_finding_stable_id(finding),
                    "legacy_numeric_id": self.extender._ensure_finding_legacy_numeric_id(finding, idx + 1),
                    "title": self._limit_text(finding.get("title", ""), 300),
                    "url": self._limit_text(finding.get("url", ""), 1000),
                })
        return full_app_unreconciled_findings(
            candidates, self._finding_update_map_from_result_body(body).keys(), risk_hunt_goals)
