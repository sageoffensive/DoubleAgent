# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk1Chunk4(object):
    def _handle_bulk_triage_findings(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        updates = body.get("updates", [])
        if not isinstance(updates, list):
            self._send_json(400, {"error": "updates must be a list"})
            return

        results = []
        errors = []
        prepared = []
        for update in updates:
            try:
                if not isinstance(update, dict):
                    errors.append({"id": None, "error": "update must be an object"})
                    continue
                raw_id = update.get("id", update.get("stable_id", ""))
                idx = self.extender._finding_index_by_reference(raw_id)
                if idx is None:
                    errors.append({"id": raw_id, "error": "finding not found"})
                    continue
                with self.extender.findings_lock_ui:
                    conflict_status, conflict = self._finding_update_precondition(
                        raw_id, self.extender.findings_list[idx], update)
                if conflict:
                    errors.append({"id": raw_id, "status": conflict_status, "error": conflict})
                    continue
                status = self._normalize_agent_status(update.get("status", "untouched"))
                if status == "valid":
                    with self.extender.findings_lock_ui:
                        finding_snapshot = dict(self.extender.findings_list[idx])
                    collaborator_result = self._collaborator_evidence_for_finding(finding_snapshot, update)
                    if not collaborator_result.get("ok"):
                        errors.append({"id": raw_id, "status": 409, "error": collaborator_result})
                        continue
                    poc_result = self._ensure_finding_poc_repeater(
                        raw_id,
                        raw_request=update.get("poc_request", update.get("request", "")),
                        queue_id=update.get("queue_id", None)
                    )
                    if not poc_result.get("ok"):
                        errors.append({
                            "id": raw_id,
                            "status": 409,
                            "error": "poc_repeater_required",
                            "poc_repeater": poc_result
                        })
                        continue
                    if collaborator_result.get("artifact"):
                        self._store_collaborator_artifact(raw_id, collaborator_result)
                prepared.append((idx, raw_id, status, update))
            except Exception as e:
                update_id = None
                try:
                    update_id = update.get("id", None)
                except:
                    pass
                errors.append({"id": update_id, "error": str(e)})

        non_deletions = [item for item in prepared if not self._triage_status_deletes_finding(item[2])]
        deletions = sorted([item for item in prepared if self._triage_status_deletes_finding(item[2])], key=lambda item: item[0], reverse=True)
        deleted_indices = []

        with self.extender.findings_lock_ui:
            for idx, raw_id, status, update in non_deletions + deletions:
                try:
                    result = self._apply_finding_triage(idx, update)
                    if result is None:
                        errors.append({"id": raw_id, "error": "not found"})
                    elif result.get("error"):
                        errors.append({"id": raw_id, "error": result.get("error")})
                    else:
                        if result.get("deleted"):
                            deleted_indices.append(result.get("internal_index"))
                        results.append(result)
                except Exception as e:
                    errors.append({"id": raw_id, "error": str(e)})

        self._remap_queue_finding_ids_after_delete(deleted_indices)
        self.extender.save_findings()
        self.extender._ui_dirty = True
        deleted_count = sum(1 for result in results if result.get("deleted"))
        self.extender.stdout.println("[AGENT API] bulk triaged %d finding(s), deleted %d finding(s), %d error(s)" % (
            len(results), deleted_count, len(errors)))
        self._send_json(200, {"status": "ok", "updated": results, "errors": errors})

    def _handle_create_finding(self):
        """Create a new finding from agent-discovered vulnerability."""
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": "invalid body", "message": str(e)})
            return

        # Required fields
        url = body.get("url", "").strip()
        title = body.get("title", "").strip()
        severity = body.get("severity", "Information")
        confidence = body.get("confidence", "Tentative")

        if not url or not title:
            self._send_json(400, {"error": "missing required fields", "required": ["url", "title"]})
            return

        # Optional triage flags
        agent_status = body.get("agent_status", "valid")
        agent_priority = body.get("agent_priority", "P2")
        agent_rationale = body.get("agent_rationale", "Discovered during active testing")
        active_test_recipe = self.extender._normalize_active_test_recipe(
            body.get("active_test_recipe", {}),
            {
                "title": title,
                "url": url,
                "severity": severity,
                "agent_status": agent_status,
                "agent_priority": agent_priority,
                "agent_rationale": agent_rationale
            }
        )
        collaborator_result = {"ok": True, "required": False, "artifact": {}}
        if self._normalize_agent_status(agent_status) == "valid":
            collaborator_result = self._collaborator_evidence_for_finding({
                "title": title,
                "cwe": body.get("cwe", ""),
                "detail": body.get("detail", ""),
                "evidence": body.get("evidence", ""),
                "request_data": body.get("request_data", body.get("request", "")),
                "response_data": body.get("response_data", body.get("response", ""))
            }, body)
            if not collaborator_result.get("ok"):
                self._send_json(409, collaborator_result)
                return

        # Create or idempotently match the finding. add_finding returns the
        # exact immutable record identity; never infer identity from list order.
        create_result = self.extender.add_finding(
            url=url,
            title=title,
            severity=severity,
            confidence=confidence,
            detail=body.get("detail", ""),
            cwe=body.get("cwe", ""),
            evidence=body.get("evidence", ""),
            remediation=body.get("remediation", ""),
            owasp=body.get("owasp", ""),
            ai_confidence=body.get("ai_confidence", 0),
            request_data=body.get("request_data"),
            response_data=body.get("response_data"),
            source="agent_active",
            agent_status=agent_status,
            agent_priority=agent_priority,
            agent_rationale=agent_rationale,
            active_test_recipe=active_test_recipe,
            agent_validated_by="B",
            agent_queue_id=body.get("agent_queue_id", body.get("queue_id", None)),
            deduplication_key=body.get("deduplication_key", body.get("idempotency_key", ""))
        )
        create_result = create_result or {"disposition": "suppressed", "reason": "finding was not stored"}
        disposition = str(create_result.get("disposition", "suppressed") or "suppressed")
        stable_id = create_result.get("stable_id", "")
        stored_title = create_result.get("title", title)
        if stable_id and disposition in ("matched", "updated"):
            matched_idx = self.extender._finding_index_by_reference(stable_id)
            queue_id = body.get("agent_queue_id", body.get("queue_id", None))
            if matched_idx is not None and queue_id is not None:
                self.extender._link_finding_to_agent_queue(queue_id, matched_idx, link_kind="agent_generated")
        poc_repeater = {}
        if stable_id and self._normalize_agent_status(agent_status) == "valid":
            poc_repeater = self._ensure_finding_poc_repeater(
                stable_id,
                raw_request=body.get("poc_request", body.get("request_data", "")),
                queue_id=body.get("agent_queue_id", body.get("queue_id", None))
            )
            if not poc_repeater.get("ok"):
                # Fail closed: a finding is not Agent-B valid until Burp holds
                # its exact editable PoC request in Repeater.
                with self.extender.findings_lock_ui:
                    failed_idx = self.extender._finding_index_by_reference_unlocked(stable_id)
                    if failed_idx is not None and 0 <= failed_idx < len(self.extender.findings_list):
                        failed = self.extender.findings_list[failed_idx]
                        failed["agent_status"] = "needs_investigation"
                        failed["agent_display_status"] = "gated"
                        failed["gate_reason"] = "poc_repeater_required"
                        failed["gate_detail"] = poc_repeater.get("message", poc_repeater.get("error", ""))
                        failed["poc_repeater"] = {
                            "created": False,
                            "error": poc_repeater.get("error", "poc_repeater_required"),
                            "message": poc_repeater.get("message", "")
                        }
                self.extender.save_findings()
                self.extender._ui_dirty = True
                self._send_json(409, {
                    "error": "poc_repeater_required",
                    "message": "Agent B cannot mark this finding valid until its PoC Repeater tab is created.",
                    "finding_id": stable_id,
                    "poc_repeater": poc_repeater,
                    "retry_endpoint": "/api/findings/%s/poc-repeater" % stable_id
                })
                return
            if collaborator_result.get("artifact"):
                self._store_collaborator_artifact(stable_id, collaborator_result)
        self.extender.save_findings()
        self.extender._ui_dirty = True
        status_code = 201 if disposition == "created" else 200
        self.extender.stdout.println("[AGENT API] %s finding %s: %s" % (
            disposition, stable_id or "(not stored)", stored_title[:80]))
        self._send_json(status_code, {
            "status": disposition,
            "disposition": disposition,
            "created": disposition == "created",
            "matched": disposition in ("matched", "updated"),
            "id": stable_id,
            "stable_id": stable_id,
            "legacy_numeric_id": create_result.get("legacy_numeric_id"),
            "version": create_result.get("version"),
            "deduplication_key": create_result.get("deduplication_key", ""),
            "match_reason": create_result.get("match_reason", ""),
            "url": url,
            "title": stored_title,
            "severity": severity,
            "agent_status": agent_status,
            "agent_priority": agent_priority,
            "poc_repeater": poc_repeater,
            "collaborator_evidence": collaborator_result.get("artifact", {}),
            "active_test_recipe": create_result.get("active_test_recipe", active_test_recipe),
            "guidance": "Use immutable id/stable_id for all later reads and writes. legacy_numeric_id is a display ordinal and may change."
        })

    def _query_value(self, query, name, default=""):
        value = query.get(name, [default])
        if isinstance(value, list):
            if not value:
                return default
            value = value[0]
        try:
            return str(value).strip()
        except:
            return default

    def _header_value(self, headers, name):
        prefix = name.lower() + ":"
        for header in headers:
            text = str(header)
            if text.lower().startswith(prefix):
                return text[len(prefix):].strip()
        return ""

    def _extract_set_cookies(self, headers):
        cookies = []
        for header in headers:
            text = str(header)
            if not text.lower().startswith("set-cookie:"):
                continue
            value = text[len("set-cookie:"):].strip()
            pair = value.split(";", 1)[0]
            if "=" in pair:
                name, cookie_value = pair.split("=", 1)
                cookies.append({
                    "name": name.strip(),
                    "value": cookie_value.strip(),
                    "header": value
                })
        return cookies

    def _extract_cookie_pairs(self, cookie_header):
        cookies = []
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip()
            if name:
                cookies.append({"name": name, "value": value})
        return cookies

    def _cookie_header_from_pairs(self, cookies):
        pairs = []
        for cookie in cookies or []:
            try:
                name = str(cookie.get("name", "")).strip()
                value = str(cookie.get("value", "")).strip()
                if name and value:
                    pairs.append("%s=%s" % (name, value))
            except:
                pass
        return "; ".join(pairs)

    def _auth_value_is_usable(self, name, value):
        value_s = str(value or "").strip()
        if not value_s:
            return False
        lower = value_s.lower()
        empty_values = set(["bearer", "bearer ", "bearer null", "bearer undefined",
                            "bearer none", "bearer nil", "null", "undefined", "none"])
        if lower in empty_values:
            return False
        if name and str(name).strip().lower() == "authorization":
            if lower.startswith("bearer") and len(value_s.split(None, 1)) < 2:
                return False
        return True

    def _extract_auth_headers(self, headers):
        interesting = []
        interesting_names = set([
            "authorization", "proxy-authorization", "x-api-key", "api-key",
            "x-auth-token", "x-access-token", "x-id-token", "x-session-token",
            "x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken",
            "x-request-verification-token", "requestverificationtoken"
        ])
        for header in headers:
            text = str(header)
            if ":" not in text:
                continue
            name, value = text.split(":", 1)
            name_l = name.strip().lower()
            if name_l in interesting_names or "csrf" in name_l or "token" in name_l:
                if self._auth_value_is_usable(name, value):
                    interesting.append({"name": name.strip(), "value": value.strip()})
        return interesting

    def _build_recommended_auth(self, credentials):
        """Build a ready-to-use auth block from newest usable same-host history."""
        headers = []
        cookie_by_name = {}
        source_history = []
        source_hosts = []

        for cred in credentials:
            try:
                history_index = cred.get("history_index")
                cred_host = str(cred.get("host", "")).strip()
                request_auth = cred.get("request_auth", {})
                response_auth = cred.get("response_auth", {})

                if not headers:
                    for header in request_auth.get("headers", []):
                        name = str(header.get("name", "")).strip()
                        value = str(header.get("value", "")).strip()
                        if self._auth_value_is_usable(name, value):
                            headers.append({"name": name, "value": value})

                for cookie in request_auth.get("cookies", []):
                    name = str(cookie.get("name", "")).strip()
                    value = str(cookie.get("value", "")).strip()
                    if name and value and name not in cookie_by_name:
                        cookie_by_name[name] = value

                for cookie in response_auth.get("set_cookies", []):
                    name = str(cookie.get("name", "")).strip()
                    value = str(cookie.get("value", "")).strip()
                    if name and value and name not in cookie_by_name:
                        cookie_by_name[name] = value

                if history_index is not None and (request_auth.get("headers") or request_auth.get("cookies") or response_auth.get("set_cookies")):
                    source_history.append(history_index)
                if cred_host and cred_host not in source_hosts:
                    source_hosts.append(cred_host)
            except:
                continue

        cookies = [{"name": name, "value": cookie_by_name[name]} for name in cookie_by_name]
        cookie_header = self._cookie_header_from_pairs(cookies)
        header_lines = []
        for header in headers:
            header_lines.append("%s: %s" % (header.get("name", ""), header.get("value", "")))
        if cookie_header:
            header_lines.append("Cookie: " + cookie_header)

        return {
            "usable": bool(headers or cookie_header),
            "headers": headers,
            "cookies": cookies,
            "cookie_header": cookie_header,
            "raw_header_lines": header_lines,
            "source_history_indices": source_history[:10],
            "source_hosts": source_hosts[:10],
            "note": "Use raw_header_lines or cookie_header for the next retry. Empty Bearer placeholders are ignored."
        }
