# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk1Chunk3(object):
    def _serialize_finding(self, idx, f, include_full=False):
        # Immutable stable IDs are the public identity. Numeric list positions
        # remain internal. The deprecated numeric ID is stored on the finding
        # so deletion never renumbers a surviving record.
        stable_id = self.extender._ensure_finding_stable_id(f)
        legacy_numeric_id = self.extender._ensure_finding_legacy_numeric_id(f, idx + 1)
        base = {
            "id": stable_id,
            "stable_id": stable_id,
            "legacy_numeric_id": legacy_numeric_id,
            "version": int(f.get("version", 1) or 1),
            "url": f.get("url", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
            "ai_confidence": f.get("ai_confidence", 0),
            "fp": bool(f.get("fp", False)),
            "agent_status": f.get("agent_status", "untouched"),
            "agent_status_display": self.extender._agent_status_display(f),
            "agent_display_status": f.get("agent_display_status", ""),
            "gate_reason": f.get("gate_reason", ""),
            "gate_detail": f.get("gate_detail", ""),
            "gate_missing": list(f.get("gate_missing", []) or []),
            "agent_validated_by": f.get("agent_validated_by", "A"),
            "agent_priority": f.get("agent_priority", ""),
            "agent_rationale": f.get("agent_rationale", ""),
            "agent_candidate_type": f.get("agent_candidate_type", ""),
            "active_test_recipe": f.get("active_test_recipe", {}),
            "agent_updated_at": f.get("agent_updated_at", ""),
            "discovered_at": f.get("discovered_at", "")
        }
        if include_full:
            base["detail"] = f.get("detail", "")
            base["evidence"] = f.get("evidence", "")
            base["cwe"] = f.get("cwe", "")
            base["owasp"] = f.get("owasp", "")
            base["remediation"] = f.get("remediation", "")
            base["request_data"] = f.get("request_data", "")
            base["response_data"] = f.get("response_data", "")
            base["notes"] = list(f.get("agent_notes", []))
        else:
            base["cwe"] = f.get("cwe", "")
            base["owasp"] = f.get("owasp", "")
            base["detail_preview"] = self.extender._safe_ascii_text(f.get("detail", ""), 1200)
            base["evidence_preview"] = self.extender._safe_ascii_text(f.get("evidence", ""), 1200)
            base["has_request_data"] = bool(f.get("request_data"))
            base["has_response_data"] = bool(f.get("response_data"))
        return base

    def _filter_fields(self, payload, fields):
        if not fields:
            return payload
        keep = []
        for field in str(fields or "").split(","):
            field = field.strip()
            if field and field not in keep:
                keep.append(field)
        if not keep:
            return payload
        filtered = {}
        for field in keep:
            if field in payload:
                filtered[field] = payload[field]
        if "id" in payload and "id" not in filtered:
            filtered["id"] = payload["id"]
        return filtered

    def _handle_list_findings(self, query=None):
        query = query or {}
        try:
            limit = max(1, min(500, int(self._query_value(query, "limit", "100"))))
            offset = max(0, int(self._query_value(query, "offset", "0")))
        except Exception:
            limit, offset = 100, 0
        fields = self._query_value(query, "fields", "")
        with self.extender.findings_lock_ui:
            all_items = [self._serialize_finding(i, f, include_full=False)
                         for i, f in enumerate(self.extender.findings_list)]
        page = all_items[offset:offset + limit]
        if fields:
            page = [self._filter_fields(item, fields) for item in page]
        next_offset = offset + len(page)
        self._send_json(200, {"findings": page, "count": len(page), "total": len(all_items),
                              "offset": offset, "limit": limit,
                              "next_offset": next_offset if next_offset < len(all_items) else None,
                              "has_more": next_offset < len(all_items),
                              "stable_order": "creation_order"})

    def _normalize_fixture_kind(self, value):
        kind = str(value or "account").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "user": "account",
            "test_user": "account",
            "profile": "account",
            "auth": "session",
            "browser": "session",
            "browser_profile": "session",
            "object_id": "object",
            "resource": "object",
            "tenant_pair": "tenant",
            "workflow": "flow_state",
            "flow": "flow_state"
        }
        kind = aliases.get(kind, kind)
        valid = set(["account", "session", "object", "tenant", "flow_state"])
        return kind if kind in valid else "account"

    def _sanitize_fixture_body(self, body):
        safe = {}
        sensitive_keys = set([
            "password", "pass", "passwd", "token", "access_token", "refresh_token",
            "authorization", "cookie", "set_cookie", "session_cookie", "api_key",
            "secret", "client_secret", "otp", "mfa_code"
        ])
        allowed = set([
            "id", "kind", "label", "name", "role", "tenant", "brand", "account_number",
            "account_id", "user_id", "email_hint", "phone_hint", "object_ids",
            "owned_object_ids", "foreign_object_ids", "session_state", "session_source",
            "browser_profile", "auth_source", "secret_ref", "consent_scope", "fixture_scope",
            "notes", "tags", "expires_at", "created_at", "updated_at"
        ])
        for key, value in (body or {}).items():
            key_s = str(key or "").strip()
            key_l = key_s.lower()
            if key_l in sensitive_keys or self.extender._fixture_secret_key(key_s):
                safe[key_s] = "[redacted; store a secret_ref or session_source instead]"
                continue
            if key_l in allowed or key_l.startswith("meta_"):
                safe[key_s] = value
        return safe

    def _normalize_fixture(self, body):
        body = self._sanitize_fixture_body(body if isinstance(body, dict) else {})
        kind = self._normalize_fixture_kind(body.get("kind", "account"))
        label = str(body.get("label", body.get("name", "")) or "").strip()
        if not label:
            label = "%s-%s" % (kind, uuid.uuid4().hex[:8])
        fid = str(body.get("id", "") or "").strip()
        if not fid:
            fid = "%s:%s" % (kind, re.sub(r"[^a-zA-Z0-9_.:-]+", "_", label.lower())[:80])
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fixture = dict(body)
        fixture["id"] = fid
        fixture["kind"] = kind
        fixture["label"] = label
        engagement = self.extender._active_engagement_context()
        fixture["engagement_id"] = str(body.get("engagement_id", "") or engagement.get("id", ""))
        fixture["engagement_authorities"] = list(body.get("engagement_authorities", []) or engagement.get("authorities", []))
        fixture["updated_at"] = now_str
        if "created_at" not in fixture:
            fixture["created_at"] = now_str
        if "consent_scope" not in fixture and "fixture_scope" in fixture:
            fixture["consent_scope"] = fixture.get("fixture_scope", "")
        return fixture

    def _fixture_counts(self):
        counts = {}
        for fixture in getattr(self.extender, "test_fixtures", []) or []:
            if not self.extender._engagement_bound_record_is_current(fixture):
                continue
            kind = str(fixture.get("kind", "unknown") or "unknown")
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def _handle_get_project_profile(self, query):
        with self.extender.fixture_lock:
            profile = dict(getattr(self.extender, "project_profile", {}) or {})
        include_stale = self._bool_query_value(query, "include_stale", "false")
        stale = bool(profile) and not self.extender._engagement_bound_record_is_current(profile)
        self._send_json(200, {
            "engagement": self.extender._active_engagement_context(),
            "project_profile": profile if include_stale or not stale else {},
            "stale_excluded": bool(stale and not include_stale),
            "guidance": "Use this for assessment metadata, auth schemes, roles, and allowed state changes. Scope fields are informational only; GET /api/agent/scope and Burp callbacks.isInScope are authoritative."
        })

    def _handle_update_project_profile(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        profile = self.extender._merge_project_profile(body, "api")
        self.extender.save_findings()
        self._send_json(200, {"status": "updated", "project_profile": profile})

    def _handle_import_project_profile_from_notes(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        notes = str(body.get("notes", body.get("text", "")) or "")
        source = str(body.get("source", "api_notes") or "api_notes")
        if not notes.strip():
            self._send_json(400, {"error": "notes is required"})
            return
        result = self.extender._import_project_profile_from_notes(notes, source)
        self._send_json(200, result)

    def _handle_get_knowledge(self, query):
        category_filter = self._query_value(query, "category", "").lower()
        status_filter = self._query_value(query, "status", "").lower()
        tag_filter = self._query_value(query, "tag", "").lower()
        try:
            limit = int(self._query_value(query, "limit", "200") or 200)
        except:
            limit = 200
        if limit <= 0:
            limit = 200
        if limit > 1000:
            limit = 1000

        with self.extender.fixture_lock:
            knowledge = self.extender._normalize_assessment_knowledge_doc(
                getattr(self.extender, "assessment_knowledge", {}) or {})
            entries = [dict(e) for e in knowledge.get("entries", []) or []]

        filtered = []
        stale_count = 0
        include_stale = self._bool_query_value(query, "include_stale", "false")
        for entry in entries:
            if not self.extender._engagement_bound_record_is_current(entry):
                stale_count += 1
                if not include_stale:
                    continue
            if category_filter and str(entry.get("category", "")).lower() != category_filter:
                continue
            if status_filter and str(entry.get("status", "")).lower() != status_filter:
                continue
            if tag_filter:
                tags = [str(t).lower() for t in entry.get("tags", []) or []]
                if tag_filter not in tags:
                    continue
            filtered.append(entry)
        filtered = filtered[-limit:]
        self._send_json(200, {
            "engagement": self.extender._active_engagement_context(),
            "knowledge": knowledge,
            "entries": filtered,
            "count": len(filtered),
            "total": len(filtered),
            "stale_excluded": 0 if include_stale else stale_count,
            "guidance": "Read this before automated testing and variant analysis. POST notes, leads, assumptions, tested controls, and environment observations as entries or free-form notes."
        })

    def _handle_update_knowledge(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "body must be an object"})
            return
        source = str(body.get("source", "api") or "api")
        entries = []
        notes = body.get("notes", body.get("text", ""))
        if notes:
            entries.extend(self.extender._knowledge_entries_from_notes(notes, source))
        if isinstance(body.get("entry"), dict):
            entries.append(body.get("entry"))
        if isinstance(body.get("entries"), list):
            for entry in body.get("entries", []):
                if isinstance(entry, dict):
                    entries.append(entry)
        # Accept the natural entry-shaped form as well as the documented
        # envelope: {title, detail/note, category, ...}.
        if not entries and any(body.get(key) for key in ("title", "detail", "note", "category")):
            direct_entry = dict(body)
            if direct_entry.get("note") and not direct_entry.get("detail"):
                direct_entry["detail"] = direct_entry.get("note")
            entries.append(direct_entry)
        if not entries:
            self._send_json(400, {
                "error": "knowledge_entry_required",
                "message": "Send notes, entry, entries, or an entry-shaped object with title/detail/category.",
                "accepted_shapes": [
                    {"title": "short label", "detail": "what was learned", "category": "note"},
                    {"entry": {"title": "short label", "detail": "what was learned"}},
                    {"entries": [{"title": "short label", "detail": "what was learned"}]},
                    {"notes": "free-form notes"}
                ]
            })
            return
        result = self.extender._upsert_knowledge_entries(entries, source, persist=True)
        if body.get("full_response", False):
            self._send_json(200, result)
            return
        self._send_json(200, {
            "status": result.get("status", "updated"),
            "created": result.get("created", 0),
            "updated": result.get("updated", 0),
            "entry_ids": [entry.get("id") for entry in result.get("entries", []) if isinstance(entry, dict)],
            "total": len(((getattr(self.extender, "assessment_knowledge", {}) or {}).get("entries", []) or [])),
            "guidance": "Knowledge updated. Use GET /api/agent/knowledge for the full redacted knowledge base, or POST with full_response=true if a write needs the full document."
        })

    def _attack_surface_snapshot(self):
        with self.extender.attack_surface_lock:
            entries = [dict(entry) for entry in (getattr(self.extender, "attack_surface", {}) or {}).get("entries", []) or []]
        return attack_surface_snapshot(entries)

    def _seed_attack_surface_from_burp(self, queue_id=None, limit=2000):
        """Seed discovery state from already-observed Burp traffic without sending requests."""
        observed = []
        seen_messages = set()
        parameter_types = {
            0: "query", 1: "body", 2: "cookie", 3: "xml", 4: "xml_attribute",
            5: "multipart", 6: "json",
        }
        static_extensions = set([
            "gif", "jpg", "jpeg", "png", "ico", "css", "woff", "woff2", "ttf", "svg",
            "mp4", "m4v", "mov", "webm", "avi", "mp3", "wav", "ogg", "pdf", "zip", "gz",
            "js", "map",
        ])
        sources = []
        try:
            sources.append(("burp_site_map", self.extender._get_burp_site_map_snapshot() or []))
        except Exception:
            pass
        try:
            sources.append(("burp_proxy_history", self.extender.callbacks.getProxyHistory() or []))
        except Exception:
            pass
        for source_name, messages in sources:
            for message in messages:
                if len(observed) >= limit:
                    break
                try:
                    identity = id(message)
                    if identity in seen_messages:
                        continue
                    seen_messages.add(identity)
                    info = self.extender.helpers.analyzeRequest(message)
                    raw_url = str(info.getUrl() or "")
                    parsed = urlparse.urlparse(raw_url)
                    extension = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path.rsplit("/", 1)[-1] else ""
                    if extension in static_extensions:
                        continue
                    guard = self._scope_guard_for_url(raw_url)
                    if guard.get("in_scope") is not True:
                        continue
                    parameters = []
                    try:
                        for parameter in info.getParameters() or []:
                            parameters.append({
                                "name": str(parameter.getName() or ""),
                                "type": parameter_types.get(int(parameter.getType()), "unknown"),
                            })
                    except Exception:
                        pass
                    observed.append(normalize_attack_surface_entry({
                        "url": raw_url,
                        "method": str(info.getMethod() or "GET"),
                        "parameters": parameters,
                        "sources": [source_name],
                        "protocols": [parsed.scheme or "http"],
                        "response_seen": message.getResponse() is not None,
                        "browser_visited": False,
                        "status": "observed",
                        "queue_ids": [queue_id] if queue_id is not None else [],
                        "scope_guard": {
                            "scope_source": "burp_suite",
                            "authoritative": True,
                            "in_scope": True,
                            "url": raw_url,
                        },
                    }, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                except Exception:
                    continue
        if not observed:
            return {"created": 0, "updated": 0, "snapshot": self._attack_surface_snapshot()}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        created = 0
        updated = 0
        with self.extender.attack_surface_lock:
            surface = self.extender._normalize_attack_surface_doc(getattr(self.extender, "attack_surface", {}) or {})
            entries = surface.get("entries", []) or []
            by_key = dict((str(entry.get("key", "")), index) for index, entry in enumerate(entries))
            for normalized in observed:
                key = normalized.get("key", "")
                if key in by_key:
                    index = by_key[key]
                    entries[index] = merge_attack_surface_entries(entries[index], normalized, now=now)
                    updated += 1
                else:
                    normalized["id"] = int(surface.get("next_id", 1) or 1)
                    surface["next_id"] = normalized["id"] + 1
                    entries.append(normalized)
                    by_key[key] = len(entries) - 1
                    created += 1
            surface["entries"] = entries[-5000:]
            surface["updated_at"] = now
            self.extender.attack_surface = surface
        return {"created": created, "updated": updated, "snapshot": self._attack_surface_snapshot()}

    def _attack_surface_review_payload(self, queue_id=None):
        options = {}
        snapshots = []
        queue_item = None
        if queue_id not in (None, ""):
            try:
                wanted = int(queue_id)
            except Exception:
                wanted = -1
            with self.extender.agent_queue_lock:
                for item in self.extender.agent_queue:
                    if item.get("id") == wanted:
                        queue_item = item
                        break
            if queue_item:
                options = dict(queue_item.get("campaign_options", {}) or {})
                snapshots = list((queue_item.get("campaign_state", {}) or {}).get("surface_snapshots", []) or [])
        with self.extender.attack_surface_lock:
            surface = getattr(self.extender, "attack_surface", {}) or {}
            entries = [dict(entry) for entry in surface.get("entries", []) or []]
        review = review_attack_surface(entries, snapshots=snapshots, options=options)
        if queue_item and str(queue_item.get("campaign_type", "")) == "full_app_assessment":
            review = apply_coverage_overwatch_to_review(
                review, (queue_item.get("campaign_state", {}) or {}).get("ai_coverage_overwatch", {}))
        review["queue_id"] = queue_item.get("id") if queue_item else None
        review["campaign_type"] = queue_item.get("campaign_type", "") if queue_item else ""
        return review

    def _handle_get_attack_surface(self, query):
        host_filter = self._query_value(query, "host", "").lower()
        status_filter = self._query_value(query, "status", "").lower()
        try:
            limit = max(1, min(2000, int(self._query_value(query, "limit", "500") or 500)))
        except Exception:
            limit = 500
        with self.extender.attack_surface_lock:
            surface = dict(getattr(self.extender, "attack_surface", {}) or {})
            entries = [dict(entry) for entry in surface.get("entries", []) or []]
        filtered = []
        for entry in entries:
            if host_filter and str(entry.get("host", "")).lower() != host_filter:
                continue
            if status_filter and str(entry.get("status", "")).lower() != status_filter:
                continue
            filtered.append(entry)
        self._send_json(200, {
            "attack_surface": {
                "entries": filtered[-limit:],
                "updated_at": surface.get("updated_at", ""),
            },
            "count": min(len(filtered), limit),
            "total": len(entries),
            "snapshot": attack_surface_snapshot(entries),
            "guidance": "This inventory is discovery state, not scope authority. Every stored URL was checked with Burp scope at ingestion; re-check exact URLs before target traffic."
        })

    def _handle_update_attack_surface(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "body must be an object"})
            return
        incoming = []
        if isinstance(body.get("entry"), dict):
            incoming.append(body.get("entry"))
        if isinstance(body.get("entries"), list):
            incoming.extend([entry for entry in body.get("entries", []) if isinstance(entry, dict)])
        if not incoming and body.get("url"):
            incoming.append(body)
        if not incoming:
            self._send_json(400, {"error": "entry, entries, or an entry-shaped body with url is required"})
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        accepted = []
        rejected = []
        normalized_incoming = []
        for raw_entry in incoming[:500]:
            try:
                normalized = normalize_attack_surface_entry(raw_entry, now=now)
            except Exception as e:
                rejected.append({"url": str(raw_entry.get("url", "")), "reason": self._safe_ascii_text(e)})
                continue
            guard = self._scope_guard_for_url(normalized.get("url_example", normalized.get("url", "")))
            if guard.get("in_scope") is not True:
                rejected.append({
                    "url": normalized.get("url_example", normalized.get("url", "")),
                    "reason": guard.get("reason", "Burp did not authorize this URL"),
                    "scope_guard": guard,
                })
                continue
            normalized["scope_guard"] = {
                "scope_source": "burp_suite",
                "authoritative": True,
                "in_scope": True,
                "url": guard.get("url", normalized.get("url", "")),
                "reason": guard.get("reason", "Burp Suite reports this URL in scope"),
            }
            normalized_incoming.append(normalized)

        if not normalized_incoming:
            self._send_json(403 if rejected else 400, {
                "error": "no in-scope attack-surface entries accepted",
                "rejected": rejected,
            })
            return

        with self.extender.attack_surface_lock:
            surface = self.extender._normalize_attack_surface_doc(getattr(self.extender, "attack_surface", {}) or {})
            entries = surface.get("entries", []) or []
            by_key = dict((str(entry.get("key", "")), index) for index, entry in enumerate(entries))
            for normalized in normalized_incoming:
                key = normalized.get("key", "")
                if key in by_key:
                    index = by_key[key]
                    entries[index] = merge_attack_surface_entries(entries[index], normalized, now=now)
                    accepted.append({"id": entries[index].get("id"), "key": key, "operation": "updated"})
                else:
                    normalized["id"] = int(surface.get("next_id", 1) or 1)
                    surface["next_id"] = normalized["id"] + 1
                    entries.append(normalized)
                    by_key[key] = len(entries) - 1
                    accepted.append({"id": normalized.get("id"), "key": key, "operation": "created"})
            surface["entries"] = entries[-5000:]
            surface["updated_at"] = now
            self.extender.attack_surface = surface
        self.extender.save_agent_queue()
        self._send_json(201, {
            "status": "updated",
            "accepted": accepted,
            "rejected": rejected,
            "snapshot": self._attack_surface_snapshot(),
            "guidance": "Continue visible BrowserOS discovery through Burp, then POST campaign surface_diff and run /api/agent/attack-surface/review."
        })

    def _handle_get_attack_surface_review(self, query):
        queue_id = self._query_value(query, "queue_id", "")
        self._send_json(200, self._attack_surface_review_payload(queue_id=queue_id))

    def _handle_run_attack_surface_review(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        if not isinstance(body, dict):
            body = {}
        queue_id = body.get("queue_id", "")
        review = self._attack_surface_review_payload(queue_id=queue_id)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        review_record = dict(review)
        review_record["reviewed_at"] = now
        with self.extender.attack_surface_lock:
            surface = self.extender._normalize_attack_surface_doc(getattr(self.extender, "attack_surface", {}) or {})
            reviews = list(surface.get("reviews", []) or [])
            reviews.append(review_record)
            surface["reviews"] = reviews[-200:]
            surface["updated_at"] = now
            self.extender.attack_surface = surface
        if review.get("queue_id") is not None:
            with self.extender.agent_queue_lock:
                for item in self.extender.agent_queue:
                    if item.get("id") == review.get("queue_id"):
                        state = item.get("campaign_state", {}) or {}
                        state["overwatch_review"] = review_record
                        for step in state.get("steps", []) or []:
                            if step.get("key") == "overwatch_review":
                                step["status"] = "completed"
                                step["updated_at"] = now
                                step["artifacts"] = [{
                                    "ready_to_complete": bool(review_record.get("ready_to_complete")),
                                    "blocker_codes": [str(blocker.get("code", "")) for blocker in review_record.get("blockers", []) if isinstance(blocker, dict)]
                                }]
                        state["updated_at"] = now
                        item["campaign_state"] = state
                        item["last_heartbeat_at"] = now
                        break
        self.extender.save_agent_queue()
        self._send_json(200, review_record)

    def _handle_list_fixtures(self, query):
        kind_filter = self._query_value(query, "kind", "").lower()
        include_stale = self._bool_query_value(query, "include_stale", "false")
        fixtures = []
        stale_count = 0
        with self.extender.fixture_lock:
            for fixture in getattr(self.extender, "test_fixtures", []) or []:
                if not self.extender._engagement_bound_record_is_current(fixture):
                    stale_count += 1
                    if not include_stale:
                        continue
                if kind_filter and str(fixture.get("kind", "")).lower() != kind_filter:
                    continue
                fixtures.append(self.extender._redacted_fixture_for_api(fixture))
        self._send_json(200, {
            "engagement": self.extender._active_engagement_context(),
            "fixtures": fixtures,
            "count": len(fixtures),
            "counts": self._fixture_counts(),
            "stale_excluded": 0 if include_stale else stale_count,
            "guidance": "Use these entries as named test context only. Keep raw credentials/tokens out of this API; store secret_ref, session_source, or browser_profile labels instead."
        })

    def _handle_upsert_fixture(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        fixture = self._normalize_fixture(body)
        updated = False
        with self.extender.fixture_lock:
            fixtures = getattr(self.extender, "test_fixtures", [])
            for i, existing in enumerate(fixtures):
                if (existing.get("id") == fixture.get("id") and
                        self.extender._engagement_bound_record_is_current(existing)):
                    original_created = existing.get("created_at", fixture.get("created_at", ""))
                    merged = dict(existing)
                    merged.update(fixture)
                    if original_created:
                        merged["created_at"] = original_created
                    fixtures[i] = merged
                    fixture = merged
                    updated = True
                    break
            if not updated:
                fixtures.append(fixture)
            self.extender.test_fixtures = fixtures
        self.extender.save_findings()
        self._send_json(200 if updated else 201, {
            "status": "updated" if updated else "created",
            "fixture": fixture
        })

    def _handle_import_fixtures_from_notes(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        notes = str(body.get("notes", body.get("text", "")) or "")
        source = str(body.get("source", "api_notes") or "api_notes")
        if not notes.strip():
            self._send_json(400, {"error": "notes is required"})
            return
        try:
            result = self.extender._import_fixtures_from_notes(notes, source)
            self._send_json(200, result)
        except Exception as e:
            self._send_json(500, {"error": "fixture import failed", "message": str(e)})

    def _normalize_confirmation_kind(self, value):
        kind = str(value or "other").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {"mail": "email", "e_mail": "email", "text": "sms", "mfa": "otp", "2fa": "otp"}
        kind = aliases.get(kind, kind)
        valid = set(["otp", "sms", "email", "push", "phone", "other"])
        return kind if kind in valid else "other"

    def _handle_list_confirmations(self, query):
        kind_filter = self._query_value(query, "kind", "").lower()
        include_stale = self._bool_query_value(query, "include_stale", "false")
        since_seconds = 0
        try:
            since_seconds = int(self._query_value(query, "since_seconds", "0") or 0)
        except:
            since_seconds = 0
        now_epoch = time.time()
        confirmations = []
        with self.extender.fixture_lock:
            for item in getattr(self.extender, "human_confirmations", []) or []:
                if not self.extender._engagement_bound_record_is_current(item) and not include_stale:
                    continue
                if kind_filter and str(item.get("kind", "")).lower() != kind_filter:
                    continue
                if since_seconds > 0:
                    try:
                        observed_epoch = float(item.get("observed_epoch", 0) or 0)
                        if observed_epoch and (now_epoch - observed_epoch) > since_seconds:
                            continue
                    except:
                        pass
                confirmations.append(dict(item))
        self._send_json(200, {
            "confirmations": confirmations,
            "count": len(confirmations),
            "guidance": "Use this as human-confirmed evidence for OTP/SMS/email/push receipt. Redact codes and destinations unless explicitly authorized."
        })

    def _handle_create_confirmation(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "body must be an object"})
            return
        now_epoch = time.time()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        confirmation = {
            "id": str(body.get("id", "") or "confirmation:%s" % uuid.uuid4().hex[:12]),
            "kind": self._normalize_confirmation_kind(body.get("kind", "")),
            "account_label": self._limit_text(body.get("account_label", body.get("account", "")), 120),
            "destination": self._limit_text(body.get("destination", ""), 200),
            "received_at": self._limit_text(body.get("received_at", ""), 120),
            "observed_at": now_str,
            "observed_epoch": now_epoch,
            "source": self._limit_text(body.get("source", "user"), 80),
            "notes": self._limit_text(body.get("notes", body.get("note", "")), 1000)
        }
        engagement = self.extender._active_engagement_context()
        confirmation["engagement_id"] = engagement.get("id", "")
        confirmation["engagement_authorities"] = list(engagement.get("authorities", []))
        with self.extender.fixture_lock:
            confirmations = getattr(self.extender, "human_confirmations", [])
            confirmations.append(confirmation)
            self.extender.human_confirmations = confirmations[-500:]
        self.extender.save_findings()
        self._send_json(201, {"status": "created", "confirmation": confirmation})

    def _normalize_agent_status(self, value):
        status = str(value or "untouched").strip().lower().replace(" ", "_").replace("-", "_")
        if status == "not_important":
            return "false_positive"
        valid = set(["untouched", "valid", "false_positive", "duplicate", "already_covered",
                     "needs_investigation"])
        return status if status in valid else "untouched"

    def _normalize_agent_priority(self, value):
        priority = str(value or "").strip().lower()
        aliases = {"p1": "P1", "p2": "P2", "p3": "P3", "p4": "P4", "defer": "defer", "": ""}
        return aliases.get(priority, "")

    def _normalize_finding_severity(self, value, fallback="Information"):
        severity = str(value or "").strip().lower()
        if not severity:
            return fallback or "Information"
        return VALID_SEVERITIES.get(severity, fallback or "Information")

    def _duplicate_triage_error(self, body, rationale):
        # Jython's str(unicode) uses the ASCII codec; model-supplied evidence text
        # routinely contains em-dashes/curly quotes, so keep it unicode throughout.
        duplicate_of = unicode_text(body.get("duplicate_of", "") or "").strip()
        evidence_match = unicode_text(body.get("duplicate_evidence_match", "") or body.get("evidence_match", "") or "").strip()
        if len(rationale.strip()) < 20:
            return "status=duplicate deletes the finding and requires a specific rationale based on actual finding data"
        if not duplicate_of and len(evidence_match) < 20:
            return "status=duplicate requires duplicate_of or duplicate_evidence_match showing matching endpoint/parameter/root cause/evidence"
        return None

    def _triage_status_deletes_finding(self, status):
        return status in ("duplicate", "already_covered")

    def _finding_update_precondition(self, reference, finding, body):
        stable_id = self.extender._ensure_finding_stable_id(finding)
        current_version = int(finding.get("version", 1) or 1)
        expected = body.get("expected_version", body.get("version", None))
        if expected is not None:
            try:
                if int(expected) != current_version:
                    return 409, {
                        "error": "finding_version_conflict",
                        "id": stable_id,
                        "expected_version": int(expected),
                        "current_version": current_version,
                    }
            except Exception:
                return 400, {"error": "expected_version must be an integer"}
        if isinstance(body.get("active_test_recipe", None), dict):
            if str(reference or "") != stable_id:
                return 428, {
                    "error": "immutable_finding_id_required",
                    "message": "active_test_recipe updates require the immutable finding id",
                    "stable_id": stable_id,
                }
            if expected is None:
                return 428, {
                    "error": "expected_version_required",
                    "message": "active_test_recipe updates require expected_version",
                    "stable_id": stable_id,
                    "current_version": current_version,
                }
        return None, None

    def _apply_finding_triage(self, idx, body):
        if idx < 0 or idx >= len(self.extender.findings_list):
            return None

        finding = self.extender.findings_list[idx]
        legacy_numeric_id = self.extender._ensure_finding_legacy_numeric_id(finding, idx + 1)
        status = self._normalize_agent_status(body.get("status", finding.get("agent_status", "untouched")))
        priority = self._normalize_agent_priority(body.get("priority", finding.get("agent_priority", "")))
        severity = self._normalize_finding_severity(body.get("severity", finding.get("severity", "Information")),
                                                    finding.get("severity", "Information"))
        # Jython's str(unicode) uses the process default ASCII codec. Model
        # rationales routinely contain curly quotes/dashes, so keep this as
        # unicode all the way through the finding store.
        rationale = unicode_text(
            body.get("rationale", body.get("note", finding.get("agent_rationale", ""))) or ""
        ).strip()
        if len(rationale) > 2000:
            rationale = rationale[:2000] + "... [truncated]"

        if self._triage_status_deletes_finding(status):
            if status == "duplicate":
                duplicate_error = self._duplicate_triage_error(body, rationale)
                if duplicate_error:
                    return {
                        "id": self.extender._ensure_finding_stable_id(finding),
                        "legacy_numeric_id": legacy_numeric_id,
                        "status": "duplicate",
                        "error": duplicate_error,
                        "deleted": False
                    }
            for fp_key in self.extender._get_fp_keys_for_finding(
                finding.get("url", ""), finding.get("title", ""), finding.get("source", ""),
                finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""),
                finding.get("request_data")
            ):
                if fp_key in self.extender.fp_suppressed:
                    self.extender.fp_suppressed.discard(fp_key)
            self.extender._record_finding_audit(finding, "deleted", {
                "status": status,
                "rationale": rationale,
                "duplicate_of": body.get("duplicate_of", ""),
            }, actor="agent_b", bump_version=True)
            removed = self.extender.findings_list.pop(idx)
            self.extender.finding_audit_log.append({
                "stable_id": removed.get("stable_id", ""),
                "legacy_numeric_id": legacy_numeric_id,
                "title": removed.get("title", ""),
                "url": removed.get("url", ""),
                "event": "deleted",
                "version": removed.get("version", 1),
                "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reason": status,
                "audit_log": list(removed.get("audit_log", []) or []),
            })
            self.extender.finding_audit_log = self.extender.finding_audit_log[-1000:]
            return {
                "id": removed.get("stable_id", ""),
                "stable_id": removed.get("stable_id", ""),
                "legacy_numeric_id": legacy_numeric_id,
                "version": removed.get("version", 1),
                "status": status,
                "priority": priority,
                "rationale": rationale,
                "fp": bool(removed.get("fp", False)),
                "deleted": True,
                "delete_reason": status,
                "duplicate_of": body.get("duplicate_of", ""),
                "duplicate_evidence_match": body.get("duplicate_evidence_match", body.get("evidence_match", "")),
                "deleted_title": removed.get("title", ""),
                "deleted_url": removed.get("url", ""),
                "internal_index": idx
            }

        finding["agent_status"] = status
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
        previous_recipe = dict(finding.get("active_test_recipe", {}) or {})
        if isinstance(body.get("active_test_recipe", None), dict):
            finding["active_test_recipe"] = self.extender._normalize_active_test_recipe(
                body.get("active_test_recipe", {}),
                finding
            )
        finding["agent_candidate_type"] = self.extender._classify_agent_candidate_type(finding)
        finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Record that Agent B triaged this finding so the Agent Status column can
        # show "(B triage)" and no longer look identical to an untested (A) item.
        finding["agent_triaged_by"] = "agent_b"
        finding["agent_triaged_at"] = finding["agent_updated_at"]

        set_fp = body.get("set_fp", None)
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

        self.extender._record_finding_audit(finding, "triage_updated", {
            "status": status,
            "priority": priority,
            "severity": severity,
            "recipe_updated": isinstance(body.get("active_test_recipe", None), dict),
            "previous_recipe": previous_recipe if isinstance(body.get("active_test_recipe", None), dict) else {},
            "new_recipe": finding.get("active_test_recipe", {}) if isinstance(body.get("active_test_recipe", None), dict) else {},
        }, actor="agent_b", bump_version=True)

        return {
            "id": finding.get("stable_id", ""),
            "stable_id": finding.get("stable_id", ""),
            "legacy_numeric_id": legacy_numeric_id,
            "version": finding.get("version", 1),
            "severity": finding.get("severity", ""),
            "status": finding.get("agent_status", ""),
            "priority": finding.get("agent_priority", ""),
            "rationale": finding.get("agent_rationale", ""),
            "agent_candidate_type": finding.get("agent_candidate_type", ""),
            "active_test_recipe": finding.get("active_test_recipe", {}),
            "poc_repeater": finding.get("poc_repeater", {}),
            "fp": bool(finding.get("fp", False))
        }

    def _remap_queue_finding_ids_after_delete(self, deleted_indices):
        """Keep queued finding references aligned after deleting findings by index."""
        if not deleted_indices:
            return
        deleted_sorted = sorted(set([int(i) for i in deleted_indices]), reverse=True)
        with self.extender.agent_queue_lock:
            for q in self.extender.agent_queue:
                old_ids = list(q.get("finding_ids", []))
                if not old_ids:
                    continue
                new_ids = []
                for fid in old_ids:
                    try:
                        fid_int = int(fid)
                    except:
                        continue
                    remove_ref = False
                    shift = 0
                    for deleted_idx in deleted_sorted:
                        if fid_int == deleted_idx:
                            remove_ref = True
                            break
                        if fid_int > deleted_idx:
                            shift += 1
                    if not remove_ref:
                        new_ids.append(fid_int - shift)
                q["finding_ids"] = new_ids
        self.extender._agent_queue_save_pending = True
        self.extender.save_agent_queue()

    def _handle_triage_finding(self, fid):
        idx = self.extender._finding_index_by_reference(fid)
        if idx is None:
            self._send_json(404, {"error": "finding not found", "id": fid})
            return
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        with self.extender.findings_lock_ui:
            if idx < 0 or idx >= len(self.extender.findings_list):
                self._send_json(404, {"error": "finding not found", "id": fid})
                return
            conflict_status, conflict = self._finding_update_precondition(
                fid, self.extender.findings_list[idx], body)
            intended_status = self._normalize_agent_status(
                body.get("status", self.extender.findings_list[idx].get("agent_status", "untouched")))
        if conflict:
            self._send_json(conflict_status, conflict)
            return
        if intended_status == "valid":
            with self.extender.findings_lock_ui:
                finding_snapshot = dict(self.extender.findings_list[idx])
            collaborator_result = self._collaborator_evidence_for_finding(finding_snapshot, body)
            if not collaborator_result.get("ok"):
                self._send_json(409, collaborator_result)
                return
            poc_result = self._ensure_finding_poc_repeater(
                fid,
                raw_request=body.get("poc_request", body.get("request", "")),
                queue_id=body.get("queue_id", None)
            )
            if not poc_result.get("ok"):
                self._send_json(409, {
                    "error": "poc_repeater_required",
                    "message": "Agent B cannot mark this finding valid until its PoC Repeater tab is created.",
                    "finding_id": fid,
                    "poc_repeater": poc_result,
                    "retry_endpoint": "/api/findings/%s/poc-repeater" % fid
                })
                return
            if collaborator_result.get("artifact"):
                self._store_collaborator_artifact(fid, collaborator_result)

        deleted_indices = []
        with self.extender.findings_lock_ui:
            result = self._apply_finding_triage(idx, body)
            if result and result.get("deleted"):
                deleted_indices.append(result.get("internal_index"))
        if result is None:
            self._send_json(404, {"error": "not found"})
            return
        if result.get("error"):
            self._send_json(400, {"error": result.get("error"), "finding": result})
            return
        self._remap_queue_finding_ids_after_delete(deleted_indices)

        self.extender.save_findings()
        self.extender._ui_dirty = True
        if result.get("deleted"):
            self.extender.stdout.println("[AGENT API] deleted %s finding #%d: %s" % (
                result.get("delete_reason", result.get("status", "triaged")),
                idx + 1, self.extender._safe_ascii_text(result.get("deleted_title", ""), 80)))
        else:
            self.extender.stdout.println("[AGENT API] triaged finding #%d: %s/%s" % (
                idx + 1, result.get("status", ""), result.get("priority", "")))
        self._send_json(200, {"status": "ok", "finding": result})
