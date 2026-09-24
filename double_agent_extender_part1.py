# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk1(object):
    def _workspace_directory(self):
        try:
            project_dir = str(getattr(self, "PROJECT_WORKSPACE_DIR", "") or "").strip()
            if project_dir and os.path.isdir(project_dir):
                return os.path.abspath(project_dir)
        except Exception:
            pass
        try:
            return os.getcwd()
        except Exception:
            return "."

    def _read_workspace_text(self, name, limit=100000):
        path = os.path.join(self._workspace_directory(), name)
        if not os.path.isfile(path):
            return ""
        try:
            fh = open(path, "rb")
            try:
                data = fh.read(limit)
            finally:
                fh.close()
            return data.decode("utf-8", "replace") if hasattr(data, "decode") else str(data)
        except Exception:
            return ""

    def _extract_scope_hosts(self, scope_text):
        hosts = []
        seen = set()
        pattern = re.compile(r'(?i)(\*\.)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?')
        for match in pattern.finditer(str(scope_text or "")):
            host = (match.group(1) or "") + (match.group(2) or "")
            host = host.strip(".,;:()[]{}<>\"'").lower()
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts[:200]

    def _looks_like_auth_header_name(self, name):
        name_l = str(name or "").strip().lower()
        if not name_l:
            return False
        exact = set([
            "authorization", "cookie", "x-api-key", "api-key", "apikey",
            "x-auth-token", "x-access-token", "x-id-token", "x-session-token",
            "x-member-token", "x-member-session", "x-api-session", "x-session-id",
            "member-token", "member-session", "api-session", "session-token"
        ])
        if name_l in exact:
            return True
        auth_words = ["token", "session", "auth", "member", "api-key", "apikey"]
        return any(word in name_l for word in auth_words)

    def _host_from_url(self, url):
        try:
            parsed = urlparse.urlparse(str(url or ""))
            return (parsed.hostname or "").lower()
        except Exception:
            try:
                from java.net import URL as JavaURL
                return str(JavaURL(str(url)).getHost() or "").lower()
            except Exception:
                return ""

    def _record_host_auth_model(self, url, headers_dict, cookie_names, source="observed_request"):
        host = self._host_from_url(url)
        if not host:
            return {}
        headers = []
        for name, value in (headers_dict or {}).items():
            if self._looks_like_auth_header_name(name) and str(name).lower() not in ("cookie",):
                headers.append(str(name).strip())
        cookies = [str(c or "").strip() for c in cookie_names or [] if str(c or "").strip()]
        if not headers and not cookies:
            return dict((getattr(self, "host_auth_models", {}) or {}).get(host, {}) or {})
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.fixture_lock:
            models = dict(getattr(self, "host_auth_models", {}) or {})
            model = dict(models.get(host, {}) or {})
            model["headers"] = self._merge_unique_list(model.get("headers", []), headers)
            model["cookies"] = self._merge_unique_list(model.get("cookies", []), cookies)
            model["sources"] = self._merge_unique_list(model.get("sources", []), [source])
            model["updated_at"] = now
            models[host] = model
            self.host_auth_models = models
            profile = self._project_profile_default()
            profile.update(dict(getattr(self, "project_profile", {}) or {}))
            auth_schemes = dict(profile.get("auth_schemes", {}) or {})
            existing = dict(auth_schemes.get(host, {}) or {})
            existing["headers"] = self._merge_unique_list(existing.get("headers", []), headers)
            existing["cookies"] = self._merge_unique_list(existing.get("cookies", []), cookies)
            existing["sources"] = self._merge_unique_list(existing.get("sources", []), [source])
            existing["updated_at"] = now
            auth_schemes[host] = existing
            profile["auth_schemes"] = auth_schemes
            profile["updated_at"] = now
            self.project_profile = profile
            return dict(model)

    def _fixture_secret_key(self, key):
        key_l = str(key or "").strip().lower().replace("-", "_").replace(" ", "_")
        compact = re.sub(r'[^a-z0-9]+', "_", key_l).strip("_")
        parts = [p for p in compact.split("_") if p]
        sensitive = set([
            "password", "pass", "passwd", "token", "access_token", "refresh_token",
            "authorization", "cookie", "set_cookie", "session_cookie", "api_key",
            "apikey", "secret", "client_secret", "otp", "mfa_code", "code", "sms",
            "2fa", "mfa"
        ])
        if compact in sensitive or key_l in sensitive:
            return True
        for part in parts:
            if part in sensitive:
                return True
        for marker in ["password", "passwd", "access_token", "refresh_token", "client_secret", "session_cookie", "api_key", "apikey"]:
            if marker in compact:
                return True
        return False

    def _redacted_fixture_for_api(self, fixture):
        if not isinstance(fixture, dict):
            return {}
        redacted = {}
        for key, value in fixture.items():
            if self._fixture_secret_key(key):
                redacted[key] = "[redacted; keep secret in notes/vault/browser]"
            else:
                redacted[key] = value
        return redacted

    def _fixture_field_name(self, key):
        key_l = str(key or "").strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "accountnumber": "account_number",
            "account_no": "account_number",
            "account": "account_number",
            "acct": "account_number",
            "user": "username",
            "username": "username",
            "email": "email_hint",
            "mail": "email_hint",
            "phone": "phone_hint",
            "mobile": "phone_hint",
            "scope": "consent_scope",
            "fixture_scope": "consent_scope",
            "auth": "session_source",
            "browser": "browser_profile",
            "profile": "browser_profile",
            "session": "session_source",
            "mfa": "session_state"
        }
        return aliases.get(key_l, key_l)

    def _parse_fixture_key_values(self, text):
        fields = {}
        try:
            pattern = re.compile(r'(?i)([a-z][a-z0-9 _-]{1,28})\s*[:=]\s*([^,;]+?)(?=\s+[a-z][a-z0-9 _-]{1,28}\s*[:=]|[,;]|$)')
            for match in pattern.finditer(str(text or "")):
                raw_key = match.group(1).strip()
                value = match.group(2).strip().strip("\"'")
                if not raw_key or not value:
                    continue
                key = self._fixture_field_name(raw_key)
                if self._fixture_secret_key(raw_key):
                    fields[key] = "[redacted; keep secret in notes/vault/browser]"
                else:
                    fields[key] = self._safe_ascii_text(value, 500)
        except Exception:
            pass
        return fields

    def _infer_fixture_label_and_rest(self, line):
        text = str(line or "").strip()
        if not text:
            return "", ""
        match = re.match(r'^([A-Za-z][A-Za-z0-9 _.-]{0,40})\s*[:\-]\s*(.+)$', text)
        if not match:
            return "", text
        prefix = match.group(1).strip()
        rest = match.group(2).strip()
        field = self._fixture_field_name(prefix)
        known_fields = set([
            "role", "tenant", "brand", "account_number", "account_id", "user_id",
            "username", "email_hint", "phone_hint", "object_id", "object_ids",
            "session_state", "session_source", "browser_profile", "consent_scope",
            "notes"
        ])
        if field in known_fields or self._fixture_secret_key(prefix):
            return "", text
        if re.search(r'(?i)\b(role|tenant|account|accountnumber|account number|user|email|session|mfa|object|order|id|scope|consent)\b', rest):
            return prefix, rest
        return "", text

    def _infer_fixture_from_note_line(self, line, source, index):
        original = str(line or "").strip()
        if not original or original.startswith("#"):
            return None
        label, rest = self._infer_fixture_label_and_rest(original)
        fields = self._parse_fixture_key_values(rest)

        lower = original.lower()
        if not fields:
            account_match = re.search(r'(?i)\baccount\s*(?:number|no|#)?\s*[:=#]?\s*([A-Za-z0-9_-]{3,})', original)
            if account_match:
                fields["account_number"] = account_match.group(1)
            role_match = re.search(r'(?i)\brole\s*[:=]?\s*([A-Za-z0-9_.-]{2,})', original)
            if role_match:
                fields["role"] = role_match.group(1)
            tenant_match = re.search(r'(?i)\btenant\s*[:=]?\s*([A-Za-z0-9_.-]{2,})', original)
            if tenant_match:
                fields["tenant"] = tenant_match.group(1)

        object_ids = []
        try:
            for match in re.finditer(r'(?i)\b([a-z][a-z0-9_-]*(?:id|_id))\s*[:=]\s*([A-Za-z0-9_.:-]{3,})', original):
                key = self._fixture_field_name(match.group(1))
                value = match.group(2)
                if key in ("user_id", "account_id"):
                    fields[key] = value
                else:
                    object_ids.append({"name": key, "value": value})
        except Exception:
            pass
        if object_ids and "object_ids" not in fields:
            fields["object_ids"] = object_ids

        if not label:
            if "username" in fields:
                label = fields.get("username", "")
            elif "email_hint" in fields:
                label = fields.get("email_hint", "")
            elif "role" in fields and "tenant" in fields:
                label = "%s-%s" % (fields.get("tenant"), fields.get("role"))
            elif "account_number" in fields:
                label = "account-%s" % fields.get("account_number")
            elif object_ids:
                label = "object-%s" % object_ids[0].get("value", "")[:12]
        if not fields and not label:
            return None

        kind = "account"
        if "session_state" in fields or "session_source" in fields or "browser_profile" in fields or "pre-mfa" in lower or "post-mfa" in lower:
            kind = "session"
        elif object_ids and not any(k in fields for k in ("role", "tenant", "account_number", "username", "email_hint")):
            kind = "object"
        elif "tenant" in fields and "role" not in fields and "account_number" not in fields and not label.lower().startswith("user"):
            kind = "tenant"

        if "pre-mfa" in lower or "pre_mfa" in lower:
            fields["session_state"] = "pre_mfa"
        elif "post-mfa" in lower or "post_mfa" in lower:
            fields["session_state"] = "post_mfa"
        elif "revoked" in lower:
            fields["session_state"] = "revoked"
        elif "expired" in lower:
            fields["session_state"] = "expired"

        fixture = {
            "kind": kind,
            "label": self._safe_ascii_text(label or "%s-note-%d" % (kind, index), 120),
            "source": self._safe_ascii_text(source, 120),
            "notes": self._safe_ascii_text(original, 1000)
        }
        fixture.update(fields)
        return fixture

    def _normalize_imported_fixture(self, fixture):
        if not isinstance(fixture, dict):
            fixture = {}
        kind = str(fixture.get("kind", "account") or "account").strip().lower().replace("-", "_").replace(" ", "_")
        if kind not in ("account", "session", "object", "tenant", "flow_state"):
            kind = "account"
        label = str(fixture.get("label", "") or "").strip()
        if not label:
            label = "%s-%s" % (kind, uuid.uuid4().hex[:8])
        fid = str(fixture.get("id", "") or "").strip()
        if not fid:
            fid = "%s:%s" % (kind, re.sub(r"[^a-zA-Z0-9_.:-]+", "_", label.lower())[:80])
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = {}
        for key, value in fixture.items():
            if self._fixture_secret_key(key):
                clean[key] = "[redacted; keep secret in notes/vault/browser]"
            else:
                clean[key] = value
        clean["id"] = fid
        clean["kind"] = kind
        clean["label"] = label
        engagement = self._active_engagement_context()
        clean["engagement_id"] = str(fixture.get("engagement_id", "") or engagement.get("id", ""))
        clean["engagement_authorities"] = list(fixture.get("engagement_authorities", []) or engagement.get("authorities", []))
        clean.setdefault("created_at", now)
        clean["updated_at"] = now
        return clean

    def _upsert_imported_fixture(self, fixture):
        fixture = self._normalize_imported_fixture(fixture)
        updated = False
        with self.fixture_lock:
            fixtures = getattr(self, "test_fixtures", []) or []
            for idx, existing in enumerate(fixtures):
                if existing.get("id") == fixture.get("id") and self._engagement_bound_record_is_current(existing):
                    created = existing.get("created_at", fixture.get("created_at", ""))
                    merged = dict(existing)
                    merged.update(fixture)
                    if created:
                        merged["created_at"] = created
                    fixtures[idx] = merged
                    fixture = merged
                    updated = True
                    break
            if not updated:
                fixtures.append(fixture)
            self.test_fixtures = fixtures
        return fixture, updated

    def _import_fixtures_from_notes(self, notes, source="notes"):
        imported = []
        ignored = []
        warnings = []
        profile_result = self._import_project_profile_from_notes(notes, source, persist=False)
        knowledge_result = self._upsert_knowledge_entries(self._knowledge_entries_from_notes(notes, source), source, persist=False)
        lines = str(notes or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for idx, line in enumerate(lines, 1):
            fixture = self._infer_fixture_from_note_line(line, source, idx)
            if fixture is None:
                if line.strip():
                    ignored.append(self._safe_ascii_text(line.strip(), 200))
                continue
            imported.append(fixture)

        if not imported:
            warnings.append("No structured account/session/object fixture lines were detected.")

        results = []
        created = 0
        updated = 0
        for fixture in imported:
            saved, was_updated = self._upsert_imported_fixture(fixture)
            results.append(saved)
            if was_updated:
                updated += 1
            else:
                created += 1

        if results or knowledge_result.get("created") or knowledge_result.get("updated"):
            self.save_findings()
            self._ui_dirty = True
            self.stdout.println("[FIXTURES] Imported %d fixture(s) from %s (%d created, %d updated)" % (
                len(results), self._safe_ascii_text(source, 80), created, updated))
            try:
                self.refreshUI()
            except Exception:
                pass

        return {
            "status": "imported",
            "created": created,
            "updated": updated,
            "fixtures": results,
            "project_profile": profile_result.get("project_profile", {}),
            "project_profile_changes": profile_result.get("changes", {}),
            "knowledge": knowledge_result,
            "ignored_lines": ignored[:25],
            "warnings": warnings
        }

    def _project_profile_default(self):
        return {
            "in_scope_hosts": [],
            "in_scope_paths": [],
            "allowed_state_changes": [],
            "auth_schemes": {},
            "roles": [],
            "notes": "",
            "sources": [],
            "updated_at": ""
        }

    def _merge_unique_list(self, current, incoming):
        result = []
        seen = set()
        for item in list(current or []) + list(incoming or []):
            if item is None:
                continue
            if isinstance(item, dict):
                key = json.dumps(item, sort_keys=True)
                value = dict(item)
            else:
                value = str(item).strip()
                key = value.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(value)
        return result

    def _merge_project_profile(self, incoming, source="api"):
        if not isinstance(incoming, dict):
            incoming = {}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.fixture_lock:
            profile = self._project_profile_default()
            existing_profile = dict(getattr(self, "project_profile", {}) or {})
            if self._engagement_bound_record_is_current(existing_profile):
                profile.update(existing_profile)
            engagement = self._active_engagement_context()
            profile["engagement_id"] = engagement.get("id", "")
            profile["engagement_authorities"] = list(engagement.get("authorities", []))
            for key in ["in_scope_hosts", "in_scope_paths", "allowed_state_changes", "roles", "sources"]:
                profile[key] = self._merge_unique_list(profile.get(key, []), incoming.get(key, []))
            auth_schemes = dict(profile.get("auth_schemes", {}) or {})
            for host, model in (incoming.get("auth_schemes", {}) or {}).items():
                host_l = str(host or "").strip().lower()
                if not host_l or not isinstance(model, dict):
                    continue
                existing = dict(auth_schemes.get(host_l, {}) or {})
                existing["headers"] = self._merge_unique_list(existing.get("headers", []), model.get("headers", []))
                existing["cookies"] = self._merge_unique_list(existing.get("cookies", []), model.get("cookies", []))
                existing["sources"] = self._merge_unique_list(existing.get("sources", []), model.get("sources", []))
                existing["updated_at"] = now
                auth_schemes[host_l] = existing
            profile["auth_schemes"] = auth_schemes
            if incoming.get("notes"):
                existing_notes = str(profile.get("notes", "") or "")
                note = self._safe_ascii_text(incoming.get("notes", ""), 4000)
                if note and note not in existing_notes:
                    profile["notes"] = (existing_notes + "\n" + note).strip() if existing_notes else note
            profile["sources"] = self._merge_unique_list(profile.get("sources", []), [source])
            profile["updated_at"] = now
            self.project_profile = profile
            self.host_auth_models = dict(getattr(self, "host_auth_models", {}) or {})
            for host, model in auth_schemes.items():
                current = dict(self.host_auth_models.get(host, {}) or {})
                current["headers"] = self._merge_unique_list(current.get("headers", []), model.get("headers", []))
                current["cookies"] = self._merge_unique_list(current.get("cookies", []), model.get("cookies", []))
                current["sources"] = self._merge_unique_list(current.get("sources", []), model.get("sources", []))
                current["updated_at"] = now
                self.host_auth_models[host] = current
        return profile

    def _normalize_attack_surface_doc(self, doc):
        doc = doc if isinstance(doc, dict) else {}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entries = []
        by_key = {}
        next_id = 1
        for raw_entry in doc.get("entries", []) or []:
            if not isinstance(raw_entry, dict):
                continue
            try:
                entry = normalize_attack_surface_entry(raw_entry, now=raw_entry.get("updated_at", now))
            except Exception:
                continue
            existing_index = by_key.get(entry.get("key"))
            if existing_index is not None:
                entries[existing_index] = merge_attack_surface_entries(entries[existing_index], entry, now=entry.get("updated_at", now))
                continue
            try:
                entry_id = int(raw_entry.get("id", next_id) or next_id)
            except Exception:
                entry_id = next_id
            entry["id"] = entry_id
            next_id = max(next_id, entry_id + 1)
            by_key[entry.get("key")] = len(entries)
            entries.append(entry)
        try:
            next_id = max(next_id, int(doc.get("next_id", next_id) or next_id))
        except Exception:
            pass
        reviews = [dict(review) for review in (doc.get("reviews", []) or []) if isinstance(review, dict)][-200:]
        return {
            "entries": entries[-5000:],
            "reviews": reviews,
            "next_id": next_id,
            "updated_at": str(doc.get("updated_at", "") or ""),
        }

    def _assessment_knowledge_default(self):
        return {
            "entries": [],
            "sources": [],
            "updated_at": ""
        }

    def _normalize_knowledge_category(self, value):
        category = str(value or "note").strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "endpoint_note": "endpoint",
            "auth_model": "auth",
            "business_logic": "business_rule",
            "idea": "lead",
            "hypothesis": "lead",
            "control": "tested_control",
            "defense": "tested_control",
            "gap": "risk",
            "block": "blocker"
        }
        category = aliases.get(category, category)
        valid = set(["note", "endpoint", "auth", "business_rule", "object_model", "lead",
                     "assumption", "tested_control", "blocker", "chain_idea", "risk", "other"])
        return category if category in valid else "other"

    def _normalize_knowledge_status(self, value):
        status = str(value or "open").strip().lower().replace("-", "_").replace(" ", "_")
        valid = set(["open", "active", "tested", "confirmed", "not_vulnerable",
                     "blocked", "superseded", "archived", "needs_review"])
        return status if status in valid else "open"

    def _redact_sensitive_note_text(self, text):
        text = self._safe_ascii_text(text, 12000)
        patterns = [
            r'(?i)\b(password|passwd|pass|secret|client_secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|cookie|session[_ -]?cookie|otp|mfa[_ -]?code)\s*[:=]\s*([^\s,;]+)',
            r'(?i)\b(Bearer)\s+([A-Za-z0-9._~+/=-]{12,})',
            r'(?i)\b(Set-Cookie|Cookie)\s*:\s*([^\n\r]+)'
        ]
        for pattern in patterns:
            try:
                text = re.sub(pattern, lambda m: "%s=[redacted]" % m.group(1), text)
            except Exception:
                pass
        return text

    def _knowledge_entry_hash(self, entry):
        basis = {
            "category": entry.get("category", ""),
            "title": entry.get("title", ""),
            "detail": entry.get("detail", ""),
            "source": entry.get("source", ""),
            "engagement_id": entry.get("engagement_id", "")
        }
        try:
            raw = json.dumps(basis, sort_keys=True, ensure_ascii=True)
        except Exception:
            raw = str(basis)
        try:
            return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]
        except Exception:
            return hashlib.md5(str(raw)).hexdigest()[:16]

    def _normalize_knowledge_entry(self, entry, source="api"):
        if not isinstance(entry, dict):
            entry = {}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        category = self._normalize_knowledge_category(entry.get("category", entry.get("kind", "note")))
        detail = entry.get("detail", entry.get("notes", entry.get("text", "")))
        detail = self._redact_sensitive_note_text(detail)
        title = self._safe_ascii_text(entry.get("title", entry.get("label", "")), 160).strip()
        if not title:
            title = detail.strip().split("\n")[0][:120] if detail.strip() else "Assessment note"
        tags = []
        raw_tags = entry.get("tags", [])
        if isinstance(raw_tags, basestring):
            raw_tags = re.split(r'[, ]+', raw_tags)
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                tag = str(tag or "").strip().lower().replace(" ", "_")
                if tag and tag not in tags:
                    tags.append(tag[:50])
        clean = {
            "category": category,
            "title": self._safe_ascii_text(title, 160),
            "detail": self._safe_ascii_text(detail, 8000),
            "tags": tags[:20],
            "status": self._normalize_knowledge_status(entry.get("status", "open")),
            "confidence": self._safe_ascii_text(entry.get("confidence", "observed"), 80),
            "source": self._safe_ascii_text(entry.get("source", source), 120),
            "created_at": self._safe_ascii_text(entry.get("created_at", now), 80),
            "updated_at": now
        }
        clean["engagement_id"] = self._safe_ascii_text(entry.get("engagement_id", ""), 120)
        clean["engagement_authorities"] = [self._safe_ascii_text(value, 300)
                                             for value in entry.get("engagement_authorities", []) or []]
        for key in ["host", "path", "method", "finding_id", "queue_id", "evidence_ref", "next_step"]:
            if entry.get(key) not in (None, ""):
                clean[key] = self._safe_ascii_text(entry.get(key), 500)
        entry_id = str(entry.get("id", "") or "").strip()
        if not entry_id:
            entry_id = "knowledge:%s" % self._knowledge_entry_hash(clean)
        clean["id"] = self._safe_ascii_text(entry_id, 120)
        return clean

    def _normalize_assessment_knowledge_doc(self, doc):
        if isinstance(doc, list):
            doc = {"entries": doc}
        if not isinstance(doc, dict):
            doc = {}
        knowledge = self._assessment_knowledge_default()
        knowledge["sources"] = self._merge_unique_list([], doc.get("sources", []))
        knowledge["updated_at"] = self._safe_ascii_text(doc.get("updated_at", ""), 80)
        entries = []
        seen = set()
        for entry in doc.get("entries", []) or []:
            normalized = self._normalize_knowledge_entry(entry, entry.get("source", "loaded") if isinstance(entry, dict) else "loaded")
            eid = normalized.get("id")
            if eid in seen:
                continue
            seen.add(eid)
            entries.append(normalized)
        knowledge["entries"] = entries[-1000:]
        return knowledge

    def _knowledge_entries_from_notes(self, notes, source="notes"):
        text = self._redact_sensitive_note_text(notes)
        if not text.strip():
            return []
        first = ""
        for line in text.split("\n"):
            if line.strip():
                first = line.strip()
                break
        if not first:
            first = "Context update"
        entry = {
            "category": "note",
            "title": first[:120],
            "detail": text,
            "tags": ["context_update"],
            "status": "open",
            "confidence": "user_provided",
            "source": source
        }
        engagement = self._active_engagement_context()
        entry["engagement_id"] = engagement.get("id", "")
        entry["engagement_authorities"] = list(engagement.get("authorities", []))
        entry["id"] = "knowledge:%s" % self._knowledge_entry_hash(entry)
        return [entry]

    def _upsert_knowledge_entries(self, entries, source="api", persist=True):
        if not isinstance(entries, list):
            entries = [entries]
        normalized_entries = []
        engagement = self._active_engagement_context()
        for entry in entries:
            if isinstance(entry, dict):
                bound_entry = dict(entry)
                bound_entry.setdefault("engagement_id", engagement.get("id", ""))
                bound_entry.setdefault("engagement_authorities", list(engagement.get("authorities", [])))
                normalized_entries.append(self._normalize_knowledge_entry(bound_entry, source))

        created = 0
        updated = 0
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.fixture_lock:
            knowledge = self._normalize_assessment_knowledge_doc(getattr(self, "assessment_knowledge", {}) or {})
            existing = {}
            ordered = []
            for entry in knowledge.get("entries", []) or []:
                existing[entry.get("id")] = entry
                ordered.append(entry.get("id"))
            for entry in normalized_entries:
                eid = entry.get("id")
                if not eid:
                    continue
                if eid in existing:
                    previous = existing[eid]
                    merged = dict(previous)
                    created_at = previous.get("created_at", entry.get("created_at", now))
                    merged.update(entry)
                    merged["created_at"] = created_at
                    merged["updated_at"] = now
                    existing[eid] = merged
                    updated += 1
                else:
                    existing[eid] = entry
                    ordered.append(eid)
                    created += 1
            final_entries = []
            seen = set()
            for eid in ordered:
                if eid in seen or eid not in existing:
                    continue
                seen.add(eid)
                final_entries.append(existing[eid])
            knowledge["entries"] = final_entries[-1000:]
            knowledge["sources"] = self._merge_unique_list(knowledge.get("sources", []), [source])
            knowledge["updated_at"] = now
            self.assessment_knowledge = knowledge

        if persist:
            self.save_findings()
            self._ui_dirty = True
        return {
            "status": "updated",
            "created": created,
            "updated": updated,
            "entries": normalized_entries,
            "knowledge": self.assessment_knowledge
        }

    def _import_project_profile_from_notes(self, notes, source="notes", persist=True):
        text = str(notes or "")
        hosts = []
        paths = []
        roles = []
        allowed = []
        auth_schemes = {}

        for host in self._extract_scope_hosts(text):
            hosts.append(host)
        for match in re.finditer(r'(?i)\b(?:path|endpoint|scope path|allowed path)\s*[:=]\s*([/][^\s,;]+)', text):
            paths.append(match.group(1).strip())
        for match in re.finditer(r'(?i)\brole\s*[:=]\s*([A-Za-z0-9_.-]+)', text):
            roles.append(match.group(1).strip())
        for match in re.finditer(r'(?i)\b(?:allowed|safe|ok)\s+(?:state[- ]changing|mutation|action|submit|write)\s*[:=]?\s*([^\n\r]+)', text):
            desc = self._safe_ascii_text(match.group(1).strip(), 300)
            allowed.append({"description": desc})

        auth_headers = []
        auth_cookies = []
        for match in re.finditer(r'(?i)\b(?:auth|authentication|session|member|api)\s*(?:header|token header|headers?)\s*[:=]\s*([A-Za-z0-9_, Xx.-]+)', text):
            for part in re.split(r'[, ]+', match.group(1)):
                part = part.strip()
                if part and len(part) > 2 and part.lower() not in ("and", "or"):
                    auth_headers.append(part)
        for match in re.finditer(r'(?i)\b(?:auth|authentication|session)\s*cookie\s*[:=]\s*([A-Za-z0-9_, .-]+)', text):
            for part in re.split(r'[, ]+', match.group(1)):
                part = part.strip()
                if part and len(part) > 2 and part.lower() not in ("and", "or"):
                    auth_cookies.append(part)

        auth_hosts = hosts or ["*"]
        if auth_headers or auth_cookies:
            for host in auth_hosts:
                auth_schemes[str(host).lower()] = {
                    "headers": auth_headers,
                    "cookies": auth_cookies,
                    "sources": [source]
                }

        incoming = {
            "in_scope_hosts": hosts,
            "in_scope_paths": paths,
            "allowed_state_changes": allowed,
            "auth_schemes": auth_schemes,
            "roles": roles,
            "notes": self._safe_ascii_text(text, 4000)
        }
        profile = self._merge_project_profile(incoming, source)
        knowledge_result = {}
        if persist:
            knowledge_result = self._upsert_knowledge_entries(self._knowledge_entries_from_notes(notes, source), source, persist=False)
        if persist:
            self.save_findings()
            self._ui_dirty = True
        return {
            "status": "imported",
            "changes": incoming,
            "project_profile": profile,
            "knowledge": knowledge_result
        }

    def _normalize_project_workspace_dir(self, path):
        try:
            path = str(path or "").strip()
            if not path:
                return ""
            resolved = os.path.abspath(os.path.expanduser(path))
            if self._unsafe_persistence_directory(resolved):
                return ""
            if not os.path.isdir(resolved):
                os.makedirs(resolved)
            if not os.access(resolved, os.W_OK):
                return ""
            return resolved
        except Exception:
            pass
        return ""

    def _project_workspace_prompt_start_dir(self):
        try:
            for candidate in [
                getattr(self, "PROJECT_WORKSPACE_DIR", ""),
                getattr(self, "PROJECT_ROOT_DIR", ""),
                os.path.expanduser("~")
            ]:
                try:
                    candidate = os.path.abspath(os.path.expanduser(str(candidate or "")))
                    if candidate and os.path.isdir(candidate) and not self._unsafe_persistence_directory(candidate):
                        return candidate
                except Exception:
                    continue
        except Exception:
            pass
        return os.path.expanduser("~")

    def _prompt_for_project_workspace_directory_on_load(self):
        """Ask which assessment folder should own this extension session."""
        try:
            from javax.swing import JFileChooser, JOptionPane
            start_dir = self._project_workspace_prompt_start_dir()
            chooser = JFileChooser(start_dir)
            chooser.setDialogTitle("Choose Double Agent Project Folder")
            chooser.setApproveButtonText("Use This Folder")
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setAcceptAllFileFilterUsed(False)
            result = chooser.showOpenDialog(None)
            if result == JFileChooser.APPROVE_OPTION:
                selected = chooser.getSelectedFile()
                if selected is not None:
                    resolved = self._normalize_project_workspace_dir(selected.getAbsolutePath())
                    if resolved:
                        self.PROJECT_WORKSPACE_DIR = resolved
                        self.save_config()
                        self.stdout.println("[PERSIST] Project folder selected: %s" % resolved)
                        return True
                    JOptionPane.showMessageDialog(
                        None,
                        "Double Agent cannot write to the selected folder.",
                        "Project Folder Not Writable",
                        JOptionPane.WARNING_MESSAGE
                    )

            fallback = self._normalize_project_workspace_dir(getattr(self, "PROJECT_WORKSPACE_DIR", ""))
            if fallback:
                self.PROJECT_WORKSPACE_DIR = fallback
                self.stdout.println("[PERSIST] Project folder prompt cancelled; using configured folder: %s" % fallback)
                return False

            fallback = self._normalize_project_workspace_dir(os.path.join(os.path.expanduser("~"), ".double-agent"))
            if fallback:
                self.PROJECT_WORKSPACE_DIR = fallback
                self.save_config()
                self.stdout.println("[PERSIST] Project folder prompt cancelled; using fallback folder: %s" % fallback)
                return False
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] Project folder prompt failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
        return False
