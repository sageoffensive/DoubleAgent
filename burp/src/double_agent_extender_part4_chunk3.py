# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk4Chunk3(object):
    def _normalized_url_path(self, url):
        try:
            try:
                from urlparse import urlparse as _urlparse
            except ImportError:
                from urllib.parse import urlparse as _urlparse
            path = _urlparse(str(url or "")).path or "/"
        except:
            path = "/"
        parts = []
        for part in path.split("/"):
            if not part:
                continue
            lower = part.lower()
            if re.match(r'^\d+$', lower):
                parts.append("{id}")
            elif re.match(r'^[0-9a-f]{8,}$', lower):
                parts.append("{hex}")
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', lower):
                parts.append("{uuid}")
            else:
                parts.append(re.sub(r'[^a-z0-9._~-]+', "_", lower))
        return "/" + "/".join(parts)

    def _method_from_request_data(self, request_data, default_method=""):
        try:
            first = str(request_data or "").split("\n", 1)[0].strip()
            method = first.split(" ", 1)[0].upper()
            if method and method.isalpha() and len(method) <= 12:
                return method
        except:
            pass
        return default_method or ""

    def _fingerprint_location(self, url, title="", detail="", evidence="", request_data=None):
        text = " ".join([str(title or ""), str(detail or ""), str(evidence or "")]).lower()
        if ("jwt" in text or "bearer token" in text or "access token" in text) and (" exp" in text or "expiration" in text or "expires" in text):
            return "jwt:exp"
        if ("jwt" in text or "bearer token" in text or "access token" in text) and ("nbf" in text or "iat" in text):
            return "jwt:nbf_iat"
        for label in ["header", "parameter", "param", "cookie"]:
            m = re.search(r'\b%s\s+[\'"`]?([a-z0-9_.:-]{2,80})' % label, text)
            if m:
                loc_label = "parameter" if label == "param" else label
                return "%s:%s" % (loc_label, m.group(1).lower())

        known_headers = [
            "access-control-allow-origin", "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
            "set-cookie", "authorization", "location"
        ]
        for header in known_headers:
            if header in text:
                return "header:%s" % header

        try:
            try:
                from urlparse import urlparse as _urlparse, parse_qsl as _parse_qsl
            except ImportError:
                from urllib.parse import urlparse as _urlparse, parse_qsl as _parse_qsl
            parsed = _urlparse(str(url or ""))
            params = [name.lower() for name, value in _parse_qsl(parsed.query, keep_blank_values=True) if name]
            if params:
                return "parameter:%s" % sorted(params)[0]
        except:
            pass

        try:
            body = str(request_data or "").split("\r\n\r\n", 1)
            if len(body) == 2 and body[1].strip():
                return "body"
        except:
            pass
        return "endpoint"

    def _finding_fingerprint(self, url, title, cwe="", detail="", evidence="", request_data=None, source=""):
        family = self._canonical_finding_family(title, cwe, detail, evidence)
        if not family:
            return None
        host = self._url_host(url)
        path = self._normalized_url_path(url)
        method = self._method_from_request_data(request_data, "")
        location = self._fingerprint_location(url, title, detail, evidence, request_data)
        global_families = set([
            "missing_csp", "missing_hsts", "x_frame_options", "x_content_type_options",
            "referrer_policy", "permissions_policy", "cors", "jwt_expiration", "jwt_claim_ordering"
        ])
        if family in global_families:
            method = "*"
            path = "/*"
        return "finding|%s|%s|%s|%s|%s" % (family, host, method or "*", path, location or "endpoint")

    def _is_scanner_finding(self, title, source=""):
        return str(source or "") == "burp_scanner" or str(title or "").lower().startswith("(burp scanner)")

    def _scanner_dedupe_key(self, url, title, source=""):
        if not self._is_scanner_finding(title, source):
            return None
        canon_title = self._canonical_scanner_title(title)
        if not canon_title:
            return None
        # Configuration-style scanner findings create lots of endpoint-level
        # duplicates. Keep one row and let details/triage explain affected area.
        global_issue_titles = set([
            "cross origin resource sharing",
            "strict transport security not enforced",
            "strict transport security disabled",
            "content security policy not enforced",
            "x frame options header not set",
            "x content type options header missing",
        ])
        if canon_title in global_issue_titles:
            return "scanner:global:%s" % canon_title
        host = self._url_host(url)
        return "scanner:%s:%s" % (host, canon_title)

    def _find_duplicate_finding(self, url, title, cwe, source="", detail="", evidence="", request_data=None):
        """Return existing duplicate finding and reason, if one is already present."""
        fingerprint = self._finding_fingerprint(url, title, cwe, detail, evidence, request_data, source)
        if fingerprint:
            for existing in self.findings_list:
                existing_fp = existing.get("finding_fingerprint") or self._finding_fingerprint(
                    existing.get("url", ""), existing.get("title", ""), existing.get("cwe", ""),
                    existing.get("detail", ""), existing.get("evidence", ""), existing.get("request_data"),
                    existing.get("source", ""))
                if existing_fp == fingerprint:
                    return existing, "fingerprint"

        scanner_key = self._scanner_dedupe_key(url, title, source)
        if scanner_key:
            for existing in self.findings_list:
                if self._scanner_dedupe_key(existing.get("url", ""), existing.get("title", ""), existing.get("source", "")) == scanner_key:
                    return existing, "scanner"

        new_key = self._normalize_finding_key(title)
        if not new_key:
            return None, ""

        for existing in self.findings_list:
            if existing.get("url") != url:
                continue

            # Exact CWE match on same URL is a duplicate
            if cwe and existing.get("cwe") and str(cwe) == str(existing.get("cwe")):
                return existing, "cwe"

            existing_key = self._normalize_finding_key(existing.get("title", ""))
            if not existing_key:
                continue

            # Calculate word overlap ratio
            overlap = len(new_key & existing_key)
            smaller = min(len(new_key), len(existing_key))
            if smaller > 0 and float(overlap) / smaller >= 0.6:
                return existing, "title_overlap"

        return None, ""

    def _is_duplicate_finding(self, url, title, cwe, source="", detail="", evidence="", request_data=None):
        existing, reason = self._find_duplicate_finding(url, title, cwe, source, detail, evidence, request_data)
        return existing is not None

    def _merge_duplicate_finding(self, existing, url, title, detail="", evidence="", reason=""):
        if not existing:
            return
        duplicate_url = str(url or "")
        if duplicate_url and duplicate_url != existing.get("url", ""):
            urls = existing.setdefault("duplicate_urls", [])
            if duplicate_url not in urls:
                urls.append(duplicate_url)
        duplicate_title = str(title or "")
        if duplicate_title and duplicate_title != existing.get("title", ""):
            titles = existing.setdefault("duplicate_titles", [])
            if duplicate_title not in titles:
                titles.append(duplicate_title[:200])
        if evidence:
            variants = existing.setdefault("evidence_variants", [])
            evidence_short = str(evidence)[:500]
            if evidence_short and evidence_short not in variants:
                variants.append(evidence_short)
                if len(variants) > 10:
                    del variants[:-10]
        existing["duplicate_count"] = int(existing.get("duplicate_count", 0) or 0) + 1
        existing["last_duplicate_reason"] = reason or "duplicate"
        self._record_finding_audit(existing, "deduplication_match", {
            "reason": reason or "duplicate",
            "submitted_url": str(url or "")[:500],
            "submitted_title": str(title or "")[:300],
        }, actor="deduplicator", bump_version=True)

    def _dedupe_existing_findings(self):
        """Collapse existing repeated findings after loading persisted state."""
        seen = {}
        deduped = []
        removed = 0
        for finding in self.findings_list:
            key = self._finding_fingerprint(
                finding.get("url", ""), finding.get("title", ""), finding.get("cwe", ""),
                finding.get("detail", ""), finding.get("evidence", ""), finding.get("request_data"),
                finding.get("source", ""))
            if key:
                finding["finding_fingerprint"] = key
                finding["canonical_family"] = key.split("|")[1] if "|" in key else ""
                finding["fingerprint_location"] = key.split("|")[-1] if "|" in key else ""
            if not key:
                key = self._scanner_dedupe_key(finding.get("url", ""), finding.get("title", ""), finding.get("source", ""))
            if key and key in seen:
                primary = seen[key]
                self._merge_duplicate_finding(primary, finding.get("url", ""), finding.get("title", ""),
                                              finding.get("detail", ""), finding.get("evidence", ""), "load_dedupe")
                removed += 1
                continue
            if key:
                seen[key] = finding
            deduped.append(finding)
        if removed:
            self.findings_list = deduped
        return removed

    def _agent_status_value(self, value):
        return str(value or "untouched").strip().lower().replace(" ", "_").replace("-", "_")

    def _ensure_finding_stable_id(self, finding):
        if not isinstance(finding, dict):
            return ""
        stable_id = str(finding.get("stable_id", "") or "").strip()
        if not stable_id:
            stable_id = "daf_" + uuid.uuid4().hex
            finding["stable_id"] = stable_id
        try:
            finding["version"] = max(1, int(finding.get("version", 1) or 1))
        except Exception:
            finding["version"] = 1
        if not isinstance(finding.get("audit_log", []), list):
            finding["audit_log"] = []
        return stable_id

    def _ensure_finding_legacy_numeric_id(self, finding, preferred=None):
        """Assign a permanent compatibility ID without using the list index."""
        if not isinstance(finding, dict):
            return None
        try:
            existing = int(finding.get("legacy_numeric_id", 0) or 0)
            if existing > 0:
                return existing
        except Exception:
            pass
        used = set()
        for candidate in getattr(self, "findings_list", []) or []:
            if candidate is finding:
                continue
            try:
                value = int(candidate.get("legacy_numeric_id", 0) or 0)
                if value > 0:
                    used.add(value)
            except Exception:
                continue
        for event in getattr(self, "finding_audit_log", []) or []:
            try:
                value = int(event.get("legacy_numeric_id", 0) or 0)
                if value > 0:
                    used.add(value)
            except Exception:
                continue
        try:
            selected = int(preferred or 0)
        except Exception:
            selected = 0
        if selected <= 0 or selected in used:
            selected = (max(used) + 1) if used else 1
            while selected in used:
                selected += 1
        finding["legacy_numeric_id"] = selected
        return selected

    def _record_finding_audit(self, finding, action, detail=None, actor="double_agent", bump_version=False):
        if not isinstance(finding, dict):
            return
        self._ensure_finding_stable_id(finding)
        if bump_version:
            finding["version"] = int(finding.get("version", 1) or 1) + 1
        entry = {
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": str(action or "updated"),
            "actor": str(actor or "double_agent"),
            "version": int(finding.get("version", 1) or 1),
            "detail": self._safe_ascii_text(detail or {}, 2000),
        }
        audit = list(finding.get("audit_log", []) or [])
        audit.append(entry)
        finding["audit_log"] = audit[-100:]

    def _finding_index_by_reference(self, reference):
        with self.findings_lock_ui:
            return self._finding_index_by_reference_unlocked(reference)

    def _finding_index_by_reference_unlocked(self, reference):
        reference_s = str(reference or "").strip()
        if not reference_s:
            return None
        for idx, finding in enumerate(self.findings_list):
            if str(finding.get("stable_id", "") or "") == reference_s:
                return idx
        try:
            numeric = int(reference_s)
            for idx, finding in enumerate(self.findings_list):
                if self._ensure_finding_legacy_numeric_id(finding, idx + 1) == numeric:
                    return idx
        except Exception:
            pass
        return None

    def _finding_hidden_from_normal_view(self, finding):
        return bool(finding.get("fp", False)) or self._agent_status_value(
            finding.get("agent_status", "")) == "false_positive"

    def _prune_already_covered_findings(self):
        """Remove findings already covered by completed work from the active list."""
        kept = []
        deleted_indices = []
        for idx, finding in enumerate(self.findings_list):
            if self._agent_status_value(finding.get("agent_status", "")) == "already_covered":
                deleted_indices.append(idx)
                continue
            kept.append(finding)
        if deleted_indices:
            self.findings_list = kept
        return deleted_indices

    def _remap_finding_ids_after_deleted_indices(self, old_ids, deleted_indices):
        deleted_sorted = sorted(set([int(i) for i in deleted_indices]), reverse=True)
        new_ids = []
        for fid in old_ids or []:
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
        return new_ids

    def _recipe_text_value(self, recipe, fallback, names, limit=600):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                value = source.get(name, None)
                if value is None:
                    continue
                text = self._safe_ascii_text(value, limit).strip()
                if text:
                    return text
        return ""

    def _recipe_bool_value(self, recipe, fallback, names, default=False):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                if name not in source:
                    continue
                value = source.get(name)
                if isinstance(value, bool):
                    return bool(value)
                text = str(value or "").strip().lower()
                if text in ("1", "true", "yes", "y", "required", "needs_second_user"):
                    return True
                if text in ("0", "false", "no", "n", "none", "not_required"):
                    return False
        return bool(default)

    def _recipe_int_value(self, recipe, fallback, names, default=2, minimum=1, maximum=10):
        for source in (recipe, fallback):
            if not isinstance(source, dict):
                continue
            for name in names:
                if name not in source:
                    continue
                try:
                    value = int(source.get(name))
                    if value < minimum:
                        value = minimum
                    if value > maximum:
                        value = maximum
                    return value
                except:
                    pass
        return int(default)

    def _infer_active_test_type(self, title, cwe, detail):
        text = ("%s %s %s" % (title or "", cwe or "", detail or "")).lower()
        if "idor" in text or "authorization" in text or "access control" in text or "privilege" in text:
            return "authorization"
        if "auth bypass" in text or "authentication bypass" in text or "missing auth" in text:
            return "authentication"
        if "ssrf" in text or "server-side request forgery" in text:
            return "ssrf"
        if "sql" in text or "injection" in text or "sqli" in text:
            return "injection"
        if "xss" in text or "cross-site scripting" in text:
            return "xss"
        if "csrf" in text:
            return "csrf"
        if "race" in text or "business logic" in text or "workflow" in text:
            return "business_logic"
        if "token" in text or "jwt" in text or "session" in text:
            return "token_or_session"
        return "focused_validation"
