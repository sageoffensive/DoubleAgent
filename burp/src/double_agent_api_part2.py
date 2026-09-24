# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk2(object):
    def _host_related_suffix(self, host):
        parts = [p for p in str(host or "").lower().split(".") if p]
        if len(parts) < 3:
            return str(host or "").lower()
        host_l = ".".join(parts)
        if host_l.endswith(".nsw.gov.au") and len(parts) >= 5:
            return ".".join(parts[-5:])
        if host_l.endswith(".gov.au") and len(parts) >= 4:
            return ".".join(parts[-4:])
        if (host_l.endswith(".com.au") or host_l.endswith(".net.au") or
                host_l.endswith(".org.au") or host_l.endswith(".edu.au")) and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-3:])

    def _host_matches_auth_scope(self, entry_host, host_filter, related_suffix, include_related):
        entry_host = str(entry_host or "").lower()
        host_filter = str(host_filter or "").lower()
        if entry_host == host_filter or entry_host.endswith("." + host_filter):
            return "exact"
        if include_related and related_suffix:
            if entry_host == related_suffix or entry_host.endswith("." + related_suffix):
                return "related"
        return ""

    def _get_latest_auth_payload(self, host_filter, path_contains="", include_related=True, limit=50):
        host_filter = str(host_filter or "").strip().lower()
        if not host_filter:
            return 400, {"error": "host query parameter is required"}

        path_contains = str(path_contains or "").strip()
        related_suffix = self._host_related_suffix(host_filter) if include_related else ""
        if limit < 1:
            limit = 1
        if limit > 250:
            limit = 250

        try:
            history = self.extender.callbacks.getProxyHistory()
        except Exception as e:
            return 500, {"error": "failed to read proxy history", "message": str(e)}

        credentials = []
        searched = 0
        helpers = self.extender.helpers

        for index in range(len(history) - 1, -1, -1):
            if searched >= limit:
                break
            try:
                entry = history[index]
                service = entry.getHttpService()
                if not service:
                    continue
                entry_host = str(service.getHost()).lower()
                match_mode = self._host_matches_auth_scope(entry_host, host_filter, related_suffix, include_related)
                if not match_mode:
                    continue

                req_info = helpers.analyzeRequest(entry)
                url = str(req_info.getUrl())
                if path_contains and match_mode == "exact" and path_contains not in url:
                    continue

                searched += 1
                req_headers = [str(h) for h in req_info.getHeaders()]
                request_cookies = self._extract_cookie_pairs(self._header_value(req_headers, "Cookie"))
                request_auth = {
                    "headers": self._extract_auth_headers(req_headers),
                    "cookies": request_cookies,
                    "cookie_header": self._cookie_header_from_pairs(request_cookies)
                }

                response_auth = {"set_cookies": [], "set_cookie_header": ""}
                response_bytes = entry.getResponse()
                if response_bytes is not None:
                    try:
                        res_info = helpers.analyzeResponse(response_bytes)
                        res_headers = [str(h) for h in res_info.getHeaders()]
                        response_auth["set_cookies"] = self._extract_set_cookies(res_headers)
                        response_auth["set_cookie_header"] = self._cookie_header_from_pairs(response_auth["set_cookies"])
                    except:
                        pass

                if request_auth["headers"] or request_auth["cookies"] or response_auth["set_cookies"]:
                    credentials.append({
                        "history_index": index,
                        "url": url,
                        "method": str(req_info.getMethod()),
                        "host": str(service.getHost()),
                        "host_match": match_mode,
                        "port": int(service.getPort()),
                        "protocol": str(service.getProtocol()),
                        "request_auth": request_auth,
                        "response_auth": response_auth
                    })
            except:
                continue

        self.extender.stdout.println("[AGENT API] auth/latest host=%s searched=%d matches=%d" % (
            host_filter, searched, len(credentials)))
        recommended_auth = self._build_recommended_auth(credentials)
        return 200, {
            "host": host_filter,
            "path_contains": path_contains,
            "include_related": include_related,
            "related_suffix": related_suffix,
            "searched": searched,
            "count": len(credentials),
            "recommended_auth": recommended_auth,
            "guidance": [
                "Prefer recommended_auth.raw_header_lines for the next retry.",
                "If recommended_auth has cookies but no Authorization header, use the Cookie header - live browser sessions are often cookie-based.",
                "Related sibling hosts are searched by default because live app sessions are often on an app host while API calls use an api host.",
                "If no usable auth appears but a live BrowserOS session exists, refresh the relevant BrowserOS page or perform one same-site action while proxied through Burp, then call this endpoint again before asking for tokens."
            ],
            "credentials": credentials
        }

    def _handle_get_latest_auth(self, query):
        host_filter = self._query_value(query, "host", "").lower()
        path_contains = self._query_value(query, "path_contains", "")
        include_related = self._query_value(query, "include_related", "true").lower() not in ("0", "false", "no")
        verbose = self._bool_query_value(query, "verbose", "false")
        try:
            limit = int(self._query_value(query, "limit", "50"))
        except:
            limit = 50
        status, payload = self._get_latest_auth_payload(host_filter, path_contains, include_related, limit)
        if status == 200 and not verbose:
            all_credentials = list(payload.get("credentials", []) or [])
            latest_by_host = []
            seen_hosts = set()
            for credential in all_credentials:
                credential_host = str(credential.get("host", "") or "").lower()
                if not credential_host or credential_host in seen_hosts:
                    continue
                seen_hosts.add(credential_host)
                latest_by_host.append(credential)
            payload["credentials"] = latest_by_host
            payload["count"] = len(latest_by_host)
            payload["credential_history_count"] = len(all_credentials)
            payload["mode"] = "latest_usable_per_host"
            payload["verbose_url"] = "/api/agent/auth/latest?host=%s&verbose=true" % host_filter
        elif status == 200:
            payload["mode"] = "verbose_history"
        self._send_json(status, payload)

    def _ensure_collaborator_client(self):
        if self.extender.collaborator is not None:
            return True
        try:
            self.extender.collaborator = self.extender.callbacks.createBurpCollaboratorClient()
            return True
        except Exception:
            try:
                self.extender.collaborator = self.extender.callbacks.createBurpCollaboratorClientContext()
                return True
            except Exception:
                self.extender.collaborator = None
        return False

    def _serialize_collaborator_interaction(self, interaction):
        keys = [
            "type", "client_ip", "time_stamp", "interaction_id", "protocol",
            "query_type", "raw_query", "request", "response",
            "smtp_from", "smtp_to", "conversation", "payload", "payload_id"
        ]
        result = {}
        for key in keys:
            try:
                value = interaction.getProperty(key)
                if value is not None:
                    result[key] = self._limit_text(value, 6000)
            except Exception:
                continue
        if not result:
            try:
                result["raw"] = self._limit_text(str(interaction), 6000)
            except Exception:
                result["raw"] = "unserializable collaborator interaction"
        return result

    def _handle_get_collaborator_interactions(self, query):
        if not self._ensure_collaborator_client():
            self._send_json(503, {
                "error": "Collaborator not available",
                "message": "Burp Collaborator is not available in this Burp edition"
            })
            return

        payload = (
            self._query_value(query, "payload", "") or
            self._query_value(query, "payloadId", "") or
            self._query_value(query, "payload_id", "")
        )
        try:
            try:
                limit = max(1, min(200, int(self._query_value(query, "limit", "100"))))
            except Exception:
                limit = 100

            interactions = None
            if payload:
                interactions = self.extender.collaborator.fetchCollaboratorInteractionsFor(payload)
            else:
                try:
                    interactions = self.extender.collaborator.fetchAllCollaboratorInteractions()
                except Exception:
                    self._send_json(400, {
                        "error": "payload required",
                        "message": "This Burp Collaborator API requires payload or payloadId. Call /api/agent/collaborator first and pass the returned payload."
                    })
                    return

            serialized = []
            for interaction in interactions or []:
                if len(serialized) >= limit:
                    break
                serialized.append(self._serialize_collaborator_interaction(interaction))
            if payload:
                registry = getattr(self.extender, "collaborator_payload_registry", {}) or {}
                record = dict(registry.get(payload, {}) or {})
                record["payload"] = payload
                record["last_polled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                record["interaction_count"] = len(serialized)
                record["interactions"] = serialized
                registry[payload] = record
                self.extender.collaborator_payload_registry = registry
            self._send_json(200, {
                "payload": payload,
                "count": len(serialized),
                "interactions": serialized,
                "burp_visible": True,
                "burp_evidence_surface": "Double Agent > Findings > Finding Details after validation",
                "native_collaborator_tab_visibility": "not_guaranteed_by_legacy_extender_api",
                "guidance": "Use this after injecting a generated Collaborator payload. Include payload and a returned interaction_id in collaborator_evidence before marking an SSRF finding valid."
            })
        except Exception as e:
            self._send_json(500, {
                "error": "collaborator interaction fetch failed",
                "message": self._safe_ascii_text(e, 500)
            })

    def _is_ssrf_finding(self, finding):
        if not isinstance(finding, dict):
            return False
        family = self.extender._canonical_finding_family(
            finding.get("title", ""), finding.get("cwe", ""),
            finding.get("detail", ""), finding.get("evidence", ""))
        return family == "ssrf"

    def _collaborator_evidence_for_finding(self, finding, body):
        """Verify SSRF evidence against Burp's Collaborator client context."""
        if not self._is_ssrf_finding(finding):
            return {"ok": True, "required": False, "artifact": {}}
        raw_items = body.get("collaborator_evidence", []) if isinstance(body, dict) else []
        if isinstance(raw_items, dict):
            raw_items = [raw_items]
        if not isinstance(raw_items, list):
            raw_items = []
        stable_id = str(finding.get("stable_id", finding.get("id", "")) or "")
        selected = None
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            item_fid = str(item.get("finding_id", item.get("id", "")) or "")
            if not item_fid or not stable_id or item_fid == stable_id:
                selected = item
                break
        if selected is None:
            return {
                "ok": False,
                "required": True,
                "error": "ssrf_collaborator_evidence_required",
                "message": "A valid SSRF finding requires a registered Burp Collaborator attempt plus either a confirmed interaction or strong structured in-band internal-resource proof.",
                "finding_id": stable_id,
                "required_fields": ["collaborator_evidence[].payload", "collaborator_evidence[].interaction_id"],
                "workflow": [
                    "GET /api/agent/collaborator",
                    "inject the returned payload through the scoped SSRF input",
                    "GET /api/agent/collaborator/interactions?payload=<payload>",
                    "retry with collaborator_evidence from the returned interaction"
                ]
            }
        payload = str(selected.get("payload", selected.get("payload_id", "")) or "").strip()
        expected_id = str(selected.get("interaction_id", "") or "").strip()
        if not payload:
            return {"ok": False, "required": True, "error": "ssrf_collaborator_payload_required", "finding_id": stable_id}
        registry = getattr(self.extender, "collaborator_payload_registry", {}) or {}
        if body.get("ssrf_inband_evidence") and payload in registry:
            inband = ssrf_inband_evidence_artifact(finding, body, payload)
            if inband.get("ok"):
                artifact = inband.get("artifact", {}) or {}
                artifact["verified_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                artifact["burp_visible"] = True
                artifact["burp_evidence_surface"] = "Double Agent > Findings > Finding Details"
                return {"ok": True, "required": True, "artifact": artifact}
        if not self._ensure_collaborator_client():
            return {"ok": False, "required": True, "error": "collaborator_unavailable", "finding_id": stable_id}
        try:
            interactions = self.extender.collaborator.fetchCollaboratorInteractionsFor(payload) or []
            serialized = [self._serialize_collaborator_interaction(item) for item in interactions]
        except Exception as exc:
            return {"ok": False, "required": True, "error": "collaborator_poll_failed", "message": self._safe_ascii_text(exc, 500), "finding_id": stable_id}
        if expected_id:
            matching = [item for item in serialized if str(item.get("interaction_id", "")) == expected_id]
        else:
            matching = serialized[:1]
        if not matching:
            return {
                "ok": False,
                "required": True,
                "error": "ssrf_collaborator_interaction_not_found",
                "message": "Burp Collaborator returned no matching interaction for this payload.",
                "finding_id": stable_id,
                "payload": payload,
                "observed_interaction_ids": [item.get("interaction_id", "") for item in serialized]
            }
        interaction = matching[0]
        artifact = {
            "payload": payload,
            "interaction_id": interaction.get("interaction_id", expected_id),
            "type": interaction.get("type", interaction.get("protocol", "")),
            "client_ip": interaction.get("client_ip", ""),
            "time_stamp": interaction.get("time_stamp", ""),
            "query_type": interaction.get("query_type", ""),
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "burp_visible": True,
            "burp_evidence_surface": "Double Agent > Findings > Finding Details",
            "native_collaborator_tab_visibility": "not_guaranteed_by_legacy_extender_api",
            "interaction": interaction
        }
        return {"ok": True, "required": True, "artifact": artifact}

    def _store_collaborator_artifact(self, finding_ref, result):
        artifact = (result or {}).get("artifact", {}) or {}
        if not artifact:
            return
        with self.extender.findings_lock_ui:
            idx = self.extender._finding_index_by_reference_unlocked(finding_ref)
            if idx is not None and 0 <= idx < len(self.extender.findings_list):
                finding = self.extender.findings_list[idx]
                finding["collaborator_evidence"] = artifact
                finding["collaborator_verified"] = True

    def _handle_proxy_http_history_regex(self, query):
        regex = self._query_value(query, "regex", "")
        if not regex:
            self._send_json(400, {"error": "regex is required"})
            return
        try:
            pattern = re.compile(regex, re.I | re.M)
        except Exception as e:
            self._send_json(400, {"error": "invalid regex", "message": self._safe_ascii_text(e, 300)})
            return

        try:
            count = max(1, min(500, int(self._query_value(query, "count", "50"))))
        except Exception:
            count = 50
        try:
            offset = max(0, int(self._query_value(
                query, "offset", self._query_value(query, "cursor", "0"))))
        except Exception:
            offset = 0
        try:
            preview_limit = max(100, min(8000, int(self._query_value(query, "preview_limit", "1200"))))
        except Exception:
            preview_limit = 1200
        include_tokens = set()
        for token in self._query_value(query, "include", "").split(","):
            token = str(token or "").strip().lower()
            if token:
                include_tokens.add(token)
        include_request = self._bool_query_value(query, "include_request", "false") or "request" in include_tokens
        include_response = self._bool_query_value(query, "include_response", "false") or "response" in include_tokens
        include_previews = self._bool_query_value(query, "include_previews", "false") or "previews" in include_tokens
        include_headers = self._bool_query_value(query, "include_headers", "false") or "headers" in include_tokens
        metadata_only = self._bool_query_value(query, "metadata_only", "true" if not include_request and not include_response and not include_previews else "false")

        try:
            helpers = self.extender.helpers
            history = self.extender.callbacks.getProxyHistory() or []
            matches_seen = 0
            returned = []
            for idx, entry in enumerate(history):
                try:
                    request_bytes = entry.getRequest()
                    if request_bytes is None:
                        continue
                    request_text = helpers.bytesToString(request_bytes)
                    response_bytes = entry.getResponse()
                    response_text = ""
                    if response_bytes is not None:
                        try:
                            response_text = helpers.bytesToString(response_bytes)
                        except Exception:
                            response_text = "[binary response]"

                    req_info = helpers.analyzeRequest(entry)
                    method = str(req_info.getMethod() or "")
                    url = str(req_info.getUrl() or "")
                    search_text = "\n".join([method, url, request_text or "", response_text or ""])
                    if not pattern.search(search_text):
                        continue

                    if matches_seen < offset:
                        matches_seen += 1
                        continue

                    if len(returned) >= count:
                        matches_seen += 1
                        continue

                    item = {
                        "history_index": idx,
                        "method": method,
                        "url": url,
                        "has_response": response_bytes is not None
                    }
                    if include_headers:
                        try:
                            item["request_headers"] = self._redact_header_lines([str(h) for h in req_info.getHeaders()])
                        except Exception:
                            item["request_headers"] = []
                    if response_bytes is not None:
                        try:
                            res_info = helpers.analyzeResponse(response_bytes)
                            item["status_code"] = int(res_info.getStatusCode())
                            if include_headers:
                                item["response_headers"] = self._redact_header_lines([str(h) for h in res_info.getHeaders()])
                        except Exception:
                            item["status_code"] = None
                            if include_headers:
                                item["response_headers"] = []
                    if not metadata_only and include_previews:
                        item["request_preview"] = self._limit_text(self._redact_sensitive_http_text(request_text), preview_limit)
                        if response_bytes is not None:
                            item["response_preview"] = self._limit_text(self._redact_sensitive_http_text(response_text), preview_limit)
                    if include_request:
                        item["request"] = self._redact_sensitive_http_text(request_text)
                    if include_response and response_bytes is not None:
                        item["response"] = self._redact_sensitive_http_text(response_text)
                    returned.append(item)
                    matches_seen += 1
                except Exception:
                    continue

            self._send_json(200, {
                "regex": regex,
                "offset": offset,
                "cursor": str(offset),
                "count": len(returned),
                "total_matches_seen": matches_seen,
                "total_matches": matches_seen,
                "next_offset": (offset + len(returned)) if (offset + len(returned)) < matches_seen else None,
                "next_cursor": str(offset + len(returned)) if (offset + len(returned)) < matches_seen else None,
                "has_more": (offset + len(returned)) < matches_seen,
                "stable_order": "oldest_history_index_first",
                "history_size": len(history),
                "metadata_only": bool(metadata_only),
                "include_headers": bool(include_headers),
                "content_included": {
                    "request": bool(include_request),
                    "response": bool(include_response),
                    "headers": bool(include_headers),
                    "previews": bool(include_previews)
                },
                "items": returned,
                "guidance": "Default output is metadata-only. Use include=request,response,headers,previews or the equivalent include_request/include_response/include_headers/include_previews booleans for redacted expansion."
            })
        except Exception as e:
            self._send_json(500, {
                "error": "proxy history regex search failed",
                "message": self._safe_ascii_text(e, 500)
            })

    def _handle_get_finding(self, fid, query=None):
        if query is None:
            query = {}
        idx = self.extender._finding_index_by_reference(fid)
        if idx is None:
            self._send_json(404, {"error": "finding not found", "id": fid})
            return
        if idx < 0:
            self._send_json(400, {"error": "invalid id (must be >= 1)"})
            return
        with self.extender.findings_lock_ui:
            if idx < 0 or idx >= len(self.extender.findings_list):
                self._send_json(404, {"error": "not found"})
                return
            f = dict(self.extender.findings_list[idx])
            summary = self._bool_query_value(query, "summary", "false")
            include_raw = self._bool_query_value(query, "include_raw", "false")
            base = self._serialize_finding(idx, f, include_full=not summary)
            base["notes"] = list(f.get("agent_notes", []))
            if not summary:
                request_data = f.get("request_data", "") or ""
                response_data = f.get("response_data", "") or ""
                base["request_data_length"] = len(str(request_data))
                base["response_data_length"] = len(str(response_data))
                base["request_data_preview"] = self._limit_text(request_data, 4000)
                base["response_data_preview"] = self._limit_text(response_data, 4000)
                if include_raw:
                    base["request_data"] = request_data
                    base["response_data"] = response_data
                else:
                    if "request_data" in base:
                        del base["request_data"]
                    if "response_data" in base:
                        del base["response_data"]
                    base["raw_omitted"] = True
                    base["raw_guidance"] = "Use ?include_raw=true only when raw request/response bodies are required, or fields=id,title,response_data for specific fields."
            fields = self._query_value(query, "fields", "")
            if fields:
                if "request_data" in str(fields) and "request_data" not in base:
                    base["request_data"] = f.get("request_data", "") or ""
                if "response_data" in str(fields) and "response_data" not in base:
                    base["response_data"] = f.get("response_data", "") or ""
                base = self._filter_fields(base, fields)
        self._send_json(200, base)

    def _coverage_surface_class(self, url, parameter_name="", parameter_type=""):
        try:
            parsed = urlparse.urlparse(str(url or ""))
            path = str(parsed.path or "/").lower()
        except Exception:
            path = str(url or "").lower()
        ptype = str(parameter_type or "").lower()
        name = str(parameter_name or "").lower()
        if ptype == "header":
            return "header"
        if ptype == "cookie":
            return "cookie"
        static_exts = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                       ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif")
        runtime_markers = ("/@vite", "/__vite", "/node_modules/", "/sockjs-node", "/webpack-hmr",
                           "hot-update", "/_next/static/", "/webpack/", "/runtime~", "remoteentry")
        if any(marker in path for marker in runtime_markers):
            return "development_runtime"
        if path.endswith(static_exts) or any(marker in path for marker in ("/static/", "/assets/", "/chunks/")):
            return "static_asset"
        noise_names = set(["_", "t", "ts", "timestamp", "v", "ver", "version", "hash", "cache", "cachebust", "cache_bust", "hmr"])
        if ptype == "query" and name in noise_names:
            return "runtime_noise"
        return "application"

    def _coverage_path_template(self, url, method="GET"):
        try:
            normalized = normalize_attack_surface_entry({"url": str(url or ""), "method": str(method or "GET")})
            return normalized.get("path_template", normalized.get("path", "/"))
        except Exception:
            try:
                return urlparse.urlparse(str(url or "")).path or "/"
            except Exception:
                return "/"
