# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk3(object):
    def _redact_header_lines(self, headers):
        redacted = []
        for header in headers or []:
            text = str(header or "")
            if ":" not in text:
                redacted.append(text)
                continue
            name, value = text.split(":", 1)
            if self._auth_header_name(name) or name.strip().lower() in ("set-cookie", "proxy-authorization"):
                redacted.append("%s: [redacted]" % name.strip())
            else:
                redacted.append("%s:%s" % (name, value))
        return redacted

    def _redact_sensitive_http_text(self, text):
        try:
            return redact_sensitive_http_text(text)
        except Exception:
            return str(text or "")

    def _sanitize_for_persistence(self, value):
        if bool(getattr(self.extender, "PERSIST_RAW_HTTP", False)):
            return value
        if isinstance(value, dict):
            return dict((key, self._sanitize_for_persistence(item)) for key, item in value.items())
        if isinstance(value, list):
            return [self._sanitize_for_persistence(item) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize_for_persistence(item) for item in value]
        try:
            if isinstance(value, basestring):
                return self._redact_sensitive_http_text(value)
        except Exception:
            if isinstance(value, str):
                return self._redact_sensitive_http_text(value)
        return value

    def _bool_query_value(self, query, name, default="true"):
        value = self._query_value(query, name, default).lower()
        return value not in ("0", "false", "no", "off")

    def _shell_quote(self, value):
        text = str(value or "")
        return "'" + text.replace("'", "'\"'\"'") + "'"

    def _split_raw_http_request(self, raw_request):
        text = str(raw_request or "")
        truncated = "... [truncated]" in text
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if "\n\n" in text:
            head, body = text.split("\n\n", 1)
        else:
            head, body = text, ""
        lines = [line for line in head.split("\n") if line is not None]
        request_line = lines[0].strip() if lines else ""
        parts = request_line.split()
        method = parts[0].upper() if len(parts) >= 1 else "GET"
        target = parts[1] if len(parts) >= 2 else ""
        headers = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip()
            if not name:
                continue
            headers.append({"name": name, "value": value.strip()})
        return {
            "request_line": request_line,
            "method": method,
            "target": target,
            "headers": headers,
            "body": body,
            "truncated": truncated
        }

    def _header_from_pairs(self, headers, name):
        name_l = str(name or "").lower()
        for header in headers or []:
            try:
                if str(header.get("name", "")).strip().lower() == name_l:
                    return str(header.get("value", "")).strip()
            except:
                pass
        return ""

    def _split_host_port(self, host_value):
        host_value = str(host_value or "").strip()
        if not host_value:
            return "", 0
        if host_value.startswith("[") and "]" in host_value:
            end = host_value.find("]")
            host = host_value[1:end]
            rest = host_value[end + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except:
                    return host, 0
            return host, 0
        if ":" in host_value:
            host, port = host_value.rsplit(":", 1)
            try:
                return host.strip(), int(port)
            except:
                return host_value, 0
        return host_value, 0

    def _url_host_port_protocol(self, url):
        parsed = urlparse.urlparse(str(url or ""))
        protocol = str(parsed.scheme or "").lower()
        netloc = str(parsed.netloc or "")
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        host, port = self._split_host_port(netloc)
        if not port:
            try:
                parsed_port = parsed.port
            except:
                parsed_port = 0
            if parsed_port:
                port = int(parsed_port)
            elif protocol == "https":
                port = 443
            elif protocol == "http":
                port = 80
        return host.lower(), port, protocol

    def _candidate_url(self, candidate, parsed):
        url = str(candidate.get("url", "") or "").strip()
        target = str(parsed.get("target", "") or "").strip()
        if url.lower().startswith("http://") or url.lower().startswith("https://"):
            host, port, protocol = self._url_host_port_protocol(url)
            return url, host, port, protocol
        if target.lower().startswith("http://") or target.lower().startswith("https://"):
            host, port, protocol = self._url_host_port_protocol(target)
            return target, host, port, protocol

        host_header = self._header_from_pairs(parsed.get("headers", []), "Host")
        host, header_port = self._split_host_port(host_header)
        if not host:
            host = str(candidate.get("host", "") or "").strip()
        protocol = str(candidate.get("protocol", "") or "").strip().lower()
        if not protocol:
            protocol = "https"
        try:
            port = int(candidate.get("port", 0) or 0)
        except:
            port = 0
        if not port:
            port = header_port
        if not port:
            port = 443 if protocol == "https" else 80
        path = target or "/"
        if not path.startswith("/"):
            path = "/" + path
        netloc = host
        if (protocol == "https" and port != 443) or (protocol == "http" and port != 80):
            netloc = "%s:%d" % (host, port)
        return "%s://%s%s" % (protocol, netloc, path), host.lower(), port, protocol

    def _auth_header_name(self, name):
        name_l = str(name or "").strip().lower()
        return (
            name_l in set([
                "authorization", "cookie", "x-api-key", "api-key",
                "x-auth-token", "x-access-token", "x-id-token",
                "x-session-token", "x-csrf-token", "x-xsrf-token",
                "csrf-token", "x-csrftoken", "x-request-verification-token",
                "requestverificationtoken"
            ]) or "token" in name_l or "csrf" in name_l
        )

    def _parse_header_line(self, line):
        text = str(line or "")
        if ":" not in text:
            return None
        name, value = text.split(":", 1)
        name = name.strip()
        if not name:
            return None
        return {"name": name, "value": value.strip()}

    def _headers_for_curl(self, parsed, auth_header_lines, note):
        skip = set(["content-length", "connection", "proxy-connection", "accept-encoding"])
        headers = []
        replacing_auth = bool(auth_header_lines)
        for header in parsed.get("headers", []):
            name = str(header.get("name", "")).strip()
            value = str(header.get("value", "")).strip()
            name_l = name.lower()
            if name_l in skip:
                continue
            if name_l == "x-eternals-agent-note":
                continue
            if replacing_auth and self._auth_header_name(name):
                continue
            if name:
                headers.append({"name": name, "value": value})

        for line in auth_header_lines or []:
            parsed_line = self._parse_header_line(line)
            if parsed_line:
                headers.append(parsed_line)

        if note:
            headers.append({"name": "X-Eternals-Agent-Note", "value": note})
        return headers

    def _headers_dict_from_pairs(self, headers):
        result = {}
        for header in headers or []:
            try:
                name = str(header.get("name", "") or "").strip()
                value = str(header.get("value", "") or "").strip()
                if name and not name.startswith(":"):
                    result[name] = value
            except Exception:
                pass
        return result

    def _http2_arguments_from_candidate(self, candidate):
        parsed = self._split_raw_http_request(candidate.get("request_data", ""))
        method = str(candidate.get("method", "") or parsed.get("method", "GET") or "GET").upper()
        url, host, port, protocol = self._candidate_url(candidate, parsed)
        target = str(parsed.get("target", "") or "/")
        if target.lower().startswith("http://") or target.lower().startswith("https://"):
            try:
                parsed_url = urlparse.urlparse(target)
                target = (parsed_url.path or "/") + (("?" + parsed_url.query) if parsed_url.query else "")
            except Exception:
                target = "/"
        if not target.startswith("/"):
            target = "/" + target
        uses_https = protocol != "http"
        authority = self._header_from_pairs(parsed.get("headers", []), "Host") or host
        if not authority:
            authority = host
        if authority and ":" not in authority:
            try:
                if (uses_https and int(port or 443) != 443) or ((not uses_https) and int(port or 80) != 80):
                    authority = "%s:%s" % (authority, port)
            except Exception:
                pass
        return {
            "targetHostname": host,
            "targetPort": int(port or (443 if uses_https else 80)),
            "usesHttps": bool(uses_https),
            "pseudoHeaders": {
                ":method": method,
                ":path": target,
                ":scheme": "https" if uses_https else "http",
                ":authority": authority or host
            },
            "headers": self._headers_dict_from_pairs(parsed.get("headers", [])),
            "requestBody": parsed.get("body", "") or "",
            "url": url,
            "method": method,
            "host": host
        }

    def _queue_protocol_profile(self, item, candidates, active_recipe):
        reasons = []
        source = str(item.get("source", "") or "")
        mode = str(item.get("mode", "") or "")
        campaign_type = str(item.get("campaign_type", "") or "")
        if source == "risk_hunt" and (mode == "campaign_parser_protocol" or campaign_type == "parser_protocol"):
            reasons.append("parser_protocol campaign")
        recipe_text = ""
        if isinstance(active_recipe, dict):
            recipe_text = " ".join([
                str(active_recipe.get("hypothesis", "") or ""),
                str(active_recipe.get("active_test_type", "") or ""),
                str(active_recipe.get("mutation_hint", "") or ""),
                str(active_recipe.get("scanner_focus", "") or ""),
                str(active_recipe.get("safety_notes", "") or "")
            ]).lower()
        if any(term in recipe_text for term in ("http/2", "http2", " h2", "pseudo-header", "pseudo header", ":authority", ":method", ":path")):
            reasons.append("active_test_recipe indicates HTTP/2 or pseudo-header sensitivity")
        for candidate in candidates or []:
            try:
                parsed = self._split_raw_http_request(candidate.get("request_data", ""))
                request_line = str(parsed.get("request_line", "") or "").lower()
                protocol = str(candidate.get("protocol", "") or "").lower()
                header_names = [str(h.get("name", "") or "").lower() for h in parsed.get("headers", []) or []]
                if "http/2" in request_line or protocol in ("h2", "http2", "http/2"):
                    reasons.append("%s captured as HTTP/2" % candidate.get("label", "request"))
                if any(name.startswith(":") for name in header_names):
                    reasons.append("%s includes HTTP/2 pseudo-headers" % candidate.get("label", "request"))
            except Exception:
                pass
        unique = []
        for reason in reasons:
            if reason and reason not in unique:
                unique.append(reason)
        template = {}
        if unique and candidates:
            try:
                template = self._http2_arguments_from_candidate(candidates[0])
                if template.get("headers"):
                    template["headers"] = {"<ordinary headers from captured request>": "omitted from next_action; use queue request_data as source"}
                if template.get("requestBody"):
                    template["requestBody"] = "<body omitted from next_action; use queue request_data as source>"
            except Exception:
                template = {}
        return {
            "requires_portswigger_mcp": bool(unique),
            "reasons": unique,
            "mcp_tool": "send_http2_request" if unique else "",
            "http2_endpoint": "/api/agent/request/http2" if unique else "",
            "request_template": template
        }

    def _workspace_directory(self):
        try:
            return self.extender._workspace_directory()
        except Exception:
            pass
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

    def _workspace_file_status(self, name, preview_limit=500):
        base = self._workspace_directory()
        path = os.path.join(base, name)
        present = os.path.isfile(path)
        result = {"path": path, "present": bool(present)}
        if present:
            try:
                result["size"] = int(os.path.getsize(path))
                fh = open(path, "rb")
                try:
                    data = fh.read(preview_limit)
                finally:
                    fh.close()
                result["preview"] = data.decode("utf-8", "replace") if hasattr(data, "decode") else str(data)
            except Exception as e:
                result["read_error"] = self._safe_ascii_text(e)
        return result

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
        except:
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

    def _scope_guard_for_url(self, url):
        host, port, protocol = self._url_host_port_protocol(url)
        if not host:
            return {
                "in_scope": None,
                "requires_confirmation": True,
                "reason": "could not determine target host",
                "host": host,
                "scope_source": "burp_suite"
            }
        # This helper is also used while Swing renders the selected queue item.
        # Never cross into Burp callbacks from the EDT: exact scope enforcement
        # still happens on the API/request worker before any target traffic.
        if self.extender._is_swing_event_thread():
            self.extender._schedule_site_map_snapshot_refresh()
            return {
                "scope_source": "burp_suite",
                "authoritative": True,
                "in_scope": None,
                "requires_confirmation": True,
                "host": host,
                "port": port,
                "protocol": protocol,
                "url": str(url or ""),
                "reason": "Burp scope check deferred outside the Swing event thread"
            }
        try:
            from java.net import URL as _JavaURL
            in_scope = bool(self.extender.callbacks.isInScope(_JavaURL(str(url))))
            return {
                "scope_source": "burp_suite",
                "authoritative": True,
                "in_scope": in_scope,
                "requires_confirmation": False,
                "host": host,
                "port": port,
                "protocol": protocol,
                "url": str(url or ""),
                "reason": "Burp Suite reports this URL in scope" if in_scope else "Burp Suite reports this URL outside scope"
            }
        except Exception as e:
            return {
                "scope_source": "burp_suite",
                "authoritative": True,
                "in_scope": None,
                "requires_confirmation": True,
                "host": host,
                "port": port,
                "protocol": protocol,
                "url": str(url or ""),
                "reason": "Burp Suite scope could not be queried",
                "error": self._safe_ascii_text(e, 300)
            }

    def _burp_scope_snapshot(self, limit=500):
        try:
            limit = max(1, min(2000, int(limit)))
        except Exception:
            limit = 500
        groups = {}
        observed_urls = []
        scanned = 0
        try:
            from java.net import URL as _JavaURL
            sitemap = self.extender._get_burp_site_map_snapshot() or []
            for entry in sitemap:
                scanned += 1
                try:
                    url = str(entry.getUrl() or "")
                    if not url or not bool(self.extender.callbacks.isInScope(_JavaURL(url))):
                        continue
                    parsed = urlparse.urlparse(url)
                    host = str(parsed.hostname or "").lower()
                    scheme = str(parsed.scheme or "https").lower()
                    port = int(parsed.port or (443 if scheme == "https" else 80))
                    key = "%s://%s:%d" % (scheme, host, port)
                    group = groups.setdefault(key, {
                        "service": key,
                        "scheme": scheme,
                        "host": host,
                        "port": port,
                        "url_examples": []
                    })
                    if len(group["url_examples"]) < 10 and url not in group["url_examples"]:
                        group["url_examples"].append(url)
                    if len(observed_urls) < limit:
                        observed_urls.append(url)
                except Exception:
                    continue
        except Exception as e:
            return {
                "source": "burp_suite",
                "authoritative": True,
                "available": False,
                "error": self._safe_ascii_text(e, 500),
                "services": [],
                "observed_urls": []
            }
        return {
            "source": "burp_suite",
            "authoritative": True,
            "available": True,
            "site_map_entries_scanned": scanned,
            "in_scope_services": len(groups),
            "services": sorted(groups.values(), key=lambda item: item.get("service", "")),
            "observed_urls": observed_urls,
            "observed_urls_truncated": len(observed_urls) >= limit,
            "guidance": "This inventories observed in-scope Burp site-map entries. Use ?url=<candidate> for the authoritative Burp isInScope decision on any exact URL."
        }

    def _handle_get_burp_scope(self, query):
        candidate_url = self._query_value(query, "url", "")
        if candidate_url:
            guard = self._scope_guard_for_url(candidate_url)
            self._send_json(200, {
                "source": "burp_suite",
                "authoritative": True,
                "url": candidate_url,
                "scope_guard": guard
            })
            return
        try:
            limit = int(self._query_value(query, "limit", "500"))
        except Exception:
            limit = 500
        snapshot = self._burp_scope_snapshot(limit)
        if self._bool_query_value(query, "summary", "false") or self._bool_query_value(query, "compact", "false"):
            snapshot = {
                "source": snapshot.get("source", "burp_suite"),
                "authoritative": True,
                "available": snapshot.get("available", False),
                "site_map_entries_scanned": snapshot.get("site_map_entries_scanned", 0),
                "in_scope_services": snapshot.get("in_scope_services", 0),
                "service_authorities": [item.get("service") for item in snapshot.get("services", [])],
                "full_scope": "/api/agent/scope",
            }
        self._send_json(200 if snapshot.get("available") else 503, snapshot)

    def _safety_gate_for_request(self, method, url):
        method_u = str(method or "GET").upper()
        parsed = urlparse.urlparse(str(url or ""))
        path_l = str(parsed.path or "").lower()
        allowed_match = None
        try:
            profile = getattr(self.extender, "project_profile", {}) or {}
            rules = profile.get("allowed_state_changes", []) if self.extender._engagement_bound_record_is_current(profile) else []
            for rule in rules or []:
                if not isinstance(rule, dict):
                    continue
                rule_method = str(rule.get("method", "") or "").upper()
                path_contains = str(rule.get("path_contains", rule.get("path", "")) or "").lower()
                if rule_method and rule_method != method_u:
                    continue
                if path_contains and path_contains not in path_l:
                    continue
                allowed_match = rule
                break
        except Exception:
            allowed_match = None
        keywords = [
            "delete", "remove", "destroy", "disable", "password", "reset",
            "payment", "checkout", "refund", "transfer", "withdraw", "order",
            "purchase", "upload", "import", "invite", "admin"
        ]
        reasons = []
        if method_u in ("DELETE", "PUT", "PATCH"):
            reasons.append("method %s can change state" % method_u)
        if method_u == "POST":
            for keyword in keywords:
                if keyword in path_l:
                    reasons.append("POST path contains '%s'" % keyword)
                    break
        return {
            "requires_confirmation": bool(reasons) and not bool(allowed_match),
            "method": method_u,
            "reasons": reasons,
            "allowed_state_change": allowed_match or {},
            "safe_to_auto_test": (not bool(reasons)) or bool(allowed_match)
        }

    def _check_tcp_listener(self, host, port, timeout_ms=750):
        sock = None
        try:
            sock = Socket()
            sock.connect(InetSocketAddress(host, int(port)), int(timeout_ms))
            return {"host": host, "port": int(port), "reachable": True}
        except:
            try:
                import sys
                e = sys.exc_info()[1]
            except:
                e = "connection failed"
            return {
                "host": host,
                "port": int(port),
                "reachable": False,
                "error": self._safe_ascii_text(e, 300)
            }
        finally:
            try:
                if sock:
                    sock.close()
            except:
                pass

    def _portswigger_mcp_status(self):
        url = str(getattr(self.extender, "PORTSWIGGER_MCP_URL", "http://127.0.0.1:9876/") or "").strip()
        if not url:
            url = "http://127.0.0.1:9876/"
        try:
            parsed = urlparse.urlparse(url)
            host = str(parsed.hostname or parsed.netloc or "127.0.0.1")
            if "@" in host:
                host = host.rsplit("@", 1)[1]
            if ":" in host and not host.startswith("["):
                host = host.split(":", 1)[0]
            port = int(parsed.port or (443 if str(parsed.scheme or "").lower() == "https" else 80))
        except Exception:
            host = "127.0.0.1"
            port = 9876
        status = self._check_tcp_listener(host, port)
        status["url"] = url
        status["sse_endpoint"] = "/"
        status["tooling"] = "PortSwigger MCP / Burp MCP"
        status["required_for"] = [
            "HTTP/2-sensitive tests",
            "pseudo-header-sensitive tests",
            "Burp-native Repeater/history/scanner workflows when MCP tools are available"
        ]
        if status.get("reachable"):
            # Preflight must stay bounded. Report the cached probe and let
            # /burp/capabilities?refresh=true refresh it asynchronously.
            capabilities = dict(getattr(self.extender, "portswigger_mcp_capabilities", {}) or {})
            status["protocol_ready"] = bool(capabilities.get("tools"))
            status["tool_names"] = capabilities.get("tool_names", [])
            status["send_http2_request_available"] = "send_http2_request" in status["tool_names"]
            status["http2_direct_retry_available"] = True
            status["discovery_ms"] = capabilities.get("discovery_ms", None)
            status["capability_error"] = capabilities.get("error", "")
            status["capabilities_stale"] = bool(capabilities.get("stale", False))
            status["last_success_at"] = capabilities.get("last_success_at", "")
            status["last_probe_at"] = capabilities.get("last_probe_at", "")
            status["refresh_in_progress"] = bool(getattr(self.extender, "portswigger_mcp_refresh_in_progress", False))
        else:
            status["protocol_ready"] = False
            status["tool_names"] = []
            status["send_http2_request_available"] = False
            status["http2_direct_retry_available"] = False
        return status

    def _queue_target_candidates(self, item, findings_full=None):
        candidates = []
        seen = set()

        def add_candidate(source, label, request_data, url="", method="", host="", port=0, protocol="", step=None, active_test_recipe=None):
            request_data = request_data or ""
            url = url or ""
            if not request_data and not url:
                return
            key = "%s|%s|%s" % (source, url, request_data[:500])
            if key in seen:
                return
            seen.add(key)
            parsed = self._split_raw_http_request(request_data)
            candidate = {
                "source": source,
                "label": label,
                "step": step,
                "request_data": request_data,
                "url": url,
                "method": method or parsed.get("method", "GET"),
                "host": host,
                "port": port,
                "protocol": protocol,
                "active_test_recipe": active_test_recipe or {}
            }
            candidates.append(candidate)

        add_candidate(
                "queue_item", "primary request",
                item.get("request_data", ""), item.get("url", ""),
                item.get("method", ""), item.get("host", ""),
                item.get("port", 0), item.get("protocol", ""), None,
                item.get("active_test_recipe", {}))

        for step in item.get("flow_requests", []) or []:
            if not isinstance(step, dict):
                continue
            add_candidate(
                "flow_request", "flow step %s" % step.get("step", ""),
                step.get("request_data", ""), step.get("url", ""),
                step.get("method", ""), step.get("host", ""),
                step.get("port", 0), step.get("protocol", ""),
                step.get("step", None), step.get("active_test_recipe", {}))

        for finding in findings_full or []:
            if not isinstance(finding, dict):
                continue
            add_candidate(
                "finding", "finding #%s" % finding.get("id", ""),
                finding.get("request_data", ""), finding.get("url", ""),
                "", "", 0, "", finding.get("id", None),
                finding.get("active_test_recipe", {}))

        return candidates

    def _build_target_curl(self, candidate, queue_id=0, refresh_auth=True, note=""):
        parsed = self._split_raw_http_request(candidate.get("request_data", ""))
        method = str(candidate.get("method", "") or parsed.get("method", "GET") or "GET").upper()
        url, host, port, protocol = self._candidate_url(candidate, parsed)
        warnings = []
        auth_header_lines = []
        auth_source = "captured_request"
        auth_payload = None

        if parsed.get("truncated"):
            warnings.append("request_data is truncated; rebuild from Burp history before relying on body/header completeness")

        if refresh_auth and host:
            status, payload = self._get_latest_auth_payload(host, "", True, 100)
            auth_payload = payload
            if status == 200 and payload.get("recommended_auth", {}).get("usable"):
                auth_header_lines = payload.get("recommended_auth", {}).get("raw_header_lines", [])
                auth_source = "auth/latest"
            elif status != 200:
                warnings.append("auth/latest failed: %s" % payload.get("error", "unknown error"))
            else:
                warnings.append("auth/latest returned no usable auth; using captured request auth if present")

        if not note:
            note = "Agent: queue #%s - replay target request - expect baseline behavior" % queue_id
        headers = self._headers_for_curl(parsed, auth_header_lines, note)

        command_parts = [
            "curl", "-x", "http://127.0.0.1:8080",
            "--path-as-is", "-k", "-i", "-sS",
            "-X", self._shell_quote(method)
        ]
        for header in headers:
            line = "%s: %s" % (header.get("name", ""), header.get("value", ""))
            command_parts.extend(["-H", self._shell_quote(line)])
        body = parsed.get("body", "")
        if body:
            command_parts.extend(["--data-binary", self._shell_quote(body)])
        command_parts.append(self._shell_quote(url))

        scope_guard = self._scope_guard_for_url(url)
        safety_gate = self._safety_gate_for_request(method, url)
        requires_confirmation = bool(scope_guard.get("requires_confirmation") or safety_gate.get("requires_confirmation"))
        if scope_guard.get("in_scope") is False:
            warnings.append("Burp Suite scope reports the target URL outside scope")
        if safety_gate.get("requires_confirmation"):
            warnings.append("safety gate requires user confirmation: %s" % "; ".join(safety_gate.get("reasons", [])))

        return {
            "ok": bool(url and host),
            "command": " ".join(command_parts),
            "proxy": "http://127.0.0.1:8080",
            "method": method,
            "url": url,
            "host": host,
            "port": port,
            "protocol": protocol,
            "note_header": note,
            "auth": {
                "source": auth_source,
                "refreshed": auth_source == "auth/latest",
                "recommended_auth": (auth_payload or {}).get("recommended_auth", {}) if auth_payload else {}
            },
            "scope_guard": scope_guard,
            "safety_gate": safety_gate,
            "requires_confirmation": requires_confirmation,
            "warnings": warnings
        }

    def _raw_repeater_request(self, candidate, refresh_auth=True, note=""):
        parsed = self._split_raw_http_request(candidate.get("request_data", ""))
        method = str(candidate.get("method", "") or parsed.get("method", "GET") or "GET").upper()
        url, host, port, protocol = self._candidate_url(candidate, parsed)
        warnings = []
        auth_header_lines = []
        if refresh_auth and host:
            status, payload = self._get_latest_auth_payload(host, "", True, 100)
            if status == 200 and payload.get("recommended_auth", {}).get("usable"):
                auth_header_lines = payload.get("recommended_auth", {}).get("raw_header_lines", [])
            elif status != 200:
                warnings.append("auth/latest failed: %s" % payload.get("error", "unknown error"))
            else:
                warnings.append("auth/latest returned no usable auth; using captured request auth if present")

        headers = self._headers_for_curl(parsed, auth_header_lines, note)
        target = parsed.get("target", "") or "/"
        if target.lower().startswith("http://") or target.lower().startswith("https://"):
            try:
                parsed_url = urlparse.urlparse(target)
                target = (parsed_url.path or "/") + (("?" + parsed_url.query) if parsed_url.query else "")
            except:
                target = "/"
        if not target.startswith("/"):
            try:
                parsed_url = urlparse.urlparse(url)
                target = (parsed_url.path or "/") + (("?" + parsed_url.query) if parsed_url.query else "")
            except:
                target = "/" + target

        has_host = False
        lines = ["%s %s HTTP/1.1" % (method, target)]
        for header in headers:
            name = str(header.get("name", "") or "").strip()
            value = str(header.get("value", "") or "").strip()
            if not name:
                continue
            if name.lower() == "host":
                has_host = True
            lines.append("%s: %s" % (name, value))
        if not has_host and host:
            host_header = host
            if (protocol == "https" and int(port or 443) != 443) or (protocol == "http" and int(port or 80) != 80):
                host_header = "%s:%s" % (host, port)
            lines.insert(1, "Host: %s" % host_header)
        raw = "\r\n".join(lines) + "\r\n\r\n" + (parsed.get("body", "") or "")
        return {
            "ok": bool(host and raw),
            "raw_request": raw,
            "host": host,
            "port": port,
            "https": protocol == "https",
            "url": url,
            "warnings": warnings
        }

    def _repeater_mutation_labels(self, recipe):
        labels = []
        if not isinstance(recipe, dict):
            return labels
        raw = recipe.get("mutations", recipe.get("mutation_recipes", []))
        if isinstance(raw, list):
            for item in raw[:5]:
                if isinstance(item, dict):
                    label = item.get("label", item.get("name", item.get("mutation", "")))
                else:
                    label = str(item or "")
                label = self._safe_ascii_text(label, 60)
                if label and label not in labels:
                    labels.append(label)
        if not labels and recipe.get("mutation_hint"):
            labels.append(self._safe_ascii_text(recipe.get("mutation_hint", ""), 60))
        return labels[:5]

    def _repeater_mutations(self, recipe):
        if not isinstance(recipe, dict):
            return []
        raw = recipe.get("mutations", recipe.get("mutation_recipes", []))
        if not isinstance(raw, list):
            return []
        return [mutation for mutation in raw[:5] if isinstance(mutation, dict)]

    def _handle_send_queue_to_repeater(self, qid):
        try:
            qid_int = int(qid)
        except:
            self._send_json(400, {"error": "invalid id"})
            return
        try:
            body = self._read_body()
        except Exception:
            body = {}
        item = self._get_queue_item_snapshot(qid_int)
        if item is None:
            self._send_json(404, {"error": "not found"})
            return
        findings_full = self._queue_findings_full(item)
        refresh_auth = bool(body.get("refresh_auth", True))
        candidates = self._queue_target_candidates(item, findings_full)
        if not candidates:
            self._send_json(404, {"error": "no replayable HTTP request attached to this queue item"})
            return
        created = []
        warnings = []
        for idx, candidate in enumerate(candidates[:10], 1):
            recipe = candidate.get("active_test_recipe", {}) or {}
            base_label = "DA q%s %s baseline" % (qid_int, candidate.get("label", "request"))
            built = self._raw_repeater_request(candidate, refresh_auth=refresh_auth, note="")
            warnings.extend(built.get("warnings", []))
            if not built.get("ok"):
                warnings.append("could not build Repeater request for candidate %s" % idx)
                continue
            try:
                request_bytes = self.extender.helpers.stringToBytes(built.get("raw_request", ""))
            except:
                request_bytes = built.get("raw_request", "")
            try:
                self.extender.callbacks.sendToRepeater(
                    built.get("host", ""),
                    int(built.get("port", 443) or 443),
                    bool(built.get("https", True)),
                    request_bytes,
                    self._safe_ascii_text(base_label, 80)
                )
                created.append({"label": self._safe_ascii_text(base_label, 80), "url": built.get("url", ""), "mutation": "baseline"})
            except Exception as e:
                warnings.append("sendToRepeater baseline failed: %s" % self._safe_ascii_text(e, 300))
                continue

            structured_mutations = self._repeater_mutations(recipe)
            for mutation in structured_mutations:
                transformed = apply_raw_http_mutation(built.get("raw_request", ""), mutation)
                label = transformed.get("label", "mutation")
                tab_label = self._safe_ascii_text("DA q%s mutate %s" % (qid_int, label), 80)
                if not transformed.get("applied"):
                    warnings.append("mutation '%s' was not applied: %s" % (
                        label, "; ".join(transformed.get("errors", []) or ["no supported operations"])))
                    continue
                try:
                    mutated_bytes = self.extender.helpers.stringToBytes(transformed.get("raw_request", ""))
                except Exception:
                    mutated_bytes = transformed.get("raw_request", "")
                try:
                    self.extender.callbacks.sendToRepeater(
                        built.get("host", ""),
                        int(built.get("port", 443) or 443),
                        bool(built.get("https", True)),
                        mutated_bytes,
                        tab_label
                    )
                    created.append({
                        "label": tab_label,
                        "url": built.get("url", ""),
                        "mutation": label,
                        "mutation_applied": True,
                        "changes": transformed.get("changes", [])
                    })
                except Exception as e:
                    warnings.append("sendToRepeater mutation tab failed: %s" % self._safe_ascii_text(e, 300))

            if not structured_mutations:
                for label in self._repeater_mutation_labels(recipe):
                    warnings.append("mutation hint '%s' is descriptive only; provide structured mutations to create transformed Repeater tabs" % label)

        self._send_json(200, {
            "status": "ok",
            "engagement": self.extender._active_engagement_context(),
            "queue_id": qid_int,
            "created_tabs": created,
            "warnings": warnings,
            "mcp_preference": "Prefer a native PortSwigger/Burp MCP Repeater tool when callable in the agent session; this endpoint is the stable callbacks.sendToRepeater fallback.",
            "note": "Structured mutations are applied before Repeater tabs are created. Descriptive mutation_hint values remain manual guidance."
        })

    def _ensure_finding_poc_repeater(self, finding_ref, raw_request="", queue_id=None, force=False):
        """Create one durable, deduplicated PoC Repeater tab for a finding.

        Creating a Repeater tab does not execute the request. The exact request
        used to validate the finding is preserved as an editable Burp artifact.
        """
        idx = self.extender._finding_index_by_reference(finding_ref)
        if idx is None:
            return {"ok": False, "error": "finding_not_found", "finding_id": str(finding_ref or "")}
        with self.extender.findings_lock_ui:
            if idx < 0 or idx >= len(self.extender.findings_list):
                return {"ok": False, "error": "finding_not_found", "finding_id": str(finding_ref or "")}
            finding = dict(self.extender.findings_list[idx])
            stable_id = self.extender._ensure_finding_stable_id(self.extender.findings_list[idx])

        request_text = str(raw_request or finding.get("request_data", "") or "")
        if not request_text.strip():
            return {
                "ok": False,
                "error": "poc_request_required",
                "finding_id": stable_id,
                "message": "A valid finding requires the exact confirmed HTTP request for its PoC Repeater tab."
            }

        request_hash = hashlib.sha256(request_text.encode("utf-8", "replace")).hexdigest()
        existing = finding.get("poc_repeater", {}) or {}
        if (not force and bool(existing.get("created")) and
                str(existing.get("request_sha256", "")) == request_hash):
            result = dict(existing)
            result.update({"ok": True, "deduplicated": True, "finding_id": stable_id})
            return result

        parsed = self._split_raw_http_request(request_text)
        candidate = {
            "url": finding.get("url", ""),
            "request_data": request_text,
            "method": parsed.get("method", "GET")
        }
        target_url, host, port, protocol = self._candidate_url(candidate, parsed)
        if not host:
            return {
                "ok": False,
                "error": "poc_target_required",
                "finding_id": stable_id,
                "message": "Could not derive the PoC target service from the finding URL/request."
            }

        tab_name = self._safe_ascii_text("Finding %s" % stable_id, 80)
        try:
            request_bytes = self.extender.helpers.stringToBytes(request_text)
        except Exception:
            request_bytes = request_text
        try:
            self.extender.callbacks.sendToRepeater(
                host,
                int(port or (443 if protocol == "https" else 80)),
                bool(protocol == "https"),
                request_bytes,
                tab_name
            )
        except Exception as e:
            return {
                "ok": False,
                "error": "poc_repeater_create_failed",
                "finding_id": stable_id,
                "message": self._safe_ascii_text(e, 500)
            }

        artifact = {
            "created": True,
            "tab_name": tab_name,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "request_sha256": request_hash,
            "url": target_url or finding.get("url", ""),
            "queue_id": queue_id,
            "transport": "callbacks.sendToRepeater"
        }
        with self.extender.findings_lock_ui:
            current_idx = self.extender._finding_index_by_reference_unlocked(stable_id)
            if current_idx is not None and 0 <= current_idx < len(self.extender.findings_list):
                self.extender.findings_list[current_idx]["poc_repeater"] = dict(artifact)
                self.extender.findings_list[current_idx]["agent_updated_at"] = artifact["created_at"]
        result = dict(artifact)
        result.update({"ok": True, "deduplicated": False, "finding_id": stable_id})
        return result

    def _handle_finding_poc_repeater(self, fid):
        try:
            body = self._read_body()
        except Exception:
            body = {}
        result = self._ensure_finding_poc_repeater(
            fid,
            raw_request=body.get("request", body.get("raw_request", body.get("poc_request", ""))),
            queue_id=body.get("queue_id", None),
            force=bool(body.get("force", False))
        )
        if not result.get("ok"):
            status = 404 if result.get("error") == "finding_not_found" else 409
            self._send_json(status, result)
            return
        self.extender.save_findings()
        self.extender._ui_dirty = True
        self._send_json(200, {"status": "ok", "poc_repeater": result})

    def _scanner_candidate_from_body(self, body):
        """Resolve a scanner target from raw request, queue item, or finding id."""
        if not isinstance(body, dict):
            body = {}
        source = "raw_request"
        candidate = None
        warnings = []

        raw_request = body.get("request", body.get("raw_request", ""))
        if raw_request:
            candidate = {
                "source": "raw_request",
                "label": "raw request",
                "request_data": raw_request,
                "url": body.get("url", ""),
                "method": body.get("method", ""),
                "host": body.get("host", ""),
                "port": body.get("port", 0),
                "protocol": "https" if self._coerce_bool(body.get("https", True), True) else "http",
                "active_test_recipe": body.get("active_test_recipe", {})
            }
            return candidate, source, warnings

        queue_id = body.get("queue_id", body.get("agent_queue_id", None))
        if queue_id is not None and str(queue_id).strip() != "":
            try:
                qid_int = int(queue_id)
            except:
                return None, "queue", ["queue_id must be an integer"]
            item = self._get_queue_item_snapshot(qid_int)
            if item is None:
                return None, "queue", ["queue item not found"]
            findings_full = self._queue_findings_full(item)
            candidates = self._queue_target_candidates(item, findings_full)
            if not candidates:
                return None, "queue", ["queue item has no replayable HTTP request"]
            try:
                candidate_index = int(body.get("candidate_index", 0) or 0)
            except:
                candidate_index = 0
            if candidate_index < 0 or candidate_index >= len(candidates):
                return None, "queue", ["candidate_index out of range; available=%d" % len(candidates)]
            candidate = candidates[candidate_index]
            source = "queue"
            return candidate, source, warnings

        finding_id = body.get("finding_id", body.get("id", None))
        if finding_id is not None and str(finding_id).strip() != "":
            idx = self.extender._finding_index_by_reference(finding_id)
            if idx is None:
                return None, "finding", ["finding_id must be a valid numeric or stable finding id"]
            with self.extender.findings_lock_ui:
                if idx < 0 or idx >= len(self.extender.findings_list):
                    return None, "finding", ["finding not found"]
                finding = dict(self.extender.findings_list[idx])
            candidate = {
                "source": "finding",
                "label": "finding #%s" % finding_id,
                "request_data": finding.get("request_data", ""),
                "url": finding.get("url", ""),
                "method": "",
                "host": "",
                "port": 0,
                "protocol": "",
                "active_test_recipe": finding.get("active_test_recipe", {})
            }
            source = "finding"
            return candidate, source, warnings

        return None, "", ["provide request, queue_id, or finding_id"]

    def _scanner_job_findings(self, job):
        findings = []
        try:
            start_index = int(job.get("finding_start_index", 0) or 0)
        except:
            start_index = 0
        job_host = self.extender._url_host(job.get("url", ""))
        job_path = self.extender._normalized_url_path(job.get("url", ""))
        job_queue_id = str(job.get("queue_id", "") or "").strip()
        with self.extender.findings_lock_ui:
            for idx, finding in enumerate(self.extender.findings_list):
                if str(finding.get("source", "") or "") != "burp_scanner":
                    continue
                same_endpoint = (
                    self.extender._url_host(finding.get("url", "")) == job_host and
                    self.extender._normalized_url_path(finding.get("url", "")) == job_path
                )
                same_queue = job_queue_id and str(finding.get("agent_queue_id", "") or "").strip() == job_queue_id
                if idx < start_index and not same_endpoint and not same_queue:
                    continue
                if same_endpoint or same_queue:
                    findings.append({
                        "id": self.extender._ensure_finding_stable_id(finding),
                        "stable_id": self.extender._ensure_finding_stable_id(finding),
                        "legacy_numeric_id": self.extender._ensure_finding_legacy_numeric_id(finding, idx + 1),
                        "title": finding.get("title", ""),
                        "severity": finding.get("severity", ""),
                        "confidence": finding.get("confidence", ""),
                        "url": finding.get("url", ""),
                        "agent_status": finding.get("agent_status", ""),
                        "agent_priority": finding.get("agent_priority", "")
                    })
        return findings[:50]
