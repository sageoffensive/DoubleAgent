# -*- coding: utf-8 -*-
from double_agent_prelude import *

class AgentAPIChunk2Chunk2(object):
    def _handle_get_coverage(self, query):
        """Cross-reference Burp's site map with findings and queue results.

        Query params:
          host=<host>         - filter to one host (recommended; sitemap can be huge)
          in_scope_only=true  - only include in-scope URLs (default true)
          limit=<n>           - cap returned endpoints (default 500)

        An endpoint is a (METHOD, path-without-query) tuple. We collapse query strings
        because the same path with different params is usually the same endpoint to test.
        Findings and completed queue results are mapped onto their URL's
        (METHOD-from-request, path) when available.
        """
        try:
            try:
                limit = int(query.get("limit", ["500"])[0])
            except:
                limit = 500
            host_filter = (query.get("host", [""])[0] or "").strip().lower()
            in_scope_only = (query.get("in_scope_only", ["true"])[0] or "true").lower() != "false"
            include_static = (query.get("include_static", ["false"])[0] or "false").lower() == "true"
            summary_only = (query.get("summary", ["false"])[0] or "false").lower() == "true"

            ext = self.extender
            try:
                sitemap = ext._get_burp_site_map_snapshot() or []
            except Exception as e:
                self._send_json(500, {"error": "sitemap unavailable", "message": str(e)})
                return

            # Build endpoint set from sitemap
            endpoints = {}  # key: "METHOD path" -> {url, host, method, path, in_scope, response_count}
            static_asset_groups = {}
            try:
                from java.net import URL as _JavaURL
            except Exception:
                _JavaURL = None

            def static_asset_group(parsed_url):
                try:
                    path_l = str(parsed_url.path or "/").lower()
                except Exception:
                    path_l = ""
                static_exts = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                               ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif")
                static_markers = ("/static/", "/assets/", "/dist/", "/build/", "/chunks/", "/_next/",
                                  "/webpack/", "chunk", "bundle", "runtime", "remoteentry")
                if not path_l.endswith(static_exts) and not any(marker in path_l for marker in static_markers):
                    return ""
                if path_l.endswith(".js") or ".chunk.js" in path_l or "bundle" in path_l or "runtime" in path_l:
                    kind = "javascript_chunks"
                elif path_l.endswith(".css"):
                    kind = "stylesheets"
                elif path_l.endswith(".map"):
                    kind = "source_maps"
                elif path_l.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif")):
                    kind = "images"
                elif path_l.endswith((".woff", ".woff2", ".ttf", ".eot")):
                    kind = "fonts"
                else:
                    kind = "static_assets"
                directory = path_l.rsplit("/", 1)[0] or "/"
                return "%s:%s" % (kind, directory)

            def record_static_asset(host, parsed_url, url, method, source):
                group = static_asset_group(parsed_url)
                if not group:
                    return False
                key = "%s %s %s" % (host, method or "GET", group)
                item = static_asset_groups.setdefault(key, {
                    "host": host,
                    "method": method or "GET",
                    "group": group,
                    "count": 0,
                    "url_examples": [],
                    "sources": []
                })
                item["count"] += 1
                if url and len(item["url_examples"]) < 5 and url not in item["url_examples"]:
                    item["url_examples"].append(url)
                if source and source not in item["sources"]:
                    item["sources"].append(source)
                return True

            for item in sitemap:
                try:
                    url_str = str(item.getUrl() or "")
                    if not url_str:
                        continue
                    # Filter by host
                    try:
                        parsed_host = item.getHost() or ""
                    except Exception:
                        parsed_host = ""
                    if host_filter and parsed_host.lower() != host_filter:
                        continue
                    # Scope
                    in_scope = True
                    if in_scope_only and _JavaURL is not None:
                        try:
                            in_scope = bool(ext.callbacks.isInScope(_JavaURL(url_str)))
                        except Exception:
                            in_scope = True
                        if not in_scope:
                            continue
                    # Method & path
                    method = "GET"
                    path_only = url_str
                    try:
                        req_bytes = item.getRequest()
                        if req_bytes:
                            analyzed = ext.helpers.analyzeRequest(item)
                            method = str(analyzed.getMethod() or "GET")
                    except Exception:
                        pass
                    try:
                        from urlparse import urlparse as _urlparse
                    except ImportError:
                        from urllib.parse import urlparse as _urlparse
                    parsed = _urlparse(url_str)
                    if not include_static and record_static_asset(parsed_host.lower(), parsed, url_str, method, "sitemap"):
                        continue
                    path_only = self._coverage_path_template(url_str, method)
                    key = "%s %s%s" % (method, parsed_host, path_only)
                    if key not in endpoints:
                        endpoints[key] = {
                            "method": method,
                            "host": parsed_host,
                            "path": path_only,
                            "surface_class": self._coverage_surface_class(url_str),
                            "protocol": str(parsed.scheme or "http").lower(),
                            "url_example": url_str,
                            "in_scope": in_scope,
                            "has_response": False,
                            "finding_count": 0,
                            "finding_ids": [],
                            "queue_result_count": 0,
                            "queue_result_ids": [],
                            "queue_outcomes": [],
                            "queue_sources": [],
                        }
                    try:
                        if item.getResponse() is not None:
                            endpoints[key]["has_response"] = True
                    except Exception:
                        pass
                except Exception:
                    continue

            # Map findings onto endpoints
            with ext.findings_lock_ui:
                findings = list(ext.findings_list)

            try:
                from urlparse import urlparse as _urlparse
            except ImportError:
                from urllib.parse import urlparse as _urlparse

            for idx, f in enumerate(findings):
                if f.get("fp"):
                    continue
                furl = str(f.get("url", ""))
                if not furl:
                    continue
                try:
                    fp_parsed = _urlparse(furl)
                except Exception:
                    continue
                fhost = (fp_parsed.hostname or "").lower()
                if host_filter and fhost != host_filter:
                    continue
                if not include_static and record_static_asset(fhost, fp_parsed, furl, "GET", "finding"):
                    continue
                # Try to extract method from request_data
                fmethod = "GET"
                req_data = f.get("request_data") or ""
                if req_data:
                    try:
                        first_line = str(req_data).split("\n", 1)[0].strip()
                        parts = first_line.split(" ")
                        if parts and parts[0].isupper() and len(parts[0]) <= 8:
                            fmethod = parts[0]
                    except Exception:
                        pass
                fpath = self._coverage_path_template(furl, fmethod)
                finding_stable_id = ext._ensure_finding_stable_id(f)
                # Match against any method for this path (loose match)
                matched = False
                for key, ep in endpoints.items():
                    if ep["host"].lower() == fhost and ep["path"] == fpath:
                        if ep["method"] == fmethod or fmethod == "GET":
                            ep["finding_count"] += 1
                            ep["finding_ids"].append(finding_stable_id)
                            matched = True
                            break
                if not matched:
                    # Endpoint not in sitemap (e.g. agent-discovered) - add synthetic entry
                    key = "%s %s%s" % (fmethod, fhost, fpath)
                    endpoints[key] = {
                        "method": fmethod,
                        "host": fhost,
                        "path": fpath,
                        "surface_class": self._coverage_surface_class(furl),
                        "protocol": str(fp_parsed.scheme or "http").lower(),
                        "url_example": furl,
                        "in_scope": True,
                        "has_response": True,
                        "finding_count": 1,
                        "finding_ids": [finding_stable_id],
                        "queue_result_count": 0,
                        "queue_result_ids": [],
                        "queue_outcomes": [],
                        "queue_sources": [],
                        "from": "finding_only",
                    }

            def method_from_request(req_data, default_method):
                method = default_method or "GET"
                if req_data:
                    try:
                        first_line = str(req_data).split("\n", 1)[0].strip()
                        parts = first_line.split(" ")
                        if parts and parts[0].isupper() and len(parts[0]) <= 12:
                            method = parts[0]
                    except Exception:
                        pass
                return method or "GET"

            def endpoint_url_in_scope(url):
                if not in_scope_only or _JavaURL is None:
                    return True
                try:
                    return bool(ext.callbacks.isInScope(_JavaURL(url)))
                except Exception:
                    return True

            def add_queue_endpoint(q, url, method, source):
                url = str(url or "")
                if not url:
                    return
                try:
                    parsed = _urlparse(url)
                except Exception:
                    return
                qhost = (parsed.hostname or "").lower()
                if not qhost:
                    return
                if host_filter and qhost != host_filter:
                    return
                if not endpoint_url_in_scope(url):
                    return
                if not include_static and record_static_asset(qhost, parsed, url, method or "GET", source or "queue_result"):
                    return
                qmethod = method or "GET"
                qpath = self._coverage_path_template(url, qmethod)
                matched = False
                for key, ep in endpoints.items():
                    if ep["host"].lower() == qhost and ep["path"] == qpath:
                        if ep["method"] == qmethod or qmethod == "GET":
                            ep["queue_result_count"] = ep.get("queue_result_count", 0) + 1
                            ep.setdefault("queue_result_ids", []).append(q.get("id"))
                            outcome = q.get("outcome", "inconclusive") or "inconclusive"
                            if outcome not in ep.setdefault("queue_outcomes", []):
                                ep["queue_outcomes"].append(outcome)
                            if source and source not in ep.setdefault("queue_sources", []):
                                ep["queue_sources"].append(source)
                            matched = True
                            break
                if not matched:
                    key = "%s %s%s" % (qmethod, qhost, qpath)
                    endpoints[key] = {
                        "method": qmethod,
                        "host": qhost,
                        "path": qpath,
                        "surface_class": self._coverage_surface_class(url),
                        "protocol": str(parsed.scheme or "http").lower(),
                        "url_example": url,
                        "in_scope": True,
                        "has_response": bool(q.get("response_data") or q.get("status_code")),
                        "finding_count": 0,
                        "finding_ids": [],
                        "queue_result_count": 1,
                        "queue_result_ids": [q.get("id")],
                        "queue_outcomes": [q.get("outcome", "inconclusive") or "inconclusive"],
                        "queue_sources": [source] if source else [],
                        "from": "queue_result",
                    }

            def iter_text_values(value, depth=0):
                if depth > 4 or value is None:
                    return
                if isinstance(value, dict):
                    for v in value.values():
                        for text in iter_text_values(v, depth + 1):
                            yield text
                elif isinstance(value, list):
                    for v in value[:100]:
                        for text in iter_text_values(v, depth + 1):
                            yield text
                else:
                    text = str(value or "")
                    if text:
                        yield self._limit_text(text, 12000)

            def urls_from_text(text):
                urls = []
                seen_urls = set()
                text = str(text or "")
                try:
                    for match in re.finditer(r'https?://[^\s"\'<>]+', text):
                        url = match.group(0).rstrip(").,;]")
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            urls.append((url, "GET"))
                            if len(urls) >= 50:
                                return urls
                except Exception:
                    pass
                try:
                    host_match = re.search(r'(?im)^Host:\s*([^\s\r\n]+)', text)
                    host = host_match.group(1).strip() if host_match else ""
                    for match in re.finditer(r'(?im)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', text):
                        method = match.group(1).upper()
                        target = match.group(2).strip()
                        if target.lower().startswith("http://") or target.lower().startswith("https://"):
                            url = target
                        elif host:
                            url = "https://%s%s" % (host, target if target.startswith("/") else "/" + target)
                        else:
                            continue
                        url = url.rstrip(").,;]")
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            urls.append((url, method))
                            if len(urls) >= 50:
                                return urls
                except Exception:
                    pass
                return urls

            def add_queue_endpoints_from_value(q, value, source):
                for text in iter_text_values(value):
                    for url, method in urls_from_text(text):
                        add_queue_endpoint(q, url, method, source)

            def add_queue_endpoints_from_linked_findings(q, source):
                ids = []
                linked_fields = (
                    (q.get("finding_ids", []) or []) +
                    (q.get("agent_generated_finding_ids", []) or []) +
                    (q.get("scanner_findings_seen_during_work", []) or []) +
                    (q.get("passive_findings_seen_during_work", []) or [])
                )
                for fid in linked_fields:
                    try:
                        fid_int = int(fid)
                    except Exception:
                        continue
                    if fid_int not in ids:
                        ids.append(fid_int)
                if not ids:
                    return
                for fid in ids:
                    if fid < 0 or fid >= len(findings):
                        continue
                    finding = findings[fid]
                    if finding.get("fp"):
                        continue
                    method = method_from_request(finding.get("request_data"), "GET")
                    add_queue_endpoint(q, finding.get("url", ""), method, source or "linked_finding")

            with ext.agent_queue_lock:
                queue_items = [dict(q) for q in ext.agent_queue]
                queue_items.extend([dict(q) for q in getattr(ext, "completed_agent_results", [])])

            for q in queue_items:
                if q.get("status") != "completed":
                    # Long-running campaigns (including Try Harder discovery)
                    # persist visited/tested URLs as step artifacts before the
                    # final result. Count those artifacts as in-progress
                    # coverage so the completion gate can measure real
                    # discovery progress without requiring premature closure.
                    if q.get("status") == "claimed" and q.get("campaign_state"):
                        for step in (q.get("campaign_state", {}) or {}).get("steps", []) or []:
                            if step.get("status") not in ("completed", "blocked", "skipped"):
                                continue
                            add_queue_endpoints_from_value(
                                q,
                                step.get("artifacts", []),
                                "in_progress_campaign:%s" % str(step.get("key", "step"))
                            )
                    continue
                source = q.get("source", "")
                if str(source).startswith("websocket"):
                    continue
                if q.get("flow_requests"):
                    for step in q.get("flow_requests", []):
                        if not isinstance(step, dict):
                            continue
                        step_url = step.get("url", "")
                        step_method = method_from_request(step.get("request_data"), step.get("method", "GET"))
                        add_queue_endpoint(q, step_url, step_method, source or "flow_analysis")
                    add_queue_endpoints_from_linked_findings(q, source or "linked_finding")
                    for field in ("reproduction", "assessment", "test_results", "evidence",
                                  "risk_hunt_goals", "notes", "amendments"):
                        add_queue_endpoints_from_value(q, q.get(field, ""), source or "queue_result_evidence")
                    continue
                q_url = q.get("url", "")
                q_method = method_from_request(q.get("request_data"), q.get("method", "GET"))
                add_queue_endpoint(q, q_url, q_method, source)
                add_queue_endpoints_from_linked_findings(q, source or "linked_finding")
                for field in ("request_data", "reproduction", "assessment", "test_results", "evidence",
                              "risk_hunt_goals", "notes", "amendments"):
                    add_queue_endpoints_from_value(q, q.get(field, ""), source or "queue_result_evidence")

            ep_list = list(endpoints.values())
            for ep in ep_list:
                finding_count = ep.get("finding_count", 0)
                queue_count = ep.get("queue_result_count", 0)
                if finding_count > 0 and queue_count > 0:
                    ep["coverage_status"] = "finding_and_queue_result"
                elif finding_count > 0:
                    ep["coverage_status"] = "finding"
                elif queue_count > 0:
                    ep["coverage_status"] = "queue_result"
                else:
                    ep["coverage_status"] = "untested"

            tested = [e for e in ep_list if e.get("finding_count", 0) > 0 or e.get("queue_result_count", 0) > 0]
            untested = [e for e in ep_list if e.get("finding_count", 0) == 0 and e.get("queue_result_count", 0) == 0]
            by_class = {}
            by_protocol = {}
            for endpoint in ep_list:
                surface_class = endpoint.get("surface_class", "application")
                bucket = by_class.setdefault(surface_class, {"endpoints": 0, "tested": 0, "untested": 0})
                bucket["endpoints"] += 1
                if endpoint.get("finding_count", 0) > 0 or endpoint.get("queue_result_count", 0) > 0:
                    bucket["tested"] += 1
                else:
                    bucket["untested"] += 1
                protocol = endpoint.get("protocol", "unknown") or "unknown"
                protocol_bucket = by_protocol.setdefault(protocol, {"endpoints": 0, "tested": 0, "untested": 0})
                protocol_bucket["endpoints"] += 1
                if endpoint.get("finding_count", 0) > 0 or endpoint.get("queue_result_count", 0) > 0:
                    protocol_bucket["tested"] += 1
                else:
                    protocol_bucket["untested"] += 1
            for bucket in by_class.values():
                bucket["coverage_percent"] = round(100.0 * bucket["tested"] / bucket["endpoints"], 1) if bucket["endpoints"] else 0.0
            for bucket in by_protocol.values():
                bucket["coverage_percent"] = round(100.0 * bucket["tested"] / bucket["endpoints"], 1) if bucket["endpoints"] else 0.0

            # Sort untested with response first (more interesting), capped
            untested.sort(key=lambda e: (not e["has_response"], e["host"], e["path"]))
            tested.sort(key=lambda e: (e["coverage_status"] == "queue_result", -e.get("finding_count", 0), -e.get("queue_result_count", 0), e["host"], e["path"]))

            response = {
                "host_filter": host_filter or None,
                "in_scope_only": in_scope_only,
                "summary_only": summary_only,
                "totals": {
                    "endpoints": len(ep_list),
                    "covered": len(tested),
                    "tested": len(tested),
                    "untested": len(untested),
                    "static_asset_groups": len(static_asset_groups),
                    "static_asset_requests_grouped": sum([g.get("count", 0) for g in static_asset_groups.values()]),
                    "coverage_percent": round(100.0 * len(tested) / len(ep_list), 1) if ep_list else 0.0,
                    "by_surface_class": by_class,
                    "by_protocol": by_protocol,
                },
                "untested": untested[:limit],
                "tested": tested[:limit],
                "static_asset_groups": list(static_asset_groups.values())[:limit],
                "note": "Endpoints are (METHOD, host, path) - query strings collapsed. Static assets/chunks are grouped out of the default denominator; pass include_static=true to include them as endpoints. 'untested' = no finding and no completed queue result recorded for that endpoint. Completed queue results count as coverage even when the outcome is not-vulnerable, needs-more-info, or inconclusive.",
            }
            if summary_only:
                def compact_endpoint(endpoint):
                    return {
                        "method": endpoint.get("method", "GET"),
                        "host": endpoint.get("host", ""),
                        "path": endpoint.get("path", "/"),
                        "url_example": endpoint.get("url_example", ""),
                        "has_response": bool(endpoint.get("has_response")),
                        "coverage_status": endpoint.get("coverage_status", "untested"),
                    }
                # Summary is a prioritization view, not counts-only. Keep a
                # bounded actionable list and link to the paged full result.
                summary_limit = min(25, max(1, int(limit or 25)))
                response["untested"] = [compact_endpoint(item) for item in untested[:summary_limit]]
                response["tested"] = [compact_endpoint(item) for item in tested[:min(10, summary_limit)]]
                response["static_asset_groups"] = []
                response["full_coverage"] = "/api/coverage"
            self._send_json(200, response)
        except Exception as e:
            self._send_json(500, {"error": "coverage failed", "message": str(e)})

    def _coverage_totals_snapshot(self):
        """Return current in-scope dynamic endpoint coverage without emitting HTTP."""
        captured = {}
        original_send_json = self._send_json

        def capture(status, payload):
            captured["status"] = status
            captured["payload"] = payload

        try:
            self._send_json = capture
            self._handle_get_coverage({
                "in_scope_only": ["true"],
                "include_static": ["false"],
                "limit": ["1"]
            })
        finally:
            self._send_json = original_send_json
        payload = captured.get("payload", {}) or {}
        totals = payload.get("totals", {}) if isinstance(payload, dict) else {}
        return {
            "available": captured.get("status") == 200 and bool(totals),
            "endpoints": int(totals.get("endpoints", 0) or 0),
            "covered": int(totals.get("covered", 0) or 0),
            "untested": int(totals.get("untested", 0) or 0),
            "coverage_percent": float(totals.get("coverage_percent", 0.0) or 0.0),
            "measured_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _handle_get_parameter_coverage(self, query):
        """Cross-reference Burp's site map with findings and queue results by parameter."""
        try:
            try:
                limit = int(query.get("limit", ["500"])[0])
            except:
                limit = 500
            host_filter = (query.get("host", [""])[0] or "").strip().lower()
            in_scope_only = (query.get("in_scope_only", ["true"])[0] or "true").lower() != "false"
            include_headers = (query.get("include_headers", ["false"])[0] or "false").lower() == "true"
            summary_only = (query.get("summary", ["false"])[0] or "false").lower() == "true"
            ext = self.extender
            try:
                from java.net import URL as _JavaURL
            except Exception:
                _JavaURL = None

            try:
                sitemap = ext._get_burp_site_map_snapshot() or []
            except Exception as e:
                self._send_json(500, {"error": "sitemap unavailable", "message": str(e)})
                return

            type_names = {
                0: "query",
                1: "body",
                2: "cookie",
                3: "xml",
                4: "xml_attr",
                5: "multipart",
                6: "json"
            }
            params = {}

            def parsed_url_parts(url):
                parsed = urlparse.urlparse(str(url or ""))
                return (parsed.hostname or "").lower(), parsed.path or "/", parsed

            def endpoint_in_scope(url):
                if not in_scope_only or _JavaURL is None:
                    return True
                try:
                    return bool(ext.callbacks.isInScope(_JavaURL(str(url or ""))))
                except Exception:
                    return True

            def add_param(method, host, path, name, ptype, url, source, has_response=False):
                host = str(host or "").lower()
                name = str(name or "").strip()
                if not host or not name:
                    return None
                if host_filter and host != host_filter:
                    return None
                ptype = str(ptype or "unknown").strip().lower() or "unknown"
                key = "%s %s %s %s %s" % (str(method or "GET").upper(), host, path or "/", ptype, name)
                item = params.setdefault(key, {
                    "method": str(method or "GET").upper(),
                    "host": host,
                    "path": path or "/",
                    "parameter": name,
                    "type": ptype,
                    "surface_class": self._coverage_surface_class(url, name, ptype),
                    "protocol": str((urlparse.urlparse(str(url or "")).scheme or "http")).lower(),
                    "url_example": str(url or ""),
                    "has_response": bool(has_response),
                    "sources": [],
                    "finding_ids": [],
                    "queue_result_ids": [],
                    "queue_outcomes": []
                })
                if has_response:
                    item["has_response"] = True
                if source and source not in item["sources"]:
                    item["sources"].append(source)
                if url and not item.get("url_example"):
                    item["url_example"] = str(url)
                return item

            def collect_json_names(value, prefix="", depth=0):
                names = []
                if depth > 4:
                    return names
                if isinstance(value, dict):
                    for key, val in value.items():
                        name = str(key or "").strip()
                        if name:
                            full = ("%s.%s" % (prefix, name)) if prefix else name
                            names.append(full)
                            names.extend(collect_json_names(val, full, depth + 1))
                elif isinstance(value, list):
                    for val in value[:20]:
                        names.extend(collect_json_names(val, prefix, depth + 1))
                return names

            def request_parameter_triplets(req_data, url_hint=""):
                triplets = []
                parsed = self._split_raw_http_request(req_data)
                target = parsed.get("target", "") or url_hint or ""
                url_for_query = target if str(target).lower().startswith(("http://", "https://")) else url_hint
                if url_for_query:
                    try:
                        parsed_url = urlparse.urlparse(url_for_query)
                        for name, value in urlparse.parse_qsl(parsed_url.query, keep_blank_values=True):
                            if name:
                                triplets.append((name, "query"))
                    except Exception:
                        pass
                content_type = self._header_from_pairs(parsed.get("headers", []), "Content-Type").lower()
                cookie_header = self._header_from_pairs(parsed.get("headers", []), "Cookie")
                if cookie_header:
                    for piece in cookie_header.split(";"):
                        if "=" in piece:
                            name = piece.split("=", 1)[0].strip()
                            if name:
                                triplets.append((name, "cookie"))
                if include_headers:
                    for header in parsed.get("headers", []):
                        name = str(header.get("name", "") or "").strip()
                        name_l = name.lower()
                        if name and (name_l.startswith("x-") or name_l in ("authorization", "origin", "referer", "content-type")):
                            triplets.append((name, "header"))
                body = parsed.get("body", "") or ""
                if body:
                    if "application/json" in content_type or body.strip().startswith(("{", "[")):
                        try:
                            for name in collect_json_names(json.loads(body)):
                                triplets.append((name, "json"))
                        except Exception:
                            pass
                    elif "xml" in content_type or body.strip().startswith("<"):
                        try:
                            for match in re.finditer(r'<\s*([A-Za-z_][A-Za-z0-9_.:-]*)', body):
                                triplets.append((match.group(1), "xml"))
                            for match in re.finditer(r'\s([A-Za-z_][A-Za-z0-9_.:-]*)\s*=', body):
                                triplets.append((match.group(1), "xml_attr"))
                        except Exception:
                            pass
                    elif "multipart/form-data" in content_type:
                        try:
                            for match in re.finditer(r'(?i)name="([^"]+)"', body):
                                triplets.append((match.group(1), "multipart"))
                        except Exception:
                            pass
                    else:
                        try:
                            for name, value in urlparse.parse_qsl(body, keep_blank_values=True):
                                if name:
                                    triplets.append((name, "body"))
                        except Exception:
                            pass
                seen = set()
                unique = []
                for name, ptype in triplets:
                    key = "%s:%s" % (ptype, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    unique.append((name, ptype))
                return unique

            for item in sitemap:
                try:
                    url_str = str(item.getUrl() or "")
                    if not url_str or not endpoint_in_scope(url_str):
                        continue
                    host, path, parsed_url = parsed_url_parts(url_str)
                    if host_filter and host != host_filter:
                        continue
                    method = "GET"
                    has_response = False
                    try:
                        req_bytes = item.getRequest()
                        if req_bytes:
                            analyzed = ext.helpers.analyzeRequest(item)
                            method = str(analyzed.getMethod() or "GET").upper()
                            path = self._coverage_path_template(url_str, method)
                            for param in analyzed.getParameters() or []:
                                try:
                                    ptype = type_names.get(int(param.getType()), "type_%s" % str(param.getType()))
                                except Exception:
                                    ptype = "unknown"
                                add_param(method, host, path, str(param.getName()), ptype, url_str, "sitemap", has_response)
                    except Exception:
                        pass
                    try:
                        has_response = item.getResponse() is not None
                    except Exception:
                        has_response = False
                    if parsed_url.query:
                        for name, value in urlparse.parse_qsl(parsed_url.query, keep_blank_values=True):
                            add_param(method, host, path, name, "query", url_str, "sitemap", has_response)
                    if has_response:
                        for p in params.values():
                            if p.get("host") == host and p.get("path") == path and p.get("method") == method:
                                p["has_response"] = True
                except Exception:
                    continue

            with ext.findings_lock_ui:
                findings = list(ext.findings_list)

            def mark_covered(url, req_data, finding_id=None, queue_id=None, outcome=""):
                host, path, parsed_url = parsed_url_parts(url)
                if not host:
                    return
                if host_filter and host != host_filter:
                    return
                method = "GET"
                if req_data:
                    method = self._split_raw_http_request(req_data).get("method", "GET")
                path = self._coverage_path_template(url, method)
                for name, ptype in request_parameter_triplets(req_data, url):
                    item = add_param(method, host, path, name, ptype, url, "finding" if finding_id else "queue_result", True)
                    if not item:
                        continue
                    if finding_id and finding_id not in item["finding_ids"]:
                        item["finding_ids"].append(finding_id)
                    if queue_id and queue_id not in item["queue_result_ids"]:
                        item["queue_result_ids"].append(queue_id)
                    if outcome and outcome not in item["queue_outcomes"]:
                        item["queue_outcomes"].append(outcome)

            for idx, finding in enumerate(findings):
                if finding.get("fp"):
                    continue
                mark_covered(finding.get("url", ""), finding.get("request_data", ""),
                             finding_id=ext._ensure_finding_stable_id(finding))

            with ext.agent_queue_lock:
                queue_items = [dict(q) for q in ext.agent_queue]
                queue_items.extend([dict(q) for q in getattr(ext, "completed_agent_results", [])])
            for q in queue_items:
                if q.get("status") != "completed":
                    continue
                mark_covered(q.get("url", ""), q.get("request_data", ""), queue_id=q.get("id"), outcome=q.get("outcome", ""))
                for step in q.get("flow_requests", []) or []:
                    if isinstance(step, dict):
                        mark_covered(step.get("url", ""), step.get("request_data", ""), queue_id=q.get("id"), outcome=q.get("outcome", ""))
                for ev in q.get("evidence", []) or []:
                    if isinstance(ev, dict):
                        mark_covered(ev.get("url", ""), ev.get("request", ""), queue_id=q.get("id"), outcome=q.get("outcome", ""))

            param_list = list(params.values())
            for item in param_list:
                if item.get("finding_ids") and item.get("queue_result_ids"):
                    item["coverage_status"] = "finding_and_queue_result"
                elif item.get("finding_ids"):
                    item["coverage_status"] = "finding"
                elif item.get("queue_result_ids"):
                    item["coverage_status"] = "queue_result"
                else:
                    item["coverage_status"] = "untested"

            tested = [p for p in param_list if p.get("finding_ids") or p.get("queue_result_ids")]
            untested = [p for p in param_list if not p.get("finding_ids") and not p.get("queue_result_ids")]
            meaningful = [p for p in param_list if p.get("surface_class", "application") == "application"]
            meaningful_tested = [p for p in meaningful if p.get("finding_ids") or p.get("queue_result_ids")]
            meaningful_untested = [p for p in meaningful if not p.get("finding_ids") and not p.get("queue_result_ids")]
            by_class = {}
            by_protocol = {}
            for parameter in param_list:
                surface_class = parameter.get("surface_class", "application")
                bucket = by_class.setdefault(surface_class, {"parameters": 0, "tested": 0, "untested": 0})
                bucket["parameters"] += 1
                if parameter.get("finding_ids") or parameter.get("queue_result_ids"):
                    bucket["tested"] += 1
                else:
                    bucket["untested"] += 1
                protocol = parameter.get("protocol", "unknown") or "unknown"
                protocol_bucket = by_protocol.setdefault(protocol, {"parameters": 0, "tested": 0, "untested": 0})
                protocol_bucket["parameters"] += 1
                if parameter.get("finding_ids") or parameter.get("queue_result_ids"):
                    protocol_bucket["tested"] += 1
                else:
                    protocol_bucket["untested"] += 1
            for bucket in by_class.values():
                bucket["coverage_percent"] = round(100.0 * bucket["tested"] / bucket["parameters"], 1) if bucket["parameters"] else 0.0
            for bucket in by_protocol.values():
                bucket["coverage_percent"] = round(100.0 * bucket["tested"] / bucket["parameters"], 1) if bucket["parameters"] else 0.0
            untested.sort(key=lambda p: (not p.get("has_response", False), p.get("host", ""), p.get("path", ""), p.get("type", ""), p.get("parameter", "")))
            tested.sort(key=lambda p: (p.get("coverage_status", ""), p.get("host", ""), p.get("path", ""), p.get("type", ""), p.get("parameter", "")))

            self._send_json(200, {
                "host_filter": host_filter or None,
                "in_scope_only": in_scope_only,
                "include_headers": include_headers,
                "totals": {
                    "parameters": len(param_list),
                    "covered": len(tested),
                    "tested": len(tested),
                    "untested": len(untested),
                    "coverage_percent": round(100.0 * len(tested) / len(param_list), 1) if param_list else 0.0,
                    "meaningful_inputs": len(meaningful),
                    "meaningful_tested": len(meaningful_tested),
                    "meaningful_untested": len(meaningful_untested),
                    "meaningful_coverage_percent": round(100.0 * len(meaningful_tested) / len(meaningful), 1) if meaningful else 0.0,
                    "by_surface_class": by_class,
                    "by_protocol": by_protocol
                },
                "summary_only": summary_only,
                "meaningful_untested": [] if summary_only else meaningful_untested[:limit],
                "meaningful_tested": [] if summary_only else meaningful_tested[:limit],
                "untested": [] if summary_only else untested[:limit],
                "tested": [] if summary_only else tested[:limit],
                "full_coverage": "/api/coverage/parameters" if summary_only else "",
                "note": "Parameters are grouped by METHOD, host, path, parameter type, and parameter name. Use this with /api/agent/campaign/crawl-audit and Burp MCP scanner delegation so endpoint-level coverage does not hide untested insertion points."
            })
        except Exception as e:
            self._send_json(500, {"error": "parameter coverage failed", "message": str(e)})

    def _handle_get_report(self, query=None):
        """Return live findings.md-style markdown rendered from current findings state."""
        try:
            query = query or {}
            summary_only = self._bool_query_value(query, "summary", "false")
            with self.extender.findings_lock_ui:
                findings = [dict(f) for f in self.extender.findings_list if not self.extender._finding_hidden_from_normal_view(f)]
            severity_counts = {}
            for finding in findings:
                severity = str(finding.get("severity", "Information") or "Information")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            summary = {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "agent_b_validated": len([f for f in findings if str(f.get("agent_validated_by", "")) == "B"]),
                "finding_ids": [self.extender._ensure_finding_stable_id(f) for f in findings],
            }
            if summary_only:
                self._send_json(200, {"summary": summary, "full_report": "/api/report"})
                return
            md = self.extender._build_report_markdown()
            self._send_json(200, {
                "summary": summary,
                "markdown": md,
                "length": len(md),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception as e:
            self._send_json(500, {"error": "report build failed", "message": str(e)})

    def _handle_list_queue(self, query=None):
        with self.extender.agent_queue_lock:
            items = []
            for q in self.extender.agent_queue:
                findings_full = self._queue_findings_full(q)
                next_action = self._queue_operational_metadata(q, findings_full)
                campaign_state = q.get("campaign_state", {}) or {}
                campaign_options = q.get("campaign_options", {}) or {}
                items.append({
                    "id": q.get("id"),
                    "status": q.get("status"),
                    "outcome": q.get("outcome", ""),
                    "created_at": q.get("created_at"),
                    "claimed_at": q.get("claimed_at"),
                    "completed_at": q.get("completed_at"),
                    "result_updated_at": q.get("result_updated_at", ""),
                    "findings_count": len(q.get("finding_ids", [])),
                    "summary": q.get("summary", ""),
                    "source": q.get("source", ""),
                    "user_context_preview": self._limit_text(q.get("user_context", ""), 500),
                    "browser_verify": bool(q.get("browser_verify", False)),
                    "detail_required": True,
                    "detail_endpoint": "/api/agent/queue/%s" % q.get("id"),
                    "campaign_type": q.get("campaign_type", ""),
                    "request_budget": campaign_state.get("request_budget"),
                    "requests_used": campaign_state.get("requests_used", 0),
                    "completion_constraints": {
                        "minimum_routes": campaign_options.get("minimum_routes"),
                        "minimum_browser_routes": campaign_options.get("minimum_browser_routes"),
                        "required_stable_passes": campaign_options.get("required_stable_passes"),
                        "stable_max_new_routes": campaign_options.get("stable_max_new_routes"),
                        "stable_max_new_parameters": campaign_options.get("stable_max_new_parameters"),
                        "expected_roles": campaign_options.get("expected_roles", []),
                    },
                    "fixture_blocked": bool((next_action.get("fixture_status", {}) or {}).get("blocked", False)),
                    "state_change_requires_confirmation": bool((next_action.get("safety_gate", {}) or {}).get("requires_confirmation", False)),
                    "state_change_policy": {
                        "requires_confirmation": bool((next_action.get("safety_gate", {}) or {}).get("requires_confirmation", False)),
                        "allowed_rule_count": len((getattr(self.extender, "project_profile", {}) or {}).get("allowed_state_changes", []) or [])
                                              if self.extender._engagement_bound_record_is_current(getattr(self.extender, "project_profile", {}) or {}) else 0,
                        "detail_field": "next_action.safety_gate",
                    },
                    "next_action": next_action
                })
        self._send_json(200, {"queue": items, "count": len(items),
                              "guidance": "Queue summaries expose critical constraints but are not the execution contract; read detail_endpoint before claiming or testing."})
