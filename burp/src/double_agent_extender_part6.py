# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk6(object):
    def _apply_agent_note_header(self, messageInfo):
        """Move X-Eternals-Agent-Note into Burp's history comment and strip it upstream."""
        try:
            request_bytes = messageInfo.getRequest()
            if not request_bytes:
                return False

            req = self.helpers.analyzeRequest(messageInfo)
            headers = list(req.getHeaders())
            clean_headers = []
            note = ""
            header_name = "x-eternals-agent-note:"

            for header in headers:
                header_s = str(header)
                if header_s.lower().startswith(header_name):
                    note = header_s[len(header_name):].strip()
                    continue
                clean_headers.append(header)

            if not note:
                return False

            if len(note) > 250:
                note = note[:250]
            existing = ""
            try:
                existing = str(messageInfo.getComment() or "")
            except:
                existing = ""
            if existing and existing != note:
                messageInfo.setComment(existing + " | " + note)
            else:
                messageInfo.setComment(note)

            body = request_bytes[req.getBodyOffset():]
            messageInfo.setRequest(self.helpers.buildHttpMessage(clean_headers, body))
            if self.VERBOSE:
                self.stdout.println("[AGENT NOTE] Added Proxy history note and stripped X-Eternals-Agent-Note header")
            return True
        except Exception as e:
            try:
                self.stderr.println("[AGENT NOTE] Failed to apply note header: %s" % self._safe_ascii_text(e))
            except:
                pass
            return False

    def should_skip_extension(self, url):
        """Check if URL has a file extension that should be skipped (static files)"""
        try:
            # Get the path from URL, removing query string
            path = url.split('?')[0].lower()
            # Get the extension (last part after the final dot in the filename)
            if '/' in path:
                filename = path.split('/')[-1]
            else:
                filename = path
            if '.' in filename:
                ext = filename.split('.')[-1]
                # Check against set of skip extensions (converted to set for faster lookup)
                skip_exts = set(self.SKIP_EXTENSIONS)
                if ext in skip_exts:
                    if self.VERBOSE:
                        self.stdout.println("[SKIP] Static file extension: .%s - %s" % (ext, url[:80]))
                    return True
                # Also check common case variations
                if ext.lower() in skip_exts:
                    if self.VERBOSE:
                        self.stdout.println("[SKIP] Static file extension (lowercase): .%s - %s" % (ext, url[:80]))
                    return True
            return False
        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[SKIP] Extension check error: %s" % self._safe_ascii_text(e))
            return False

    def _url_extension(self, url):
        try:
            path = str(url or "").split("?", 1)[0].lower()
            filename = path.rsplit("/", 1)[-1]
            if "." not in filename:
                return ""
            return filename.rsplit(".", 1)[-1]
        except:
            return ""

    def _is_javascript_url(self, url):
        ext = self._url_extension(url)
        if ext in ("js", "mjs", "cjs"):
            return True
        path = str(url or "").split("?", 1)[0].lower()
        return path.endswith(".chunk.js") or path.endswith(".bundle.js") or path.endswith("/remoteentry.js")

    def _passive_request_priority(self, req, url_str, messageInfo=None):
        """Score proxy traffic so high-signal requests are not dropped by coarse intake throttles."""
        score = 0
        reasons = []
        try:
            method = str(req.getMethod() or "").upper()
        except:
            method = ""
        url_l = str(url_str or "").lower()
        path_l = url_l.split("?", 1)[0]

        if method not in ("", "GET", "HEAD", "OPTIONS"):
            score += 2
            reasons.append("method:%s" % method)

        high_value_markers = [
            "/api/", "/graphql", "/auth", "/login", "/logout", "/session", "/sessions",
            "/token", "/oauth", "/sso", "/mfa", "/member", "/members", "/account",
            "/user", "/users", "/profile", "/policy", "/claim", "/claims", "/payment",
            "/billing", "/admin", "/preferences", "/personalisedcontent"
        ]
        for marker in high_value_markers:
            if marker in path_l:
                score += 2
                reasons.append("path:%s" % marker)
                break

        if self._is_javascript_url(url_str):
            score += 1
            reasons.append("javascript")

        try:
            params = req.getParameters()
            non_cookie_params = 0
            for p in params:
                try:
                    if int(p.getType()) != 2:
                        non_cookie_params += 1
                except:
                    non_cookie_params += 1
            if non_cookie_params > 0:
                score += 1
                reasons.append("params:%d" % non_cookie_params)
        except:
            pass

        try:
            headers_l = "\n".join([str(h).lower() for h in req.getHeaders()])
            if ("authorization:" in headers_l or "cookie:" in headers_l or
                    "x-api" in headers_l or "x-auth" in headers_l or "csrf" in headers_l):
                score += 1
                reasons.append("auth_headers")
            if ("content-type:" in headers_l and
                    ("json" in headers_l or "x-www-form-urlencoded" in headers_l or "graphql" in headers_l)):
                score += 1
                reasons.append("structured_body")
        except:
            pass

        try:
            if messageInfo is not None and messageInfo.getResponse() is not None:
                res = self.helpers.analyzeResponse(messageInfo.getResponse())
                status = int(res.getStatusCode())
                if status in (401, 403, 404, 409, 429, 500):
                    score += 1
                    reasons.append("status:%d" % status)
                response_headers_l = "\n".join([str(h).lower() for h in res.getHeaders()[:20]])
                if "application/json" in response_headers_l or "graphql" in response_headers_l:
                    score += 1
                    reasons.append("json_response")
        except:
            pass

        try:
            if score > 10:
                score = 10
        except:
            pass
        return score, reasons

    def _passive_http_tool_source(self, toolFlag):
        """Return the Agent A source label for Burp traffic that should be analyzed."""
        try:
            flag = int(toolFlag)
        except Exception:
            return ""

        # BrowserOS/browser traffic enters through Proxy. PortSwigger MCP direct
        # sends are Extender traffic. Native crawl/audit traffic is Scanner.
        # Repeater is included because Agent B commonly uses it for baselines and
        # may discover a new response while refining a request.
        tool_sources = (
            ("TOOL_PROXY", "PROXY"),
            ("TOOL_EXTENDER", "EXTENDER"),
            ("TOOL_REPEATER", "REPEATER"),
            ("TOOL_SCANNER", "SCANNER")
        )
        for constant_name, source in tool_sources:
            try:
                if flag == int(getattr(self.callbacks, constant_name)):
                    return source
            except Exception:
                continue
        return ""

    def _is_double_agent_control_plane_message(self, messageInfo):
        """Keep local Double Agent and PortSwigger MCP control traffic out of Agent A."""
        try:
            url_str = str(self.helpers.analyzeRequest(messageInfo).getUrl() or "").lower()
        except Exception:
            return False
        control_markers = (
            "127.0.0.1:8777", "localhost:8777", "[::1]:8777",
            "127.0.0.1:9876", "localhost:9876", "[::1]:9876"
        )
        return any(marker in url_str for marker in control_markers)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        listener_start = time.time()
        passive_source = self._passive_http_tool_source(toolFlag)

        if messageIsRequest:
            try:
                req = self.helpers.analyzeRequest(messageInfo)
                url_str = str(req.getUrl())
                if "127.0.0.1:8777" in url_str or "localhost:8777" in url_str:
                    # Add comment to identify Agent API requests
                    current = messageInfo.getComment()
                    if not current:
                        messageInfo.setComment("Agent API")
            except:
                pass
            # Semantic MCP actions carry the same note header as proxied curl.
            # Convert it to a Burp comment for every supported Burp tool so it is
            # visible as evidence without leaking the internal note upstream.
            if passive_source:
                self._apply_agent_note_header(messageInfo)
            elapsed_ms = self._perf_ms_since(listener_start)
            if elapsed_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)):
                self._perf_debug("listener request slow=%dms source=%s" % (elapsed_ms, passive_source or "ignored"), key="listener-request-slow", min_interval=1.0)
            return

        if not passive_source or self._is_double_agent_control_plane_message(messageInfo):
            return

        self._http_listener_count += 1
        if self._http_listener_count % 50 == 0:
            self._perf_debug(
                "listener saw %d supported Burp responses | %s" % (int(self._http_listener_count), self._perf_counts_snapshot()),
                key="listener-count", min_interval=5.0)
        self._queue_proxy_traffic_analysis(messageInfo, passive_source)
        elapsed_ms = self._perf_ms_since(listener_start)
        if elapsed_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)):
            self._perf_debug("listener response slow=%dms source=%s | %s" % (elapsed_ms, passive_source, self._perf_counts_snapshot()), key="listener-response-slow", min_interval=1.0)

    def processWebSocketMessage(self, toolFlag, messageIsRequest, message):
        """Capture WebSocket messages for AI analysis.

        Called by Burp for every WebSocket message sent or received.
        Messages are queued for the agent to analyze for injection points,
        auth issues, and data leakage.
        """
        try:
            if not self.PASSIVE_SCANNING_ENABLED:
                return

            direction = message.getDirection()
            direction_str = "client-to-server" if direction == message.DIRECTION_CLIENT_TO_SERVER else "server-to-client"
            payload = message.getPayload()
            if not payload or len(payload) == 0:
                return

            # Decode payload
            try:
                payload_str = self.helpers.bytesToString(payload)
            except:
                payload_str = "[binary payload: %d bytes]" % len(payload)

            # Skip empty or trivial messages
            if not payload_str or len(payload_str.strip()) < 2:
                return

            # Get WebSocket annotations for URL context
            ws_url = ""
            try:
                annotations = message.getAnnotations()
                if annotations:
                    ws_url = str(annotations.getUrl() if hasattr(annotations, 'getUrl') else "")
            except:
                pass

            if self.VERBOSE:
                self.stdout.println("[WS] %s | %s | %s" % (direction_str, ws_url[:60], payload_str[:100]))

            # Queue for agent analysis
            self._sendWebSocketToAgent(message, direction_str, payload_str, ws_url)

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[WS] Error: %s" % self._safe_ascii_text(e))

    def _sendWebSocketToAgent(self, message, direction_str, payload_str, ws_url):
        """Queue a WebSocket message for the agent to analyze."""
        try:
            if self.agent_server is None:
                return

            with self.agent_queue_lock:
                if len(self.agent_queue) >= self.MAX_AGENT_QUEUE_SIZE:
                    return

                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1

                summary = "WS %s: %s" % (direction_str, payload_str[:60])

                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "summary": summary,
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "source": "websocket",
                    "browser_verify": False,
                    "user_context": "",
                    "finding_ids": [],
                    # WebSocket-specific data
                    "ws_direction": direction_str,
                    "ws_url": ws_url,
                    "ws_payload": payload_str[:10240],
                    "ws_payload_length": len(payload_str)
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            if self.VERBOSE:
                self.stdout.println("[WS] Queued for agent: %s" % summary)

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[WS] Queue error: %s" % self._safe_ascii_text(e))

    def analyze(self, messageInfo, url_str=None, task_id=None):
        worker_wait_start = time.time()
        self.semaphore.acquire()
        worker_wait_ms = self._perf_ms_since(worker_wait_start)
        task_type_for_debug = self._task_type_for_id(task_id)
        if worker_wait_ms > int(getattr(self, "PERF_DEBUG_SLOW_MS", 75)) or task_type_for_debug == "PROXY":
            self._perf_debug(
                "analysis worker acquired task=%s type=%s wait=%dms active_threads=%d url=%s" % (
                    str(task_id), task_type_for_debug, worker_wait_ms,
                    int(getattr(self, "_active_analysis_threads", 0)), str(url_str or "")[:120]),
                key="analysis-worker-acquired" if task_type_for_debug == "PROXY" else "analysis-worker-slow",
                min_interval=1.0 if task_type_for_debug == "PROXY" else 0.0)
        try:
            try:
                if not self._wait_if_paused_or_cancelled(task_id):
                    if task_id is not None:
                        self.updateTask(task_id, "Cancelled")
                    return

                with self.rate_limit_lock:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        self._perf_debug(
                            "analysis rate wait task=%s type=%s wait=%.2fs url=%s" % (
                                str(task_id), self._task_type_for_id(task_id), wait_time, str(url_str or "")[:120]),
                            key="analysis-rate-wait", min_interval=1.0)
                        if not self._interruptible_sleep(wait_time, task_id):
                            if task_id is not None:
                                self.updateTask(task_id, "Cancelled")
                            return
                    self.last_request_time = time.time()
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                        return
                    self.updateTask(task_id, "Analyzing")

                self._perform_analysis(messageInfo, "HTTP", url_str, task_id)

                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                    else:
                        with self.tasks_lock:
                            current_status = self.tasks[task_id].get("status", "") if task_id < len(self.tasks) else "Cancelled"
                        if not self._is_terminal_status(current_status):
                            self.updateTask(task_id, "Completed")
            except Exception as e:
                if task_id is not None and self._is_task_cancelled(task_id):
                    self.updateTask(task_id, "Cancelled")
                else:
                    self.stderr.println("[!] HTTP error: %s" % self._safe_ascii_text(e))
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % self._safe_ascii_text(e, 30))
                    self.updateStats("errors")
            finally:
                task_type = self._task_type_for_id(task_id)
                with self._analysis_thread_lock:
                    old_count = self._active_analysis_threads
                    self._active_analysis_threads = max(0, self._active_analysis_threads - 1)
                    if old_count != self._active_analysis_threads and task_type != "PROXY":
                        self.stdout.println("[THREAD] Counter decremented: %d -> %d (analyze)" % (old_count, self._active_analysis_threads))
                self._release_task_url_hash(task_id)
                if task_type == "PROXY" and getattr(self, "PROXY_UI_LAZY_REFRESH", True):
                    self._ui_dirty = True
                else:
                    self.refreshUI()
        finally:
            try:
                self.semaphore.release()
            except:
                pass

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        """
        Forced analysis that bypasses deduplication.
        Used for context menu re-analysis of already-analyzed requests.
        """
        # Skip static file extensions even for forced analysis
        if url_str and self.should_skip_extension(url_str):
            if self.VERBOSE:
                self.stdout.println("[FORCE SKIP] Static file: %s" % url_str[:80])
            if task_id is not None:
                self.updateTask(task_id, "Skipped (Static File)")
            return

        # Skip static asset paths (bundler output, fonts, sourcemaps) that will never yield findings
        if url_str:
            _path_lower = url_str.lower().split("?")[0]
            _static_path_markers = [
                "/_next/static/", "/static/chunks/", "/static/media/",
                "/__webpack", "/.nuxt/", "/dist/static/", "/assets/static/",
                ".chunk.js", ".bundle.js", "-manifest.json", "/_buildmanifest",
                "/_ssgmanifest", "/webpack-runtime", "/runtime~main"
            ]
            if any(m in _path_lower for m in _static_path_markers):
                if self.VERBOSE:
                    self.stdout.println("[FORCE SKIP] Static asset path: %s" % url_str[:80])
                if task_id is not None:
                    self.updateTask(task_id, "Skipped (Static Asset)")
                return

        with self.semaphore:
            try:
                if not self._wait_if_paused_or_cancelled(task_id):
                    if task_id is not None:
                        self.updateTask(task_id, "Cancelled")
                    return

                with self.rate_limit_lock:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        if not self._interruptible_sleep(wait_time, task_id):
                            if task_id is not None:
                                self.updateTask(task_id, "Cancelled")
                            return
                    self.last_request_time = time.time()
                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                        return
                    self.updateTask(task_id, "Analyzing (Forced)")

                # Call _perform_analysis with bypass_dedup=True
                self._perform_analysis(messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True)

                if task_id is not None:
                    if self._is_task_cancelled(task_id):
                        self.updateTask(task_id, "Cancelled")
                    else:
                        with self.tasks_lock:
                            current_status = self.tasks[task_id].get("status", "") if task_id < len(self.tasks) else "Cancelled"
                        if not self._is_terminal_status(current_status):
                            self.updateTask(task_id, "Completed")
            except Exception as e:
                if task_id is not None and self._is_task_cancelled(task_id):
                    self.updateTask(task_id, "Cancelled")
                else:
                    self.stderr.println("[!] Context menu error: %s" % self._safe_ascii_text(e))
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % self._safe_ascii_text(e, 30))
                    self.updateStats("errors")
            finally:
                with self._analysis_thread_lock:
                    old_count = self._active_analysis_threads
                    self._active_analysis_threads = max(0, self._active_analysis_threads - 1)
                    if old_count != self._active_analysis_threads:
                        self.stdout.println("[THREAD] Counter decremented: %d -> %d (analyze_forced)" % (old_count, self._active_analysis_threads))
                self._release_task_url_hash(task_id)
                self.refreshUI()

    def _get_raw_url_hash(self, url, params, req=None, request_bytes=None):
        method = ""
        try:
            method = req.getMethod()
        except:
            pass
        body_component = ""
        try:
            method_u = str(method or "").upper()
            if request_bytes is not None and method_u not in ("GET", "HEAD", "OPTIONS"):
                body_offset = req.getBodyOffset() if req is not None else 0
                body_bytes = request_bytes[body_offset:]
                if body_bytes:
                    try:
                        body_text = self.helpers.bytesToString(body_bytes)
                    except:
                        body_text = str(body_bytes)
                    body_text = str(body_text or "").strip()
                    if body_text:
                        if len(body_text) > 8192:
                            body_text = body_text[:8192]
                        try:
                            body_component = hashlib.md5(body_text.encode('utf-8')).hexdigest()
                        except:
                            body_component = hashlib.md5(body_text.encode('ascii', 'replace')).hexdigest()
        except:
            body_component = ""
        normalized_url = self._canonicalize_url_for_scan_cache(url)
        normalized = str(method or "") + "|" + str(normalized_url) + "|body:" + str(body_component)
        try:
            return hashlib.md5(normalized.encode('utf-8')).hexdigest()
        except (UnicodeDecodeError, UnicodeEncodeError):
            return hashlib.md5(normalized.encode('ascii', 'replace')).hexdigest()

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        key = "%s|%s|%s|%s" % (str(url).split('?')[0], title.lower().strip(), cwe, param_name)
        return hashlib.md5(key.encode('utf-8')).hexdigest()

    def _ingest_response_hygiene(self, messageInfo, url, req, res):
        """Create low-noise deterministic candidates before LLM triage."""
        try:
            request_headers = [str(item) for item in req.getHeaders()]
            response_headers = [str(item) for item in res.getHeaders()]
            content_type = ""
            for line in response_headers:
                if line.lower().startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip()
                    break
            candidates = analyze_response_hygiene(
                url,
                req.getMethod(),
                request_headers,
                response_headers,
                res.getStatusCode(),
                content_type,
            )
            if not candidates:
                return 0
            request_data = self._bytes_to_str(messageInfo.getRequest())
            response_data = self._bytes_to_str(messageInfo.getResponse())
            if request_data and len(request_data) > 10240:
                request_data = request_data[:10240] + "... [truncated]"
            if response_data and len(response_data) > 10240:
                response_data = response_data[:10240] + "... [truncated]"
            created = 0
            for candidate in candidates:
                result = self.add_finding(
                    url=url,
                    title=candidate.get("title", "Response security baseline candidate"),
                    severity=candidate.get("severity", "Information"),
                    confidence=candidate.get("confidence", "Firm"),
                    detail=candidate.get("detail", ""),
                    cwe=candidate.get("cwe", ""),
                    evidence=candidate.get("evidence", ""),
                    remediation=candidate.get("remediation", ""),
                    ai_confidence=100,
                    request_data=request_data,
                    response_data=response_data,
                    source="deterministic_hygiene",
                    agent_status=candidate.get("agent_status", "needs_investigation"),
                    agent_priority=candidate.get("agent_priority", "P4"),
                    agent_rationale="Deterministic response-header baseline; Agent B must reconcile exploitability and representative coverage.",
                    active_test_recipe=candidate.get("active_test_recipe", {}),
                    agent_validated_by="A",
                    deduplication_key=candidate.get("deduplication_key", ""),
                )
                if isinstance(result, dict) and result.get("disposition") == "created":
                    created += 1
            return created
        except Exception as exc:
            if self.VERBOSE:
                self.stderr.println("[HYGIENE] Analysis error: %s" % self._safe_ascii_text(exc))
            return 0
