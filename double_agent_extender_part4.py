# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk4(object):
    def _exportSelectedCSV(self):
        """Export selected findings (or all if none selected) to a CSV file."""
        try:
            import csv
            from javax.swing import JFileChooser
            from javax.swing.filechooser import FileNameExtensionFilter

            chooser = JFileChooser()
            chooser.setDialogTitle("Export Findings to CSV")
            chooser.setFileFilter(FileNameExtensionFilter("CSV Files", ["csv"]))
            result = chooser.showSaveDialog(self.panel)
            if result != JFileChooser.APPROVE_OPTION:
                return

            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"):
                path += ".csv"

            selected_rows = self.findingsTable.getSelectedRows()
            if len(selected_rows) > 0:
                model_rows = [self.findingsTable.convertRowIndexToModel(r) for r in selected_rows]
            else:
                model_rows = range(len(self.findings_list))

            with self.findings_lock_ui:
                to_export = []
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        to_export.append(dict(self.findings_list[model_row]))

            with open(path, "wb") as f:
                writer = csv.writer(f)
                writer.writerow(["Discovered At", "URL", "Finding", "Severity", "Confidence",
                                 "Agent Status", "Agent Priority", "Agent Rationale", "Agent Updated At",
                                 "CWE", "OWASP", "Detail", "Evidence", "Remediation"])
                for finding in to_export:
                    writer.writerow([
                        finding.get("discovered_at", ""),
                        finding.get("url", ""),
                        finding.get("title", ""),
                        finding.get("severity", ""),
                        finding.get("confidence", ""),
                        finding.get("agent_status", ""),
                        finding.get("agent_priority", ""),
                        finding.get("agent_rationale", ""),
                        finding.get("agent_updated_at", ""),
                        finding.get("cwe", ""),
                        finding.get("owasp", ""),
                        finding.get("detail", ""),
                        finding.get("evidence", ""),
                        finding.get("remediation", "")
                    ])
            self.log_to_console("[EXPORT] Exported %d findings to %s" % (len(to_export), path))
        except Exception as e:
            self.stderr.println("[EXPORT] CSV export error: %s" % self._safe_ascii_text(e))

    # === Feature #5: Persist column widths ===
    def _get_column_widths(self):
        """Read current column widths from tables."""
        widths = {}
        saved = getattr(self, "_saved_column_widths", None)
        if isinstance(saved, dict):
            widths.update(saved)
        for name, attr in [("tasks", "taskTable"), ("findings", "findingsTable")]:
            try:
                table = getattr(self, attr, None)
                if table is None:
                    continue
                col_widths = []
                for i in range(table.getColumnModel().getColumnCount()):
                    col_widths.append(table.getColumnModel().getColumn(i).getWidth())
                widths[name] = col_widths
            except Exception:
                continue
        return widths

    def _add_column_resize_cursor(self, table):
        """Disable column reordering and add wider resize cursor zone."""
        from java.awt import Cursor
        from java.awt.event import MouseMotionAdapter

        header = table.getTableHeader()
        header.setReorderingAllowed(False)
        resize_zone = 10  # pixels from column edge

        class HeaderCursorListener(MouseMotionAdapter):
            def mouseMoved(self, e):
                try:
                    col = header.columnAtPoint(e.getPoint())
                    if col < 0:
                        header.setCursor(Cursor.getDefaultCursor())
                        return
                    rect = header.getHeaderRect(col)
                    right_edge = rect.x + rect.width
                    if abs(e.getX() - right_edge) <= resize_zone:
                        header.setCursor(Cursor(Cursor.E_RESIZE_CURSOR))
                        return
                    if col > 0:
                        left_edge = rect.x
                        if abs(e.getX() - left_edge) <= resize_zone:
                            header.setCursor(Cursor(Cursor.E_RESIZE_CURSOR))
                            return
                    header.setCursor(Cursor.getDefaultCursor())
                except:
                    pass

        header.addMouseMotionListener(HeaderCursorListener())

    def _restore_column_widths(self):
        """Restore saved column widths from config."""
        widths = getattr(self, "_saved_column_widths", None)
        if not widths:
            return
        for name, table in [("tasks", self.taskTable), ("findings", self.findingsTable)]:
            col_widths = widths.get(name, [])
            for i, w in enumerate(col_widths):
                if i < table.getColumnModel().getColumnCount():
                    try:
                        table.getColumnModel().getColumn(i).setPreferredWidth(int(w))
                    except:
                        pass

    def cancelAllTasks(self, event):
        """Cancel all running/queued tasks (kill switch)"""
        self.stdout.println("\n[CANCEL ALL] Cancelling all active tasks...")

        cancelled_count = 0
        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                # Cancel anything that's not already done
                if "Completed" not in status and "Error" not in status and "Cancelled" not in status:
                    task["cancel_requested"] = True
                    task["status"] = "Cancelled"
                    task["end_time"] = time.time()
                    cancelled_count += 1
        with self.control_lock:
            self.pause_all = False

        self.stdout.println("[CANCEL ALL] Cancelled %d tasks" % cancelled_count)
        self._ui_dirty = True
        self.refreshUI()

    def pauseAllTasks(self, event):
        """Pause/Resume all running tasks"""
        with self.control_lock:
            should_pause = not self.pause_all
            self.pause_all = should_pause

        if should_pause:
            self.stdout.println("\n[PAUSE ALL] Pausing all active tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if ("Completed" not in status and
                        "Error" not in status and
                        "Cancelled" not in status and
                        "Skipped" not in status):
                        task["status"] = "Paused"
            self.stdout.println("[PAUSE ALL] All tasks paused")
        else:
            self.stdout.println("\n[RESUME ALL] Resuming all paused tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if "Paused" in status:
                        task["status"] = "Queued"
            self.stdout.println("[RESUME ALL] All tasks resumed")

        self._ui_dirty = True
        self.refreshUI()

    def _rescanSelectedTask(self):
        """Rescan the selected task from the Tasks table."""
        try:
            # Get selected row
            selected_row = self.taskTable.getSelectedRow()
            if selected_row < 0:
                self.stderr.println("[RESCAN] No task selected")
                return

            # Convert view row to model row (accounting for sorting)
            model_row = self.taskTable.convertRowIndexToModel(selected_row)

            # Get task data from the table model
            timestamp = self.taskTableModel.getValueAt(model_row, 0)
            task_type = self.taskTableModel.getValueAt(model_row, 1)
            url = self.taskTableModel.getValueAt(model_row, 2)
            status = self.taskTableModel.getValueAt(model_row, 3)

            self.stdout.println("[RESCAN] Rescanning task: %s (%s)" % (url, task_type))

            # Find the original task to get full details
            with self.tasks_lock:
                original_task = None
                for task in self.tasks:
                    if (task.get("timestamp") == timestamp and
                        task.get("url") == url and
                        task.get("type") == task_type):
                        original_task = task
                        break

                if original_task is None:
                    self.stderr.println("[RESCAN] Could not find original task data")
                    return

                # Create new task as a copy
                new_task = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": original_task.get("type", "PASSIVE"),
                    "url": original_task.get("url", ""),
                    "status": "Queued",
                    "messageInfo": original_task.get("messageInfo"),
                    "analysis": original_task.get("analysis", ""),
                    "url_hash": None,
                    "start_time": None,
                    "end_time": None
                }

                # Mark original as rescan origin
                original_task["rescan_origin"] = True

                # Add to tasks list
                self.tasks.append(new_task)
                task_id = len(self.tasks) - 1

            with self.stats_lock:
                self.stats["total_requests"] += 1

            message_info = new_task.get("messageInfo")
            if message_info is None:
                self.updateTask(task_id, "Error (No Request)")
                self.stderr.println("[RESCAN] Original task has no request/response object to rescan")
                return

            # Start forced analysis thread so right-click rescan bypasses dedupe.
            with self._analysis_thread_lock:
                if self._active_analysis_threads >= self.MAX_QUEUED_ANALYSES:
                    self.updateTask(task_id, "Skipped (Queue Full)")
                    self.stderr.println("[RESCAN] Analysis queue full, skipping")
                    return
                self._active_analysis_threads += 1
                self.stdout.println("[THREAD] Counter incremented: %d/%d (RESCAN)" % (
                    self._active_analysis_threads, self.MAX_QUEUED_ANALYSES))
            t = threading.Thread(target=self.analyze_forced, args=(message_info, str(url), task_id))
            t.setDaemon(True)
            t.start()

            self.stdout.println("[RESCAN] Task %d queued for rescan" % task_id)
            self._ui_dirty = True
            self.refreshUI()

        except Exception as e:
            self.stderr.println("[RESCAN] Error: %s" % self._safe_ascii_text(e))

    def debugTasks(self, event):
        """Debug stuck/stalled tasks - provides detailed diagnostic information"""
        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] Task Status Diagnostic Report")
        self.stdout.println("="*60)

        current_time = time.time()

        with self.tasks_lock:
            total_tasks = len(self.tasks)
            active_tasks = []
            queued_tasks = []
            stuck_tasks = []

            for idx, task in enumerate(self.tasks):
                status = task.get("status", "Unknown")
                task_type = task.get("type", "Unknown")
                url = task.get("url", "Unknown")[:50]
                start_time = task.get("start_time", 0)

                # Calculate duration
                if start_time > 0:
                    duration = current_time - start_time
                else:
                    duration = 0

                # Categorize tasks
                if "Analyzing" in status or "Waiting" in status:
                    active_tasks.append((idx, task_type, status, duration, url))

                    # Check if stuck (analyzing for >5 minutes)
                    if duration > 300:  # 5 minutes
                        stuck_tasks.append((idx, task_type, status, duration, url))

                elif "Queued" in status:
                    queued_tasks.append((idx, task_type, status, duration, url))

            # Print summary
            self.stdout.println("\n[DEBUG] Summary:")
            self.stdout.println("  Total Tasks: %d" % total_tasks)
            self.stdout.println("  Active (Analyzing/Waiting): %d" % len(active_tasks))
            self.stdout.println("  Queued: %d" % len(queued_tasks))
            self.stdout.println("  Stuck (>5 min): %d" % len(stuck_tasks))

            # Print active tasks
            if active_tasks:
                self.stdout.println("\n[DEBUG] Active Tasks:")
                for idx, task_type, status, duration, url in active_tasks[:10]:  # Show first 10
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" %
                                      (idx, task_type, status, duration, url))

            # Print queued tasks
            if queued_tasks:
                self.stdout.println("\n[DEBUG] Queued Tasks:")
                for idx, task_type, status, duration, url in queued_tasks[:10]:
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" %
                                      (idx, task_type, status, duration, url))

            # Print stuck tasks with detailed diagnostics
            if stuck_tasks:
                self.stdout.println("\n[DEBUG] WARNING: STUCK TASKS DETECTED:")
                for idx, task_type, status, duration, url in stuck_tasks:
                    self.stdout.println("  [%d] %s | %s | %.1f minutes | %s" %
                                      (idx, task_type, status, duration/60, url))

                self.stdout.println("\n[DEBUG] Possible causes:")
                self.stdout.println("  1. AI request timeout (increase in Settings)")
                self.stdout.println("  2. Network issues (check connectivity)")
                self.stdout.println("  3. AI provider unavailable (test connection)")
                self.stdout.println("  4. Thread deadlock (restart Burp Suite)")
                self.stdout.println("\n[DEBUG] Recommended actions:")
                self.stdout.println("  - Click 'Stop Analysis' to clear stuck tasks")
                self.stdout.println("  - Check AI connection: Settings → Test Connection")
                self.stdout.println("  - Increase timeout: Settings → Advanced → AI Request Timeout")
                self.stdout.println("  - Check Console for error messages")

            # Check semaphore status
            self.stdout.println("\n[DEBUG] Threading Status:")
            self.stdout.println("  Analysis Workers: %d" % int(self.ANALYSIS_WORKERS))
            self.stdout.println("  AI Request Concurrency: %d" % int(self.AI_REQUEST_CONCURRENCY))
            self.stdout.println("  Analysis Backlog Limit: %d waiting+running" % int(self.MAX_QUEUED_ANALYSES))
            self.stdout.println("  Proxy Backlog Limit: %d waiting+running" % int(self.MAX_PROXY_QUEUED_ANALYSES))
            self.stdout.println("  Proxy Intake Interval: %.1fs" % float(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS))
            self.stdout.println("  Rate Limit Delay: %.1fs" % self.min_delay)
            self.stdout.println("  Last Request: %.1fs ago" % (current_time - self.last_request_time))

            # Check if semaphore might be blocked
            if len(active_tasks) > 0 and len(queued_tasks) > 5:
                self.stdout.println("\n[DEBUG] Warning: Many queued tasks with active task")
                self.stdout.println("  This is normal - tasks are worker-bounded and rate-limited to prevent API overload")
                self.stdout.println("  Max parallel workers: %d | Global pacing: 1 request every %.1f seconds" %
                                    (int(self.ANALYSIS_WORKERS), self.min_delay))

        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] End of diagnostic report")
        self.stdout.println("="*60)

        self.refreshUI()

    def load_config(self):
        """Load configuration from disk"""
        try:
            import os
            if os.path.exists(self.config_file):
                # Tighten perms on any pre-existing config so a key saved before
                # this hardening (world-readable 0644) becomes owner-only now.
                try:
                    import stat
                    os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
                with open(self.config_file, 'r') as f:
                    config = json.load(f)

                # Load settings
                self.AI_PROVIDER = config.get("ai_provider", self.AI_PROVIDER)
                self.API_URL = config.get("api_url", self.API_URL)
                self.API_KEY = config.get("api_key", self.API_KEY)
                self.API_KEYS_PER_PROVIDER = config.get("api_keys_per_provider", {})
                self.JEV_DEDUP_ENABLED = config.get("jev_dedup_enabled", False) is True
                self.JEV_API_KEY = unicode_text(config.get("jev_api_key", "")).strip()
                self.MODEL = config.get("model", self.MODEL)
                # Legacy bedrock_access_key/secret_key/session_token ignored (bearer token used via API_KEY)
                self.MAX_TOKENS = config.get("max_tokens", self.MAX_TOKENS)
                try:
                    min_scan_tokens = int(getattr(self, "MIN_SCAN_OUTPUT_TOKENS", 4096))
                    if int(self.MAX_TOKENS) < min_scan_tokens:
                        self.stdout.println("[CONFIG] Max Tokens raised from %d to %d so passive JSON findings are not truncated" %
                                            (int(self.MAX_TOKENS), min_scan_tokens))
                        self.MAX_TOKENS = min_scan_tokens
                except:
                    self.MAX_TOKENS = int(getattr(self, "MIN_SCAN_OUTPUT_TOKENS", 4096))
                self.AI_REQUEST_TIMEOUT = config.get("ai_request_timeout", self.AI_REQUEST_TIMEOUT)
                try:
                    if str(self.AI_PROVIDER or "") == "Bedrock" and int(self.AI_REQUEST_TIMEOUT) < int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120)):
                        old_timeout = int(self.AI_REQUEST_TIMEOUT)
                        self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                        self.stdout.println("[CONFIG] Bedrock timeout raised from %ds to %ds to prevent false No AI Response errors" %
                                            (old_timeout, int(self.AI_REQUEST_TIMEOUT)))
                except:
                    self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                try:
                    self.ANALYSIS_WORKERS = max(1, int(config.get("analysis_workers", self.ANALYSIS_WORKERS)))
                except:
                    self.ANALYSIS_WORKERS = 1
                try:
                    self.AI_REQUEST_CONCURRENCY = max(1, min(5, int(config.get("ai_request_concurrency", self.AI_REQUEST_CONCURRENCY))))
                except:
                    self.AI_REQUEST_CONCURRENCY = 2
                self.VERBOSE = config.get("verbose", self.VERBOSE)
                saved_theme = config.get("theme", self.THEME)
                self.THEME = saved_theme if saved_theme in ("Auto", "Light", "Dark") else "Auto"
                self.PASSIVE_SCANNING_ENABLED = config.get("passive_scanning_enabled", True)
                self.PROXY_DEDUPE_ENABLED = config.get("proxy_dedupe_enabled", True)
                self.AGENT_BROWSEROS_ENABLED = bool(config.get("agent_browseros_enabled", False))
                self.PROJECT_ROOT_DIR = config.get("project_root_dir", self.PROJECT_ROOT_DIR)
                try:
                    self.MAX_QUEUED_ANALYSES = max(1, int(config.get("max_queued_analyses", self.MAX_QUEUED_ANALYSES)))
                except:
                    self.MAX_QUEUED_ANALYSES = 12
                try:
                    self.MAX_PROXY_QUEUED_ANALYSES = max(1, int(config.get("max_proxy_queued_analyses", self.MAX_PROXY_QUEUED_ANALYSES)))
                except:
                    self.MAX_PROXY_QUEUED_ANALYSES = 3
                try:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = max(0.0, float(config.get("proxy_analysis_min_interval_seconds", self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS)))
                except:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0
                self.PROXY_UI_LAZY_REFRESH = config.get("proxy_ui_lazy_refresh", True)
                self.PROJECT_WORKSPACE_DIR = config.get("project_workspace_dir", self.PROJECT_WORKSPACE_DIR)
                self.PORTSWIGGER_MCP_URL = config.get("portswigger_mcp_url", self.PORTSWIGGER_MCP_URL)
                self.PERSIST_RAW_HTTP = bool(config.get("persist_raw_http", self.PERSIST_RAW_HTTP))

                # Load context enrichment settings
                self.CONTEXT_ENRICHMENT_ENABLED = config.get("context_enrichment_enabled", self.CONTEXT_ENRICHMENT_ENABLED)
                self.CONTEXT_NEIGHBOR_COUNT = config.get("context_neighbor_count", self.CONTEXT_NEIGHBOR_COUNT)
                self.CONTEXT_MAX_AGE_MINUTES = config.get("context_max_age_minutes", self.CONTEXT_MAX_AGE_MINUTES)
                self._saved_column_widths = config.get("column_widths", {})
                self.CUSTOM_SCAN_PROMPT = config.get("custom_scan_prompt", "")

                self.stdout.println("\n[CONFIG] Loaded saved configuration from %s" % self.config_file)
                self.stdout.println("[CONFIG] Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL))
            else:
                self.stdout.println("\n[CONFIG] No saved configuration found - using defaults")
                self.stdout.println("[CONFIG] Config will be saved to: %s" % self.config_file)
        except Exception as e:
            self.stderr.println("[!] Failed to load config: %s" % self._safe_ascii_text(e))
            self.stderr.println("[!] Using default settings")

    def save_config(self):
        """Save configuration to disk"""
        try:
            config = {
                "ai_provider": self.AI_PROVIDER,
                "api_url": self.API_URL,
                "api_key": self.API_KEY,
                "api_keys_per_provider": self.API_KEYS_PER_PROVIDER,
                "jev_dedup_enabled": bool(self.JEV_DEDUP_ENABLED),
                "jev_api_key": self.JEV_API_KEY,
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "analysis_workers": self.ANALYSIS_WORKERS,
                "ai_request_concurrency": self.AI_REQUEST_CONCURRENCY,
                "verbose": self.VERBOSE,
                "theme": self.THEME,
                "passive_scanning_enabled": self.PASSIVE_SCANNING_ENABLED,
                "proxy_dedupe_enabled": self.PROXY_DEDUPE_ENABLED,
                "agent_browseros_enabled": bool(self.AGENT_BROWSEROS_ENABLED),
                "project_root_dir": self.PROJECT_ROOT_DIR,
                "max_queued_analyses": self.MAX_QUEUED_ANALYSES,
                "max_proxy_queued_analyses": self.MAX_PROXY_QUEUED_ANALYSES,
                "proxy_analysis_min_interval_seconds": self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS,
                "proxy_ui_lazy_refresh": self.PROXY_UI_LAZY_REFRESH,
                "project_workspace_dir": self.PROJECT_WORKSPACE_DIR,
                "portswigger_mcp_url": self.PORTSWIGGER_MCP_URL,
                "persist_raw_http": bool(self.PERSIST_RAW_HTTP),
                "context_enrichment_enabled": self.CONTEXT_ENRICHMENT_ENABLED,
                "context_neighbor_count": self.CONTEXT_NEIGHBOR_COUNT,
                "context_max_age_minutes": self.CONTEXT_MAX_AGE_MINUTES,
                "column_widths": self._get_column_widths(),
                "custom_scan_prompt": self.CUSTOM_SCAN_PROMPT,
                "version": self.VERSION,
                "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)

            # The config holds the AI provider API key in plaintext. We do not
            # encrypt it (that needs key management with its own failure modes),
            # but we restrict the file to owner-only (0600) so it isn't world-
            # readable on a shared host. Best-effort; no-op on platforms without
            # POSIX perms.
            try:
                import os, stat
                os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

            self.stdout.println("[CONFIG] Configuration saved to %s (owner-only perms)" % self.config_file)
            return True
        except Exception as e:
            self.stderr.println("[!] Failed to save config: %s" % self._safe_ascii_text(e))
            return False

    def save_findings(self):
        """Persist findings to double-agent.json in the working directory.
        double-agent.json is the source of truth - see _persist_eternals_file."""
        try:
            if self._is_swing_event_thread():
                self._request_persistence_async("save_findings")
                return
            self._persist_eternals_file()
        except Exception as e:
            self.stderr.println("[FINDINGS] Save error: %s" % self._safe_ascii_text(e))

    def load_findings(self):
        """Restore findings and FP suppression list.

        Source priority:
          1. double-agent.json in the working directory (primary, source of truth)
          2. Burp project storage (legacy compressed or plain-JSON)
          3. ~/.double-agent/ sidecar fallback or ~/.eternals/ legacy files
        """
        try:
            data = None
            doc = self._read_eternals_file()
            if doc and isinstance(doc, dict) and ("findings" in doc or "agent_queue" in doc):
                # double-agent.json carries findings + agent_queue together; queue is
                # restored separately by load_agent_queue from the same doc.
                data = {
                    "findings": doc.get("findings", []),
                    "finding_audit_log": doc.get("finding_audit_log", []),
                    "fp_suppressed": doc.get("fp_suppressed", []),
                    "passive_scan_cache": doc.get("passive_scan_cache", {}),
                }
                self._eternals_doc_cache = doc

            if data is None:
                raw = self._load_setting("eternals_findings")
                if not raw:
                    return
                decoded = self._decompress_payload(raw)
                if not decoded:
                    return
                data = json.loads(decoded)
                project_doc = {
                    "findings": data.get("findings", []),
                    "agent_queue": {"items": []},
                }
                if not self._persistence_doc_matches_current_context(project_doc, "Burp project storage eternals_findings"):
                    return

            findings = data.get("findings", [])
            self.finding_audit_log = [dict(event) for event in data.get("finding_audit_log", []) or [] if isinstance(event, dict)][-1000:]
            fp_list = data.get("fp_suppressed", [])
            for finding_index, finding in enumerate(findings):
                self._ensure_finding_stable_id(finding)
                self._ensure_finding_legacy_numeric_id(finding, finding_index + 1)
                if "agent_status" not in finding:
                    finding["agent_status"] = "false_positive" if finding.get("fp", False) else "untouched"
                elif self._agent_status_value(finding.get("agent_status", "")) == "not_important":
                    finding["agent_status"] = "false_positive"
                    finding["fp"] = True
                    if not finding.get("agent_priority"):
                        finding["agent_priority"] = "defer"
                    if not finding.get("agent_rationale"):
                        finding["agent_rationale"] = "Migrated deprecated not_important status to false_positive."
                if "agent_validated_by" not in finding:
                    source_l = str(finding.get("source", "") or "").lower()
                    finding["agent_validated_by"] = "B" if source_l in ("agent_active", "agent_api", "automated_testing") else "A"
                if "agent_priority" not in finding:
                    finding["agent_priority"] = "defer" if finding.get("fp", False) else ""
                if "agent_rationale" not in finding:
                    finding["agent_rationale"] = ""
                if "agent_updated_at" not in finding:
                    finding["agent_updated_at"] = ""
                if "active_test_recipe" not in finding:
                    finding["active_test_recipe"] = {}
                elif isinstance(finding.get("active_test_recipe"), dict) and finding.get("active_test_recipe"):
                    finding["active_test_recipe"] = self._normalize_active_test_recipe(
                        finding.get("active_test_recipe", {}), finding)
                else:
                    finding["active_test_recipe"] = {}
                if "agent_candidate_type" not in finding:
                    finding["agent_candidate_type"] = self._classify_agent_candidate_type(finding)
                recomputed_family = self._canonical_finding_family(
                    finding.get("title", ""), finding.get("cwe", ""),
                    finding.get("detail", ""), finding.get("evidence", ""))
                recomputed_fingerprint = self._finding_fingerprint(
                    finding.get("url", ""), finding.get("title", ""), finding.get("cwe", ""),
                    finding.get("detail", ""), finding.get("evidence", ""), finding.get("request_data"),
                    finding.get("source", "")) or ""
                recomputed_location = self._fingerprint_location(
                    finding.get("url", ""), finding.get("title", ""),
                    finding.get("detail", ""), finding.get("evidence", ""), finding.get("request_data"))
                if recomputed_family:
                    finding["canonical_family"] = recomputed_family
                if recomputed_fingerprint:
                    finding["finding_fingerprint"] = recomputed_fingerprint
                if recomputed_location:
                    finding["fingerprint_location"] = recomputed_location
            with self.findings_lock_ui:
                self.findings_list = findings
                removed_duplicates = self._dedupe_existing_findings()
                deleted_already_covered_indices = self._prune_already_covered_findings()
                suppressed = set()
                for entry in fp_list:
                    try:
                        if len(entry) != 2:
                            continue
                        if entry[0] == "scanner":
                            suppressed.add(("scanner", str(entry[1])))
                        elif entry[0] == "fingerprint":
                            suppressed.add(("fingerprint", str(entry[1])))
                        else:
                            suppressed.add((entry[0], frozenset(entry[1])))
                    except:
                        pass
                for finding in self.findings_list:
                    if finding.get("fp", False) or self._agent_status_value(finding.get("agent_status", "")) == "false_positive":
                        for fp_key in self._get_fp_keys_for_finding(
                            finding.get("url", ""), finding.get("title", ""), finding.get("source", ""),
                            finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""),
                            finding.get("request_data")):
                            suppressed.add(fp_key)
                self.fp_suppressed = suppressed
            self.stdout.println("[FINDINGS] Restored %d finding(s)" % len(self.findings_list))
            self._load_passive_scan_cache(data.get("passive_scan_cache", {}))
            if deleted_already_covered_indices:
                self._deleted_finding_indices_pending_queue_remap = deleted_already_covered_indices
                self.stdout.println("[FINDINGS] Removed %d already-covered finding(s) from persisted findings" % len(deleted_already_covered_indices))
            if removed_duplicates:
                self.stdout.println("[DEDUP] Removed %d duplicate scanner finding(s) from persisted findings" % removed_duplicates)
            loaded_legacy_path = str(getattr(self, "_loaded_legacy_sidecar_path", "") or "")
            if loaded_legacy_path:
                self.stdout.println("[PERSIST] Imported legacy sidecar %s; will save canonical double-agent.json" % loaded_legacy_path)
                self._loaded_legacy_sidecar_path = ""
            if removed_duplicates or deleted_already_covered_indices or loaded_legacy_path:
                self._findings_load_cleanup_pending_save = True
        except Exception as e:
            self.stderr.println("[FINDINGS] Load error: %s" % self._safe_ascii_text(e))

    def openSettings(self, event):
        """Open settings dialog with AI provider and advanced configuration"""
        try:
            self._do_open_settings()
        except Exception as e:
            import traceback
            self.stderr.println("[SETTINGS ERROR] Failed to open settings dialog: %s" % str(e))
            self.stderr.println(traceback.format_exc())
