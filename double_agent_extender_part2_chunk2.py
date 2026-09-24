# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk2Chunk2(object):
    def _reproduceFinding(self):
        """Queue a 'reproduce' work item for the AI agent.

        The agent is instructed to rebuild and re-send the captured request
        through the native Burp proxy first so the user can observe the
        reproduction live in Burp's HTTP history with a note attached.
        If the original auth has expired, the agent is told to refresh it via
        /api/agent/auth/latest before sending.
        """
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                self.log_to_console("[REPRODUCE] No finding selected")
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row >= len(self.findings_list):
                    return
                finding = dict(self.findings_list[model_row])

            url = finding.get("url", "")
            request_data = finding.get("request_data")
            title = finding.get("title", "")
            external_id = model_row + 1  # 1-based for display / agent
            fallback_request = None

            if not request_data and url:
                fallback_request = self._build_request_from_url(url)
                if fallback_request:
                    request_data = fallback_request.get("request_data")
                    self.stdout.println("[REPRODUCE] Finding #%d has no captured request; queued fallback GET from URL" % external_id)

            if not url or not request_data:
                JOptionPane.showMessageDialog(
                    None,
                    "This finding has no captured request data and no usable URL,\n"
                    "so the agent has nothing to rebuild and replay.\n\nURL: %s" % url,
                    "Cannot reproduce",
                    JOptionPane.WARNING_MESSAGE,
                )
                return

            # Build the user_context message for the agent. This is what shows
            # up in the queue item's USER CONTEXT field and tells the agent
            # exactly what to do.
            user_context = (
                "REPRODUCE finding #%d (\"%s\").\n\n"
                "Build and send this exact HTTP request using native curl through "
                "Burp Proxy. The curl command MUST include -x http://127.0.0.1:8080. Add header "
                "X-Eternals-Agent-Note: Agent: reproduce finding #%d - replay captured request - expect original behavior. "
                "The extension copies that header into the visible Proxy history note and strips it before upstream. "
                "Use POST /api/agent/request only as a fallback/convenience path. Use the request shown in this work "
                "item's `findings[0].request_data` or `request_data` field as the source of truth.\n"
                "If this work item says the request was synthesized, treat it as a starting point only and recover better auth/method/body from Burp history before deciding reproducibility.\n\n"
                "AUTH: If the captured Authorization / Cookie / CSRF headers look "
                "stale or you get 401/403/419, do NOT ask the user to paste a token. "
                "First call GET /api/agent/auth/latest?host=<host> to pull the "
                "freshest matching auth material from Burp history, then re-build "
                "the request with those headers/cookies. Only ask the user for a "
                "valid token if /api/agent/auth/latest has nothing usable for this host.\n\n"
                "OUTPUT: After sending, POST a queue result with:\n"
                "  - the request you actually sent (after any auth refresh)\n"
                "  - the response status line and a short body snippet\n"
                "  - whether the original finding still reproduces (yes/no/unclear)\n"
                "Do NOT change finding triage state - this is a verification, not retesting."
            ) % (external_id, title[:120], external_id)

            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1
                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "finding_ids": [model_row],  # internal 0-based
                    "summary": "Reproduce: %s" % (title[:80]),
                    "assessment": "",
                    "test_results": [],
                    "source": "reproduce",
                    "user_context": user_context,
                    "browser_verify": False,
                    "url": url,
                    "request_data": request_data,
                    "response_data": finding.get("response_data") or "",
                    "host": (fallback_request or {}).get("host", ""),
                    "port": (fallback_request or {}).get("port", 0),
                    "protocol": (fallback_request or {}).get("protocol", ""),
                    "notes": ([{
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "Captured request was missing; generated a fallback GET from the finding URL."
                    }] if fallback_request else []),
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[REPRODUCE] Queued reproduction of finding #%d as work item #%d" % (
                external_id, qid))
            self.log_to_console("[REPRODUCE] Agent endpoint: http://%s:%d/api/agent/queue/%d" % (
                self.agent_server_host, self.agent_server_port, qid))
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()

            # Friendly nudge if the agent server isn't running yet, so the
            # user knows nothing will happen until they start it.
            try:
                if not getattr(self, "agent_server", None):
                    JOptionPane.showMessageDialog(
                        None,
                        "Reproduction queued as work item #%d.\n\n"
                        "The agent API server is NOT currently running.\n"
                        "Start it from the Agent AI tab so the agent can claim "
                        "the work item and send the request through Burp." % qid,
                        "Reproduce queued",
                        JOptionPane.INFORMATION_MESSAGE,
                    )
            except Exception:
                pass
        except Exception as e:
            self.stderr.println("[REPRODUCE] Error: %s" % self._safe_ascii_text(e))

    def _showReproduceDialog(self, title, body, original_response, new_response):
        """Render the reproduce comparison dialog."""
        from javax.swing import JDialog, JTextArea, JScrollPane, JButton, JLabel
        from java.awt import Dimension as _Dim
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(1100, 700)
        dialog.setLocationRelativeTo(None)
        dialog.setLayout(BorderLayout())

        header = JTextArea(body)
        header.setEditable(False)
        header.setFont(Font("Monospaced", Font.PLAIN, 12))
        dialog.add(header, BorderLayout.NORTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setResizeWeight(0.5)

        origArea = JTextArea(original_response or "")
        origArea.setEditable(False)
        origArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        origPanel = JPanel(BorderLayout())
        origPanel.add(JLabel("  ORIGINAL RESPONSE (captured)"), BorderLayout.NORTH)
        origPanel.add(JScrollPane(origArea), BorderLayout.CENTER)
        split.setLeftComponent(origPanel)

        newArea = JTextArea(new_response or "")
        newArea.setEditable(False)
        newArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        newPanel = JPanel(BorderLayout())
        newPanel.add(JLabel("  NEW RESPONSE (just now)"), BorderLayout.NORTH)
        newPanel.add(JScrollPane(newArea), BorderLayout.CENTER)
        split.setRightComponent(newPanel)

        dialog.add(split, BorderLayout.CENTER)

        closeBtn = JButton("Close")
        closeBtn.addActionListener(lambda e: dialog.dispose())
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btnPanel.add(closeBtn)
        dialog.add(btnPanel, BorderLayout.SOUTH)

        dialog.setVisible(True)

    def _deleteFinding(self):
        """Delete the selected finding from the findings list."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row < len(self.findings_list):
                    removed = self.findings_list.pop(model_row)
                    self.log_to_console("[FINDINGS] Deleted: %s" % str(removed.get("title", ""))[:80])
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Delete error: %s" % self._safe_ascii_text(e))

    # === False Positive / Severity / Bulk action helpers ===
    def _toggleShowFP(self):
        """Toggle visibility of hidden non-reportable findings in the table."""
        self._show_fp_findings = not self._show_fp_findings
        try:
            self._showFPBtn.setText("Hide Hidden" if self._show_fp_findings else "Show Hidden")
        except:
            pass
        if hasattr(self, "findingsSorter") and self._fp_row_filter is not None:
            self.findingsSorter.setRowFilter(None if self._show_fp_findings else self._fp_row_filter)
        self._ui_dirty = True
        self.refreshUI()

    def _get_fp_key(self, url, title):
        """Return a hashable key (url, frozenset_of_words) for FP suppression lookup."""
        words = self._normalize_finding_key(title)
        if not words:
            return None
        return (str(url), words)

    def _get_fp_keys_for_finding(self, url, title, source="", cwe="", detail="", evidence="", request_data=None):
        keys = []
        fp_key = self._get_fp_key(url, title)
        if fp_key:
            keys.append(fp_key)
        scanner_key = self._scanner_dedupe_key(url, title, source)
        if scanner_key:
            keys.append(("scanner", scanner_key))
        fingerprint = self._finding_fingerprint(url, title, cwe, detail, evidence, request_data, source)
        if fingerprint:
            keys.append(("fingerprint", fingerprint))
        return keys

    def _getSelectedModelRows(self):
        """Return model row indices for all selected view rows, sorted highest-first."""
        rows = self.findingsTable.getSelectedRows()
        return sorted([self.findingsTable.convertRowIndexToModel(r) for r in rows], reverse=True)

    def _markAsFP(self):
        """Mark selected findings as false positives (hidden + future suppression)."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        finding = self.findings_list[model_row]
                        fp_keys = self._get_fp_keys_for_finding(
                            finding.get("url", ""), finding.get("title", ""), finding.get("source", ""),
                            finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""),
                            finding.get("request_data")
                        )
                        for fp_key in fp_keys:
                            self.fp_suppressed.add(fp_key)
                        finding["fp"] = True
                        finding["agent_status"] = "false_positive"
                        finding["agent_priority"] = "defer"
                        finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            count = len(model_rows)
            self.log_to_console("[FP] Marked %d finding(s) as false positive" % count)
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FP] Mark error: %s" % self._safe_ascii_text(e))

    def _unmarkAsFP(self):
        """Remove false positive flag from selected findings and re-enable future detection."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        finding = self.findings_list[model_row]
                        for fp_key in self._get_fp_keys_for_finding(
                            finding.get("url", ""), finding.get("title", ""), finding.get("source", ""),
                            finding.get("cwe", ""), finding.get("detail", ""), finding.get("evidence", ""),
                            finding.get("request_data")
                        ):
                            if fp_key in self.fp_suppressed:
                                self.fp_suppressed.discard(fp_key)
                        finding["fp"] = False
                        if finding.get("agent_status") == "false_positive":
                            finding["agent_status"] = "untouched"
                            finding["agent_priority"] = ""
                            finding["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_to_console("[FP] Unmarked %d finding(s)" % len(model_rows))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FP] Unmark error: %s" % self._safe_ascii_text(e))

    def _setSeverity(self, severity):
        """Override severity on all selected findings."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        self.findings_list[model_row]["severity"] = severity
            self.log_to_console("[FINDINGS] Set severity=%s on %d finding(s)" % (severity, len(model_rows)))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Severity override error: %s" % self._safe_ascii_text(e))

    def _deleteSelected(self):
        """Delete all currently selected findings."""
        try:
            model_rows = self._getSelectedModelRows()
            with self.findings_lock_ui:
                for model_row in model_rows:
                    if model_row < len(self.findings_list):
                        self.findings_list.pop(model_row)
            self.log_to_console("[FINDINGS] Deleted %d finding(s)" % len(model_rows))
            self.save_findings()
            self._ui_dirty = True
            self.refreshUI()
        except Exception as e:
            self.stderr.println("[FINDINGS] Delete selected error: %s" % self._safe_ascii_text(e))

    def _askBrowserVerify(self, n_items):
        """Prompt the user whether the agent should verify via browser. Returns True/False/None (cancelled)."""
        try:
            from javax.swing import JOptionPane
            options = ["API/curl only", "Verify in browser", "Cancel"]
            msg = (
                "How should Agent B verify the %d finding(s)?\n\n"
                "- 'API/curl only' = Agent B uses curl through Burp proxy (default, fast)\n"
                "- 'Verify in browser' = Agent B ALSO uses BrowserOS MCP to reproduce in a real browser\n"
                "  (traffic still routed through Burp; Agent B will ask you before destructive actions)"
            ) % n_items
            choice = JOptionPane.showOptionDialog(
                None, msg, "Send to Agent B",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                None, options, options[0]
            )
            if choice == 0:
                return False
            if choice == 1:
                return True
            return None  # Cancel or closed
        except Exception as e:
            self.stderr.println("[AGENT] Browser verify dialog error: %s" % self._safe_ascii_text(e))
            return False

    def _sendFindingsToAgent(self):
        """Queue selected findings for agent AI to pick up via the local API."""
        try:
            # Debug: log selection state
            selected_view_rows = self.findingsTable.getSelectedRows()
            self.stdout.println("[DEBUG] Selected view rows: %s (count: %d)" % (list(selected_view_rows), len(selected_view_rows)))

            model_rows = self._getSelectedModelRows()
            self.stdout.println("[DEBUG] Converted model rows: %s (count: %d)" % (model_rows, len(model_rows)))

            if not model_rows:
                self.stderr.println("[AGENT] No findings selected")
                return

            with self.findings_lock_ui:
                finding_ids = []
                summaries = []
                request_data = None
                response_data = None
                url = None
                for model_row in model_rows:
                    if 0 <= model_row < len(self.findings_list):
                        finding_ids.append(model_row)
                        finding = self.findings_list[model_row]
                        summaries.append(finding.get("title", "")[:80])
                        # Capture request/response from first finding that has it
                        if request_data is None and finding.get("request_data"):
                            request_data = finding.get("request_data")
                            response_data = finding.get("response_data")
                            url = finding.get("url", "")

            if not finding_ids:
                self.stderr.println("[AGENT] No valid findings selected")
                return

            # Ask for optional context/question + browser verification toggle
            n = len(finding_ids)
            placeholder_text = (
                "e.g. 'Does this really have impact given the endpoint is admin-only?', "
                "'User session cookie is HttpOnly - is the XSS still exploitable?', "
                "'Please confirm exploitability end-to-end and rate real severity'..."
            )
            ctx_result = self._askAgentContext(
                title="Send Finding(s) to Agent B - Add Context",
                info_text="%d finding(s) selected for Agent B review." % n,
                placeholder_text=placeholder_text,
            )
            if ctx_result is None:
                # User cancelled
                return
            user_context = ctx_result.get("context", "")
            browser_verify = bool(ctx_result.get("browser_verify", False))

            # Auto-start server if not running
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue")
                    return

            with self.agent_queue_lock:
                qid = self.agent_queue_next_id
                self.agent_queue_next_id += 1
                summary = "; ".join(summaries[:3])
                if len(summaries) > 3:
                    summary += " (+%d more)" % (len(summaries) - 3)
                queue_item = {
                    "id": qid,
                    "status": "pending",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "claimed_at": None,
                    "completed_at": None,
                    "finding_ids": finding_ids,
                    "summary": summary,
                    "assessment": "",
                    "test_results": [],
                    "notes": [],
                    "user_context": user_context,
                    "source": "findings",
                    "browser_verify": browser_verify,
                    # Include HTTP data from the finding for agent testing
                    "url": url,
                    "request_data": request_data,
                    "response_data": response_data
                }
                self.agent_queue.append(queue_item)
                self.selected_agent_queue_index = len(self.agent_queue) - 1

            self.save_agent_queue()
            self.log_to_console("[AGENT] Queued %d finding(s) as work item #%d" % (len(finding_ids), qid))
            self.log_to_console("[AGENT] Finding IDs: %s" % ", ".join(str(x + 1) for x in finding_ids))
            self.log_to_console("[AGENT] Agent can pick it up at: http://%s:%d/api/agent/queue/%d" % (
                self.agent_server_host, self.agent_server_port, qid))
            self._ui_dirty = True
            self.refreshUI()
            self._focus_agent_tab()

        except Exception as e:
            self.stderr.println("[AGENT] Error: %s" % self._safe_ascii_text(e))

    def _askAgentContext(self, title, info_text, placeholder_text, submit_label="Queue for Agent"):
        """Show a modal dialog collecting optional context + browser_verify toggle.

        Returns a dict {'context': str, 'browser_verify': bool} on submit, or None if
        the user cancelled / closed the dialog.
        """
        from javax.swing import JDialog, JTextArea, JButton, JLabel, JScrollPane, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets
        from java.awt.event import WindowAdapter

        is_dark_ui = False
        try:
            is_dark_ui = (self._detect_burp_theme() == "Dark")
        except:
            pass
        if not is_dark_ui:
            try:
                is_dark_ui = (self._resolved_theme() == "Dark")
            except:
                pass

        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setModal(True)
        dialog.setSize(600, 380)
        dialog.setLocationRelativeTo(None)

        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 5, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST

        # Info label
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        infoLabel = JLabel(info_text)
        infoLabel.setFont(Font("Dialog", Font.BOLD, 12))
        panel.add(infoLabel, gbc)

        # Context label
        gbc.gridy = 1
        gbc.insets = Insets(10, 10, 2, 10)
        panel.add(JLabel("Context / question (optional) - anything the agent should know or answer:"), gbc)

        # Context text area
        gbc.gridy = 2
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 10, 5, 10)

        contextArea = JTextArea(7, 40)
        contextArea.setLineWrap(True)
        contextArea.setWrapStyleWord(True)
        contextArea.setText(placeholder_text)
        if is_dark_ui:
            contextArea.setForeground(Color(0x86, 0xA8, 0x9A))
            try:
                contextArea.setCaretColor(Color(0x00, 0xF5, 0xA0))
            except:
                pass
        else:
            contextArea.setForeground(Color.GRAY)

        from java.awt.event import FocusListener
        class PlaceholderFocusListener(FocusListener):
            def __init__(self, area, placeholder, dark):
                self.area = area
                self.placeholder = placeholder
                self.dark = bool(dark)
                self.is_placeholder = True

            def focusGained(self, e):
                if self.is_placeholder:
                    self.area.setText("")
                    self.area.setForeground(Color.WHITE if self.dark else Color.BLACK)
                    self.is_placeholder = False

            def focusLost(self, e):
                if self.area.getText().strip() == "":
                    self.area.setText(self.placeholder)
                    self.area.setForeground(Color(0x86, 0xA8, 0x9A) if self.dark else Color.GRAY)
                    self.is_placeholder = True

        focus_listener = PlaceholderFocusListener(contextArea, placeholder_text, is_dark_ui)
        contextArea.addFocusListener(focus_listener)
        panel.add(JScrollPane(contextArea), gbc)

        # Browser verification checkbox
        gbc.gridy = 3
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 10, 5, 10)
        browserVerifyCheck = JCheckBox("Verify findings via browser (agent will use BrowserOS MCP)")
        browserVerifyCheck.setEnabled(bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False)))
        browserVerifyCheck.setToolTipText(
            "If checked, the agent is instructed to verify exploits in a real browser "
            "using BrowserOS MCP tools, with traffic routed through Burp proxy. "
            "Agent must ask you in chat before any state-changing actions."
        )
        panel.add(browserVerifyCheck, gbc)

        # Buttons
        gbc.gridy = 4
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 10, 10, 10)
        buttonPanel = JPanel()

        result = [None]  # mutable container to pass result out of inner class

        def onQueue(e):
            try:
                e.getSource().setEnabled(False)
            except:
                pass
            context = contextArea.getText().strip()
            if focus_listener.is_placeholder:
                context = ""
            result[0] = {"context": context, "browser_verify": browserVerifyCheck.isSelected()}
            dialog.dispose()

        def onCancel(e):
            result[0] = None
            dialog.dispose()

        class DialogWindowListener(WindowAdapter):
            def windowClosing(self, e):
                result[0] = None

        dialog.addWindowListener(DialogWindowListener())

        queueBtn = JButton(submit_label)
        queueBtn.addActionListener(onQueue)
        buttonPanel.add(queueBtn)

        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(onCancel)
        buttonPanel.add(cancelBtn)

        panel.add(buttonPanel, gbc)

        dialog.add(panel)
        self._apply_dark_theme_to_container(dialog)
        dialog.setVisible(True)

        # Dialog is modal - execution continues here after it closes
        return result[0]

    def _activeScanContextDialog(self, messages):
        """Show a context dialog before queuing requests for agent active scan."""
        n = len(messages)
        placeholder_text = (
            "e.g. 'Test for IDOR on the user ID parameter', "
            "'Auth token is in the Authorization header', "
            "'This endpoint changes account email - check for CSRF and auth bypass'..."
        )
        result = self._askAgentContext(
            title="Active Scan with Agent - Add Context",
            info_text="%d request(s) selected for agent active scan." % n,
            placeholder_text=placeholder_text,
        )
        if result is not None:
            self._sendRequestsToAgent(
                messages,
                user_context=result.get("context", ""),
                browser_verify=result.get("browser_verify", False),
            )

    def _extract_flow_ids(self, text, limit=20):
        ids = []
        seen = set()
        try:
            for match in re.finditer(r'(?i)\b([a-z][a-z0-9_-]{1,40}(?:id|_id|number|_number))\b["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.:-]{3,80})', str(text or "")):
                name = match.group(1)
                value = match.group(2)
                key = "%s=%s" % (name.lower(), value)
                if key not in seen:
                    seen.add(key)
                    ids.append({"name": name, "value": value})
                if len(ids) >= limit:
                    break
        except Exception:
            pass
        return ids

    def _infer_flow_step_state(self, step, method, url, request_data, response_data, status_code):
        method_u = str(method or "GET").upper()
        text = "%s\n%s\n%s" % (url or "", request_data or "", response_data or "")
        path = ""
        try:
            from java.net import URL as JavaURL
            path = str(JavaURL(str(url)).getPath() or "")
        except Exception:
            try:
                path = urlparse.urlparse(str(url or "")).path
            except Exception:
                path = ""
        lower = text.lower()
        auth_actor = "unknown"
        if "authorization:" in lower or "cookie:" in lower:
            auth_actor = "authenticated"
        if "pre_mfa" in lower or "pre-mfa" in lower:
            auth_actor = "pre_mfa"
        elif "post_mfa" in lower or "post-mfa" in lower:
            auth_actor = "post_mfa"

        csrf_tokens = []
        one_time_tokens = []
        try:
            for match in re.finditer(r'(?i)\b(csrf|xsrf|anti_forgery|requestverificationtoken)[A-Za-z0-9_-]*\b["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.:-]{6,120})', text):
                csrf_tokens.append(match.group(1))
            for match in re.finditer(r'(?i)\b(otp|nonce|state|code|transaction[_-]?id|challenge|authid)\b["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.:-]{4,120})', text):
                one_time_tokens.append(match.group(1))
        except Exception:
            pass

        state_changing = method_u in ("POST", "PUT", "PATCH", "DELETE")
        if not state_changing:
            for keyword in ["checkout", "submit", "confirm", "verify", "reset", "password", "payment", "transfer", "order", "upload", "delete", "create", "update"]:
                if keyword in str(path or "").lower():
                    state_changing = True
                    break

        replayability = "safe_baseline"
        if state_changing and one_time_tokens:
            replayability = "one_time_or_stateful"
        elif state_changing:
            replayability = "state_changing_requires_confirmation"
        elif csrf_tokens:
            replayability = "tokenized_read_or_form"

        return {
            "step": step,
            "purpose_hint": str(path or url or "")[:160],
            "actor_session_hint": auth_actor,
            "state_changing": bool(state_changing),
            "object_ids": self._extract_flow_ids(text),
            "csrf_token_hints": sorted(list(set(csrf_tokens)))[:10],
            "one_time_token_hints": sorted(list(set(one_time_tokens)))[:10],
            "replayability": replayability,
            "status_code": status_code
        }

    def _showTestContextDialog(self):
        """View and edit current test context as one editable document."""
        try:
            from javax.swing import JOptionPane
            panel = JPanel(BorderLayout())
            panel.add(JLabel("Edit scope, roles, auth model, users, sessions, object IDs, allowed actions, risk leads, or target notes:"), BorderLayout.NORTH)

            original_text = self._fixtures_summary_text()
            contextArea = JTextArea(28, 100)
            contextArea.setEditable(True)
            contextArea.setFont(Font("Monospaced", Font.PLAIN, 12))
            contextArea.setLineWrap(True)
            contextArea.setWrapStyleWord(True)
            contextArea.setText(original_text)
            contextArea.setCaretPosition(0)
            panel.add(JScrollPane(contextArea), BorderLayout.CENTER)

            result = JOptionPane.showConfirmDialog(
                None,
                panel,
                "View/Edit Test Context",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            )
            if result != JOptionPane.OK_OPTION:
                return
            notes = contextArea.getText().strip()
            if not notes or notes == original_text.strip():
                return
            imported = self._import_fixtures_from_notes(notes, "ui_context_edit")
            msg = "Imported %d fixture(s): %d created, %d updated." % (
                len(imported.get("fixtures", [])),
                imported.get("created", 0),
                imported.get("updated", 0))
            if imported.get("warnings"):
                msg += "\n\n" + "\n".join(imported.get("warnings", []))
            knowledge = imported.get("knowledge", {}) or {}
            if knowledge.get("created") or knowledge.get("updated"):
                msg += "\n\nKnowledge entries: %d created, %d updated." % (
                    knowledge.get("created", 0),
                    knowledge.get("updated", 0))
            JOptionPane.showMessageDialog(None, msg, "Test Context Updated", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            try:
                self.stderr.println("[FIXTURES] Import dialog error: %s" % self._safe_ascii_text(e))
            except:
                pass

    def _showFixtureImportDialog(self):
        """Compatibility wrapper for older callbacks."""
        self._showTestContextDialog()

    def _fixtures_summary_text(self):
        parts = []
        with self.fixture_lock:
            profile = dict(getattr(self, "project_profile", {}) or {})
            auth_models = dict(getattr(self, "host_auth_models", {}) or {})
            fixtures = [dict(f) for f in getattr(self, "test_fixtures", []) or []]
            confirmations = [dict(c) for c in getattr(self, "human_confirmations", []) or []]
            knowledge = self._normalize_assessment_knowledge_doc(getattr(self, "assessment_knowledge", {}) or {})
            knowledge_entries = [dict(e) for e in knowledge.get("entries", []) or []]
        parts.append("PROJECT PROFILE")
        parts.append("=" * 60)
        parts.append("Scope authority: Burp Suite (/api/agent/scope)")
        parts.append("Legacy host notes (non-authoritative): %s" % ", ".join(profile.get("in_scope_hosts", []) or []))
        if profile.get("in_scope_paths"):
            parts.append("Legacy path notes (non-authoritative): %s" % ", ".join(profile.get("in_scope_paths", []) or []))
        if profile.get("roles"):
            parts.append("Roles: %s" % ", ".join(profile.get("roles", []) or []))
        if profile.get("allowed_state_changes"):
            parts.append("Allowed state changes: %s" % self._safe_ascii_text(profile.get("allowed_state_changes"), 1200))
        if auth_models:
            parts.append("Auth models:")
            for host, model in sorted(auth_models.items())[:20]:
                parts.append("  %s headers=%s cookies=%s" % (
                    host,
                    ",".join(model.get("headers", []) or []),
                    ",".join(model.get("cookies", []) or [])))
        if profile.get("notes"):
            parts.append("Notes: %s" % self._safe_ascii_text(profile.get("notes", ""), 1200))
        parts.append("")
        parts.append("FIXTURES (%d)" % len(fixtures))
        parts.append("=" * 60)
        for fixture in fixtures:
            parts.append("[%s] %s" % (fixture.get("kind", ""), fixture.get("label", fixture.get("id", ""))))
            for key in ["role", "tenant", "brand", "account_number", "account_id", "user_id", "email_hint", "phone_hint", "session_state", "session_source", "browser_profile", "consent_scope", "secret_ref"]:
                if fixture.get(key):
                    parts.append("  %s: %s" % (key, self._safe_ascii_text(fixture.get(key), 500)))
            if fixture.get("object_ids"):
                parts.append("  object_ids: %s" % self._safe_ascii_text(fixture.get("object_ids"), 800))
            if fixture.get("notes"):
                parts.append("  notes: %s" % self._safe_ascii_text(fixture.get("notes"), 800))
            parts.append("")
        parts.append("CONFIRMATIONS (%d)" % len(confirmations))
        parts.append("=" * 60)
        for item in confirmations[-50:]:
            parts.append("[%s] %s -> %s at %s" % (
                item.get("kind", ""),
                item.get("account_label", ""),
                item.get("destination", ""),
                item.get("received_at", item.get("observed_at", ""))))
            if item.get("notes"):
                parts.append("  notes: %s" % self._safe_ascii_text(item.get("notes"), 800))
        parts.append("")
        parts.append("KNOWLEDGE BASE (%d)" % len(knowledge_entries))
        parts.append("=" * 60)
        for entry in knowledge_entries[-50:]:
            parts.append("[%s/%s] %s" % (
                entry.get("category", ""),
                entry.get("status", ""),
                entry.get("title", entry.get("id", ""))))
            if entry.get("tags"):
                parts.append("  tags: %s" % ", ".join(entry.get("tags", []) or []))
            if entry.get("host") or entry.get("path"):
                parts.append("  target: %s %s %s" % (
                    entry.get("method", ""),
                    entry.get("host", ""),
                    entry.get("path", "")))
            if entry.get("detail"):
                parts.append("  detail: %s" % self._safe_ascii_text(entry.get("detail"), 1000))
            if entry.get("next_step"):
                parts.append("  next_step: %s" % self._safe_ascii_text(entry.get("next_step"), 500))
            parts.append("")
        if not fixtures and not confirmations and not knowledge_entries:
            parts.append("No fixtures, confirmations, or knowledge entries recorded yet.")
        return "\n".join(parts)

    def _sendSelectedAgentQueueToRepeater(self):
        try:
            idx = self.selected_agent_queue_index
            with self.agent_queue_lock:
                if idx < 0 or idx >= len(self.agent_queue):
                    self.log_to_console("[AGENT] No selected queue item to send to Repeater")
                    return
                qid = self.agent_queue[idx].get("id")
            api_view = AgentAPIHandler.__new__(AgentAPIHandler)
            api_view.extender = self
            item = api_view._get_queue_item_snapshot(qid)
            if item is None:
                self.log_to_console("[AGENT] Selected queue item not found")
                return
            findings_full = api_view._queue_findings_full(item)
            candidates = api_view._queue_target_candidates(item, findings_full)
            created = 0
            for candidate in candidates[:10]:
                recipe = candidate.get("active_test_recipe", {}) or {}
                built = api_view._raw_repeater_request(candidate, refresh_auth=True, note="")
                if not built.get("ok"):
                    continue
                try:
                    request_bytes = self.helpers.stringToBytes(built.get("raw_request", ""))
                except:
                    request_bytes = built.get("raw_request", "")
                base_label = self._safe_ascii_text("DA q%s %s baseline" % (qid, candidate.get("label", "request")), 80)
                self.callbacks.sendToRepeater(
                    built.get("host", ""),
                    int(built.get("port", 443) or 443),
                    bool(built.get("https", True)),
                    request_bytes,
                    base_label
                )
                created += 1
                for label in api_view._repeater_mutation_labels(recipe):
                    tab_label = self._safe_ascii_text("DA q%s mutate %s" % (qid, label), 80)
                    self.callbacks.sendToRepeater(
                        built.get("host", ""),
                        int(built.get("port", 443) or 443),
                        bool(built.get("https", True)),
                        request_bytes,
                        tab_label
                    )
                    created += 1
            self.log_to_console("[AGENT] Created %d Repeater tab(s) for queue #%s" % (created, qid))
        except Exception as e:
            self.stderr.println("[AGENT] Send selected queue to Repeater error: %s" % self._safe_ascii_text(e))

    def _risk_hunt_context_text(self, user_context="", focus=""):
        parts = []
        parts.append("AUTOMATED TESTING - VERIFY FINDINGS")
        parts.append("")
        parts.append("You now have working knowledge of this app from Burp history, existing findings, project profile, and test context.")
        parts.append("Your primary job is to verify every visible finding that has not been actively tested by Agent B. This is a findings-list verification pass, not the deep solo bug-hunt mode.")
        parts.append("")
        parts.append("Required startup for this work item:")
        parts.append("- Fetch /api/agent/burp/skill and follow combined_markdown as $burpsuite-operator, then read /api/agent/burp/capabilities, /api/agent/burp/workspace, /api/agent/scope, /api/agent/preflight, /api/agent/project-profile, /api/agent/knowledge, /api/agent/fixtures, /api/agent/confirmations, /api/findings, /api/coverage?in_scope_only=true&limit=500, /api/coverage/parameters?in_scope_only=true&limit=500, and /api/report. No local skill folder is required.")
        parts.append("- Use /api/agent/history/http/regex to inspect Burp history for endpoint families, auth/session flows, object IDs, roles, account/tenant boundaries, and untested parameters before asking the user for more context.")
        parts.append("- First validate existing findings whose Agent Status shows (A) or (B triage), because those have not been actively tested by Agent B yet ((B triage) means Agent B only classified it).")
        parts.append("- A single umbrella goal with category=linked_validation is acceptable if it covers every linked finding. The goal must explain how each finding was confirmed, rejected, already covered, or marked Gated.")
        parts.append("- Every linked finding should be accounted for through finding_updates, or through a Gated goal/blocker that names the missing fixture, approval, object ID, account pair, MFA/OOB evidence, or scope limit.")
        parts.append("")
        parts.append("Prioritize goals in this order unless the project context says otherwise:")
        parts.append("1. Auth/authorization boundaries: unauth access, IDOR, tenant isolation, role confusion, custom auth headers, stale/revoked session behavior.")
        parts.append("2. Business logic and workflow abuse: skipped steps, replay, state machine jumps, race/retry behavior, negative amounts, payment/order/approval edges.")
        parts.append("3. Sensitive data exposure: account/profile/export endpoints, excessive response data, cross-user data, logs/debug/config endpoints.")
        parts.append("4. Injection and parser risk: SSRF, SQL/NoSQL/template/command/path traversal, file upload/parser features, GraphQL, XML/XXE, deserialization where applicable.")
        parts.append("5. Chains: combine lower-risk behavior into account takeover, data access, financial impact, admin impact, or durable persistence.")
        parts.append("")
        parts.append("Execution rules:")
        parts.append("- Validate untested existing findings first. If you discover a new vulnerability while doing this, POST it to /api/findings, but do not turn this queue item into an open-ended hunt.")
        parts.append("- Do not retest endpoints/techniques already covered by findings or completed queue results unless a new variant or chain changes impact.")
        parts.append("- Use /api/agent/knowledge to carry forward target observations, risk leads, assumptions, tested controls, blockers, and chain ideas discovered during the hunt.")
        parts.append("- For target traffic, every curl must use -x http://127.0.0.1:8080 and X-Eternals-Agent-Note. Local Double Agent API calls do not use the proxy.")
        parts.append("- For high-signal XSS/SQLi/SSTI/open-redirect/injection candidates, delegate payload breadth to Burp Scanner first: prefer a native Burp MCP scanner action when available, otherwise POST /api/agent/scanner/active with queue_id/finding_id. Poll /api/agent/scanner/jobs/<id>, then validate any Scanner issue with focused evidence before reporting.")
        parts.append("- Prefer semantic POST /api/agent/burp/action calls with dry-run, Agent note, and receipt over raw MCP calls. Never invent a capability; use the advertised fallback or mark the lead Gated.")
        parts.append("- Use focused campaign endpoints for known critical blind spots: crawl/audit discovery, parameter coverage, authz matrix, race/concurrency, browser DOM, and parser/protocol surfaces.")
        parts.append("- Treat Burp Suite as the only scope authority. Check /api/agent/scope or scope_guard for every target; project profile scope fields do not authorize traffic. Respect allowed_state_changes and destructive-action confirmation rules.")
        parts.append("- If a goal needs A/B users, object IDs, account numbers, MFA, OTP/SMS/email receipt, or other missing context, record it as blocked instead of guessing.")
        parts.append("- Confirmed new vulnerabilities discovered during verification must be written with POST /api/findings immediately, including queue_id for this automated-testing item, URL, title, severity, confidence, detail, evidence, request/response snippets, agent_status=valid, agent_priority, agent_rationale, and active_test_recipe. These are Agent B findings.")
        parts.append("- The markdown report is generated from the findings list; after POST /api/findings, verify the new issue appears via GET /api/report.")
        parts.append("- Finish by POSTing this queue item's result with risk_hunt_goals. One linked_validation goal is enough when every linked finding is accounted for. Include finding_updates for actively tested findings, Gated blockers for anything you cannot safely validate, controls, and recommended next steps.")
        if focus:
            parts.append("")
            parts.append("User-requested focus:")
            parts.append(str(focus))
        if user_context:
            parts.append("")
            parts.append("User context:")
            parts.append(str(user_context))
        return "\n".join(parts)
