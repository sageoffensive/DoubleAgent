# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk2(object):
    def apply_hacker_ui_theme(self):
        resolved = self._resolved_theme()
        self._style_all_tab_panes()
        self._style_finding_detail_panel()
        self._style_try_harder_button()
        if resolved != "Dark":
            return
        bg_root = Color(0x08, 0x0C, 0x10)
        bg_panel = Color(0x12, 0x20, 0x30)
        bg_surface = Color(0x1A, 0x2F, 0x42)
        bg_input = Color(0x0C, 0x18, 0x26)
        fg_primary = Color(0xD5, 0xF9, 0xEA)
        fg_muted = Color(0x86, 0xA8, 0x9A)
        fg_accent = Color(0x00, 0xF5, 0xA0)
        fg_info = Color(0x59, 0xE1, 0xFF)
        border_color = Color(0x2D, 0x4F, 0x6E)
        selection_bg = Color(0x00, 0x6A, 0x4E)

        mono_regular = Font("Monospaced", Font.PLAIN, 12)
        mono_bold = Font("Monospaced", Font.BOLD, 12)

        def _style_tab_pane(tabbed):
            """Style tab headers using native Swing APIs — no custom JLabel components."""
            try:
                if tabbed is None:
                    return
                tabbed.setBackground(bg_panel)
                tabbed.setForeground(Color.WHITE)
                tabbed.setFont(Font("Monospaced", Font.BOLD, 11))

                def _apply_tab_colors():
                    selected_index = tabbed.getSelectedIndex()
                    for i in range(tabbed.getTabCount()):
                        tabbed.setForegroundAt(i, Color.WHITE)
                        if i == selected_index:
                            tabbed.setBackgroundAt(i, Color(0x1E, 0x3D, 0x55))
                        else:
                            tabbed.setBackgroundAt(i, Color(0x14, 0x2A, 0x3C))

                _apply_tab_colors()

                if tabbed.getClientProperty("eternals_tab_color_listener") is None:
                    class TabColorSyncListener(ChangeListener):
                        def stateChanged(self_inner, e):
                            _apply_tab_colors()

                    tabbed.addChangeListener(TabColorSyncListener())
                    tabbed.putClientProperty("eternals_tab_color_listener", True)
            except:
                pass

        def _style_component(comp):
            try:
                if isinstance(comp, JPanel):
                    comp.setBackground(bg_panel)
                    border = comp.getBorder()
                    if isinstance(border, TitledBorder):
                        border.setTitleColor(fg_accent)
                        border.setBorder(BorderFactory.createLineBorder(border_color, 1))

                if isinstance(comp, JLabel):
                    text = self._safe_ascii_text(comp.getText() or "")
                    comp.setForeground(Color.WHITE)
                    comp.setBackground(bg_panel)
                    comp.setOpaque(False)
                    if "Double Agent" in text:
                        comp.setForeground(fg_accent)
                        comp.setFont(Font("Monospaced", Font.BOLD, 17))
                    elif "AI-Powered" in text:
                        comp.setForeground(fg_info)
                    elif "Total:" in text and "Crit:" in text:
                        comp.setForeground(fg_info)
                        comp.setFont(Font("Monospaced", Font.BOLD, 11))

                if isinstance(comp, JButton):
                    comp.setBackground(bg_surface)
                    comp.setForeground(fg_accent)
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    comp.setFont(mono_bold)
                    comp.setOpaque(True)
                    try:
                        comp.setFocusPainted(False)
                    except:
                        pass

                if isinstance(comp, JCheckBox):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                    comp.setFont(mono_regular)
                    comp.setOpaque(False)

                if isinstance(comp, JTextArea):
                    if comp is getattr(self, "consoleTextArea", None):
                        comp.setBackground(bg_input)
                        comp.setForeground(Color(0x7A, 0xF7, 0xBE))
                    else:
                        comp.setBackground(bg_input)
                        comp.setForeground(Color.WHITE)
                    comp.setCaretColor(fg_accent)
                    comp.setSelectionColor(Color(0x1B, 0x3A, 0x2D))
                    comp.setSelectedTextColor(Color.WHITE)
                    comp.setFont(mono_regular)

                if isinstance(comp, JTable):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                    comp.setGridColor(border_color)
                    comp.setSelectionBackground(selection_bg)
                    comp.setSelectionForeground(Color.WHITE)
                    comp.setFont(mono_regular)
                    header = comp.getTableHeader()
                    if header is not None:
                        header.setBackground(bg_surface)
                        header.setForeground(fg_accent)
                        header.setFont(mono_bold)
                        header.setDefaultRenderer(ThemeAwareHeaderRenderer(self))

                if isinstance(comp, JScrollPane):
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    viewport = comp.getViewport()
                    if viewport is not None and viewport.getView() is not None:
                        try:
                            viewport.getView().setBackground(bg_input)
                        except:
                            pass

                if isinstance(comp, JSplitPane):
                    comp.setBackground(bg_root)
                    comp.setBorder(BorderFactory.createEmptyBorder())

                if hasattr(comp, "getComponents"):
                    children = comp.getComponents()
                    if children:
                        for child in children:
                            _style_component(child)
            except:
                pass

        try:
            self.panel.setBackground(bg_root)
            _style_component(self.panel)

            # Explicitly theme tables and their scroll pane viewports
            # The recursive walk may not fully reach viewport backgrounds
            for table in (self.taskTable, self.findingsTable):
                try:
                    table.setBackground(bg_input)
                    table.setForeground(fg_primary)
                    table.setGridColor(border_color)
                    table.setSelectionBackground(selection_bg)
                    table.setSelectionForeground(Color.WHITE)
                    parent = table.getParent()
                    if parent is not None:
                        parent.setBackground(bg_input)  # viewport
                except:
                    pass

            # Theme popup menu
            try:
                self.findingsPopupMenu.setBackground(bg_surface)
                self.findingsPopupMenu.setBorder(BorderFactory.createLineBorder(border_color, 1))
                for i in range(self.findingsPopupMenu.getComponentCount()):
                    item = self.findingsPopupMenu.getComponent(i)
                    if isinstance(item, JMenu):
                        item.setBackground(bg_surface)
                        item.setForeground(fg_primary)
                        item.setFont(mono_regular)
                        item.setOpaque(True)
                        sub = item.getPopupMenu()
                        if sub is not None:
                            sub.setBackground(bg_surface)
                            sub.setBorder(BorderFactory.createLineBorder(border_color, 1))
                            for j in range(sub.getComponentCount()):
                                sub_item = sub.getComponent(j)
                                if isinstance(sub_item, JMenuItem):
                                    sub_item.setBackground(bg_surface)
                                    sub_item.setForeground(fg_primary)
                                    sub_item.setFont(mono_regular)
                                    sub_item.setOpaque(True)
            except:
                pass

            # Theme Agent tab components
            try:
                self.agentHistoryCombo.setBackground(bg_input)
                self.agentHistoryCombo.setForeground(fg_primary)
                self.agentStatsLabel.setForeground(fg_primary)
                self.agentAssessmentText.setBackground(bg_input)
                self.agentAssessmentText.setForeground(fg_primary)
                self.agentServerStatusLabel.setForeground(fg_primary)
                self.agentPortField.setBackground(bg_input)
                self.agentPortField.setForeground(fg_primary)
                self.agentPortField.setCaretColor(fg_accent)
            except:
                pass

            # The details inspector gets a distinct surface from the findings grid.
            self._style_finding_detail_panel()
            self._style_try_harder_button()

            self.panel.revalidate()
            self.panel.repaint()
        except:
            pass

        try:
            for tab_name in ("workspaceTabs",):
                tabbed = getattr(self, tab_name, None)
                if tabbed is not None:
                    tabbed.setBackground(bg_panel)
                    _style_tab_pane(tabbed)
        except:
            pass

    def applyConsoleTheme(self):
        """Apply theme colors to console"""
        resolved = self._resolved_theme()
        if resolved == "Dark":
            self.consoleTextArea.setBackground(Color(0x0C, 0x18, 0x26))
            self.consoleTextArea.setForeground(Color(0x7A, 0xF7, 0xBE))
        else:
            self.consoleTextArea.setBackground(Color.WHITE)
            self.consoleTextArea.setForeground(Color(0x36, 0x45, 0x4F))

    def _apply_dark_theme_to_container(self, container):
        """Apply dark theme colors to any component tree (dialogs, panels, etc.)."""
        if self._resolved_theme() != "Dark":
            return
        bg_panel = Color(0x12, 0x20, 0x30)
        bg_input = Color(0x0C, 0x18, 0x26)
        fg_primary = Color(0xD5, 0xF9, 0xEA)
        border_color = Color(0x2D, 0x4F, 0x6E)

        def _walk(comp):
            try:
                if isinstance(comp, JPanel):
                    comp.setBackground(bg_panel)
                if isinstance(comp, JLabel):
                    comp.setForeground(Color.WHITE)
                if isinstance(comp, JButton):
                    comp.setBackground(Color(0x1A, 0x2F, 0x42))
                    comp.setForeground(Color(0x00, 0xF5, 0xA0))
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    comp.setOpaque(True)
                if isinstance(comp, JTextArea):
                    comp.setBackground(bg_input)
                    comp.setForeground(Color.WHITE)
                    comp.setCaretColor(Color(0x00, 0xF5, 0xA0))
                if isinstance(comp, JCheckBox):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                    comp.setOpaque(False)
                if isinstance(comp, JScrollPane):
                    comp.setBorder(BorderFactory.createLineBorder(border_color, 1))
                    viewport = comp.getViewport()
                    if viewport and viewport.getView():
                        try:
                            viewport.getView().setBackground(bg_input)
                        except:
                            pass
                # Handle JTextField, JPasswordField via duck typing (has getColumns)
                if hasattr(comp, "setBackground") and hasattr(comp, "getColumns") and not isinstance(comp, JTextArea):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                    try:
                        comp.setCaretColor(Color(0x00, 0xF5, 0xA0))
                    except:
                        pass
                # Handle JComboBox via duck typing (has getItemCount)
                if hasattr(comp, "getItemCount") and hasattr(comp, "getSelectedItem"):
                    comp.setBackground(bg_input)
                    comp.setForeground(fg_primary)
                # Handle JTabbedPane
                if hasattr(comp, "getTabCount") and hasattr(comp, "setTabComponentAt"):
                    comp.setBackground(bg_panel)
                    comp.setForeground(Color.WHITE)
                if hasattr(comp, "getComponents"):
                    for child in (comp.getComponents() or []):
                        _walk(child)
            except:
                pass

        try:
            if hasattr(container, "getContentPane"):
                container.getContentPane().setBackground(bg_panel)
                _walk(container.getContentPane())
            else:
                _walk(container)
        except:
            pass

    def refreshUI(self, event=None):
        # Skip if a refresh is already queued on the EDT
        if self._refresh_pending:
            queued_at = float(getattr(self, "_last_ui_refresh_queued_at", 0) or 0)
            pending_ms = int((time.time() - queued_at) * 1000) if queued_at else 0
            if pending_ms > 1000:
                self._perf_debug(
                    "refresh skip: EDT refresh already pending for %dms | %s" % (
                        pending_ms, self._perf_counts_snapshot()),
                    key="refresh-pending", min_interval=2.0)
            return
        # Skip if nothing changed since last refresh
        if not self._ui_dirty:
            return

        def _activity_task_visible(task):
            status = str(task.get("status", ""))
            task_type = str(task.get("type", ""))
            url = str(task.get("url", ""))
            if "OPTIONS Request" in status:
                return False
            if "Skipped" in status:
                return False
            if task_type == "PROXY" and "Completed" in status:
                return False
            if self.should_skip_extension(url):
                return False
            return True

        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender

            def run(self):
                queued_at = float(getattr(self.extender, "_last_ui_refresh_queued_at", 0) or 0)
                queue_lag_ms = int((time.time() - queued_at) * 1000) if queued_at else 0
                refresh_start = time.time()
                self.extender._last_ui_refresh_started_at = refresh_start
                timings = []
                try:
                    try:
                        if getattr(self.extender, "agentImportFixturesBtn", None) is not None:
                            self.extender.agentImportFixturesBtn.setText("View/Edit Test Context")
                    except:
                        pass
                    # --- Copy data out of locks (fast) ---
                    phase_start = time.time()
                    with self.extender.tasks_lock:
                        tasks_snapshot = []
                        for task in self.extender.tasks[-1000:]:
                            if not _activity_task_visible(task):
                                continue
                            status = str(task.get("status", ""))
                            duration = ""
                            if task.get("end_time"):
                                duration = "%.2fs" % (task["end_time"] - task["start_time"])
                            elif task.get("start_time"):
                                duration = "%.2fs" % (time.time() - task["start_time"])
                            tasks_snapshot.append([
                                task.get("timestamp", ""),
                                task.get("type", ""),
                                task.get("url", ""),
                                status,
                                duration
                            ])
                        activity_signature = tuple(
                            (row[0], row[1], row[2], row[3], row[4])
                            for row in tasks_snapshot
                        )
                    activity_snapshot_count = len(tasks_snapshot)
                    timings.append(("activity snapshot", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    with self.extender.findings_lock_ui:
                        findings_snapshot = []
                        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0}
                        total_findings = 0
                        hidden_count = 0
                        for fid, finding in enumerate(self.extender.findings_list):
                            is_hidden = self.extender._finding_hidden_from_normal_view(finding)
                            severity = finding.get("severity", "Information")
                            if is_hidden:
                                hidden_count += 1
                            else:
                                total_findings += 1
                                if severity in severity_counts:
                                    severity_counts[severity] += 1
                            # Display the permanent compatibility number; it is
                            # never derived from a mutable list position.
                            findings_snapshot.append([
                                self.extender._ensure_finding_legacy_numeric_id(finding, fid + 1),
                                finding.get("url", ""),
                                finding.get("title", ""),
                                severity,
                                finding.get("confidence", ""),
                                self.extender._agent_status_display(finding),
                                finding.get("agent_priority", "")
                            ])
                        findings_signature = tuple(
                            (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
                            for row in findings_snapshot
                        )
                    findings_snapshot_count = len(findings_snapshot)
                    timings.append(("findings snapshot", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    with self.extender.console_lock:
                        current_len = len(self.extender.console_messages)
                        prev_len = self.extender._last_console_len
                        if current_len != prev_len:
                            new_messages = list(self.extender.console_messages[prev_len:])
                            console_changed = True
                        else:
                            new_messages = []
                            console_changed = False
                        # Handle case where messages were trimmed (list shortened)
                        if current_len < prev_len:
                            console_changed = True
                            new_messages = list(self.extender.console_messages)
                            prev_len = 0
                    console_new_count = len(new_messages)
                    timings.append(("console snapshot", int((time.time() - phase_start) * 1000)))

                    # --- Update Swing components (no locks held) ---

                    phase_start = time.time()
                    activity_changed = activity_signature != getattr(self.extender, "_last_activity_sig", None)
                    if activity_changed:
                        self.extender.taskTableModel.setRowCount(0)
                        for row in tasks_snapshot:
                            self.extender.taskTableModel.addRow(row)
                        self.extender._last_activity_sig = activity_signature
                    try:
                        tab_idx = getattr(self.extender, "_activityTabIndex", 0)
                        title = "Activity"
                        active_count = 0
                        for row in tasks_snapshot:
                            if not self.extender._is_terminal_status(str(row[3])):
                                active_count += 1
                        if active_count > 0:
                            title = "Activity (%d)" % active_count
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != title:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, title)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("activity table", int((time.time() - phase_start) * 1000)))

                    # Findings table — preserve selection across rebuild
                    phase_start = time.time()
                    findings_changed = findings_signature != getattr(self.extender, "_last_findings_sig", None)
                    if findings_changed:
                        selected_finding_id = None
                        sel_row = self.extender.findingsTable.getSelectedRow()
                        if sel_row >= 0:
                            try:
                                sel_model = self.extender.findingsTable.convertRowIndexToModel(sel_row)
                                selected_finding_id = self.extender.findingsTableModel.getValueAt(sel_model, 0)
                            except:
                                pass

                        self.extender.findingsTableModel.setRowCount(0)
                        for row in findings_snapshot:
                            self.extender.findingsTableModel.addRow(row)

                        # Restore selection
                        if selected_finding_id is not None:
                            for i in range(self.extender.findingsTableModel.getRowCount()):
                                if self.extender.findingsTableModel.getValueAt(i, 0) == selected_finding_id:
                                    try:
                                        view_row = self.extender.findingsTable.convertRowIndexToView(i)
                                        self.extender.findingsTable.setRowSelectionInterval(view_row, view_row)
                                    except:
                                        pass
                                    break
                        self.extender._last_findings_sig = findings_signature
                    timings.append(("findings table", int((time.time() - phase_start) * 1000)))

                    phase_start = time.time()
                    hidden_label = "  |  Hidden: %d" % hidden_count if hidden_count > 0 else ""
                    self.extender.findingsStatsLabel.setText(
                        "Total: %d | Crit: %d | High: %d | Medium: %d | Low: %d | Info: %d%s" %
                        (total_findings, severity_counts["Critical"], severity_counts["High"], severity_counts["Medium"],
                         severity_counts["Low"], severity_counts["Information"], hidden_label)
                    )

                    # Update Findings tab title with count, then re-apply tab colors
                    try:
                        tab_idx = getattr(self.extender, "_findingsTabIndex", 0)
                        title = "Findings (%d)" % total_findings
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != title:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, title)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("findings labels", int((time.time() - phase_start) * 1000)))

                    # Agent queue — rebuild combo box when queue or status changes
                    phase_start = time.time()
                    with self.extender.agent_queue_lock:
                        agent_snapshot = [dict(q) for q in self.extender.agent_queue]
                    agent_count = len(agent_snapshot)
                    browseros_enabled = bool(getattr(self.extender, "AGENT_BROWSEROS_ENABLED", False))
                    status_signature = tuple((q.get("id"), q.get("status"), q.get("outcome", ""), bool(q.get("browser_verify", False)) and browseros_enabled) for q in agent_snapshot)
                    last_agent_sig = getattr(self.extender, "_last_agent_sig", None)
                    if status_signature != last_agent_sig:
                        self.extender._agent_combo_updating = True
                        prev_selected = self.extender.agentHistoryCombo.getSelectedIndex()
                        self.extender.agentHistoryCombo.removeAllItems()
                        for q in agent_snapshot:
                            status = str(q.get("status", ""))
                            status_badge = {
                                "pending": "[PEND]",
                                "claimed": "[WIP ]",
                                "completed": "[DONE]",
                                "failed": "[FAIL]",
                                "cancelled": "[CANC]"
                            }.get(status, "[????]")
                            bv_badge = "[BV] " if q.get("browser_verify") and browseros_enabled else ""
                            flow_badge = "[FLOW] " if q.get("source") == "flow_analysis" else ""
                            summary = str(q.get("summary", ""))[:50]
                            self.extender.agentHistoryCombo.addItem("#%d %s %s%s%s" % (q.get("id", 0), status_badge, flow_badge, bv_badge, summary))
                        if agent_count > 0:
                            target = prev_selected if 0 <= prev_selected < agent_count else agent_count - 1
                            try:
                                self.extender.agentHistoryCombo.setSelectedIndex(target)
                                self.extender.selected_agent_queue_index = target
                            except:
                                pass
                        self.extender._agent_combo_updating = False
                        self.extender._last_agent_sig = status_signature
                    timings.append(("agent combo", int((time.time() - phase_start) * 1000)))

                    # Agent stats label
                    phase_start = time.time()
                    pending = sum(1 for q in agent_snapshot if q.get("status") == "pending")
                    claimed = sum(1 for q in agent_snapshot if q.get("status") == "claimed")
                    completed = sum(1 for q in agent_snapshot if q.get("status") == "completed")
                    failed = sum(1 for q in agent_snapshot if q.get("status") == "failed")
                    self.extender.agentStatsLabel.setText(
                        "Pending: %d | Claimed: %d | Completed: %d | Failed: %d" % (pending, claimed, completed, failed))

                    # Server status label + button enable/disable
                    try:
                        if self.extender.agent_server is not None:
                            self.extender.agentServerStatusLabel.setText(
                                "Status: Running @ http://%s:%d" % (
                                    self.extender.agent_server_host, self.extender.agent_server_port))
                            # Start button shows "Running" in green when server is active
                            self.extender.agentStartBtn.setText("Running")
                            self.extender.agentStartBtn.setForeground(Color(0x00, 0x80, 0x00))
                            self.extender.agentStartBtn.setEnabled(False)
                            self.extender.agentStopBtn.setEnabled(True)
                        else:
                            self.extender.agentServerStatusLabel.setText("Status: Stopped")
                            # Reset Start button to default state
                            self.extender.agentStartBtn.setText("Start Server")
                            self.extender.agentStartBtn.setForeground(Color.BLACK)
                            self.extender.agentStartBtn.setEnabled(True)
                            self.extender.agentStopBtn.setEnabled(False)
                    except:
                        pass
                    timings.append(("agent status", int((time.time() - phase_start) * 1000)))

                    # Update Agent tab title with pending count
                    phase_start = time.time()
                    try:
                        tab_idx = getattr(self.extender, "_agentTabIndex", 1)
                        label = "Agent AI"
                        if pending + claimed > 0:
                            label = "Agent AI (%d)" % (pending + claimed)
                        if self.extender.workspaceTabs.getTitleAt(tab_idx) != label:
                            self.extender.workspaceTabs.setTitleAt(tab_idx, label)
                            self.extender._style_all_tab_panes()
                    except:
                        pass
                    timings.append(("tab titles", int((time.time() - phase_start) * 1000)))

                    # Update agent details only when the queue state/selection changed.
                    phase_start = time.time()
                    selected_agent_sig = (
                        status_signature,
                        self.extender.selected_agent_queue_index
                    )
                    if self.extender.selected_agent_queue_index >= 0 and selected_agent_sig != getattr(self.extender, "_last_agent_detail_sig", None):
                        self.extender.updateAgentAssessmentDetails(self.extender.selected_agent_queue_index)
                        self.extender._last_agent_detail_sig = selected_agent_sig
                    timings.append(("agent details", int((time.time() - phase_start) * 1000)))

                    # Console — incremental append
                    phase_start = time.time()
                    if console_changed:
                        if prev_len == 0:
                            # Full rebuild (first load or after trim)
                            console_text = "\n".join(new_messages)
                            self.extender.consoleTextArea.setText(console_text)
                        else:
                            # Append only new messages
                            doc = self.extender.consoleTextArea.getDocument()
                            append_text = "\n" + "\n".join(new_messages)
                            doc.insertString(doc.getLength(), append_text, None)

                        self.extender._last_console_len = current_len

                        was_scrolled = self.extender.console_user_scrolled
                        if not was_scrolled:
                            try:
                                doc = self.extender.consoleTextArea.getDocument()
                                self.extender.consoleTextArea.setCaretPosition(doc.getLength())
                            except:
                                pass
                    timings.append(("console append", int((time.time() - phase_start) * 1000)))

                    # Never persist on Swing's event thread. Burp collection
                    # callbacks used by engagement snapshots can lock-invert
                    # with passive workers that are waiting for this same EDT.
                    phase_start = time.time()
                    if getattr(self.extender, '_agent_queue_save_pending', False):
                        self.extender._agent_queue_save_pending = False
                        try:
                            self.extender._request_persistence_async("ui_refresh")
                        except:
                            pass
                    timings.append(("queue persist", int((time.time() - phase_start) * 1000)))

                finally:
                    total_ms = int((time.time() - refresh_start) * 1000)
                    self.extender._last_ui_refresh_completed_at = time.time()
                    threshold_ms = int(getattr(self.extender, "PERF_DEBUG_SLOW_MS", 75))
                    if total_ms > threshold_ms or queue_lag_ms > threshold_ms:
                        try:
                            slow_parts = ", ".join("%s=%dms" % (name, ms) for name, ms in timings if ms > 15)
                            if not slow_parts:
                                slow_parts = "no single phase >15ms"
                            self.extender._perf_debug(
                                "refresh#%d total=%dms queue_lag=%dms rows(activity=%d findings=%d console_new=%d) phases=(%s) | %s" % (
                                    int(getattr(self.extender, "_ui_refresh_seq", 0)),
                                    total_ms, queue_lag_ms,
                                    int(locals().get("activity_snapshot_count", 0)),
                                    int(locals().get("findings_snapshot_count", 0)),
                                    int(locals().get("console_new_count", 0)),
                                    slow_parts,
                                    self.extender._perf_counts_snapshot()),
                                key="refresh-slow", min_interval=0.5, force=True)
                        except:
                            pass
                    self.extender._refresh_pending = False

        self._ui_dirty = False
        self._ui_refresh_seq += 1
        self._last_ui_refresh_queued_at = time.time()
        self._refresh_pending = True
        self._perf_debug(
            "refresh#%d queued | %s" % (int(self._ui_refresh_seq), self._perf_counts_snapshot()),
            key="refresh-queued", min_interval=2.0)
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        """Auto-refresh UI and check for stuck tasks"""
        def refresh_timer():
            check_interval = 0
            debug_interval = 0
            while True:
                try:
                    time.sleep(1)

                    self.refreshUI()

                    debug_interval += 1
                    if debug_interval >= 5:
                        debug_interval = 0
                        pending_age = 0
                        if getattr(self, "_refresh_pending", False):
                            queued_at = float(getattr(self, "_last_ui_refresh_queued_at", 0) or 0)
                            pending_age = int((time.time() - queued_at) * 1000) if queued_at else 0
                        self._perf_debug(
                            "timer heartbeat pending_age=%dms | %s" % (pending_age, self._perf_counts_snapshot()),
                            key="timer-heartbeat", min_interval=5.0)

                    check_interval += 1
                    if check_interval >= 30:
                        self.check_stuck_tasks()
                        self.check_stale_agent_claims()
                        check_interval = 0
                except Exception as e:
                    try:
                        self.stderr.println("[AUTO-REFRESH] Timer loop error: %s" % self._safe_ascii_text(e))
                    except:
                        pass
                    time.sleep(1)

        timer_thread = threading.Thread(target=refresh_timer)
        timer_thread.setDaemon(True)
        timer_thread.start()

    def check_stuck_tasks(self):
        """Automatically check for stuck tasks and log warnings"""
        current_time = time.time()
        stuck_found = False

        with self.tasks_lock:
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "")
                start_time = task.get("start_time", 0)

                # Check if task has been analyzing for >5 minutes
                if ("Analyzing" in status or "Waiting" in status) and start_time > 0:
                    duration = current_time - start_time

                    if duration > 300:  # 5 minutes
                        if not stuck_found:
                            self.stderr.println("\n[AUTO-CHECK] WARNING: STUCK TASK DETECTED")
                            stuck_found = True

                        task_type = task.get("type", "Unknown")
                        url = task.get("url", "Unknown")[:50]
                        self.stderr.println("[AUTO-CHECK] Task %d stuck: %s | %.1f min | %s" %
                                          (idx, task_type, duration/60, url))

        if stuck_found:
            self.stderr.println("[AUTO-CHECK] Run 'Debug Tasks' button for detailed diagnostics")
            self.stderr.println("[AUTO-CHECK] Or click 'Stop Analysis' to clear stuck tasks")

    def check_stale_agent_claims(self):
        """Auto-release agent queue items that have been claimed but inactive too long.

        An item is "stale" if its status is "claimed" and the most recent activity
        timestamp (last_heartbeat_at, result_updated_at, or claimed_at) is older
        than AGENT_CLAIM_TIMEOUT_SEC. The item is moved back to "pending" so it
        can be re-claimed.
        """
        try:
            timeout = float(self.AGENT_CLAIM_TIMEOUT_SEC)
        except Exception:
            timeout = 900.0

        now = time.time()
        released = []
        released_full_app = []
        with self.agent_queue_lock:
            for q in self.agent_queue:
                if q.get("status") != "claimed":
                    continue
                # Pick the most recent activity timestamp we have.
                last_activity_str = (q.get("last_heartbeat_at")
                                     or q.get("result_updated_at")
                                     or q.get("claimed_at"))
                if not last_activity_str:
                    continue
                try:
                    last_ts = time.mktime(time.strptime(str(last_activity_str), "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    continue
                if (now - last_ts) > timeout:
                    q["status"] = "pending"
                    q["claimed_at"] = None
                    q["last_heartbeat_at"] = None
                    q.setdefault("notes", []).append({
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "Auto-released: claim went stale (no activity for %ds)" % int(timeout)
                    })
                    released.append(q.get("id"))
                    if str(q.get("campaign_type", "")) == "full_app_assessment":
                        released_full_app.append(q.get("id"))

        for queue_id in released_full_app:
            self._set_full_app_passive_scan(queue_id, False)

        if released:
            self.stdout.println("[AGENT] Auto-released %d stale claim(s): %s" % (
                len(released), ", ".join(str(x) for x in released)))
            self._agent_queue_save_pending = True
            self._ui_dirty = True

    def clearCompleted(self, event):
        with self.tasks_lock:
            self.tasks = [t for t in self.tasks if not (
                t.get("status") == "Completed" or
                "Skipped" in t.get("status", "") or
                "Error" in t.get("status", "") or
                "Cancelled" in t.get("status", "")
            )]
        self._ui_dirty = True
        self.refreshUI()

    def clearFindings(self, event):
        """Clear all findings from the findings table"""
        with self.findings_lock_ui:
            self.findings_list = []
        with self.findings_lock:
            self.findings_cache.clear()
        self.fp_suppressed = set()
        self.save_findings()
        self.stdout.println("[FINDINGS] Cleared all findings")
        self._ui_dirty = True
        self.refreshUI()

    # === Feature #1: Finding detail panel ===
    def _updateFindingDetailPanel(self):
        """Update the finding detail panel based on currently selected finding row."""
        start = time.time()
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                self.findingDetailText.setText("Select a finding to view details.")
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            with self.findings_lock_ui:
                if model_row >= len(self.findings_list):
                    self.findingDetailText.setText("Select a finding to view details.")
                    return
                finding = dict(self.findings_list[model_row])

            parts = []
            parts.append("FINDING: %s" % self._safe_ascii_text(finding.get("title", ""), 1000))
            parts.append("URL: %s" % self._safe_ascii_text(finding.get("url", ""), 2000))
            parts.append("Severity: %s  |  Confidence: %s  |  AI Confidence: %s%%" % (
                self._safe_ascii_text(finding.get("severity", ""), 100),
                self._safe_ascii_text(finding.get("confidence", ""), 100),
                self._safe_ascii_text(finding.get("ai_confidence", ""), 100)))
            if finding.get("agent_status") and finding.get("agent_status") != "untouched":
                parts.append("Agent Triage: %s  |  Priority: %s  |  Updated: %s" % (
                    self._safe_ascii_text(finding.get("agent_status", ""), 100),
                    self._safe_ascii_text(finding.get("agent_priority", ""), 100),
                    self._safe_ascii_text(finding.get("agent_updated_at", ""), 100)))
                if finding.get("agent_rationale"):
                    parts.append("Agent Rationale: %s" % self._safe_ascii_text(finding.get("agent_rationale", ""), 4000))
            self._append_remote_reporting_detail(parts, finding)
            recipe = finding.get("active_test_recipe", {}) or {}
            if isinstance(recipe, dict) and recipe:
                parts.append("")
                parts.append("ACTIVE TEST RECIPE:")
                parts.append("Hypothesis: %s" % self._safe_ascii_text(recipe.get("hypothesis", ""), 1200))
                parts.append("Type: %s  |  Max Requests: %s  |  Needs Second User: %s" % (
                    self._safe_ascii_text(recipe.get("active_test_type", ""), 120),
                    self._safe_ascii_text(recipe.get("max_requests", ""), 20),
                    self._safe_ascii_text(recipe.get("needs_second_user", ""), 20)))
                if recipe.get("why_now"):
                    parts.append("Why Now: %s" % self._safe_ascii_text(recipe.get("why_now", ""), 1200))
                if recipe.get("baseline_request"):
                    parts.append("Baseline: %s" % self._safe_ascii_text(recipe.get("baseline_request", ""), 1200))
                if recipe.get("mutation_hint"):
                    parts.append("Mutation: %s" % self._safe_ascii_text(recipe.get("mutation_hint", ""), 1600))
                if recipe.get("expected_vulnerable_signal"):
                    parts.append("Expected Vulnerable Signal: %s" % self._safe_ascii_text(recipe.get("expected_vulnerable_signal", ""), 1200))
                if recipe.get("expected_safe_signal"):
                    parts.append("Expected Safe Signal: %s" % self._safe_ascii_text(recipe.get("expected_safe_signal", ""), 1200))
                if recipe.get("safety_notes"):
                    parts.append("Safety: %s" % self._safe_ascii_text(recipe.get("safety_notes", ""), 1200))
            parts.append("")
            if finding.get("detail"):
                parts.append("DESCRIPTION:")
                parts.append(self._safe_ascii_text(finding.get("detail", ""), 12000))
                parts.append("")
            if finding.get("evidence"):
                parts.append("EVIDENCE:")
                parts.append(self._safe_ascii_text(finding.get("evidence", ""), 12000))
                parts.append("")
            collaborator_evidence = finding.get("collaborator_evidence", {}) or {}
            if isinstance(collaborator_evidence, dict) and collaborator_evidence:
                parts.extend(collaborator_evidence_lines(collaborator_evidence))
            if finding.get("cwe"):
                parts.append("CWE: %s" % self._safe_ascii_text(finding.get("cwe", ""), 200))
            if finding.get("owasp"):
                parts.append("OWASP: %s" % self._safe_ascii_text(finding.get("owasp", ""), 200))
            if finding.get("remediation"):
                parts.append("")
                parts.append("REMEDIATION:")
                parts.append(self._safe_ascii_text(finding.get("remediation", ""), 12000))

            self.findingDetailText.setText(self._safe_ascii_text("\n".join(parts), 40000))
            self.findingDetailText.setCaretPosition(0)
            elapsed_ms = int((time.time() - start) * 1000)
            if elapsed_ms > 250:
                self.stdout.println("[UI PERF] Finding detail render slow: %dms row=%d chars=%d" % (
                    elapsed_ms, model_row + 1, len("\n".join(parts))))
        except Exception as e:
            self.findingDetailText.setText("Error loading finding details: %s" % self._safe_ascii_text(e))

    # === Feature #6: Right-click context menu helpers ===
    def _copyFindingField(self, col_index):
        """Copy a field from the selected finding to the clipboard."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            value = str(self.findingsTable.getModel().getValueAt(model_row, col_index) or "")
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(value), None)
            self.log_to_console("[FINDINGS] Copied to clipboard: %s" % value[:80])
        except Exception as e:
            self.stderr.println("[FINDINGS] Copy error: %s" % self._safe_ascii_text(e))

    def _sendFindingToRepeater(self):
        """Send the selected finding's URL to Burp Repeater."""
        try:
            row = self.findingsTable.getSelectedRow()
            if row < 0:
                return
            model_row = self.findingsTable.convertRowIndexToModel(row)
            url = str(self.findingsTable.getModel().getValueAt(model_row, 1) or "")
            if url:
                self._navigate_to_url(url)
        except Exception as e:
            self.stderr.println("[FINDINGS] Send to Repeater error: %s" % self._safe_ascii_text(e))

    def _build_request_from_url(self, url):
        """Create a minimal replay request when a finding has URL but no captured request."""
        try:
            from java.net import URL as JavaURL
            parsed = JavaURL(str(url))
            protocol = str(parsed.getProtocol() or "https").lower()
            host = str(parsed.getHost() or "")
            port = int(parsed.getPort())
            if port <= 0:
                port = 443 if protocol == "https" else 80
            path = str(parsed.getFile() or "/")
            if not path:
                path = "/"
            host_header = host
            if (protocol == "https" and port != 443) or (protocol == "http" and port != 80):
                host_header = "%s:%d" % (host, port)
            request_data = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ) % (path, host_header)
            return {
                "request_data": request_data,
                "host": host,
                "port": port,
                "protocol": protocol,
            }
        except Exception as e:
            self.stderr.println("[REPRODUCE] Could not build fallback request from URL: %s" % self._safe_ascii_text(e))
            return None
