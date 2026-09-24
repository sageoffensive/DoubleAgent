# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk1Chunk3(object):
    def initUI(self):
        # Main panel
        self.panel = JPanel(BorderLayout())

        # Top panel with stats
        topPanel = JPanel()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Title
        titleLabel = JLabel("%s v%s" % (self.PRODUCT_NAME, self.VERSION))
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 16))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        topPanel.add(titlePanel)

        # Product subtitle
        subtitleLabel = JLabel("AI-Powered Application Testing for BurpSuite")
        subtitleLabel.setFont(Font("Dialog", Font.ITALIC, 12))
        subtitleLabel.setForeground(Color(0xD5, 0x59, 0x35))
        subtitlePanel = JPanel()
        subtitlePanel.add(subtitleLabel)
        topPanel.add(subtitlePanel)

        topPanel.add(Box.createRigidArea(Dimension(0, 10)))

        # Internal stats are still tracked for diagnostics, but the usage stats
        # widget is intentionally not shown in the main UI.
        self.statsLabels = {}

        # Control panel
        controlPanel = JPanel()

        # Settings button
        self.settingsButton = JButton("Settings", actionPerformed=self.openSettings)

        self.clearFindingsButton = JButton("Clear Findings", actionPerformed=self.clearFindings)

        # Cancel/Pause all buttons (kill switches)
        self.cancelAllButton = JButton("Stop Analysis", actionPerformed=self.cancelAllTasks)

        self.pauseAllButton = JButton("Pause Analysis", actionPerformed=self.pauseAllTasks)

        controlPanel.add(self.settingsButton)
        controlPanel.add(self.clearFindingsButton)
        controlPanel.add(self.cancelAllButton)
        controlPanel.add(self.pauseAllButton)

        # Passive scanning toggle
        self.passiveScanCheck = JCheckBox("Analyze Burp Traffic", self.PASSIVE_SCANNING_ENABLED)
        self.passiveScanCheck.setToolTipText(
            "Analyzes completed in-scope HTTP responses from Proxy/browser, Extender/MCP, Repeater, and Scanner/crawl traffic.")
        def onPassiveScanToggle(e):
            self.PASSIVE_SCANNING_ENABLED = self.passiveScanCheck.isSelected()
            self.stdout.println("[SETTINGS] Burp traffic analysis: %s" % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled"))
            self.save_config()
        self.passiveScanCheck.addActionListener(onPassiveScanToggle)
        controlPanel.add(self.passiveScanCheck)

        self.proxyDedupeCheck = JCheckBox("Dedupe Burp Traffic", self.PROXY_DEDUPE_ENABLED)
        self.proxyDedupeCheck.setToolTipText("Skip exact duplicate method+URL traffic from supported Burp tools within the analysis window.")
        def onProxyDedupeToggle(e):
            self.PROXY_DEDUPE_ENABLED = self.proxyDedupeCheck.isSelected()
            self.stdout.println("[SETTINGS] Proxy traffic dedupe: %s" % ("Enabled" if self.PROXY_DEDUPE_ENABLED else "Disabled"))
            self.save_config()
        self.proxyDedupeCheck.addActionListener(onProxyDedupeToggle)
        controlPanel.add(self.proxyDedupeCheck)

        self.consoleWindowCheck = JCheckBox("Show Console Window", False)
        self.consoleWindowCheck.setToolTipText("Open/close the console in a separate window")
        self.consoleWindowCheck.addActionListener(self.toggleConsoleWindow)
        controlPanel.add(self.consoleWindowCheck)

        topPanel.add(controlPanel)

        self.panel.add(topPanel, BorderLayout.NORTH)

        # Workspace tabs: Activity, Findings, Agent AI, Report
        from javax.swing import JTabbedPane, JPopupMenu
        self.workspaceTabs = JTabbedPane()

        # ===== ACTIVITY TAB =====
        activityPanel = JPanel(BorderLayout())
        activityToolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        activityToolbar.add(JLabel("Recent meaningful analysis activity"))
        activityPanel.add(activityToolbar, BorderLayout.NORTH)

        self.taskTableModel = DefaultTableModel()
        self.taskTableModel.addColumn("Timestamp")
        self.taskTableModel.addColumn("Type")
        self.taskTableModel.addColumn("URL")
        self.taskTableModel.addColumn("Status")
        self.taskTableModel.addColumn("Duration")

        self.taskTable = JTable(self.taskTableModel)
        self.taskTable.setAutoCreateRowSorter(True)
        self.taskTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.taskTable.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.taskTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        self.taskTable.getColumnModel().getColumn(3).setPreferredWidth(130)
        self.taskTable.getColumnModel().getColumn(4).setPreferredWidth(80)

        # Apply theme-aware base renderer to all columns, then override specific ones
        baseRenderer = ThemeAwareCellRenderer(self)
        for col_idx in range(self.taskTable.getColumnModel().getColumnCount()):
            self.taskTable.getColumnModel().getColumn(col_idx).setCellRenderer(baseRenderer)
        statusRenderer = StatusCellRenderer(self)
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(statusRenderer)
        self.taskTable.getColumnModel().getColumn(2).setCellRenderer(TruncatedUrlCellRenderer(60, self))
        self.taskTable.getTableHeader().setDefaultRenderer(ThemeAwareHeaderRenderer(self))
        self._add_column_resize_cursor(self.taskTable)

        # Add right-click context menu for rescan
        from javax.swing import JPopupMenu
        self.taskPopupMenu = JPopupMenu()
        rescanItem = JMenuItem("Rescan")
        def onRescan(e):
            self._rescanSelectedTask()
        rescanItem.addActionListener(onRescan)
        self.taskPopupMenu.add(rescanItem)
        self.taskTable.setComponentPopupMenu(self.taskPopupMenu)

        activityPanel.add(JScrollPane(self.taskTable), BorderLayout.CENTER)
        self.workspaceTabs.addTab("Activity", activityPanel)
        self._activityTabIndex = self.workspaceTabs.getTabCount() - 1

        # ===== FINDINGS TAB =====
        findingsPanel = JPanel(BorderLayout())

        # Findings stats bar
        findingsStatsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.findingsStatsLabel = JLabel("Total: 0 | Crit: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.findingsStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        self._showFPBtn = JButton("Show Hidden")
        self._showFPBtn.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._showFPBtn.setFocusPainted(False)
        self._showFPBtn.addActionListener(lambda e: self._toggleShowFP())
        findingsStatsPanel.add(self.findingsStatsLabel)
        findingsStatsPanel.add(self._showFPBtn)
        self.jevReviewButton = JButton("Review duplicates", actionPerformed=self._queue_duplicate_review)
        self.jevReviewButton.setToolTipText("Queue a duplicate-review task for Agent B; it marks genuine duplicates using the model configured in Double Agent. Fetch the queue in Agent B to run it.")
        findingsStatsPanel.add(self.jevReviewButton)
        self._sync_jev_controls()
        findingsPanel.add(findingsStatsPanel, BorderLayout.NORTH)

        self.findingsTableModel = DefaultTableModel()
        self.findingsTableModel.addColumn("#")
        self.findingsTableModel.addColumn("URL")
        self.findingsTableModel.addColumn("Finding")
        self.findingsTableModel.addColumn("Severity")
        self.findingsTableModel.addColumn("Confidence")
        self.findingsTableModel.addColumn("Agent Status")
        self.findingsTableModel.addColumn("Agent Priority")

        self.findingsTable = JTable(self.findingsTableModel)
        self.findingsTable.setAutoCreateRowSorter(True)
        self.findingsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS)
        self.findingsTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self.findingsTable.setRowHeight(18)

        # Custom sorting for Severity and Confidence columns
        from java.util import Comparator
        from javax.swing.table import TableRowSorter

        class IntComparator(Comparator):
            def compare(self, o1, o2):
                try:
                    return int(o1) - int(o2)
                except:
                    return 0

        class SeverityComparator(Comparator):
            def __init__(self):
                self.order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Information": 4}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 5) - self.order.get(str(o2) if o2 else "", 5)

        class ConfidenceComparator(Comparator):
            def __init__(self):
                self.order = {"Certain": 0, "Firm": 1, "Tentative": 2}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 3) - self.order.get(str(o2) if o2 else "", 3)

        class PriorityComparator(Comparator):
            def __init__(self):
                self.order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "defer": 5, "": 6}
            def compare(self, o1, o2):
                return self.order.get(str(o1) if o1 else "", 6) - self.order.get(str(o2) if o2 else "", 6)

        sorter = TableRowSorter(self.findingsTableModel)
        sorter.setComparator(0, IntComparator())
        sorter.setComparator(3, SeverityComparator())
        sorter.setComparator(4, ConfidenceComparator())
        sorter.setComparator(6, PriorityComparator())
        self.findingsTable.setRowSorter(sorter)
        # Sort by Confidence ascending (Certain first), then Severity ascending (Critical first)
        from javax.swing import SortOrder
        from javax.swing import RowSorter
        sorter.setSortKeys([
            RowSorter.SortKey(4, SortOrder.ASCENDING),  # Confidence: Certain > Firm > Tentative
            RowSorter.SortKey(3, SortOrder.ASCENDING),  # Severity: Critical > High > Medium > Low
        ])
        self.findingsSorter = sorter
        self._fp_row_filter = FPRowFilter(self)
        sorter.setRowFilter(self._fp_row_filter)

        self.findingsTable.getColumnModel().getColumn(0).setPreferredWidth(35)   # #
        self.findingsTable.getColumnModel().getColumn(0).setMaxWidth(50)
        self.findingsTable.getColumnModel().getColumn(1).setPreferredWidth(400)  # URL
        self.findingsTable.getColumnModel().getColumn(1).setMinWidth(200)
        self.findingsTable.getColumnModel().getColumn(2).setPreferredWidth(500)  # Finding
        self.findingsTable.getColumnModel().getColumn(2).setMinWidth(200)
        self.findingsTable.getColumnModel().getColumn(3).setPreferredWidth(80)   # Severity
        self.findingsTable.getColumnModel().getColumn(3).setMinWidth(70)
        self.findingsTable.getColumnModel().getColumn(4).setPreferredWidth(90)   # Confidence
        self.findingsTable.getColumnModel().getColumn(4).setMinWidth(80)
        self.findingsTable.getColumnModel().getColumn(5).setPreferredWidth(130)  # Agent Status
        self.findingsTable.getColumnModel().getColumn(5).setMinWidth(100)
        self.findingsTable.getColumnModel().getColumn(6).setPreferredWidth(90)   # Agent Priority
        self.findingsTable.getColumnModel().getColumn(6).setMinWidth(70)

        # Apply theme-aware base renderer to all columns, then override specific ones
        baseRenderer = ThemeAwareCellRenderer(self)
        for col_idx in range(self.findingsTable.getColumnModel().getColumnCount()):
            self.findingsTable.getColumnModel().getColumn(col_idx).setCellRenderer(baseRenderer)
        severityRenderer = SeverityCellRenderer(self)
        confidenceRenderer = ConfidenceCellRenderer(self)
        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(severityRenderer)
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(confidenceRenderer)
        self.findingsTable.getTableHeader().setDefaultRenderer(ThemeAwareHeaderRenderer(self))
        self._add_column_resize_cursor(self.findingsTable)

        # Selection listener for detail panel (#1)
        from javax.swing.event import ListSelectionListener
        class FindingsSelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            def valueChanged(self, e):
                if not e.getValueIsAdjusting():
                    self.extender._updateFindingDetailPanel()
        self.findingsTable.getSelectionModel().addListSelectionListener(FindingsSelectionListener(self))

        # Double-click sends to Repeater
        from java.awt.event import MouseAdapter
        class FindingsMouseListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender

            def mouseClicked(self, e):
                if e.getClickCount() == 2:
                    table = e.getSource()
                    row = table.getSelectedRow()
                    if row >= 0:
                        model_row = table.convertRowIndexToModel(row)
                        url = table.getModel().getValueAt(model_row, 1)  # URL is col 1
                        self.extender._navigate_to_url(str(url))

            def mousePressed(self, e):
                self._maybeShowPopup(e)

            def mouseReleased(self, e):
                self._maybeShowPopup(e)

            def _maybeShowPopup(self, e):
                if e.isPopupTrigger():
                    table = e.getSource()
                    row = table.rowAtPoint(e.getPoint())
                    # Only change selection if clicked row is not already in selection
                    if row >= 0 and not table.isRowSelected(row):
                        # Clear previous selection and select only this row
                        table.clearSelection()
                        table.setRowSelectionInterval(row, row)
                    # If clicked row IS selected, preserve existing multi-selection
                    self.extender.findingsPopupMenu.show(e.getComponent(), e.getX(), e.getY())

        self.findingsTable.addMouseListener(FindingsMouseListener(self))

        # Right-click context menu on findings table
        from javax.swing.event import PopupMenuListener as _PML
        self.findingsPopupMenu = JPopupMenu()
        copyUrlItem = JMenuItem("Copy URL")
        copyTitleItem = JMenuItem("Copy Finding Title")
        sendToRepeaterItem = JMenuItem("Send to Repeater")
        sendToAgentItem = JMenuItem("Send to Agent B")
        reproduceItem = JMenuItem("Reproduce (ask Agent B to send via Burp)")
        self._writeUpFindingItem = JMenuItem("Write it up for me")
        markFPItem = JMenuItem("Mark as False Positive")
        unmarkFPItem = JMenuItem("Unmark False Positive")
        self._deleteSelectedItem = JMenuItem("Delete Selected")
        exportItem = JMenuItem("Export to CSV")

        severityMenu = JMenu("Set Severity")
        for _sev in ["Critical", "High", "Medium", "Low", "Information"]:
            _sevItem = JMenuItem(_sev)
            _sevItem.addActionListener(lambda e, s=_sev: self._setSeverity(s))
            severityMenu.add(_sevItem)

        copyUrlItem.addActionListener(lambda e: self._copyFindingField(1))
        copyTitleItem.addActionListener(lambda e: self._copyFindingField(2))
        sendToRepeaterItem.addActionListener(lambda e: self._sendFindingToRepeater())
        sendToAgentItem.addActionListener(lambda e: self._sendFindingsToAgent())
        reproduceItem.addActionListener(lambda e: self._reproduceFinding())
        self._writeUpFindingItem.addActionListener(lambda e: self._writeFindingsUp())
        markFPItem.addActionListener(lambda e: self._markAsFP())
        unmarkFPItem.addActionListener(lambda e: self._unmarkAsFP())
        self._deleteSelectedItem.addActionListener(lambda e: self._deleteSelected())
        exportItem.addActionListener(lambda e: self._exportSelectedCSV())

        self.findingsPopupMenu.add(copyUrlItem)
        self.findingsPopupMenu.add(copyTitleItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(sendToRepeaterItem)
        self.findingsPopupMenu.add(sendToAgentItem)
        self.findingsPopupMenu.add(reproduceItem)
        self.findingsPopupMenu.add(self._writeUpFindingItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(markFPItem)
        self.findingsPopupMenu.add(unmarkFPItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(severityMenu)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(self._deleteSelectedItem)
        self.findingsPopupMenu.addSeparator()
        self.findingsPopupMenu.add(exportItem)

        class _FindingsPopupListener(_PML):
            def __init__(self_l, ext):
                self_l.ext = ext
            def popupMenuWillBecomeVisible(self_l, e):
                try:
                    n = len(self_l.ext.findingsTable.getSelectedRows())
                    self_l.ext._deleteSelectedItem.setText(
                        "Delete Selected (%d)" % n if n > 0 else "Delete Selected")
                    self_l.ext._writeUpFindingItem.setText(
                        "Write them up for me (%d)" % n if n > 1 else "Write it up for me")
                    self_l.ext._writeUpFindingItem.setEnabled(n > 0)
                except:
                    pass
            def popupMenuWillBecomeInvisible(self_l, e):
                pass
            def popupMenuCanceled(self_l, e):
                pass
        self.findingsPopupMenu.addPopupMenuListener(_FindingsPopupListener(self))

        findingsScrollPane = JScrollPane(self.findingsTable)

        # Findings detail panel (#1): shows description/evidence/CWE when a finding is selected
        self.findingDetailText = JTextArea()
        self.findingDetailText.setEditable(False)
        self.findingDetailText.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.findingDetailText.setLineWrap(True)
        self.findingDetailText.setWrapStyleWord(True)
        self.findingDetailText.setText("Select a finding to view details.")
        findingDetailScroll = JScrollPane(self.findingDetailText)
        self.findingDetailScroll = findingDetailScroll
        findingDetailScroll.setBorder(BorderFactory.createTitledBorder("Finding Details"))
        self._style_finding_detail_panel()

        findingsSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        findingsSplitPane.setResizeWeight(0.65)
        findingsSplitPane.setTopComponent(findingsScrollPane)
        findingsSplitPane.setBottomComponent(findingDetailScroll)
        self.findingsSplitPane = findingsSplitPane

        findingsPanel.add(findingsSplitPane, BorderLayout.CENTER)
        self.workspaceTabs.addTab("Findings (0)", findingsPanel)
        self._findingsTabIndex = self.workspaceTabs.getTabCount() - 1

        # ===== AGENT AI TAB =====
        agentPanel = JPanel(BorderLayout())

        # Top: server controls
        agentServerPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentServerPanel.setBorder(BorderFactory.createTitledBorder("Agent API Server"))

        self.agentServerStatusLabel = JLabel("Status: Stopped")
        self.agentServerStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        agentServerPanel.add(self.agentServerStatusLabel)

        agentServerPanel.add(JLabel("  Port:"))
        self.agentPortField = JTextField(str(self.agent_server_port), 6)
        agentServerPanel.add(self.agentPortField)

        self.agentStartBtn = JButton("Start Server")
        def _startAgent(e):
            try:
                p = int(self.agentPortField.getText().strip())
                self.agent_server_port = p
            except:
                pass
            self.start_agent_server()
            self._ui_dirty = True
            self.refreshUI()
        self.agentStartBtn.addActionListener(_startAgent)
        agentServerPanel.add(self.agentStartBtn)

        self.agentStopBtn = JButton("Stop Server")
        def _stopAgent(e):
            self.stop_agent_server()
            self._ui_dirty = True
            self.refreshUI()
        self.agentStopBtn.addActionListener(_stopAgent)
        agentServerPanel.add(self.agentStopBtn)

        self.agentCopyEndpointBtn = JButton("Copy Agent B's Prompt")
        def _copyEndpoint(e):
            try:
                url = "http://%s:%d" % (self.agent_server_host, self.agent_server_port)
                text = self._build_agent_burp_expert_prompt(url)
                from java.awt import Toolkit
                from java.awt.datatransfer import StringSelection
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
                self.log_to_console("[AGENT] Bootstrap prompt copied to clipboard")
                # Visual feedback: change button text temporarily
                original_text = self.agentCopyEndpointBtn.getText()
                self.agentCopyEndpointBtn.setText("Copied")
                from javax.swing import Timer
                def _restore_text(event):
                    self.agentCopyEndpointBtn.setText(original_text)
                t = Timer(2000, _restore_text)
                t.setRepeats(False)
                t.start()
            except Exception as ex:
                self.stderr.println("[AGENT] Copy error: %s" % self._safe_ascii_text(ex))
        self.agentCopyEndpointBtn.addActionListener(_copyEndpoint)
        agentServerPanel.add(self.agentCopyEndpointBtn)

        self.agentCopyResumePromptBtn = JButton("Copy Resume Prompt")
        def _copyResumePrompt(e):
            try:
                url = "http://%s:%d" % (self.agent_server_host, self.agent_server_port)
                text = self._build_agent_resume_prompt(url)
                from java.awt import Toolkit
                from java.awt.datatransfer import StringSelection
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
                self.log_to_console("[AGENT] Resume prompt copied to clipboard")
                original_text = self.agentCopyResumePromptBtn.getText()
                self.agentCopyResumePromptBtn.setText("Copied")
                from javax.swing import Timer
                def _restore_text(event):
                    self.agentCopyResumePromptBtn.setText(original_text)
                t = Timer(2000, _restore_text)
                t.setRepeats(False)
                t.start()
            except Exception as ex:
                self.stderr.println("[AGENT] Copy resume prompt error: %s" % self._safe_ascii_text(ex))
        self.agentCopyResumePromptBtn.addActionListener(_copyResumePrompt)
        agentServerPanel.add(self.agentCopyResumePromptBtn)

        self.agentBrowserOSCheck = JCheckBox("Enable BrowserOS", self.AGENT_BROWSEROS_ENABLED)
        self.agentBrowserOSCheck.setToolTipText(
            "Allow Agent B to use and configure BrowserOS for browser-dependent work. "
            "When disabled, BrowserOS setup instructions and completion requirements are omitted."
        )
        def _toggleAgentBrowserOS(e):
            self.AGENT_BROWSEROS_ENABLED = bool(self.agentBrowserOSCheck.isSelected())
            self.save_config()
            self.log_to_console("[AGENT] BrowserOS for Agent B: %s" % (
                "Enabled" if self.AGENT_BROWSEROS_ENABLED else "Disabled"))
            self._ui_dirty = True
            self.refreshUI()
        self.agentBrowserOSCheck.addActionListener(_toggleAgentBrowserOS)

        agentPanel.add(agentServerPanel, BorderLayout.NORTH)

        # Middle: queue selector/status plus action buttons on a second row.
        agentQueuePanel = JPanel(BorderLayout())
        agentQueuePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        agentQueueStatusPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentQueueActionsPanel = JPanel(BorderLayout())
        agentPrimaryActionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        agentSecondaryActionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        agentQueueStatusPanel.add(JLabel("Work Items:"))
        self.agentHistoryCombo = JComboBox()
        self.agentHistoryCombo.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.agentHistoryCombo.setPreferredSize(Dimension(360, 25))
        self._agent_combo_updating = False

        def onAgentComboSelected(e):
            if self._agent_combo_updating:
                return
            idx = self.agentHistoryCombo.getSelectedIndex()
            if idx >= 0:
                self.selected_agent_queue_index = idx
                self.updateAgentAssessmentDetails(idx)

        self.agentHistoryCombo.addActionListener(onAgentComboSelected)
        agentQueueStatusPanel.add(self.agentHistoryCombo)

        self.agentStatsLabel = JLabel("Pending: 0 | Claimed: 0 | Completed: 0")
        self.agentStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        agentQueueStatusPanel.add(self.agentStatsLabel)
        agentQueueStatusPanel.add(self.agentBrowserOSCheck)

        self.agentClearBtn = JButton("Clear Queue")
        def _clearQueue(e):
            try:
                with self.agent_queue_lock:
                    count = len(self.agent_queue)
                    self.agent_queue = []
                    self.agent_queue_next_id = 0
                    self.selected_agent_queue_index = -1
                self.save_agent_queue()
                self.log_to_console("[AGENT] Queue cleared (%d items removed)" % count)
                self._ui_dirty = True
                self.refreshUI()
                self.agentAssessmentText.setText(
                    "Queue cleared.\n\n"
                    + self._agent_quick_start_text()
                )
            except Exception as ex:
                self.stderr.println("[AGENT] Clear queue error: %s" % self._safe_ascii_text(ex))
        self.agentClearBtn.addActionListener(_clearQueue)
        agentSecondaryActionsPanel.add(self.agentClearBtn)

        # Import WebSocket button (since context menu doesn't work in WebSockets history)
        self.agentImportWsBtn = JButton("Import WebSocket")
        def _importWs(e):
            self._showWebSocketImportDialog()
        self.agentImportWsBtn.addActionListener(_importWs)
        agentSecondaryActionsPanel.add(self.agentImportWsBtn)

        self.agentSendRepeaterBtn = JButton("Send to Repeater")
        self.agentSendRepeaterBtn.setToolTipText("Create Burp Repeater tabs for the selected agent queue item")
        self.agentSendRepeaterBtn.addActionListener(lambda e: self._sendSelectedAgentQueueToRepeater())
        agentSecondaryActionsPanel.add(self.agentSendRepeaterBtn)

        self.agentRiskHuntBtn = JButton("Queue Automated Testing")
        self.agentRiskHuntBtn.setToolTipText("Queue active Agent B testing to verify every Agent A finding in the current list")
        self.agentRiskHuntBtn.addActionListener(lambda e: self._queueRiskHunt())
        agentPrimaryActionsPanel.add(self.agentRiskHuntBtn)

        self.agentFullAppBtn = JButton("Full App Assessment")
        self.agentFullAppBtn.setToolTipText("Queue visible application-wide discovery through Burp, attack-surface mapping, active testing, and deterministic coverage overwatch")
        self.agentFullAppBtn.addActionListener(lambda e: self._queueFullAppAssessment())
        agentPrimaryActionsPanel.add(self.agentFullAppBtn)

        self.agentTryHarderBtn = JButton("Try Harder")
        self.agentTryHarderBtn.setToolTipText("Queue a bounded autonomous hunt for one previously undiscovered High/Critical web app bug")
        self.agentTryHarderBtn.addActionListener(lambda e: self._queueTryHarder())
        self._style_try_harder_button()
        agentPrimaryActionsPanel.add(self.agentTryHarderBtn)

        self.agentImportFixturesBtn = JButton("View/Edit Test Context")
        self.agentImportFixturesBtn.setToolTipText("View current context and paste kickoff or mid-test updates for scope, auth, accounts, sessions, objects, and consent context")
        self.agentImportFixturesBtn.addActionListener(lambda e: self._showTestContextDialog())
        agentPrimaryActionsPanel.add(self.agentImportFixturesBtn)

        agentQueueActionsPanel.add(agentPrimaryActionsPanel, BorderLayout.NORTH)
        agentQueueActionsPanel.add(agentSecondaryActionsPanel, BorderLayout.SOUTH)

        agentQueuePanel.add(agentQueueStatusPanel, BorderLayout.NORTH)
        agentQueuePanel.add(agentQueueActionsPanel, BorderLayout.SOUTH)

        # Combine server panel + queue panel into one north panel
        agentNorth = JPanel(BorderLayout())
        agentNorth.add(agentServerPanel, BorderLayout.NORTH)
        agentNorth.add(agentQueuePanel, BorderLayout.SOUTH)
        agentPanel.removeAll()
        agentPanel.setLayout(BorderLayout())
        agentPanel.add(agentNorth, BorderLayout.NORTH)

        # Center: work item details
        centerPanel = JPanel(BorderLayout())

        # Assessment text area fills remaining space and is scrollable
        self.agentAssessmentText = JTextArea()
        self.agentAssessmentText.setEditable(False)
        self.agentAssessmentText.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.agentAssessmentText.setLineWrap(True)
        self.agentAssessmentText.setWrapStyleWord(True)
        self.agentAssessmentText.setText(self._agent_quick_start_text())
        centerPanel.add(JScrollPane(self.agentAssessmentText), BorderLayout.CENTER)

        agentPanel.add(centerPanel, BorderLayout.CENTER)

        self.workspaceTabs.addTab("Agent AI", agentPanel)
        self._agentTabIndex = self.workspaceTabs.getTabCount() - 1

        self.reportIncludeFP = None
        self.reportIncludeDeferred = None
        self.reportTextArea = None

        # Log tab switching performance while debugging UI pauses.
        def _onTabChange(e):
            start = time.time()
            try:
                selected_idx = self.workspaceTabs.getSelectedIndex()
                try:
                    selected_title = self.workspaceTabs.getTitleAt(selected_idx)
                except:
                    selected_title = "unknown"
                self._last_tab_switch_started_at = start
                self.stdout.println("[UI PERF] Tab switch -> %s" % selected_title)
                elapsed_ms = int((time.time() - start) * 1000)
                if elapsed_ms > 250:
                    self.stdout.println("[UI PERF] Tab switch handler slow: %dms -> %s" % (elapsed_ms, selected_title))
            except Exception as ex:
                try:
                    self.stderr.println("[UI PERF] Tab switch handler error: %s" % self._safe_ascii_text(ex))
                except:
                    pass
        self.workspaceTabs.addChangeListener(_onTabChange)

        self.panel.add(self.workspaceTabs, BorderLayout.CENTER)

        # Console Panel (shown in popup dialog via checkbox)
        consolePanel = JPanel(BorderLayout())
        consolePanel.setBorder(BorderFactory.createTitledBorder("Console"))

        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self.consoleTextArea.setLineWrap(True)
        self.consoleTextArea.setWrapStyleWord(False)
        self.applyConsoleTheme()

        consoleScrollPane = JScrollPane(self.consoleTextArea)
        consoleScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        self.console_user_scrolled = False

        from java.awt.event import AdjustmentListener
        class ScrollListener(AdjustmentListener):
            def __init__(self, extender):
                self.extender = extender
                self.last_value = 0

            def adjustmentValueChanged(self, e):
                scrollbar = e.getAdjustable()
                current_value = scrollbar.getValue()
                max_value = scrollbar.getMaximum() - scrollbar.getVisibleAmount()
                if current_value < max_value - 10:
                    self.extender.console_user_scrolled = True
                else:
                    self.extender.console_user_scrolled = False

        consoleScrollPane.getVerticalScrollBar().addAdjustmentListener(ScrollListener(self))
        consolePanel.add(consoleScrollPane, BorderLayout.CENTER)

        from javax.swing import JDialog, WindowConstants
        from java.awt.event import WindowAdapter

        self.consoleDialog = JDialog()
        self.consoleDialog.setTitle("Console")
        self.consoleDialog.setModal(False)
        self.consoleDialog.setSize(1000, 320)
        self.consoleDialog.setLocationRelativeTo(self.panel)
        self.consoleDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE)
        self.consoleDialog.add(consolePanel)

        class ConsoleWindowListener(WindowAdapter):
            def __init__(self, extender):
                self.extender = extender
            def windowClosing(self, e):
                try:
                    if hasattr(self.extender, "consoleWindowCheck") and self.extender.consoleWindowCheck is not None:
                        self.extender.consoleWindowCheck.setSelected(False)
                except:
                    pass

        self.consoleDialog.addWindowListener(ConsoleWindowListener(self))
        self._apply_dark_theme_to_container(self.consoleDialog)
        self.consoleDialog.setVisible(False)

        # Restore persisted column widths (#5)
        self._restore_column_widths()

        self.apply_hacker_ui_theme()

    def toggleConsoleWindow(self, event=None):
        if not hasattr(self, "consoleDialog") or self.consoleDialog is None:
            return

        show_console = False
        try:
            if hasattr(self, "consoleWindowCheck") and self.consoleWindowCheck is not None:
                show_console = bool(self.consoleWindowCheck.isSelected())
        except:
            show_console = False

        try:
            if show_console:
                self.consoleDialog.setLocationRelativeTo(self.panel)
                self.consoleDialog.setVisible(True)
                self.consoleDialog.toFront()
                self.consoleDialog.requestFocus()
            else:
                self.consoleDialog.setVisible(False)
        except Exception as e:
            self.stderr.println("[UI] Failed to toggle console window: %s" % self._safe_ascii_text(e))

    def _detect_burp_theme(self):
        """Detect whether Burp Suite is running a dark or light theme."""
        try:
            bg = UIManager.getColor("Panel.background")
            if bg is not None:
                luminance = (bg.getRed() * 299 + bg.getGreen() * 587 + bg.getBlue() * 114) / 1000
                return "Dark" if luminance < 128 else "Light"
        except:
            pass
        return "Dark"

    def _resolved_theme(self):
        """Return 'Dark' or 'Light' based on current theme setting."""
        if self.THEME == "Auto":
            return self._detect_burp_theme()
        return self.THEME

    def _agent_quick_start_text(self):
        """Short new-user guide for the Agent AI tab."""
        return (
            "Double Agent quick start\n"
            "------------------------\n"
            "1. Click 'Start Server'. Keep Burp open while the agent is working.\n"
            "2. Click 'View/Edit Test Context' whenever scope, roles, auth model, test accounts,\n"
            "   sessions, allowed actions, useful object IDs, or target knowledge change during the test.\n"
            "3. In the Agent B harness, click 'Connect to Burp' to load this prompt automatically.\n"
            "   'Copy Agent B's Prompt' remains available for other harnesses. Use 'Copy Resume Prompt' when continuing later.\n"
            "4. Use the primary action row under Work Items:\n"
            "   - 'Queue Automated Testing' sends Agent B to verify every Agent A finding\n"
            "     in the list. One umbrella goal is OK if every finding is updated or Gated.\n"
            "   - 'Full App Assessment' uses BrowserOS when Enable BrowserOS is selected;\n"
            "     otherwise it uses Burp history, Site Map, and available native actions.\n"
            "     It persists an attack-surface map and actively tests prioritized gaps.\n"
            "   - 'Try Harder' sends Agent B on a bounded solo hunt for one previously\n"
            "     undiscovered High/Critical bug, using available skills/tools and stopping at clear limits.\n"
            "   - 'View/Edit Test Context' shows scope, test context, confirmations, and the knowledge base; it merges updates.\n"
            "5. For focused validation, right-click findings or HTTP requests and choose Double Agent.\n"
            "   'Send to Repeater' creates Burp tabs for the selected work item.\n"
            "6. Use the Work Items dropdown to review queued, claimed, and completed work.\n"
            "7. The agent posts outcomes back here. Findings update automatically, completed\n"
            "   results can be amended, and the live report is available at GET /api/report.\n"
            "\n"
        )

    def _style_finding_detail_panel(self):
        """Give the bottom Finding Details inspector a distinct surface."""
        try:
            dark = self._resolved_theme() == "Dark"
            if dark:
                bg = Color(0x06, 0x10, 0x18)
                fg = Color(0xE6, 0xF2, 0xFF)
                border_color = Color(0x2D, 0x4B, 0x63)
            else:
                bg = Color(0xE8, 0xEA, 0xED)
                fg = Color(0x1F, 0x1F, 0x1F)
                border_color = Color(0xB8, 0xC0, 0xC8)

            text = getattr(self, "findingDetailText", None)
            if text is not None:
                text.setOpaque(True)
                text.setBackground(bg)
                text.setForeground(fg)
                text.setCaretColor(fg)

            scroll = getattr(self, "findingDetailScroll", None)
            if scroll is not None:
                scroll.setOpaque(True)
                scroll.setBackground(bg)
                try:
                    viewport = scroll.getViewport()
                    if viewport is not None:
                        viewport.setOpaque(True)
                        viewport.setBackground(bg)
                except:
                    pass
                try:
                    title_border = TitledBorder(BorderFactory.createLineBorder(border_color), "Finding Details")
                    title_border.setTitleColor(fg)
                    scroll.setBorder(title_border)
                except:
                    scroll.setBorder(BorderFactory.createTitledBorder("Finding Details"))
        except:
            pass

    def _style_try_harder_button(self):
        """Keep the autonomous hunt action visually distinct from normal queue actions."""
        try:
            btn = getattr(self, "agentTryHarderBtn", None)
            if btn is None:
                return
            dark = self._resolved_theme() == "Dark"
            if dark:
                bg = Color(0xB5, 0x1F, 0x2D)
                border = Color(0xFF, 0x6B, 0x6B)
            else:
                bg = Color(0xD9, 0x2D, 0x20)
                border = Color(0x9F, 0x1D, 0x18)
            btn.setBackground(bg)
            btn.setForeground(Color.WHITE)
            btn.setFont(Font("Monospaced", Font.BOLD, 12))
            btn.setBorder(BorderFactory.createLineBorder(border, 1))
            btn.setOpaque(True)
            try:
                btn.setFocusPainted(False)
            except:
                pass
        except:
            pass

    def _style_all_tab_panes(self):
        """Apply tab title colors using custom JLabel tab components.
        setForegroundAt is ignored by Burp's L&F, so we must use setTabComponentAt."""
        from javax.swing import JLabel
        dark = self._resolved_theme() == "Dark"
        fg = Color.WHITE if dark else Color(0x33, 0x33, 0x33)
        for tab_name in ("workspaceTabs",):
            tabbed = getattr(self, tab_name, None)
            if tabbed is None:
                continue
            for i in range(tabbed.getTabCount()):
                title = tabbed.getTitleAt(i)
                lbl = tabbed.getTabComponentAt(i)
                if lbl is None or not isinstance(lbl, JLabel):
                    lbl = JLabel(title)
                    lbl.setFont(Font("Monospaced", Font.BOLD, 11))
                    lbl.setOpaque(False)
                    tabbed.setTabComponentAt(i, lbl)
                else:
                    lbl.setText(title)
                lbl.setForeground(fg)
