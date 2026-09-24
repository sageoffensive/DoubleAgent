# -*- coding: utf-8 -*-
"""Optional Swing controls for Jev duplicate review.

The review itself is read-only; after it finishes, same_issue pairs at or above
JEV_AUTO_APPLY_CONFIDENCE are auto-marked agent_status=duplicate with a jev
marker so the Agent Status column shows "duplicate (jev)". Pairs below the
threshold, or with no confidence, are left untouched as suggestions only.
"""
import threading
from datetime import datetime
from jev_duplicate_review import candidate_pairs, review_pairs, text, MAX_PAIRS, MAX_FINDINGS

# Only high-confidence same_issue decisions are auto-applied; everything else
# stays a suggestion. Keep this conservative because it mutates saved findings.
JEV_AUTO_APPLY_CONFIDENCE = 0.8


class JevReviewMixin(object):
    def _add_jev_settings_tab(self, tabs):
        from javax.swing import JPanel, JCheckBox, JPasswordField, JLabel, JTextArea, BoxLayout, BorderFactory
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        enabled = JCheckBox("Enable Jev duplicate review for Agent A findings", self.JEV_DEDUP_ENABLED)
        key = JPasswordField(self.JEV_API_KEY, 35)
        panel.add(enabled)
        panel.add(JLabel("Jev API key (OpenRouter):"))
        key.setMaximumSize(key.getPreferredSize())
        panel.add(key)
        info = JTextArea(
            "Uses Jev through OpenRouter. Enter an OpenRouter key, not a direct TypeSafe key.\n\n"
            "After saving, use Review duplicates in Findings. Selected Agent A findings are\n"
            "reviewed when two or more are selected; otherwise the review uses existing\n"
            "Agent A findings. Each review compares up to 40 candidate pairs.\n\n"
            "Redacted titles, URLs, descriptions and evidence summaries are sent to OpenRouter.\n"
            "Raw HTTP messages are omitted. Review summaries before using this with sensitive data.\n"
            "Suggestions leave the original findings and their evidence intact.\n\n"
            "The key is masked here and saved locally with your other provider settings."
        )
        info.setEditable(False)
        info.setBackground(panel.getBackground())
        panel.add(info)
        tabs.addTab("Jev Deduplication", panel)
        return enabled, key

    def _jev_settings_values(self, controls):
        enabled, key = controls
        value = u"".join(key.getPassword()).strip()
        if enabled.isSelected() and not value:
            raise ValueError("Enter an OpenRouter API key or disable Jev duplicate review.")
        return bool(enabled.isSelected()), value

    def _sync_jev_controls(self):
        check = getattr(self, "jevDedupeCheck", None)
        if check is not None:
            check.setSelected(bool(self.JEV_DEDUP_ENABLED))
        button = getattr(self, "jevReviewButton", None)
        if button is not None:
            # Review duplicates now queues a task for Agent B (uses the model
            # configured in Double Agent), so it no longer needs an OpenRouter key.
            button.setEnabled(not getattr(self, "_jev_review_running", False))

    def _toggle_jev_review(self, event):
        from javax.swing import JOptionPane
        enabled = self.jevDedupeCheck.isSelected()
        if enabled and not self.JEV_API_KEY:
            self.jevDedupeCheck.setSelected(False)
            JOptionPane.showMessageDialog(self.panel, "Add an OpenRouter API key in Settings > Jev Deduplication.", "Jev duplicate review", JOptionPane.INFORMATION_MESSAGE)
            return
        previous = self.JEV_DEDUP_ENABLED
        self.JEV_DEDUP_ENABLED = bool(enabled)
        if not self.save_config():
            self.JEV_DEDUP_ENABLED = previous
            JOptionPane.showMessageDialog(self.panel, "Could not save the Jev setting. Check the extension error log.", "Jev duplicate review", JOptionPane.ERROR_MESSAGE)
        if not self.JEV_DEDUP_ENABLED:
            self._cancel_jev_review()
        self._sync_jev_controls()

    def _cancel_jev_review(self):
        stop = getattr(self, "_jev_review_stop", None)
        if stop is not None:
            stop.set()

    def _queue_duplicate_review(self, event):
        """Review duplicates button: queue a read-only duplicate-review task for
        Agent B, which marks genuine duplicates with the model configured in
        Double Agent. Replaces the direct OpenRouter/Jev call."""
        from javax.swing import JOptionPane
        ids = self._automated_testing_finding_ids()
        if len(ids) < 2:
            JOptionPane.showMessageDialog(self.panel,
                "Need at least two Agent A findings to review for duplicates.",
                "Duplicate review", JOptionPane.INFORMATION_MESSAGE)
            return
        choice = JOptionPane.showConfirmDialog(self.panel,
            ("Queue a duplicate-review task for Agent B?\n\n%d Agent A finding(s) will be compared pairwise. "
             "Agent B marks genuine duplicates as 'duplicate' using your configured model (no target traffic is sent). "
             "In Agent B, click Fetch Burp queue to run it." % len(ids)),
            "Queue duplicate review", JOptionPane.OK_CANCEL_OPTION)
        if choice != JOptionPane.OK_OPTION:
            return
        try:
            qid = self._enqueueDuplicateReview(requested_by="ui")
        except Exception as exc:
            self.stderr.println("[JEV] Queue duplicate review error: %s" % self._safe_ascii_text(exc))
            qid = None
        if qid is None:
            JOptionPane.showMessageDialog(self.panel,
                "Could not queue the duplicate review. Check the extension error log.",
                "Duplicate review", JOptionPane.ERROR_MESSAGE)
            return
        JOptionPane.showMessageDialog(self.panel,
            "Queued duplicate review as work item #%d.\nIn Agent B, click Fetch Burp queue to run it." % qid,
            "Duplicate review", JOptionPane.INFORMATION_MESSAGE)

    def _apply_jev_duplicates(self, results, threshold=JEV_AUTO_APPLY_CONFIDENCE):
        """Auto-mark high-confidence same_issue pairs as duplicate (jev). Keeps the
        earlier-discovered finding as canonical and marks the later one; never
        touches findings already validated by Agent B or already resolved."""
        applied = 0
        same_issue_seen = 0
        skipped_low_conf = 0
        with self.findings_lock_ui:
            for result in results or []:
                if not isinstance(result, dict) or result.get("choice") != "same_issue":
                    continue
                same_issue_seen += 1
                # Some models return only a probability distribution, not a scalar
                # confidence; fall back to the same_issue probability.
                confidence = result.get("confidence")
                if confidence is None:
                    confidence = result.get("same_issue_probability")
                if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or confidence < threshold:
                    skipped_low_conf += 1
                    continue
                left_id = text((result.get("left") or {}).get("id", ""))
                right_id = text((result.get("right") or {}).get("id", ""))
                # snapshot- ids have no stable_id and cannot be located safely.
                if not left_id or not right_id or left_id.startswith("snapshot-") or right_id.startswith("snapshot-"):
                    continue
                left_idx = self._finding_index_by_reference_unlocked(left_id)
                right_idx = self._finding_index_by_reference_unlocked(right_id)
                if left_idx is None or right_idx is None or left_idx == right_idx:
                    continue
                if not (0 <= left_idx < len(self.findings_list)) or not (0 <= right_idx < len(self.findings_list)):
                    continue
                dup_idx, primary_idx = (right_idx, left_idx) if right_idx > left_idx else (left_idx, right_idx)
                dup = self.findings_list[dup_idx]
                primary = self.findings_list[primary_idx]
                if self._agent_validation_marker(dup) == "B":
                    continue
                if self._agent_status_value(dup.get("agent_status", "")) in ("duplicate", "false_positive", "already_covered"):
                    continue
                dup["agent_status"] = "duplicate"
                dup["jev_duplicate"] = True
                dup["duplicate_of"] = text(primary.get("stable_id", "") or self._ensure_finding_stable_id(primary))
                dup["agent_priority"] = "defer"
                dup["agent_rationale"] = "Jev auto-review: same issue as %s (confidence %.2f)." % (
                    text(primary.get("stable_id", "primary")), confidence)
                dup["agent_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                applied += 1
        if applied:
            self.save_findings()
        try:
            self.log_to_console(
                "[JEV] Auto-apply: %d same_issue pair(s), %d below confidence %.2f, %d marked duplicate (jev)."
                % (same_issue_seen, skipped_low_conf, threshold, applied))
        except Exception:
            pass
        return applied

    def _review_jev_duplicates(self, event):
        from javax.swing import JDialog, JPanel, JLabel, JTable, JTextArea, JScrollPane, JSplitPane, JButton, SwingUtilities
        from javax.swing.table import DefaultTableModel
        from javax.swing.event import ListSelectionListener
        from java.awt import BorderLayout, FlowLayout
        from java.awt.event import WindowAdapter
        if not self.JEV_DEDUP_ENABLED or not self.JEV_API_KEY or getattr(self, "_jev_review_running", False):
            return
        selected = [self.findingsTable.convertRowIndexToModel(row) for row in self.findingsTable.getSelectedRows()]
        selected_ids = set(text(self.findingsTableModel.getValueAt(row, 0)) for row in selected)
        stop = threading.Event()
        self._jev_review_stop = stop
        self._jev_review_running = True
        self._sync_jev_controls()
        key = self.JEV_API_KEY
        dialog = JDialog()
        dialog.setTitle("Jev duplicate review - auto-marks high-confidence duplicates")
        dialog.setModal(False)
        dialog.setSize(980, 650)
        dialog.setLocationRelativeTo(self.panel)
        status = JLabel("Reading saved findings...")
        class PreviewModel(DefaultTableModel):
            def isCellEditable(self, row, column):
                return False
        model = PreviewModel()
        for name in ("Finding A", "Finding B", "Relationship", "Confidence"):
            model.addColumn(name)
        table = JTable(model)
        detail = JTextArea()
        detail.setEditable(False)
        detail.setLineWrap(True)
        detail.setWrapStyleWord(True)
        results = []
        class Selection(ListSelectionListener):
            def valueChanged(self_l, event):
                row = table.getSelectedRow()
                if row < 0 or row >= len(results):
                    return
                result = results[row]
                sections = []
                for label in ("left", "right"):
                    finding = result[label]
                    sections.append(u"%s\n%s\n%s\nCWE: %s | Method: %s\nLocation: %s\n\n%s\n\nEvidence:\n%s" % (
                        finding["id"], finding["title"], finding["url"], finding["cwe"], finding["method"],
                        finding["fingerprint_location"], finding["detail"], finding["evidence"]))
                detail.setText(u"\n\n--------------------\n\n".join(sections) + u"\n\nModel: " + result["model"] + u"\nSnapshot preview; original findings are unchanged. Confidence is not verified accuracy.")
                detail.setCaretPosition(0)
        table.getSelectionModel().addListSelectionListener(Selection())
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), JScrollPane(detail))
        split.setResizeWeight(0.45)
        controls = JPanel(FlowLayout(FlowLayout.RIGHT))
        cancel = JButton("Stop review")
        def stop_review(e):
            stop.set()
            cancel.setEnabled(False)
            status.setText("Stopping review...")
        cancel.addActionListener(stop_review)
        close = JButton("Close")
        def close_dialog(e):
            stop.set()
            dialog.dispose()
        close.addActionListener(close_dialog)
        controls.add(cancel)
        controls.add(close)
        class Closing(WindowAdapter):
            def windowClosing(self_l, event):
                stop.set()
        dialog.addWindowListener(Closing())
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
        dialog.add(status, BorderLayout.NORTH)
        dialog.add(split, BorderLayout.CENTER)
        dialog.add(controls, BorderLayout.SOUTH)
        self._apply_dark_theme_to_container(dialog)
        dialog.setVisible(True)

        def worker():
            reviewed = [0]
            marked = [0]
            collected = []
            pairs = []
            outcome = "Complete"
            try:
                # Never wait for the findings lock on Swing's event thread.
                while not stop.is_set():
                    if self.findings_lock_ui.acquire(False):
                        try:
                            if len(selected_ids) >= 2:
                                rows = []
                                for reference in selected_ids:
                                    idx = self._finding_index_by_reference_unlocked(reference)
                                    if idx is not None and 0 <= idx < len(self.findings_list):
                                        rows.append(dict(self.findings_list[idx]))
                            else:
                                rows = [dict(row) for row in self.findings_list]
                        finally:
                            self.findings_lock_ui.release()
                        break
                    stop.wait(0.1)
                else:
                    rows = []
                def set_status(message):
                    def display_status():
                        if dialog.isDisplayable() and not stop.is_set():
                            status.setText(message)
                    SwingUtilities.invokeLater(display_status)
                set_status("Preparing candidate pairs...")
                pairs = candidate_pairs(rows, cancelled=stop.is_set)
                def progress(number, total):
                    set_status("Waiting for Jev: pair %d of %d (25-second response limit)..." % (number, total))
                def add(result):
                    reviewed[0] += 1
                    count = reviewed[0]
                    # Runs on the worker thread; keep a copy for the apply pass.
                    collected.append(result)
                    def display():
                        if not dialog.isDisplayable() or stop.is_set():
                            return
                        results.append(result)
                        confidence = result["confidence"]
                        model.addRow([result["left"]["title"], result["right"]["title"], result["choice"].replace("_", " "),
                                      "unknown" if confidence is None else "%.2f" % confidence])
                        status.setText("Reviewed %d / %d candidate pairs" % (count, len(pairs)))
                    SwingUtilities.invokeLater(display)
                review_pairs(pairs, key, stop.is_set, add, on_progress=progress)
                if stop.is_set():
                    outcome = "Stopped"
                elif not pairs:
                    outcome = "No candidate pairs found among eligible Agent A findings"
            except Exception as exc:
                # compare_pair returns sanitized errors; never log raw finding payloads.
                outcome = text(exc) if isinstance(exc, ValueError) else "Review failed. No findings were changed."
            finally:
                # Apply whatever high-confidence same_issue pairs were successfully
                # compared, even if a later pair failed (e.g. HTTP 403) or the run
                # was stopped. review_pairs raises on the first failure, so doing
                # this only in the success path discarded already-reviewed results.
                try:
                    if collected and not stop.is_set():
                        marked[0] = self._apply_jev_duplicates(collected)
                except Exception:
                    marked[0] = 0
                if marked[0]:
                    def refresh():
                        self._ui_dirty = True
                        self.refreshUI()
                    SwingUtilities.invokeLater(refresh)
                def finish():
                    self._jev_review_running = False
                    self._sync_jev_controls()
                    cancel.setEnabled(False)
                    if dialog.isDisplayable():
                        # Two short lines keep errors and completion visible.
                        from xml.sax.saxutils import escape
                        if marked[0]:
                            tail = "marked %d as duplicate (jev); others unchanged." % marked[0]
                        else:
                            tail = "no high-confidence duplicates auto-marked."
                        status.setText("<html>%s<br>%d / %d pairs reviewed. %s</html>" % (
                            escape(outcome), reviewed[0], len(pairs), escape(tail)))
                SwingUtilities.invokeLater(finish)
        thread = threading.Thread(target=worker, name="JevDuplicateReview")
        thread.daemon = True
        thread.start()
