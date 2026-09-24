# -*- coding: utf-8 -*-
from double_agent_prelude import *

# UI Component Classes

class FPRowFilter(RowFilter):
    """RowFilter that hides non-reportable findings unless show hidden is enabled."""
    def __init__(self, extender):
        super(FPRowFilter, self).__init__()
        self.extender = extender

    def include(self, entry):
        try:
            row = entry.getIdentifier()
            if self.extender._show_fp_findings:
                return True
            with self.extender.findings_lock_ui:
                if row < len(self.extender.findings_list):
                    return not self.extender._finding_hidden_from_normal_view(
                        self.extender.findings_list[row])
        except:
            pass
        return True


class ThemeAwareHeaderRenderer(DefaultTableCellRenderer):
    """Header renderer that applies dark/light theme colors with visible column separators."""
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)
        if dark:
            c.setBackground(Color(0x1A, 0x2F, 0x42))
            c.setForeground(Color(0x00, 0xF5, 0xA0))
            sep_color = Color(0x00, 0xF5, 0xA0, 0x60)
        else:
            c.setBackground(UIManager.getColor("TableHeader.background"))
            c.setForeground(UIManager.getColor("TableHeader.foreground"))
            sep_color = Color(0x99, 0x99, 0x99)
        c.setFont(Font("Monospaced", Font.BOLD, 12))
        c.setOpaque(True)
        # Add a visible right-edge separator so drag zones are obvious
        from javax.swing.border import MatteBorder
        c.setBorder(MatteBorder(0, 0, 0, 2, sep_color))
        return c


def _renderer_dark_mode(extender=None, table=None):
    try:
        if extender is not None and extender._detect_burp_theme() == "Dark":
            return True
    except:
        pass

    try:
        if extender is not None and extender._resolved_theme() == "Dark":
            return True
    except:
        pass

    try:
        if table is not None:
            bg = table.getBackground()
            if bg is not None:
                return (bg.getRed() + bg.getGreen() + bg.getBlue()) < 384
    except:
        pass

    try:
        panel_bg = UIManager.getColor("Panel.background")
        if panel_bg is not None:
            return (panel_bg.getRed() + panel_bg.getGreen() + panel_bg.getBlue()) < 384
    except:
        pass

    return True


class ThemeAwareCellRenderer(DefaultTableCellRenderer):
    """Base renderer that applies dark/light alternating row colors to any column."""
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
        else:
            if dark:
                c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
                c.setForeground(Color(0xD5, 0xF9, 0xEA))
            else:
                c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))
                c.setForeground(Color.BLACK)
            c.setFont(Font("Monospaced", Font.PLAIN, 12))

        c.setOpaque(True)
        return c


class StatusCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
            c.setOpaque(True)
            return c

        if dark:
            c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
        else:
            c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))

        c.setFont(Font("Monospaced", Font.BOLD, 12))

        if value:
            status = str(value)
            if "Cancelled" in status:
                c.setForeground(Color(0xFF, 0x6B, 0x6B) if dark else Color(0xCC, 0x00, 0x00))
            elif "Paused" in status:
                c.setForeground(Color(0xFF, 0xD1, 0x66) if dark else Color(0xCC, 0x88, 0x00))
            elif "Error" in status:
                c.setForeground(Color(0xFF, 0x4D, 0x67) if dark else Color(0xCC, 0x00, 0x00))
            elif "Skipped" in status:
                c.setForeground(Color(0xFF, 0xA8, 0x4A) if dark else Color(0xCC, 0x66, 0x00))
            elif "Completed" in status:
                c.setForeground(Color(0x2E, 0xF2, 0x9B) if dark else Color(0x00, 0x88, 0x00))
            elif "Analyzing" in status or "Waiting" in status:
                c.setForeground(Color(0x62, 0xE7, 0xFF) if dark else Color(0x00, 0x66, 0xCC))
            elif "Queued" in status:
                c.setForeground(Color(0x8B, 0x9A, 0xA7) if dark else Color(0x66, 0x66, 0x66))
            else:
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)

        c.setOpaque(True)
        return c

class SeverityCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        c.setFont(Font("Monospaced", Font.BOLD, 12))

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E))
            c.setForeground(Color(0xE0, 0xFF, 0xF0))
            c.setOpaque(True)
            return c

        # Severity colors are high-contrast and work in both themes
        if value:
            severity = str(value)
            if severity == "Critical":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xB5, 0x1F, 0x2D))
            elif severity == "High":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xE6, 0x3B, 0x2E))
            elif severity == "Medium":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0xFF, 0x8A, 0x24))
            elif severity == "Low":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0x3E, 0xB7, 0x72))
            elif severity == "Information":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0x1E, 0x8C, 0xC7))
            else:
                dark = _renderer_dark_mode(self.extender, table)
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)
                c.setBackground(Color(0x0E, 0x1A, 0x24) if dark else Color.WHITE)

        c.setOpaque(True)
        return c

class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)
        c.setFont(Font("Monospaced", Font.BOLD, 11))

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 11))
            c.setOpaque(True)
            return c

        if dark:
            c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
        else:
            c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))

        if value:
            confidence = str(value)
            if confidence == "Certain":
                c.setForeground(Color(0x2E, 0xF2, 0x9B) if dark else Color(0x00, 0x88, 0x00))
            elif confidence == "Firm":
                c.setForeground(Color(0x62, 0xE7, 0xFF) if dark else Color(0x00, 0x66, 0xCC))
            elif confidence == "Tentative":
                c.setForeground(Color(0xFF, 0xC3, 0x66) if dark else Color(0xCC, 0x88, 0x00))
            else:
                c.setForeground(Color(0xD5, 0xF9, 0xEA) if dark else Color.BLACK)

        c.setOpaque(True)
        return c


class TruncatedUrlCellRenderer(DefaultTableCellRenderer):
    """Renderer that truncates long URLs and shows full URL in tooltip."""
    def __init__(self, max_chars=80, extender=None):
        DefaultTableCellRenderer.__init__(self)
        self.max_chars = max_chars
        self.extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        dark = _renderer_dark_mode(self.extender, table)

        if isSelected:
            c.setBackground(Color(0x00, 0x6A, 0x4E) if dark else Color(0x00, 0x78, 0xD4))
            c.setForeground(Color(0xE0, 0xFF, 0xF0) if dark else Color.WHITE)
            c.setFont(Font("Monospaced", Font.BOLD, 12))
        else:
            if dark:
                c.setBackground(Color(0x0C, 0x18, 0x26) if row % 2 == 0 else Color(0x16, 0x24, 0x38))
                c.setForeground(Color(0xD5, 0xF9, 0xEA))
            else:
                c.setBackground(Color.WHITE if row % 2 == 0 else Color(0xF0, 0xF0, 0xF0))
                c.setForeground(Color.BLACK)
            c.setFont(Font("Monospaced", Font.PLAIN, 12))

        c.setOpaque(True)
        if value:
            url_str = str(value)
            if len(url_str) > self.max_chars:
                c.setText(url_str[:self.max_chars] + "...")
            c.setToolTipText("<html><body style='width:600px'>%s</body></html>" % url_str)
        return c

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, messages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._messages = messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x80000003
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueDetail(self): return self._detail
    def getHttpMessages(self): return self._messages
    def getHttpService(self): return self._httpService
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getRemediationDetail(self): return None
