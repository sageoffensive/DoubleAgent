# -*- coding: utf-8 -*-
# Burp Suite Python Extension: Double Agent (formerly Eternals Burp Agent)
# Name: two AI agents - one for passive scanning, one for active scanning
# Version: 3.0
# Release Date: 2026-07-15
# License: MIT License
# Build-ID: F9246771-93EE-4346-BC61-FD2448B38147
#
# AI-powered security scanner for Burp Suite
#
# WHAT'S NEW:
# - Agent B can delegate high-signal XSS/injection candidates to Burp's native active scanner
# - Added scanner job API for starting, polling, and cancelling Burp Scanner work from agent workflows
# - Added campaign queue APIs for crawl/audit discovery, parameter coverage, authz matrix, race, browser DOM, and parser/protocol testing
# - First-class project profile for scope, auth schemes, roles, test context, and allowed state-changing actions
# - Resume prompt for continuing assessments after agent/session restarts
# - Structured fixture and human confirmation APIs with kickoff-notes import
# - Queue work now exposes fixture readiness, attack campaigns, and Burp Repeater handoff
# - Passive triage now labels reportable candidates, fixture-dependent work, theory-only items, and scanner noise
# - Automated Testing work items verify Agent A findings; Try Harder hunts for new high-risk bugs
# - Assessment knowledge base persists target notes, risk leads, assumptions, and tested controls
#


# Burp executes the selected extension with execfile(), which does not always
# add the extension's directory to sys.path. Keep sibling support modules
# importable regardless of Burp's working directory.
import os as _bootstrap_os
import sys as _bootstrap_sys
try:
    _extension_directory = _bootstrap_os.path.dirname(
        _bootstrap_os.path.abspath(__file__))
    if _extension_directory and _extension_directory not in _bootstrap_sys.path:
        _bootstrap_sys.path.insert(0, _extension_directory)
except Exception:
    pass


from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab, IContextMenuFactory, IExtensionStateListener
try:
    from burp import IWebSocketListener
    HAS_WEBSOCKET_LISTENER = True
except ImportError:
    HAS_WEBSOCKET_LISTENER = False
try:
    from burp import IScannerListener
    HAS_SCANNER_LISTENER = True
except ImportError:
    HAS_SCANNER_LISTENER = False
from java.io import PrintWriter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color, FlowLayout
from javax.swing import JPanel, JScrollPane, JTextArea, JTable, JLabel, JSplitPane, BorderFactory, SwingUtilities, JButton, JCheckBox, BoxLayout, Box, JMenuItem, UIManager, JMenu, RowFilter, JComboBox, JTextField
from javax.swing.event import ChangeListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import TitledBorder
from java.lang import Runnable
from java.util import ArrayList
from java.net import InetSocketAddress, Socket
import json
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import urlparse
import threading
import urllib2
import time
import hashlib
import hmac
import re
import os
import uuid
import copy
from datetime import datetime

try:
    TEXT_TYPE = unicode
    BINARY_TYPE = str
except NameError:
    TEXT_TYPE = str
    BINARY_TYPE = bytes


def unicode_text(value):
    """Return text without Python 2/Jython's implicit ASCII conversion."""
    if value is None:
        return u""
    if isinstance(value, TEXT_TYPE):
        return value
    if isinstance(value, BINARY_TYPE):
        try:
            return value.decode("utf-8", "replace")
        except AttributeError:
            return TEXT_TYPE(value)
    try:
        return TEXT_TYPE(value)
    except Exception:
        return TEXT_TYPE(repr(value))

from double_agent_core import (
    apply_coverage_overwatch_to_review,
    apply_raw_http_mutation,
    analyze_response_hygiene,
    attack_surface_snapshot,
    build_burpsuite_operator_package,
    build_campaign_steps,
    classify_mcp_tool,
    collaborator_evidence_lines,
    extract_mcp_target,
    full_app_unreconciled_findings,
    merge_attack_surface_entries,
    mcp_tool_policy,
    normalize_attack_surface_entry,
    redact_sensitive_http_text,
    review_attack_surface,
    semantic_burp_capabilities,
    ssrf_inband_evidence_artifact,
)
from remote_reporting import AgentCoverageOverwatchMixin, AgentScannerCampaignMixin, RemoteReportingMixin, full_app_campaign_context_lines, scanner_campaign_api_docs

VALID_SEVERITIES = {
    "critical": "Critical", "crit": "Critical",
    "high": "High", "medium": "Medium", "low": "Low",
    "information": "Information", "informational": "Information",
    "info": "Information", "inform": "Information"
}

def map_confidence(ai_confidence):
    if ai_confidence < 50: return None
    elif ai_confidence < 75: return "Tentative"
    elif ai_confidence < 90: return "Firm"
    else: return "Certain"


class ThreadedAgentHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# Custom PrintWriter wrapper to capture console output
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref

    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, 'log_to_console'):
            try:
                self.extender.log_to_console(str(message))
            except:
                pass

    def print_(self, message):
        self.original.print_(message)

    def write(self, data):
        self.original.write(data)

    def flush(self):
        self.original.flush()



# Burp callback interface composition.
if HAS_WEBSOCKET_LISTENER and HAS_SCANNER_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IWebSocketListener, IScannerListener):
        pass
elif HAS_WEBSOCKET_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IWebSocketListener):
        pass
elif HAS_SCANNER_LISTENER:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener, IScannerListener):
        pass
else:
    class _BurpExtenderBase(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory, IExtensionStateListener):
        pass
