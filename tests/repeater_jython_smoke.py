# -*- coding: utf-8 -*-
"""Offline Jython/Swing handoff check: no Burp, model or target connection."""
import os
import sys
import threading
import types
from java.lang import Runnable
from javax.swing import SwingUtilities

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BURP_SRC = os.path.join(ROOT, "burp", "src")
if not os.path.isdir(BURP_SRC):
    BURP_SRC = ROOT
sys.path.insert(0, BURP_SRC)
for name in sorted(os.listdir(BURP_SRC)):
    if name.endswith(".py"):
        with open(os.path.join(BURP_SRC, name)) as source:
            compile(source.read(), name, 'exec')

prelude = types.ModuleType('double_agent_prelude')
prelude.threading = threading
prelude.unicode_text = lambda value: u"" if value is None else unicode(value)
sys.modules['double_agent_prelude'] = prelude
api = types.ModuleType('double_agent_api')
api.AgentAPIHandler = object
sys.modules['double_agent_api'] = api
sys.modules['double_agent_ui'] = types.ModuleType('double_agent_ui')
from double_agent_extender_part2 import BurpExtenderChunk2


class Helpers(object):
    def stringToBytes(self, text):
        return text.encode('utf-8')


class Callbacks(object):
    def __init__(self):
        self.sent = []
        self.edt = []
        self.done = threading.Event()
        self.history_calls = 0

    def getProxyHistory(self):
        self.history_calls += 1
        return []

    def sendToRepeater(self, *args):
        self.sent.append(args)
        self.edt.append(SwingUtilities.isEventDispatchThread())
        self.done.set()

    def makeHttpRequest(self, *args):
        raise AssertionError('Repeater handoff must not send target traffic')


class Table(object):
    def getSelectedRow(self):
        return 0

    def convertRowIndexToModel(self, row):
        return 1


class Log(object):
    def println(self, value):
        pass


h = BurpExtenderChunk2()
h.helpers, h.callbacks = Helpers(), Callbacks()
h.stderr = Log()
h.log_to_console = lambda message: None
h._safe_ascii_text = lambda value, limit=1000: unicode(value)[:limit]
h.findings_lock_ui = threading.RLock()
h.findingsTable = Table()
raw = u'POST /private?q=7 HTTP/1.1\r\nHost: example.test:8443\r\n\r\nname=café'
h.findings_list = [
    {'url': 'https://other.test/', 'request_data': 'wrong row'},
    {'stable_id': 'daf_fixture', 'url': 'https://example.test:8443/private?q=7', 'request_data': raw},
]


class Click(Runnable):
    def run(self):
        h._sendFindingToRepeater()


SwingUtilities.invokeAndWait(Click())
h.callbacks.done.wait(3)
assert len(h.callbacks.sent) == 1, h.callbacks.sent
assert h.callbacks.sent[0][:3] == ('example.test', 8443, True)
assert h.callbacks.sent[0][3] == raw.encode('utf-8')
assert h.callbacks.sent[0][4] == 'Finding daf_fixture'
assert h.callbacks.edt == [False]
assert h.callbacks.history_calls == 0
assert h._send_finding_to_repeater({'url': 'http://example.test:8080/path?q=1'})
assert 'GET /path?q=1 HTTP/1.1' in h.callbacks.sent[-1][3]
assert h.callbacks.sent[-1][:3] == ('example.test', 8080, False)
assert h.callbacks.sent[-1][4].startswith('URL starter:')
print('PASS: Jython source compilation, saved request/Unicode, sorted selection, service, URL fallback and off-EDT callback')
