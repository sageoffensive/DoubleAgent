# -*- coding: utf-8 -*-
"""Run with Jython 2.7.4 and -Djava.awt.headless=true; no network calls.

The top-level dialog is replaced because a headless JVM cannot create windows.
All table, selection, button and event-dispatch components are real Swing.
"""
import os
import sys
import threading
import time
import types
from javax.swing import SwingUtilities, JTable, JPanel
from javax.swing.table import DefaultTableModel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BURP_SRC = os.path.join(ROOT, "burp", "src")
sys.path.insert(0, BURP_SRC)
import jev_duplicate_review as core


class Dialog(object):
    DISPOSE_ON_CLOSE = 2
    latest = None

    def __init__(self):
        Dialog.latest = self
        self.parts = {}
        self.visible = True

    def add(self, item, position):
        self.parts[position] = item

    def isDisplayable(self):
        return self.visible

    def dispose(self):
        self.visible = False

    def __getattr__(self, name):
        return lambda *args: None


mod = types.ModuleType("jev_ui_probe")
mod.JDialog = Dialog
with open(os.path.join(BURP_SRC, "double_agent_jev.py")) as source_file:
    source = source_file.read().replace("from javax.swing import JDialog, JPanel", "from javax.swing import JPanel")
exec(compile(source, "double_agent_jev.py", "exec"), mod.__dict__)


class Harness(mod.JevReviewMixin):
    JEV_DEDUP_ENABLED = True
    JEV_API_KEY = "synthetic-unused"
    _jev_review_running = False

    def _sync_jev_controls(self):
        assert SwingUtilities.isEventDispatchThread()

    def _apply_dark_theme_to_container(self, dialog):
        pass


def setup(rows=True):
    harness = Harness()
    harness.panel = JPanel()
    harness.findings_lock_ui = threading.Lock()
    model = DefaultTableModel()
    model.addColumn("#")
    harness.findingsTableModel = model
    harness.findingsTable = JTable(model)
    harness.findings_list = [dict(stable_id=str(n), url="https://example.test/", title=u"Same caf\u00e9 policy", cwe="X") for n in range(2)] if rows else []
    return harness


def launch(harness):
    SwingUtilities.invokeAndWait(lambda: harness._review_jev_duplicates(None))
    return Dialog.latest


def await_finish(harness):
    deadline = time.time() + 3
    while harness._jev_review_running and time.time() < deadline:
        time.sleep(.01)
    SwingUtilities.invokeAndWait(lambda: None)
    assert not harness._jev_review_running, "Review never finished"


def status(dialog):
    return dialog.parts["North"].getText()


def result_table(dialog):
    return dialog.parts["Center"].getTopComponent().getViewport().getView()


def success(left, right, key):
    return dict(left=left, right=right, choice="same_issue", confidence=.9, model="synthetic")


def configure(compare, timeout=25):
    def review(pairs, key, cancelled, on_result, **kwargs):
        return core.review_pairs(pairs, key, cancelled, on_result, compare=compare, timeout=timeout, **kwargs)
    mod.review_pairs = review


configure(success)
h = setup()
d = launch(h)
await_finish(h)
assert result_table(d).getRowCount() == 1
assert "Complete" in status(d)
SwingUtilities.invokeAndWait(lambda: result_table(d).setRowSelectionInterval(0, 0))
assert "Evidence:" in d.parts["Center"].getBottomComponent().getViewport().getView().getText()

h = setup(False)
d = launch(h)
await_finish(h)
assert "No candidate pairs" in status(d)


def failure(*args):
    raise ValueError("Synthetic failure")
configure(failure)
h = setup()
d = launch(h)
await_finish(h)
assert "Synthetic failure" in status(d)

# A held findings lock must not block the event thread or Stop.
h = setup()
h.findings_lock_ui.acquire()
d = launch(h)
try:
    SwingUtilities.invokeAndWait(lambda: d.parts["South"].getComponent(0).doClick())
    await_finish(h)
    assert "Stopped" in status(d)
finally:
    h.findings_lock_ui.release()

release = threading.Event()
started = threading.Event()
def stalled(left, right, key):
    started.set()
    release.wait(5)
    return success(left, right, key)

configure(stalled)
h = setup()
d = launch(h)
assert started.wait(2)
SwingUtilities.invokeAndWait(lambda: None)
assert "Waiting for Jev: pair 1 of 1" in status(d)
SwingUtilities.invokeAndWait(lambda: d.parts["South"].getComponent(0).doClick())
await_finish(h)
assert "Stopped" in status(d)
assert result_table(d).getRowCount() == 0
release.set()

release = threading.Event()
configure(stalled, .1)
h = setup()
d = launch(h)
await_finish(h)
assert "did not respond" in status(d)
assert result_table(d).getRowCount() == 0
release.set()
print("PASS: real Jython/Swing success, details, empty review, error, lock cancellation, request cancellation and timeout")
