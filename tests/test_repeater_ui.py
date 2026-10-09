"""Operator Repeater handoffs create tabs without sending target traffic."""
import sys
import threading
import unittest
import urllib.parse
from types import SimpleNamespace, ModuleType
from unittest.mock import Mock, patch

from test_duplicate_queue import load


class JavaURL:
    def __init__(self, value):
        self.parsed = urllib.parse.urlsplit(value)
        if not self.parsed.scheme:
            raise ValueError("Invalid URL")
    def getProtocol(self): return self.parsed.scheme
    def getHost(self): return self.parsed.hostname or ""
    def getPort(self): return self.parsed.port or -1
    def getFile(self): return (self.parsed.path or "/") + ("?" + self.parsed.query if self.parsed.query else "")


class RepeaterUiTests(unittest.TestCase):
    def setUp(self):
        java, net = ModuleType("java"), ModuleType("java.net")
        net.URL = JavaURL
        self.java_patch = patch.dict(sys.modules, {"java": java, "java.net": net})
        self.java_patch.start()
        self.h = load("double_agent_extender_part2.py", {"_sendFindingToRepeater", "_send_finding_to_repeater", "_build_request_from_url"})
        globals_ = self.h._send_finding_to_repeater.__func__.__globals__
        globals_.update(unicode_text=lambda v: "" if v is None else str(v), threading=threading)
        self.h.helpers = SimpleNamespace(stringToBytes=lambda text: text.encode("utf-8"), analyzeRequest=lambda entry: entry.info)
        self.h.callbacks = SimpleNamespace(getProxyHistory=Mock(return_value=[]), sendToRepeater=Mock(),
                                           makeHttpRequest=Mock(side_effect=AssertionError("No target traffic")))
        self.h.log_to_console = Mock()
        self.h.stderr = SimpleNamespace(println=Mock())
        self.h._safe_ascii_text = lambda value, limit=1000: str(value)[:limit]
        self.h.findings_lock_ui = threading.RLock()

    def tearDown(self):
        self.java_patch.stop()

    def finding(self, **changes):
        finding = {"stable_id": "daf_saved", "url": "https://example.test:8443/api/item?id=7",
                   "request_data": "POST /api/item?id=7 HTTP/1.1\r\nHost: example.test:8443\r\nCookie: session=fixture\r\nContent-Length: 7\r\n\r\nitem=7"}
        return dict(finding, **changes)

    def test_saved_request_works_without_proxy_history_and_preserves_exact_content(self):
        finding = self.finding()
        self.assertTrue(self.h._send_finding_to_repeater(finding))
        self.h.callbacks.getProxyHistory.assert_not_called()
        self.h.callbacks.sendToRepeater.assert_called_once_with("example.test", 8443, True,
                                                               finding["request_data"].encode(), "Finding daf_saved")
        self.h.callbacks.makeHttpRequest.assert_not_called()
        self.assertNotIn("session=fixture", str(self.h.log_to_console.call_args))

    def test_http_default_and_nondefault_ports(self):
        for url, port, tls in (("http://example.test/path",80,False), ("http://example.test:8080/path",8080,False),
                               ("https://example.test/path",443,True)):
            self.h._send_finding_to_repeater(self.finding(url=url))
            self.assertEqual(self.h.callbacks.sendToRepeater.call_args.args[:3], ("example.test",port,tls))

    def entry(self, url, method="GET", request=b"exact raw bytes"):
        service = SimpleNamespace(getHost=lambda:"example.test", getPort=lambda:8443, getProtocol=lambda:"https")
        return SimpleNamespace(info=SimpleNamespace(getUrl=lambda:url,getMethod=lambda:method),
                               getRequest=lambda:request,getHttpService=lambda:service)

    def test_exact_history_fallback_preserves_bytes_and_ignores_partial_or_wrong_method(self):
        url = self.finding()["url"]
        exact = self.entry(url,"POST",b"POST exact binary\x00\xff")
        self.h.callbacks.getProxyHistory.return_value = [exact,self.entry(url,"GET"),self.entry(url+"0","POST"),SimpleNamespace()]
        self.assertTrue(self.h._send_finding_to_repeater(self.finding(request_data="",method="POST")))
        self.assertEqual(self.h.callbacks.sendToRepeater.call_args.args[3], b"POST exact binary\x00\xff")

    def test_no_history_creates_labelled_url_starter_without_browser_navigation(self):
        self.assertTrue(self.h._send_finding_to_repeater(self.finding(request_data="")))
        sent = self.h.callbacks.sendToRepeater.call_args.args[3]
        self.assertIn(b"GET /api/item?id=7 HTTP/1.1",sent)
        self.assertIn(b"Host: example.test:8443",sent)
        self.assertTrue(self.h.callbacks.sendToRepeater.call_args.args[4].startswith("URL starter:"))
        self.assertIn("URL starter GET",str(self.h.log_to_console.call_args))
        self.h.callbacks.makeHttpRequest.assert_not_called()

    def test_invalid_target_and_callback_failure_report_failure(self):
        self.assertFalse(self.h._send_finding_to_repeater(self.finding(url="file:///tmp/test")))
        self.h.callbacks.sendToRepeater.assert_not_called()
        self.h.callbacks.sendToRepeater.side_effect = RuntimeError("callback unavailable")
        self.assertFalse(self.h._send_finding_to_repeater(self.finding()))
        self.assertIn("Could not create Repeater",str(self.h.log_to_console.call_args))

    def test_worker_uses_snapshot_of_sorted_selected_row(self):
        self.h.findings_list = [self.finding(stable_id="daf_other"),self.finding()]
        self.h.findingsTable = SimpleNamespace(getSelectedRow=lambda:0,convertRowIndexToModel=lambda row:1)
        worker = Mock()
        factory = Mock(return_value=worker)
        globals_ = self.h._sendFindingToRepeater.__func__.__globals__
        with patch.dict(globals_,threading=SimpleNamespace(Thread=factory)):
            self.h._sendFindingToRepeater()
        worker.start.assert_called_once()
        self.h.callbacks.sendToRepeater.assert_not_called()
        self.h.findings_list[1]["request_data"] = "changed after selection"
        factory.call_args.kwargs["target"](*factory.call_args.kwargs["args"])
        self.assertEqual(self.h.callbacks.sendToRepeater.call_args.args[4],"Finding daf_saved")
        self.assertTrue(self.h.callbacks.sendToRepeater.call_args.args[3].startswith(b"POST /api/item"))

    def test_queue_selection_is_snapshotted_before_background_callbacks(self):
        h = load("double_agent_extender_part2_chunk2.py", {"_sendSelectedAgentQueueToRepeater"})
        h.agent_queue_lock = threading.RLock()
        h.agent_queue = [{"id":42}]
        h.selected_agent_queue_index = 0
        h._send_agent_queue_to_repeater = Mock()
        h.stderr = SimpleNamespace(println=Mock())
        worker, factory = Mock(), Mock()
        factory.return_value = worker
        with patch.dict(h._sendSelectedAgentQueueToRepeater.__func__.__globals__,threading=SimpleNamespace(Thread=factory)):
            h._sendSelectedAgentQueueToRepeater()
        h.agent_queue[0]["id"] = 99
        self.assertEqual(factory.call_args.kwargs["args"],(42,))
        worker.start.assert_called_once()
        h._send_agent_queue_to_repeater.assert_not_called()

    def test_queue_url_starter_preserves_path_and_query(self):
        h = load("double_agent_extender_part2_chunk2.py", {"_send_agent_queue_to_repeater"})
        candidate = {"url":"http://example.test:8080/path?q=7","request_data":""}
        class API:
            def _get_queue_item_snapshot(self,qid): return {"id":qid}
            def _queue_findings_full(self,item): return []
            def _queue_target_candidates(self,*args): return [candidate]
            def _raw_repeater_request(self,candidate,**kwargs):
                return {"ok":True,"host":"example.test","port":8080,"https":False,"raw_request":candidate["request_data"]}
            def _repeater_mutation_labels(self,recipe): return []
        h._build_request_from_url = self.h._build_request_from_url
        h.helpers,h.callbacks = self.h.helpers,self.h.callbacks
        h._safe_ascii_text,h.log_to_console,h.stderr = self.h._safe_ascii_text,self.h.log_to_console,self.h.stderr
        with patch.dict(h._send_agent_queue_to_repeater.__func__.__globals__,AgentAPIHandler=API):
            h._send_agent_queue_to_repeater(42)
        request = h.callbacks.sendToRepeater.call_args.args[3]
        self.assertIn(b"GET /path?q=7 HTTP/1.1",request)
        self.assertEqual(candidate["request_data"],"")
        h.callbacks.makeHttpRequest.assert_not_called()


if __name__ == "__main__":
    unittest.main()
