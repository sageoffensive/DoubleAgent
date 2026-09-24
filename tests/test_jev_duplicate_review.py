import copy
import json
import unittest
import ast
import datetime
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BURP_SRC = ROOT / "burp" / "src"
sys.path.insert(0, str(BURP_SRC))

from double_agent_jev import JevReviewMixin

from jev_duplicate_review import (
    candidate_pairs, finding_summary, clean_text, compare_pair, review_pairs,
    safe_url, NoRedirect, CHOICES, ENDPOINT, MODEL,
)


def finding(number, **changes):
    row = dict(stable_id="daf_%s" % number, url="https://example.test/profile",
               title="Missing response policy", cwe="CWE-693", canonical_family="policy",
               evidence="Policy absent in saved response.", detail="A saved observation.",
               agent_validated_by="A", source="eternals_passive", request_data="GET /profile HTTP/1.1\r\n\r\n")
    row.update(changes)
    return row


class Response:
    def __init__(self, data):
        self.raw = json.dumps(data).encode("utf-8")
        self.closed = False

    def read(self, size):
        return self.raw[:size]

    def close(self):
        self.closed = True


class Opener:
    def __init__(self, data):
        self.response = Response(data)
        self.request = None

    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        return self.response


def answer(**changes):
    decision = dict(type="choice", choice="same_issue", confidence=0.8)
    decision.update(changes)
    return dict(answers={"relationship": decision}, model="typesafe/test", usage={"cost": 0.001})


class DuplicateReviewTests(unittest.TestCase):
    def test_settings_require_key_only_when_enabled(self):
        class Check:
            def __init__(self, enabled):
                self.enabled = enabled
            def isSelected(self):
                return self.enabled
        class Key:
            def __init__(self, key):
                self.key = key
            def getPassword(self):
                return list(self.key)
        mixin = JevReviewMixin()
        self.assertEqual(mixin._jev_settings_values((Check(False), Key(""))), (False, ""))
        with self.assertRaises(ValueError):
            mixin._jev_settings_values((Check(True), Key("  ")))
        self.assertEqual(mixin._jev_settings_values((Check(True), Key(" test-key "))), (True, "test-key"))

    def test_real_config_methods_roundtrip_and_old_config_defaults(self):
        # Load the actual persistence methods without importing Burp's Java interfaces.
        tree = ast.parse((BURP_SRC / "double_agent_extender_part4.py").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in ("load_config", "save_config")]
        module = ast.Module(body=[cls], type_ignores=[])
        namespace = dict(json=json, datetime=datetime.datetime, unicode_text=str)
        exec(compile(ast.fix_missing_locations(module), "config-under-test", "exec"), namespace)
        class Log:
            def __init__(self):
                self.lines = []
            def println(self, value):
                self.lines.append(str(value))
        class Harness(namespace[cls.name]):
            def __getattr__(self, name):
                if name.isupper():
                    return 1
                raise AttributeError(name)
            def _get_column_widths(self):
                return {}
            def _safe_ascii_text(self, value):
                return str(value)
        with tempfile.TemporaryDirectory() as directory:
            harness = Harness()
            harness.config_file = os.path.join(directory, "settings.json")
            harness.stdout, harness.stderr = Log(), Log()
            harness.AI_PROVIDER, harness.THEME = "Ollama", "Auto"
            harness.API_KEYS_PER_PROVIDER = {}
            harness.MAX_TOKENS = 4096
            harness.JEV_DEDUP_ENABLED, harness.JEV_API_KEY = True, "private-test-key"
            self.assertTrue(harness.save_config())
            self.assertEqual(stat.S_IMODE(os.stat(harness.config_file).st_mode), 0o600)
            harness.JEV_DEDUP_ENABLED, harness.JEV_API_KEY = False, ""
            harness.load_config()
            self.assertTrue(harness.JEV_DEDUP_ENABLED)
            self.assertEqual(harness.JEV_API_KEY, "private-test-key")
            self.assertNotIn("private-test-key", str(harness.stdout.lines + harness.stderr.lines))
            stored = json.loads(Path(harness.config_file).read_text())
            del stored["jev_dedup_enabled"]
            del stored["jev_api_key"]
            Path(harness.config_file).write_text(json.dumps(stored))
            harness.load_config()
            self.assertFalse(harness.JEV_DEDUP_ENABLED)
            self.assertEqual(harness.JEV_API_KEY, "")

    def test_snapshot_does_not_mutate_or_send_http(self):
        row = finding(1, title="Unicode caf\u00e9", response_data="private raw body",
                      request_data="POST /x HTTP/1.1\r\nAuthorization: secret\r\n\r\nprivate")
        before = copy.deepcopy(row)
        summary = finding_summary(row, 0)
        self.assertEqual(row, before)
        self.assertEqual(summary["method"], "POST")
        self.assertNotIn("request_data", summary)
        self.assertNotIn("response_data", summary)
        self.assertNotIn("private", json.dumps(summary))
        self.assertEqual(summary["title"], "Unicode caf\u00e9")

    def test_filters_b_and_hidden(self):
        for changes in (dict(agent_validated_by="B"), dict(source="agent_api"), dict(fp=True),
                        dict(agent_status="false_positive"), dict(agent_status="already_covered")):
            self.assertIsNone(finding_summary(finding(1, **changes), 0))

    def test_url_redacts_values_userinfo_and_fragment(self):
        url, origin = safe_url("https://user:password@example.test/x?token=secret&query=value#private")
        self.assertEqual(origin, "https://example.test:443")
        for secret in ("password", "secret", "value", "private", "user:"):
            self.assertNotIn(secret, url)
        self.assertIn("query=", url)
        self.assertEqual(safe_url("file:///tmp/file"), ("", ""))

    def test_redacts_credentials_before_truncating(self):
        source = 'Authorization: Bearer topsecret\nCookie: sid=123\n{"password":"secretword"}\napi_key=hiddenkey\nBearer inline-secret'
        clean = clean_text(source)
        for secret in ("topsecret", "sid=123", "secretword", "hiddenkey", "inline-secret"):
            self.assertNotIn(secret, clean)

    def test_candidate_scope_and_cap_and_no_transitive_merge(self):
        rows = [finding(i) for i in range(20)]
        rows += [finding(50, url="https://other.test/profile"), finding(51, url="http://example.test/profile")]
        pairs = candidate_pairs(rows, limit=4)
        self.assertEqual(len(pairs), 4)
        self.assertEqual(len(set(tuple(sorted((a["id"], b["id"]))) for a, b in pairs)), 4)
        for left, right in pairs:
            self.assertEqual(left["origin"], right["origin"])
        self.assertEqual(len(rows), 22)

    def test_shared_cwe_is_only_a_candidate(self):
        pairs = candidate_pairs([finding(1, title="One", fingerprint_location="parameter:a"),
                                 finding(2, title="Two", fingerprint_location="parameter:b")])
        self.assertEqual(len(pairs), 1)
        self.assertNotIn("choice", pairs[0][0])

    def test_distinct_title_and_category_not_shortlisted(self):
        self.assertEqual(candidate_pairs([finding(1), finding(2, title="Unrelated storage permission", cwe="X", canonical_family="other")]), [])

    def test_api_contract_and_closed_response(self):
        opener = Opener(answer())
        left, right = candidate_pairs([finding(1), finding(2)])[0]
        result = compare_pair(left, right, "test-key", opener)
        payload = json.loads(opener.request.data.decode("utf-8"))
        self.assertEqual(opener.request.full_url, ENDPOINT)
        self.assertEqual(payload["model"], MODEL)
        self.assertNotIn("test-key", opener.request.data.decode("utf-8"))
        self.assertEqual(result["choice"], "same_issue")
        self.assertTrue(opener.response.closed)
        self.assertEqual(opener.timeout, 20)

    def test_invalid_schema_and_probabilities(self):
        for changes in (dict(choice="merge_now"), dict(type="text"), dict(confidence=True),
                        dict(confidence=float("nan")), dict(confidence=1.01),
                        dict(probabilities={key: 0 for key in CHOICES})):
            with self.assertRaises(ValueError):
                compare_pair({}, {}, "test-key", Opener(answer(**changes)))
        result = compare_pair({}, {}, "test-key", Opener(answer(confidence=None)))
        self.assertIsNone(result["confidence"])

    def test_error_does_not_echo_key_or_payload(self):
        class Failure:
            def open(self, request, timeout):
                raise RuntimeError("secret-key private-evidence")
        with self.assertRaises(ValueError) as raised:
            compare_pair({}, {}, "secret-key", Failure())
        self.assertNotIn("secret-key", str(raised.exception))
        self.assertNotIn("private-evidence", str(raised.exception))

    def test_redirects_refused(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_cancelled_review_never_calls_provider(self):
        def never(*args):
            self.fail("Provider should not be called")
        review_pairs([({}, {})], "key", lambda: True, never, compare=never)

    def test_failure_stops_remaining_pairs_without_retry(self):
        calls = []
        def failure(*args):
            calls.append(1)
            raise ValueError("failed")
        with self.assertRaises(ValueError):
            review_pairs([({}, {})] * 4, "key", lambda: False, lambda result: None, compare=failure)
        self.assertEqual(len(calls), 1)

    def test_stalled_request_times_out_without_late_results_or_retry(self):
        release, done = threading.Event(), threading.Event()
        calls, results, progress = [], [], []
        def stalled(*args):
            calls.append(1)
            release.wait(2)
            done.set()
            return {"choice": "same_issue"}
        try:
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, "did not respond"):
                review_pairs([({}, {})] * 3, "key", lambda: False, results.append,
                             compare=stalled, timeout=0.05,
                             on_progress=lambda n, total: progress.append((n, total)))
            self.assertLess(time.monotonic() - start, 1)
        finally:
            release.set()
        self.assertTrue(done.wait(1))
        self.assertEqual(calls, [1])
        self.assertEqual(results, [])
        self.assertEqual(progress, [(1, 3)])

    def test_stop_returns_while_request_is_still_in_flight(self):
        stop, release, started = threading.Event(), threading.Event(), threading.Event()
        results, calls = [], []
        def stalled(*args):
            calls.append(1)
            started.set()
            release.wait(2)
            return "late"
        worker = threading.Thread(target=lambda: review_pairs(
            [({}, {})] * 3, "key", stop.is_set, results.append, compare=stalled))
        worker.start()
        try:
            self.assertTrue(started.wait(1))
            stop.set()
            worker.join(0.5)
            self.assertFalse(worker.is_alive())
            self.assertFalse(release.is_set())
            self.assertEqual(calls, [1])
            self.assertEqual(results, [])
        finally:
            release.set()
            worker.join(1)

    def test_candidate_preparation_can_be_cancelled(self):
        self.assertEqual(candidate_pairs([finding(i) for i in range(10)], cancelled=lambda: True), [])


if __name__ == "__main__":
    unittest.main()
