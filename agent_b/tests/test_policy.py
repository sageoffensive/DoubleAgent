import unittest
import tempfile
from pathlib import Path

from agent_b_harness.clients import _loopback_url
from agent_b_harness.engine import (
    curl_command_to_request,
    is_queue_fetch,
    no_tool_directive,
    normalize_queue_result_body,
    queue_http2_payload,
    normalize_user_request,
    requires_claim,
    snapshot_queue_empty,
    target_receipt,
)
from agent_b_harness.policy import allow_get, allow_post, signature
from agent_b_harness.store import redact_text
from agent_b_harness.store import Store


class PolicyTests(unittest.TestCase):
    def test_double_agent_must_be_loopback(self):
        self.assertEqual(_loopback_url("http://127.0.0.1:8777/"), "http://127.0.0.1:8777")
        with self.assertRaises(ValueError):
            _loopback_url("https://example.com")

    def test_get_contract(self):
        allow_get("/api/agent/queue?status=pending")
        allow_get("/api/agent/queue/7/curl?refresh_auth=true")
        allow_get("/api/agent/prompt")
        with self.assertRaises(ValueError):
            allow_get("https://example.com/api/agent/queue")
        with self.assertRaises(ValueError):
            allow_get("/private/data")

    def test_queue_curl_post_explains_correct_transport(self):
        with self.assertRaisesRegex(ValueError, "GET-only.*POST /api/agent/request"):
            allow_post("/api/agent/queue/7/curl?refresh_auth=true", {"response": "wrong destination"})

    def test_valid_finding_requires_evidence(self):
        with self.assertRaises(ValueError):
            allow_post("/api/findings", {"title": "Possible XSS"})
        allow_post("/api/findings", {
            "title": "Reflected XSS",
            "agent_status": "valid",
            "deduplication_key": "xss-preview-parameter",
            "request_data": "GET /preview?q=%3Csvg%20onload%3Dalert(1)%3E HTTP/1.1\r\nHost: test",
            "response_data": "HTTP/1.1 200 OK\r\n\r\n<svg onload=alert(1)>",
        })

    def test_confirmed_result_requires_reproduction(self):
        with self.assertRaises(ValueError):
            allow_post("/api/agent/queue/4/result", {"outcome": "confirmed", "evidence": {"x": "y"}})
        allow_post("/api/agent/queue/4/result", {
            "outcome": "confirmed",
            "evidence": [
                {"request": "GET /baseline HTTP/1.1", "response": "baseline response"},
                {"request": "GET /mutation HTTP/1.1", "response": "different protected object returned"},
            ],
            "reproduction": "Replay the baseline as Alice, then change only the object identifier.",
        })

    def test_signature_is_stable(self):
        self.assertEqual(signature("x", {"a": 1, "b": 2}), signature("x", {"b": 2, "a": 1}))

    def test_double_agent_queue_shortcut_is_expanded(self):
        expanded = normalize_user_request("q")
        self.assertIn("assessment_snapshot", expanded)
        self.assertIn("Do not interpret this as a shell command", expanded)
        self.assertEqual(normalize_user_request("queue status"), "queue status")

    def test_chat_logs_redact_bearer_credentials(self):
        value = redact_text("Bearer: abcdef0123456789abcdef0123456789\nAuthorization: Bearer secret-token")
        self.assertNotIn("abcdef0123456789abcdef0123456789", value)
        self.assertNotIn("secret-token", value)
        self.assertEqual(value.count("[REDACTED]"), 2)

    def test_empty_queue_guard_only_applies_to_queue_fetches(self):
        self.assertTrue(is_queue_fetch("q"))
        self.assertTrue(is_queue_fetch("Fetch the Double Agent queue, run preflight"))
        self.assertTrue(is_queue_fetch("Resume the claimed Double Agent queue item and follow its campaign contract"))
        self.assertFalse(is_queue_fetch("Assess this application"))
        self.assertTrue(snapshot_queue_empty({"queue": {"count": 0, "queue": []}}))
        self.assertFalse(snapshot_queue_empty({"queue": {"count": 1, "queue": [{"id": 7}]}}))

    def test_no_tool_guard_requires_real_claim_and_result(self):
        before_claim = no_tool_directive(None)
        self.assertIn("no queue claim has succeeded", before_claim)
        self.assertIn("double_agent_post", before_claim)
        after_claim = no_tool_directive("7")
        self.assertIn("queue #7 is still claimed", after_claim)
        self.assertIn("/result", after_claim)

    def test_target_execution_requires_claim(self):
        self.assertTrue(requires_claim("/api/agent/request"))
        self.assertTrue(requires_claim("/api/agent/burp/action?dry=false"))
        self.assertFalse(requires_claim("/api/agent/queue/7/claim"))
        self.assertIsNone(target_receipt("/api/agent/request", {"status_code": 0}))
        self.assertEqual(
            target_receipt("/api/agent/request", {"status_code": 200, "url": "https://example.test/"})["status_code"],
            200,
        )

    def test_generated_curl_becomes_mutated_raw_request_without_shell(self):
        converted = curl_command_to_request(
            "curl -x http://127.0.0.1:8080 -k -i -sS -X 'GET' "
            "-H 'Host: example.test' -H 'Cookie: session=test' "
            "'https://example.test/search?q=base'",
            {"q": "<svg/onload=alert(1)>"},
        )
        self.assertEqual(converted["host"], "example.test")
        self.assertTrue(converted["https"])
        self.assertIn("GET /search?q=%3Csvg%2Fonload%3Dalert%281%29%3E HTTP/1.1", converted["request"])
        self.assertIn("Cookie: session=test", converted["request"])

    def test_single_finding_queue_route_is_allowed(self):
        allow_post("/api/agent/queue/finding", {"finding_id": "daf_test"})

    def test_cyberstrike_result_aliases_use_recorded_evidence(self):
        evidence = [
            {"request": "GET /?q=base HTTP/1.1", "status_code": 200, "response_snippet": "baseline", "notes": "baseline"},
            {"request": "GET /?q=payload HTTP/1.1", "status_code": 200, "response_snippet": "payload reflected", "notes": "exploit mutation"},
        ]
        body = normalize_queue_result_body({
            "outcome": "vulnerable",
            "linked_finding_id": "daf_example",
            "agent_rationale": "The response reflects executable markup.",
            "reproduction_steps": ["Send baseline.", "Change q to the payload."],
        }, evidence)
        self.assertEqual(body["outcome"], "confirmed")
        self.assertEqual(body["evidence"], evidence)
        self.assertIn("1. Send baseline.", body["reproduction"])
        self.assertEqual(body["finding_updates"][0]["poc_request"], evidence[1]["request"])

        fallback = normalize_queue_result_body({
            "outcome": "vulnerable", "finding_ids": ["daf_example"], "summary": "Reflected payload"
        }, evidence)
        self.assertGreater(len(fallback["reproduction"]), 20)
        self.assertEqual(fallback["finding_updates"][0]["id"], "daf_example")

    def test_http2_payload_preserves_protocol_and_allows_query_mutation(self):
        payload = queue_http2_payload({
            "request_data": "GET /search?q=base HTTP/2\r\nHost: example.test\r\nCookie: session=test\r\n\r\n",
            "next_action": {"protocol_profile": {"request_template": {
                "targetHostname": "example.test", "targetPort": 443, "usesHttps": True,
            }}},
        }, "Agent: HTTP/2 mutation", {"q": "payload"})
        self.assertEqual(payload["pseudoHeaders"][":path"], "/search?q=payload")
        self.assertEqual(payload["headers"]["Cookie"], "session=test")
        self.assertEqual(payload["targetHostname"], "example.test")

    def test_questions_are_redacted_before_first_read(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "store.sqlite3")
            qid = store.ask(
                "Use Cookie: session=abcdef0123456789abcdef0123456789",
                "API key=super-secret-value",
                ["Bearer: another-secret"],
            )
            question = store.question(qid)
            self.assertNotIn("abcdef0123456789abcdef0123456789", question["question"])
            self.assertNotIn("super-secret-value", question["reason"])
            self.assertNotIn("another-secret", question["options"][0])

if __name__ == "__main__":
    unittest.main()
