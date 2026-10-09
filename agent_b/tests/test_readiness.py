import json
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from agent_b_harness.engine import Engine, authentication_failed
from agent_b_harness.readiness import ReadinessBlocked, SIGNED_IN, PUBLIC_APP, STOP, captured_access
from agent_b_harness.store import Store


def row(index, status=200, *, auth=False, url="https://example.test/private", preview=""):
    return {"history_index": index, "url": url, "method": "GET", "status_code": status,
            "has_response": True, "request_headers": ["Cookie: session=DO-NOT-STORE"] if auth else [],
            "response_preview": preview}


class HistoryClient:
    def __init__(self, rows=(), scope=True):
        self.rows, self.scope, self.gets, self.posts = list(rows), scope, [], []

    def get(self, path):
        self.gets.append(path)
        if path.startswith("/api/agent/scope?"):
            return {"scope_guard": {"in_scope": self.scope}}
        if path.startswith("/api/agent/history/http/regex?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            offset = int(query.get("offset", [0])[0])
            count = int(query["count"][0])
            return {"total_matches": len(self.rows), "items": self.rows[offset:offset + count]}
        if path == "/api/agent/queue":
            return {"queue": [{"id": 4, "status": "claimed"}]}
        if path == "/api/agent/queue/4":
            return {"id": 4, "status": "claimed", "campaign_type": "full_app_assessment",
                    "url": "https://example.test/private"}
        raise AssertionError(path)

    def post(self, path, body):
        self.posts.append((path, body))
        return {"status_code": 401, "url": "https://example.test/private"}


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "chat.sqlite3")
        self.engine = Engine(self.store)

    def tearDown(self):
        self.directory.cleanup()

    def test_authenticated_history_requires_protected_route_evidence(self):
        client = HistoryClient([row(1, 401), row(2, auth=True)])
        evidence = captured_access(client, "https://example.test/")
        self.assertTrue(evidence["authenticated"])
        self.assertEqual(evidence["history_index"], 2)
        self.assertNotIn("DO-NOT-STORE", json.dumps(evidence))
        self.assertEqual(client.posts, [])

    def test_cookie_and_200_alone_are_ambiguous(self):
        self.assertFalse(captured_access(HistoryClient([row(1, auth=True)]), "https://example.test/")["authenticated"])

    def test_new_rejection_and_login_page_override_old_success(self):
        for latest in (row(3, 401, auth=True), row(3, auth=True, preview='<input type="password">'), row(3, 503)):
            evidence = captured_access(HistoryClient([row(1, 401), row(2, auth=True), latest]), "https://example.test/")
            self.assertFalse(evidence["access"])
            self.assertFalse(evidence["authenticated"])

    def test_other_origin_or_port_cannot_supply_access_evidence(self):
        for url in ("http://example.test/private", "https://example.test:8443/private", "https://other.test/private"):
            self.assertFalse(captured_access(HistoryClient([row(1, url=url)]), "https://example.test/")["access"])

    def test_unknown_scope_cannot_be_overridden_by_operator(self):
        for scope in (False, None, "true"):
            with patch.object(self.engine, "_ask", side_effect=AssertionError("No scope override")):
                with self.assertRaises(ReadinessBlocked):
                    self.engine._ensure_app_ready(HistoryClient(scope=scope), "https://example.test/")

    def test_history_success_is_passive_and_never_stores_http_material(self):
        client = HistoryClient([row(1, 401), row(2, auth=True)])
        with patch.object(self.engine, "_ask", side_effect=AssertionError("Evidence already supplied")):
            evidence = self.engine._ensure_app_ready(client, "https://example.test/")
        self.assertEqual(evidence["source"], "burp_history")
        self.assertNotIn("DO-NOT-STORE", json.dumps(self.store.events(0)))
        self.engine._checkpoint()
        self.assertEqual(Engine(self.store).app_readiness, {})
        self.assertEqual(client.posts, [])

    def test_missing_history_asks_and_public_access_is_explicit(self):
        client = HistoryClient()
        with patch.object(self.engine, "_ask", return_value=PUBLIC_APP) as ask:
            result = self.engine._ensure_app_ready(client, "https://example.test/")
        self.assertEqual(result, {"access": True, "authenticated": False, "source": "operator_confirmation", "login_not_required": True})
        self.assertIn(PUBLIC_APP, ask.call_args.args[2])
        self.assertEqual(ask.call_args.kwargs["kind"], "readiness")
        self.assertEqual(client.posts, [])

    def test_credentials_required_excludes_public_option(self):
        with patch.object(self.engine, "_ask", return_value=SIGNED_IN) as ask:
            self.engine._ensure_app_ready(HistoryClient(), "https://example.test/", auth_required=True)
        self.assertEqual(ask.call_args.args[2], [SIGNED_IN, STOP])

    def test_public_app_does_not_keep_prompting_for_ambient_cookies(self):
        with patch.object(self.engine, "_ask", return_value=PUBLIC_APP) as ask:
            self.engine._ensure_app_ready(HistoryClient(), "https://example.test/")
            self.engine._guard_auth_payload(HistoryClient(), {"host": "example.test", "https": True,
                                           "request": "GET / HTTP/1.1\r\nCookie: preferences=dark\r\n\r\n"})
        self.assertEqual(ask.call_count, 1)

    def test_authenticated_request_stops_before_dispatch_when_access_unconfirmed(self):
        self.engine.active_queue = "4"
        client = HistoryClient()
        with patch.object(self.engine, "_ask", return_value=STOP):
            result, finished = self.engine._tool(client, "double_agent_post", {
                "path": "/api/agent/request", "body": {"host": "example.test", "port": 443, "https": True,
                "request": "GET /private HTTP/1.1\r\nHost: example.test\r\nCookie: session=DO-NOT-STORE\r\n\r\n"}})
        self.assertTrue(finished)
        self.assertTrue(result["blocked"])
        self.assertFalse(any(path == "/api/agent/request" for path, _ in client.posts))
        self.assertEqual(self.engine.active_queue, None)

    def test_new_origin_and_http2_credentials_require_confirmation(self):
        self.engine.app_readiness["https://other.test:443"] = {"authenticated": True}
        with patch.object(self.engine, "_ask", return_value=STOP):
            with self.assertRaises(ReadinessBlocked):
                self.engine._guard_auth_payload(HistoryClient(), {"targetHostname": "example.test", "targetPort": 443,
                                               "usesHttps": True, "pseudoHeaders": {":path": "/private"},
                                               "headers": {"Authorization": "Bearer DO-NOT-STORE"}})

    def test_anonymous_negative_control_does_not_ask_for_login(self):
        self.engine.active_queue = "4"
        client = HistoryClient()
        with patch.object(self.engine, "_ask", side_effect=AssertionError("Expected unauthenticated response")):
            result, finished = self.engine._tool(client, "send_burp_request", {
                "url": "https://example.test/private", "use_auth": False})
        self.assertFalse(finished)
        self.assertEqual(result["status_code"], 401)
        self.assertEqual(len(client.posts), 1)

    def test_stop_invalidates_previous_readiness(self):
        self.engine.app_readiness["https://example.test:443"] = {"authenticated": True}
        with patch.object(self.engine, "_ask", return_value=STOP):
            with self.assertRaises(ReadinessBlocked):
                self.engine._ensure_app_ready(HistoryClient(), "https://example.test/", force=True)
        self.assertEqual(self.engine.app_readiness, {})

    def test_full_app_gate_precedes_planning_and_rechecks_on_resume(self):
        self.engine.queue_fetch_mode = True
        for resume in (False, True):
            self.engine.resume_requested = resume
            self.engine.resume_queue_id = "4"
            self.engine.assessment_plan = {"planned_tests": []} if resume else {}
            with patch.object(self.engine, "_ask", return_value=STOP), patch.object(self.engine, "_prepare_full_assessment") as prepare:
                with self.assertRaises(ReadinessBlocked):
                    self.engine._bootstrap_queue(HistoryClient())
            prepare.assert_not_called()

    def test_regular_queue_and_duplicate_review_do_not_need_access(self):
        for mode in ("duplicate_review", "validation"):
            client = HistoryClient()
            original_get = client.get
            client.get = lambda path: {"id": 4, "status": "claimed", "mode": mode} if path == "/api/agent/queue/4" else original_get(path)
            with patch.object(self.engine, "_ensure_app_ready", side_effect=AssertionError("No readiness gate")):
                self.engine._bootstrap_queue(client)
            self.assertFalse(any("history/" in p for p in client.gets))

    def test_auth_question_uses_safe_access_confirmation(self):
        self.engine.target_url = "https://example.test/"
        with patch.object(self.engine, "_ask", return_value=SIGNED_IN) as ask:
            result, finished = self.engine._tool(HistoryClient(), "ask_user", {"question": "Paste your password", "reason": "Need credentials"})
        self.assertFalse(finished)
        self.assertNotIn("Paste your password", ask.call_args.args[0])
        self.assertEqual(result["app_readiness"]["source"], "operator_confirmation")

    def test_pending_access_answer_is_button_only_and_single_use(self):
        qid = self.store.ask("Can you access the app?", "Sign in through Burp", [SIGNED_IN, STOP], kind="readiness")
        self.assertTrue(qid.startswith("approval-readiness-"))
        for answer in ("yes", "password=secret", PUBLIC_APP):
            with self.assertRaises(ValueError):
                self.engine.answer(qid, answer)
        self.engine.answer(qid, SIGNED_IN)
        with self.assertRaises(ValueError):
            self.engine.answer(qid, SIGNED_IN)
        self.assertNotIn("password=secret", json.dumps(self.store.messages(50)))

    def test_restart_cancels_readiness_and_does_not_restore_authorization(self):
        qid = self.store.ask("Can you access the app?", "", [SIGNED_IN, STOP], kind="readiness")
        restarted = Engine(self.store)
        self.assertEqual(self.store.question(qid)["status"], "cancelled")
        self.assertEqual(restarted.app_readiness, {})

    def test_stop_cancels_wait_without_traffic(self):
        client = HistoryClient()
        errors = []
        def check():
            try:
                self.engine._ensure_app_ready(client, "https://example.test/")
            except ReadinessBlocked as exc:
                errors.append(exc)
        thread = threading.Thread(target=check)
        thread.start()
        # Wait for the real question, bounded independently of app traffic.
        for _ in range(100):
            if self.store.pending():
                break
            threading.Event().wait(.01)
        self.engine.stop()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(errors)
        self.assertEqual(client.posts, [])

    def test_password_form_is_recognized_as_login_failure(self):
        self.assertTrue(authentication_failed({"status_code": 200, "body": "<input type='password'>"}))


if __name__ == "__main__":
    unittest.main()
