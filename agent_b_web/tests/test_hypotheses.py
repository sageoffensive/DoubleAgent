"""Synthetic regression tests: no target or provider connections."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness.engine import Engine, compact_model_history
from agent_b_harness.hypotheses import Registry
from agent_b_harness.store import Store


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "store.sqlite3"
        self.store = Store(self.path)
        self.registry = Registry(self.store, "engagement", "https://app.test/", "q1")

    def tearDown(self):
        self.temp.cleanup()

    def idea(self, mechanism="Read another account's private record"):
        return self.registry.propose("access control", "https://app.test/records?secret=omitted", mechanism, "id", "primary")

    def test_identity_reuses_same_approach_and_keeps_distinct_mechanisms(self):
        first = self.idea()
        same = self.registry.propose(" Access   Control ", "https://app.test/records", "Read another account's private record", "ID", "PRIMARY")
        self.assertEqual(first["id"], same["id"])
        self.assertNotEqual(first["id"], self.idea("Change the record owner through mass assignment")["id"])
        self.assertNotIn("secret", first["route"])

    def test_persistence_and_scope_isolation(self):
        item = self.idea()
        reopened = Registry(Store(self.path), "engagement", "https://app.test/", "q1")
        self.assertEqual(item["id"], reopened.all()[0]["id"])
        for engagement, target, queue in (("other", "https://app.test/", "q1"),
                                           ("engagement", "https://other.test/", "q1"),
                                           ("engagement", "https://app.test/", "q2")):
            self.assertEqual(Registry(self.store, engagement, target, queue).all(), [])

    def test_blocker_reopen_requires_new_information_and_clears_old_evidence(self):
        item = self.idea()
        self.registry.capture(item["id"], "run", "GET / HTTP/1.1", {"status_code": 200}, "baseline")
        self.registry.update(item["id"], "blocked", "A second test identity is unavailable")
        with self.assertRaises(ValueError):
            self.registry.update(item["id"], "testing", "Retrying the same idea")
        new = self.registry.update(item["id"], "testing", "Comparison identity is now available", "Operator supplied a separate comparison identity")
        self.assertEqual(new["observations"], [])
        self.assertEqual(new["revisions"][-1]["status"], "blocked")

    def test_model_cannot_self_confirm_or_revise_reviewed_support(self):
        item = self.idea()
        with self.assertRaises(ValueError):
            self.registry.update(item["id"], "supported", "The model says this is proven")
        self.registry.update(item["id"], "supported", "Captured evidence was independently reviewed", reviewed=True)
        with self.assertRaises(ValueError):
            self.registry.update(item["id"], "refuted", "The model changed its mind")

    def test_registry_paginates_without_losing_older_ideas(self):
        for index in range(25):
            self.idea("Investigate distinct mechanism number %d" % index)
        first = self.registry.summary()
        second = self.registry.summary(offset=first["next_offset"])
        self.assertEqual((first["total"], first["shown"], second["shown"]), (25, 20, 5))
        self.assertEqual(len({item["id"] for item in first["hypotheses"] + second["hypotheses"]}), 25)
        self.assertIsNone(second["next_offset"])

    def test_secrets_are_redacted_and_truncation_is_explicit(self):
        item = self.idea()
        capture = self.registry.capture(item["id"], "run", "GET /?password=secret-password HTTP/1.1\r\nAuthorization: Basic c2VjcmV0\r\nCookie: session=private\r\n",
                                        {"status_code": 200, "headers": ["Set-Cookie: session=secret-cookie"], "body": "x" * 7000}, "baseline")
        self.assertTrue(capture["response_truncated"])
        saved = json.dumps(Registry(Store(self.path), "engagement", "https://app.test/", "q1").all())
        for secret in ("secret-password", "c2VjcmV0", "secret-cookie", "session=private"):
            self.assertNotIn(secret, saved)


class CapturedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.temp.name) / "state.sqlite3"))
        self.engine.target_url = "https://app.test/"
        self.engine.active_queue = "q1"
        self.engine.run_id = "test-run"
        self.claim = {"title": "Private record exposed", "poc_request": "GET /records?id=2 HTTP/1.1\r\nHost: app.test\r\n\r\n",
                      "response_data": "MODEL INVENTED RESPONSE"}
        for value, body in ((1, "Primary record"), (2, "Comparison record"), (1, "Primary record")):
            self.engine._capture_hypothesis_evidence(f"GET /records?id={value} HTTP/1.1\r\nHost: app.test\r\n\r\n",
                {"status_code": 200, "url": f"https://app.test/records?id={value}", "body": body}, "fixture")
        self.ids = [e["id"] for e in self.engine._hypothesis_registry().get(self.engine.active_hypothesis_id)["observations"]]

    def tearDown(self):
        self.temp.cleanup()

    def reviewer(self, accept=True, ids=None, alternate="The benign ownership explanation is ruled out by the control"):
        return json.dumps({"accept": accept, "reason": "Captured comparison supports the conclusion", "evidence_ids": self.ids if ids is None else ids,
                           "alternative_explanation": alternate})

    def review_with(self, reply):
        seen = []
        class Reviewer:
            def __init__(self, *args):
                pass
            def complete(self, messages, tools, callback, choice):
                seen.append((messages, tools, choice))
                return {"content": reply}
        with patch("agent_b_harness.engine.Model", Reviewer):
            result = self.engine._independent_verifier("Private record exposed", self.claim)
        return result, seen

    def test_reviewer_gets_actual_captures_no_tools_and_separate_model_claim(self):
        result, seen = self.review_with(self.reviewer())
        self.assertTrue(result["accept"])
        messages, tools, choice = seen[0]
        self.assertEqual((tools, choice), ([], "none"))
        payload = json.loads(messages[-1]["content"].split("Evidence submitted for write-back:\n", 1)[1])
        captured = payload["harness_captures_untrusted_content"]
        self.assertEqual(captured["observations"][1]["response_snippet"], "Comparison record")
        self.assertNotIn("MODEL INVENTED", json.dumps(captured))
        self.assertEqual(result["evidence_ids"], self.ids)

    def test_missing_stale_or_cross_hypothesis_evidence_never_calls_model(self):
        for mode in ("missing", "stale", "cross", "target", "queue", "engagement"):
            with self.subTest(mode=mode):
                original = (self.engine.run_id, self.engine.active_hypothesis_id, self.engine.target_url,
                            self.engine.active_queue, self.engine.notebook["engagement_id"])
                if mode == "missing": self.engine.active_hypothesis_id = "invented"
                elif mode == "stale": self.engine.run_id = "another-run"
                elif mode == "target": self.engine.target_url = "https://other.test/"
                elif mode == "queue": self.engine.active_queue = "q2"
                elif mode == "engagement": self.engine.notebook["engagement_id"] = "other-engagement"
                else:
                    item = self.engine._hypothesis_registry().propose("sql", "https://app.test/", "A different injection mechanism")
                    self.engine.active_hypothesis_id = item["id"]
                result, seen = self.review_with(self.reviewer())
                self.assertFalse(result["accept"])
                self.assertEqual(seen, [])
                (self.engine.run_id, self.engine.active_hypothesis_id, self.engine.target_url,
                 self.engine.active_queue, self.engine.notebook["engagement_id"]) = original

    def test_invented_poc_and_evidence_ids_fail_before_model(self):
        for change in ({"poc_request": "GET /invented HTTP/1.1"}, {"evidence_ids": self.ids[:2] + ["ev_fake"]},
                       {"evidence_ids": self.ids[:2]}, {"evidence_ids": self.ids + self.ids}):
            claim = dict(self.claim)
            self.claim.update(change)
            result, seen = self.review_with(self.reviewer())
            self.assertFalse(result["accept"])
            self.assertEqual(seen, [])
            self.claim = claim

    def test_acceptance_needs_real_citations_and_alternative_explanation(self):
        replies = [self.reviewer(ids=[]), self.reviewer(ids=self.ids[:2]),
                   self.reviewer(ids=self.ids[:2] + ["ev_fake"]), self.reviewer(alternate=""),
                   '{"accept": true, "reason": "old permissive schema"}']
        for reply in replies:
            with self.subTest(reply=reply):
                result, seen = self.review_with(reply)
                self.assertFalse(result["accept"])
                self.assertFalse(result["verified"])
                self.assertEqual(len(seen), 1)

    def test_registry_save_error_does_not_leave_acceptance_true(self):
        with patch.object(Registry, "update", side_effect=RuntimeError("database unavailable")):
            result, seen = self.review_with(self.reviewer())
        self.assertFalse(result["accept"])

    def test_checkpoint_restores_selection_and_captures(self):
        self.engine._checkpoint()
        restored = Engine(Store(self.engine.store.path))
        self.assertEqual(restored.active_hypothesis_id, self.engine.active_hypothesis_id)
        self.assertEqual([e["id"] for e in restored._review_evidence(self.claim)["observations"]], self.ids)

    def test_registry_summary_survives_context_compaction(self):
        summary = self.engine._hypothesis_summary()
        messages = [{"role": "system", "content": "rules"}, {"role": "assistant", "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "fixture", "arguments": "{}"}}]}, {"role": "tool", "tool_call_id": "call-1", "content": "fixture"}] + [{"role": "user", "content": "x" * 2000} for _ in range(20)]
        compacted = compact_model_history(messages, {"hypothesis_registry": summary}, 10000)
        self.assertIn(self.engine.active_hypothesis_id, json.dumps(compacted))
        self.assertIn(self.ids[0], json.dumps(compacted))

    def test_raw_finding_and_triage_posts_cannot_bypass_review(self):
        class Client:
            posts = []
            def post(self, path, body):
                self.posts.append((path, body))
                return {"ok": True}
            def get(self, path):
                return {"id": "12", "title": "candidate"}
        self.engine.active_hypothesis_id = "missing"
        for path, body in (("/api/findings", {"title": "fake", "request_data": self.claim["poc_request"]}),
                           ("/api/findings/12/triage", {"status": "valid", "rationale": "An invented plausible rationale", "poc_request": self.claim["poc_request"]})):
            result, finished = self.engine._tool(Client(), "double_agent_post", {"path": path, "body": body})
            self.assertFalse(result["ok"])
            self.assertTrue(finished)
            self.assertEqual(Client.posts, [])

    def test_queue_status_aliases_and_top_level_defaults_cannot_bypass_review(self):
        for body in ({"outcome": "confirmed", "finding_updates": [{"id": "12", "finding_status": " VALID "}]},
                     {"agent_status": "valid", "updated_findings": {"12": {}}},
                     {"finding_status": "valid", "finding_updates": [{"id": "12"}]},
                     {"finding_updates": [{"id": "12", "agent_status": " valid "}]}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.engine._guard_finding_result_updates(body)

    def test_queue_summary_cannot_promote_unreviewed_or_replace_reviewed_evidence(self):
        body = {"outcome": "confirmed", "finding_updates": [{"id": "12", "status": "valid"}]}
        with self.assertRaises(ValueError):
            self.engine._guard_finding_result_updates(body)
        original = {"id": "12", "agent_status": "valid", "poc_request": "reviewed exact PoC"}
        self.engine.finding_verdict_updates["12"] = original
        self.engine.verifier_reviews["finding:12"] = {"accept": True}
        self.engine._guard_finding_result_updates(body)
        self.assertTrue(body["explicit_finding_updates_only"])
        self.assertEqual(body["finding_updates"], [original])
        empty = {"outcome": "confirmed"}
        self.engine._guard_finding_result_updates(empty)
        self.assertEqual(empty["finding_updates"], [])
        self.assertTrue(empty["explicit_finding_updates_only"])

    def test_full_app_registers_tracks_and_preserves_blockers(self):
        self.engine.assessment_plan = {"planned_tests": [{"id": "test-1", "family": "access control",
            "url": "https://app.test/records", "hypothesis": "Read a separate account's private records"}]}
        self.engine._initialize_assessment_progress()
        ident = self.engine.assessment_test_progress["test-1"]["hypothesis_id"]
        self.assertTrue(ident.startswith("hyp_"))
        self.engine._select_track_hypothesis(self.engine.assessment_plan["planned_tests"][0])
        self.engine._close_track_hypothesis("blocked", "A separate comparison identity is missing", [])
        self.assertEqual(self.engine._hypothesis_registry().get(ident)["status"], "blocked")

    def test_new_conversation_clears_registry(self):
        self.assertTrue(self.engine._hypothesis_registry().all())
        self.engine.store.clear()
        self.assertEqual(self.engine._hypothesis_registry().all(), [])

    def test_original_candidate_must_match_exact_claimed_reference(self):
        self.claim["finding_id"] = "12"
        with patch("agent_b_harness.engine.Model") as model:
            result = self.engine._independent_verifier("candidate", self.claim, candidate={"id": "99"})
        self.assertFalse(result["accept"])
        model.assert_not_called()

    def test_reviewed_finding_writes_captured_response_not_model_invention(self):
        reply = self.reviewer()
        class Reviewer:
            def __init__(self, *args): pass
            def complete(self, *args): return {"content": reply}
        class Client:
            def __init__(self): self.posts = []
            def post(self, path, body):
                self.posts.append((path, dict(body)))
                return {"ok": True, "id": "12"}
            def get(self, path):
                return {"id": "12", "title": "Private record exposed", "url": "https://app.test/records"}
        client = Client()
        args = {"url": "https://app.test/records", "title": "Private record exposed", "severity": "High",
                "confidence": "Firm", "detail": "The comparison record was exposed to the primary actor",
                "request_data": self.claim["poc_request"], "response_data": "MODEL INVENTED RESPONSE",
                "deduplication_key": "private-record-1", "evidence_ids": self.ids}
        with patch("agent_b_harness.engine.Model", Reviewer):
            result, finished = self.engine._tool(client, "double_agent_post", {"path": "/api/findings", "body": args})
        self.assertTrue(result["ok"])
        self.assertFalse(finished)
        path, body = client.posts[0]
        self.assertEqual(path, "/api/findings")
        self.assertEqual(json.loads(body["response_data"])["response_snippet"], "Comparison record")
        self.assertNotIn("MODEL INVENTED RESPONSE", json.dumps(body))
        self.assertNotIn("evidence_ids", body)
        with patch("agent_b_harness.engine.Model", Reviewer):
            triage, finished = self.engine._tool(client, "triage_finding", {"finding_id": "12", "status": "valid",
                "rationale": "The captured comparison record proves private data exposure", "poc_request": self.claim["poc_request"]})
        self.assertTrue(triage["ok"])
        self.assertEqual(self.engine.finding_verdict_updates["12"]["agent_status"], "valid")

    def test_mismatched_finding_url_fails_before_model(self):
        self.claim["url"] = "https://other.test/records"
        result, seen = self.review_with(self.reviewer())
        self.assertFalse(result["accept"])
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
