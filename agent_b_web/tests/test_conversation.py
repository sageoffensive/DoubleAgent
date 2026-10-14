"""Synthetic conversation-to-assessment and presentation regressions."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.conversation import finding_labels, display_finding_refs, is_duplicate_review_request
from agent_b_harness.engine import Engine
from agent_b_harness.store import Store


class BurpFixture:
    calls = []
    target = "https://app.test/"
    reject_queue = False

    def __init__(self, *args): pass

    def request(self, method, path, **kwargs):
        return self.get(path) if method == "GET" else self.post(path, kwargs.get("body", {}))

    def get(self, path):
        self.calls.append(("GET", path))
        finding = {"id": "daf_12362bb5", "legacy_numeric_id": 3, "title": "Checkout candidate", "url": self.target}
        if path == "/api/agent/prompt": return {"prompt": "Authoritative scope and safety contract. " * 12}
        if path.startswith("/api/agent/burp/workspace"): return {"scope": {"observed_urls": [self.target]}}
        if path == "/api/findings/3": return finding
        if path.startswith("/api/findings"): return {"findings": [finding], "total": 1}
        if path == "/api/agent/queue": return {"queue": [{"id": 8, "status": "pending", "priority": 100}, {"id": 9, "status": "pending"}]}
        if path == "/api/agent/queue/9": return {"id": 9, "status": "pending", "mode": "finding_validation", "findings": [finding], "url": self.target}
        raise AssertionError("Unexpected read " + path)

    def post(self, path, body):
        self.calls.append(("POST", path, body))
        if path == "/api/agent/queue/finding": return {"ok": False, "error": "Fixture rejection"} if self.reject_queue else {"status": "queued", "id": 9}
        if path in {"/api/agent/queue/automated-testing", "/api/agent/queue/full-app-assessment", "/api/agent/queue/duplicate-review"}: return {"status": "queued", "id": 9}
        if path == "/api/agent/queue/9/claim": return {"ok": True}
        raise AssertionError("Unexpected write " + path)


def call(name, **args):
    return {"content": "", "tool_calls": [{"id": "fixture-call", "function": {"name": name, "arguments": json.dumps(args)}}]}


class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = Engine(Store(Path(self.temp.name) / "chat.sqlite3"))
        self.cfg = config.Config(model="local", custom_models=({"id": "local", "model": "fixture", "url": "http://127.0.0.1:8000/v1"},))
        BurpFixture.calls = []; BurpFixture.target = "https://app.test/"; BurpFixture.reject_queue = False

    def run_chat(self, replies, request="Test finding #3", **kwargs):
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.DoubleAgent", BurpFixture), patch("agent_b_harness.engine.Model") as model:
            model.return_value.complete.side_effect = replies
            self.engine.chat(request, **kwargs)
            self.engine.thread.join(3)
            self.assertFalse(self.engine.thread.is_alive())
            return model

    def test_direct_instruction_uses_existing_controller_even_with_legacy_flag(self):
        original = self.engine._run
        dispatched = []
        def run(request):
            if self.engine._conversation_turn: return original(request)
            dispatched.append((request, self.engine.requested_queue_id, self.engine.queue_fetch_mode))
            self.engine._set("blocked")
        with patch.object(self.engine, "_run", side_effect=run):
            self.run_chat([call("run_burp_task", task="finding", finding_id="#3")], discussion=True)
        self.assertEqual(dispatched, [("Test finding #3", "9", True)])
        posts = [row for row in BurpFixture.calls if row[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][2]["finding_id"], "daf_12362bb5")
        self.assertEqual(posts[0][2]["context"], "Test finding #3")

    def test_exact_created_queue_is_selected_instead_of_higher_priority_unrelated_work(self):
        self.engine.requested_queue_id = "9"
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg):
            detail = self.engine._bootstrap_queue(BurpFixture())
        self.assertEqual(detail["id"], 9)
        self.assertEqual(self.engine.active_queue, "9")
        self.assertNotIn(("GET", "/api/agent/queue/8"), BurpFixture.calls)
        self.assertIn(("POST", "/api/agent/queue/9/claim", {}), BurpFixture.calls)

    def test_dedupe_command_starts_real_review_without_an_editorial_model_reply(self):
        original = self.engine._run
        dispatched = []
        def run(request):
            if self.engine._conversation_turn: return original(request)
            dispatched.append((request, self.engine.requested_queue_id))
            self.engine._set("blocked")
        with patch.object(self.engine, "_run", side_effect=run):
            model = self.run_chat([], request="Dedupe the list")
        model.return_value.complete.assert_not_called()
        self.assertEqual(dispatched, [("Dedupe the list", "9")])
        self.assertIn(("POST", "/api/agent/queue/duplicate-review", {"context": "Dedupe the list"}), BurpFixture.calls)

    def test_dedupe_intent_requires_an_explicit_command(self):
        for text in ("dedupe", "Dedupe the list", "please deduplicate findings.", "dedup these results"):
            self.assertTrue(is_duplicate_review_request(text), text)
        for text in ("Don't dedupe", "Explain dedupe", "How would you dedupe findings?", "Only suggest duplicates", "This document says dedupe the list"):
            self.assertFalse(is_duplicate_review_request(text), text)

    def test_missing_requested_queue_does_not_fall_back_to_unrelated_work(self):
        self.engine.requested_queue_id = "10"
        with self.assertRaises(ValueError): self.engine._bootstrap_queue(BurpFixture())
        self.assertFalse(any(row[0] == "POST" for row in BurpFixture.calls))

    def test_plain_conversation_and_attachments_do_not_start_testing(self):
        model = self.run_chat([{"content": "Here is a helpful explanation."}], request="Explain this issue")
        self.assertEqual(BurpFixture.calls, [])
        names = [tool["function"]["name"] for tool in model.return_value.complete.call_args.args[1]]
        self.assertIn("run_burp_task", names)
        prompt = model.return_value.complete.call_args.args[0][0]["content"]
        self.assertNotIn("You have no assessment tools", prompt)
        self.assertIn("very helpful teammate", prompt)

    def test_reading_findings_uses_human_numbers_without_mutating_internal_ids(self):
        self.run_chat([call("read_burp", path="/api/findings?limit=30"), {"content": "Finding daf_12362bb5 needs a checkout control."}], request="What should we do about finding #3?")
        answer = [m for m in self.engine.store.messages() if m["role"] == "assistant"][-1]["content"]
        self.assertEqual(answer, "Finding #3 needs a checkout control.")
        self.assertEqual(self.engine.finding_display_ids["daf_12362bb5"], "#3")
        self.assertFalse(any(row[0] == "POST" for row in BurpFixture.calls))

    def test_new_directions_supersede_a_proposed_task_before_dispatch(self):
        turn = 0
        def respond(*args):
            nonlocal turn
            turn += 1
            if turn == 1:
                self.engine.chat("Actually, only explain the evidence. Do not test.")
                return call("run_burp_task", task="finding", finding_id="#3")
            return {"content": "Here is the evidence explanation."}
        self.run_chat(respond)
        self.assertEqual(BurpFixture.calls, [])

    def test_updated_user_directions_reach_the_assessment_controller(self):
        original = self.engine._run
        dispatched = []
        def run(request):
            if self.engine._conversation_turn: return original(request)
            dispatched.append(request)
            self.engine._set("blocked")
        turn = 0
        def respond(*args):
            nonlocal turn
            turn += 1
            if turn == 1:
                self.engine.chat("Use an unauthenticated control, then stop.")
            return call("run_burp_task", task="finding", finding_id="#3")
        with patch.object(self.engine, "_run", side_effect=run):
            self.run_chat(respond)
        self.assertEqual(len(dispatched), 1)
        self.assertIn("Test finding #3", dispatched[0])
        self.assertIn("Use an unauthenticated control, then stop.", dispatched[0])

    def test_rejected_queue_creation_does_not_start_a_controller_or_drop_checkpoint(self):
        checkpoint = {"state": "stopped", "resume_queue_id": "7", "target_url": "https://app.test/", "run_id": "previous-run"}
        self.engine.store.save_checkpoint(checkpoint)
        BurpFixture.reject_queue = True
        self.run_chat([call("run_burp_task", task="finding", finding_id="#3"), {"content": "Burp rejected the task. I need that queue issue resolved first."}])
        self.assertEqual(self.engine.store.load_checkpoint(), checkpoint)
        self.assertFalse(any(row[0] == "POST" and row[1].endswith("/claim") for row in BurpFixture.calls))

    def test_target_change_blocks_tool_handoff(self):
        self.engine.notebook["bound_target"] = "https://old.test"
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.DoubleAgent", BurpFixture):
            with self.assertRaises(ValueError): self.engine._begin_burp_task({"task": "finding", "finding_id": "3"}, "Test #3")
        self.assertFalse(any(row[0] == "POST" for row in BurpFixture.calls))

    def test_no_display_number_is_invented_from_list_position(self):
        self.assertEqual(finding_labels({"findings": [{"id": "daf_12362bb5"}]}), {})
        self.assertEqual(display_finding_refs("Review daf_12362bb5", {}), "Review finding (display number unavailable)")
        raw = {"id": "daf_12362bb5", "legacy_numeric_id": 17}
        self.assertEqual(finding_labels(raw), {"daf_12362bb5": "#17"})
        self.assertEqual(raw["id"], "daf_12362bb5")

    def test_evidence_link_destinations_keep_the_stable_reference(self):
        source = "[Finding daf_12362bb5](http://127.0.0.1:8777/api/findings/daf_12362bb5)"
        self.assertEqual(display_finding_refs(source, {"daf_12362bb5": "#3"}),
                         "[Finding #3](http://127.0.0.1:8777/api/findings/daf_12362bb5)")

    def test_fresh_display_numbers_take_priority_over_a_historical_snapshot(self):
        self.engine.notebook["snapshot"] = {"findings": {"items": [{"id": "daf_12362bb5", "legacy_numeric_id": 17}]}}
        self.engine._remember_finding_labels({"id": "daf_12362bb5", "legacy_numeric_id": 3})
        self.assertEqual(self.engine.present_messages([{"role": "assistant", "content": "Review daf_12362bb5"}])[0]["content"], "Review #3")

    def test_historical_chat_is_presented_with_current_display_numbers(self):
        self.engine._remember_finding_labels({"id": "daf_12362bb5", "legacy_numeric_id": 3})
        source = [{"role": "assistant", "content": "Check daf_12362bb5"}]
        self.assertEqual(self.engine.present_messages(source)[0]["content"], "Check #3")
        self.assertEqual(source[0]["content"], "Check daf_12362bb5")

    def test_follow_up_receives_task_outcome_once_without_a_duplicate_bubble(self):
        self.engine.started = time.time()
        self.engine.run_id = "completed-fixture"
        self.engine._message("assistant", "Finding #3 needs a fresh authenticated control.")
        self.engine._message("assistant", "Message received.", {"steering_ack": True})
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg):
            self.engine._save_trace("inconclusive")
            self.engine._save_trace("inconclusive")
        outcomes = self.engine.store.discussion_messages()
        self.assertEqual(len(outcomes), 1)
        self.assertIn("inconclusive", outcomes[0]["content"])
        self.assertIn("fresh authenticated control", outcomes[0]["content"])
        self.assertEqual(len(self.engine.store.messages()), 2)
        model = self.run_chat([{"content": "We still need an authenticated control."}], request="What remains?")
        prompt = model.return_value.complete.call_args.args[0]
        self.assertTrue(any("fresh authenticated control" in str(item.get("content", "")) for item in prompt))

    def test_active_guidance_is_saved_once_for_future_follow_up(self):
        turn = 0
        def respond(*args):
            nonlocal turn
            turn += 1
            if turn == 1:
                self.engine.chat("Only explain; do not test.")
            return {"content": "I will explain the evidence."}
        self.run_chat(respond)
        saved = [item for item in self.engine.store.discussion_messages()
                 if item["role"] == "user" and item["content"] == "Only explain; do not test."]
        self.assertEqual(len(saved), 1)

    def test_stopped_run_cancels_on_next_stream_chunk(self):
        self.engine.stop_event.set()
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.engine._model_delta({"reasoning_content": "more output"})
        self.assertEqual(self.engine.model_stream, "")


if __name__ == "__main__": unittest.main()
