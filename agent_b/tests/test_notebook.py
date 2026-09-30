"""Discussion continuity and read-only grounding; no live model or target calls."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.collaboration import discussion_context, render_reference_context
from agent_b_harness.engine import Engine
from agent_b_harness.store import Store


class SnapshotClient:
    calls = []
    target = "https://example.test/"
    fail = ""

    def __init__(self, base):
        self.base = base

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        if self.fail and self.fail in path:
            raise RuntimeError("API_key=sensitive-provider-body")
        if "workspace" in path:
            return {"scope": {"observed_urls": [self.target]}, "raw_cookie": "secret-cookie"}
        if path.startswith("/api/findings"):
            return {"findings": [{"id": "daf_example", "title": "Fixture candidate",
                                  "agent_status": "needs_investigation", "url": self.target + "?token=secret-query",
                                  "evidence_preview": "Observed fixture response", "response_data": "secret-raw-body"}], "total": 1}
        if path.startswith("/api/agent/queue"):
            return {"queue": [{"id": 7, "status": "blocked", "summary": "Fixture review",
                               "fixture_blocked": True, "next_action": {"fixture_status": {"blocked": True, "reason": "Needs operator context"}, "credentials": "secret-credential"}}]}
        raise AssertionError("Unexpected endpoint " + path)


class NotebookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "chat.sqlite3"
        self.store = Store(self.path)
        self.engine = Engine(self.store)
        SnapshotClient.calls = []
        SnapshotClient.target = "https://example.test/"
        SnapshotClient.fail = ""
        self.cfg = config.Config(model="local", custom_models=({"id": "local", "model": "fixture", "url": "http://127.0.0.1:8000/v1"},))

    def save(self, **fields):
        return self.engine.update_notebook({"revision": self.engine.notebook["revision"], **fields})

    def discuss(self, engine, request, attachments=None):
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.Model") as model:
            model.return_value.complete.return_value = {"content": "Fixture advice grounded in the supplied notes."}
            engine.chat(request, attachment_ids=attachments, discussion=True)
            engine.thread.join(3)
            self.assertFalse(engine.thread.is_alive())
            args = model.return_value.complete.call_args.args
            self.assertEqual(args[1], [])
            self.assertEqual(args[3], "none")
            return json.dumps(args[0], ensure_ascii=False)

    def test_restart_recovers_notes_dialogue_and_file_contents(self):
        self.save(objective="Explain the release checklist", facts="Fixture fact from notes.txt", questions="Which requirement is unresolved?")
        file = self.engine.attachments.add("notes.txt", base64.b64encode(b"A retained reference fact.").decode())
        with patch("agent_b_harness.engine.DoubleAgent", side_effect=AssertionError("Opt-in required")):
            self.discuss(self.engine, "Review the retained notes", [file["id"]])
            restarted = Engine(Store(self.path))
            prompt = self.discuss(restarted, "What did we discuss previously?")
        self.assertIn("release checklist", prompt)
        self.assertIn("retained reference fact", prompt)
        self.assertIn("Review the retained notes", prompt)
        self.assertEqual(len(restarted.store.discussion_messages()), 4)
        self.assertEqual(restarted.discussion_context[0]["attachments"], [file["id"]])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_notes_are_redacted_validated_and_revision_checked(self):
        self.save(decisions="API_key=secret-notebook-value\nKeep the release in beta")
        self.assertNotIn("secret-notebook-value", json.dumps(self.store.collaboration()))
        for update in ({"revision": 0, "facts": "stale"}, {"revision": self.engine.notebook["revision"], "facts": ["invalid"]},
                       {"revision": self.engine.notebook["revision"], "burp_context_enabled": "true"},
                       {"revision": self.engine.notebook["revision"], "snapshot": {"status": "forged"}}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.engine.update_notebook(update)
        self.assertIn("Keep the release in beta", self.engine.notebook["decisions"])

    def test_snapshot_is_explicit_fixed_gets_with_sources_and_no_secrets(self):
        with self.assertRaises(ValueError):
            self.engine.refresh_discussion_snapshot()
        self.save(burp_context_enabled=True)
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient):
            snapshot = self.engine.refresh_discussion_snapshot()
        self.assertEqual(snapshot["status"], "ready")
        self.assertEqual(len(SnapshotClient.calls), 3)
        self.assertTrue(all(method == "GET" for method, _ in SnapshotClient.calls))
        self.assertGreater(snapshot["captured_at"], 0)
        self.assertIn("/api/findings/daf_example", json.dumps(snapshot))
        self.assertIn("Needs operator context", json.dumps(snapshot))
        for secret in ("secret-raw-body", "secret-cookie", "secret-query", "secret-credential"):
            self.assertNotIn(secret, json.dumps(snapshot))
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient):
            prompt = self.discuss(self.engine, "Why is the fixture blocked?")
        self.assertIn("Observed fixture response", prompt)
        self.assertIn("needs_investigation", prompt)
        self.assertIn("Needs operator context", prompt)
        self.assertEqual(len(SnapshotClient.calls), 6)

    def test_refresh_failure_replaces_previous_snapshot_and_is_not_an_empty_success(self):
        self.save(burp_context_enabled=True)
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient):
            self.engine.refresh_discussion_snapshot()
            SnapshotClient.fail = "workspace"
            failed = self.engine.refresh_discussion_snapshot()
        self.assertEqual(failed["status"], "unavailable")
        self.assertNotIn("findings", failed)
        self.assertNotIn("sensitive-provider-body", json.dumps(failed))
        SnapshotClient.fail = "findings"
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient):
            partial = self.engine.refresh_discussion_snapshot()
        self.assertEqual(partial["status"], "partial")
        self.assertNotIn("findings", partial)
        self.assertIn("queue", partial)

    def test_different_target_cannot_mix_into_existing_engagement(self):
        self.save(burp_context_enabled=True, objective="Work on the first engagement")
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient):
            self.engine.refresh_discussion_snapshot()
            SnapshotClient.target = "https://different.test/"
            SnapshotClient.calls = []
            snapshot = self.engine.refresh_discussion_snapshot()
        self.assertEqual(snapshot["status"], "target_changed")
        self.assertEqual(len(SnapshotClient.calls), 1)
        self.assertNotIn("findings", snapshot)
        self.assertEqual(self.engine.notebook["bound_target"], "https://example.test")

    def test_malformed_snapshot_payload_is_marked_partial(self):
        self.save(burp_context_enabled=True)
        original = SnapshotClient.request
        def invalid(client, method, path, **kwargs):
            return {} if path.startswith("/api/findings") else original(client, method, path, **kwargs)
        with patch("agent_b_harness.engine.DoubleAgent", SnapshotClient), patch.object(SnapshotClient, "request", invalid):
            result = self.engine.refresh_discussion_snapshot()
        self.assertEqual(result["status"], "partial")

    def test_saved_and_dismissed_decisions_ground_advice_and_acknowledge_changes(self):
        suggestion = {"subject": "Clarify the fixture", "route": "needs-info", "rationale": "Missing context",
                      "evidence": [{"source": "notes.txt", "summary": "Fixture dependency"}]}
        self.engine._save_suggestion(suggestion)
        ident = self.engine.suggestions()[0]["id"]
        self.engine.decide_suggestion(ident, "dismissed")
        restarted = Engine(Store(self.path))
        prompt = self.discuss(restarted, "What fixture advice did I dismiss?")
        self.assertIn("dismissed", prompt)
        self.assertIn("Fixture dependency", prompt)
        self.assertTrue(any("Dismissed:" in m["content"] for m in self.store.messages()))
        restarted.decide_suggestion(ident, "open")
        prompt = self.discuss(restarted, "Discuss recommendation " + ident)
        self.assertIn("requested_recommendations", prompt)
        self.assertIn("Fixture dependency", prompt)

    def test_discussion_preserves_paused_work_checkpoint(self):
        checkpoint = {"state": "stopped", "active_queue": "7", "resume_queue_id": "7", "queue_fetch_mode": True,
                      "target_url": "https://example.test/", "assessment_plan": {"fixture": "kept"}, "run_id": "paused-run"}
        self.store.save_checkpoint(checkpoint)
        engine = Engine(Store(self.path))
        self.discuss(engine, "Explain the release notes")
        self.assertEqual(self.store.load_checkpoint(), checkpoint)
        self.assertEqual(engine.active_queue, "7")
        self.assertEqual(engine.state, "stopped")

    def test_new_conversation_clears_engagement_and_attachment_refs(self):
        self.save(objective="Old engagement")
        old_id = self.engine.notebook["engagement_id"]
        file = self.engine.attachments.add("old.txt", base64.b64encode(b"Old reference").decode())
        self.discuss(self.engine, "Old discussion", [file["id"]])
        self.engine.clear()
        restarted = Engine(Store(self.path))
        self.assertNotEqual(restarted.notebook["engagement_id"], old_id)
        self.assertEqual(restarted.notebook["objective"], "")
        self.assertFalse(restarted.notebook["burp_context_enabled"])
        self.assertEqual(restarted.store.discussion_messages(), [])
        self.assertEqual(restarted.attachments.references(), [])

    def test_older_relevant_discussion_is_recalled_and_reference_json_stays_bounded(self):
        self.store.discussion_message("user", "Release requirement: the fixture needs a quarantine check")
        for i in range(240):
            self.store.discussion_message("assistant", "Unrelated discussion " + str(i))
        context = discussion_context(self.store, self.engine.notebook, [], "Which quarantine requirement remains?")
        self.assertIn("quarantine check", json.dumps(context["earlier_discussion_excerpts"]))
        context["snapshot"] = {"findings": {"shown": 30, "items": [{"id": str(i), "evidence_preview": "x" * 2000} for i in range(30)]}}
        rendered = render_reference_context(context)
        data = json.loads(rendered.split("\n", 1)[1])
        self.assertLessEqual(len(json.dumps(data, ensure_ascii=False, separators=(",", ":"))), 18000)
        self.assertTrue(data["context_sections_limited"])
        self.assertEqual(data["snapshot"]["findings"]["shown"], len(data["snapshot"]["findings"]["items"]))
        self.assertEqual(len(context["snapshot"]["findings"]["items"]), 30)

    def test_legacy_discuss_messages_migrate_without_assessment_history(self):
        legacy_path = Path(self.temp.name) / "legacy.sqlite3"
        legacy = Store(legacy_path)
        legacy.message("user", "Review my release notes", {"discussion": True})
        legacy.message("assistant", "Legacy discussion advice")
        legacy.message("user", "Assessment task", {"discussion": False})
        legacy.message("assistant", "Assessment output must stay separate")
        recovered = Engine(Store(legacy_path))
        self.assertEqual(len(recovered.store.discussion_messages()), 2)
        self.assertNotIn("Assessment output", json.dumps(recovered.discussion_context))
        self.assertEqual(len(Engine(Store(legacy_path)).store.discussion_messages()), 2)

    def test_decision_changes_are_received_at_the_next_discussion_boundary(self):
        self.engine._save_suggestion({"subject": "Review release notes", "route": "needs-info", "rationale": "Fixture requirement"})
        ident = self.engine.suggestions()[0]["id"]
        prompts = []
        engine = self.engine
        class BoundaryModel:
            def __init__(self, *args): pass
            def complete(self, messages, tools, on_delta=None, tool_choice=None):
                prompts.append(json.dumps(messages))
                if len(prompts) == 1:
                    engine.decide_suggestion(ident, "dismissed")
                    engine.chat("Consider my dismissal", discussion=True)
                return {"content": "Acknowledged fixture advice"}
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.Model", BoundaryModel):
            self.engine.chat("Review the release notes", discussion=True)
            self.engine.thread.join(3)
        self.assertEqual(len(prompts), 2)
        self.assertIn('"dismissed"', prompts[1].replace('\\"', '"'))
        self.assertIn("Consider my dismissal", prompts[1])


if __name__ == "__main__":
    unittest.main()
