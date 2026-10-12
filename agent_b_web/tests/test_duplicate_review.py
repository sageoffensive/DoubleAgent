"""Regression coverage for the empty-table/false-completion duplicate review."""
import tempfile
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from agent_b_harness.clients import HTTPError
from agent_b_harness.config import Config
from agent_b_harness.engine import Engine, compact_model_history
from agent_b_harness.store import Store


def detail():
    return {"id": 0, "source": "duplicate_review", "finding_ids": ["daf_a", "daf_b"],
            "duplicate_review": {"finding_count": 2}, "findings": [
                {"id": "daf_a", "stable_id": "daf_a", "legacy_numeric_id": 8, "title": "First"},
                {"id": "daf_b", "stable_id": "daf_b", "legacy_numeric_id": 9, "title": "Second"}]}


class Client:
    def __init__(self, response=None):
        self.posts = []
        self.response = response or {"id": 0, "status": "completed", "outcome": "inconclusive", "queue_removed": True}
    def post(self, path, body):
        self.posts.append((path, body))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class DuplicateReviewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.directory.name) / "store.sqlite3"))
        self.engine.queue_fetch_mode = True
        self.engine.active_queue = "0"
        self.engine._duplicate_review_active = True
        self.assertEqual(self.engine._prepare_duplicate_review(detail()), "")
    def tearDown(self):
        self.directory.cleanup()

    def test_empty_partial_unresolved_or_repeated_tables_are_blocked(self):
        cases = [dict(detail(), findings=[]), dict(detail(), findings=detail()["findings"][:1]),
                 dict(detail(), duplicate_review={"finding_count": 3}),
                 dict(detail(), linked_findings_resolution={"requested_count": 2, "unresolved_stable_ids": ["daf_missing"]}),
                 dict(detail(), findings=[detail()["findings"][0]] * 2)]
        for value in cases:
            with self.subTest(value=value):
                self.assertTrue(self.engine._prepare_duplicate_review(value))

    def run_with_model(self, model, queue_detail):
        with (patch("agent_b_harness.engine.config.load", return_value=Config(max_steps=4)),
              patch("agent_b_harness.engine.config.resolve_model_connection", return_value={
                  "base_url": "http://127.0.0.1:8000/v1", "api_key": "", "model": "fixture", "provider": "openai_compatible"}),
              patch("agent_b_harness.engine.Model", return_value=model),
              patch("agent_b_harness.engine.DoubleAgent", return_value=Client()),
              patch.object(self.engine, "_bootstrap_queue", return_value=queue_detail),
              patch.object(self.engine, "_heartbeat", return_value=None)):
            self.engine._run("Fetch Burp queue")

    def test_reported_empty_queue_is_blocked_before_model_inference(self):
        model = Mock()
        self.engine.burp_prompt_loaded = True
        self.run_with_model(model, dict(detail(), findings=[], finding_ids=[]))
        model.complete.assert_not_called()
        self.assertEqual(self.engine.state, "blocked")
        self.assertIn("No duplicate review was completed", self.engine.store.messages(1)[0]["content"])

    def test_stalled_review_keeps_claim_and_does_not_submit_completion(self):
        model = Mock()
        model.complete.return_value = {"role": "assistant", "content": "Reviewing the table", "tool_calls": []}
        self.engine.burp_prompt_loaded = True
        with patch.object(self.engine, "_submit_duplicate_review_result") as submit:
            self.run_with_model(model, detail())
        submit.assert_not_called()
        self.assertEqual(self.engine.state, "blocked")
        self.assertEqual(self.engine.active_queue, "0")
        runtime = [row["content"] for row in model.complete.call_args.args[0] if "findings_to_compare" in str(row.get("content", ""))]
        self.assertTrue(any('"id": "daf_a"' in row for row in runtime))
        self.assertFalse(any('"id": 8' in row for row in runtime))

    def test_partial_finish_cannot_close_review(self):
        client = Client()
        result, finished = self.engine._tool(client, "finish", {
            "status": "completed", "summary": "Done", "reviewed_finding_ids": ["daf_a"]})
        self.assertFalse(result["ok"])
        self.assertFalse(finished)
        self.assertEqual(client.posts, [])

    def test_accepted_finish_uses_supported_protocol_and_preserves_canonical(self):
        client = Client()
        result, finished = self.engine._tool(client, "finish", {
            "status": "completed", "summary": "Done", "reviewed_finding_ids": ["daf_a", "daf_b"]})
        self.assertTrue(result["ok"])
        self.assertTrue(finished)
        self.assertEqual(self.engine.state, "completed")
        self.assertIsNone(self.engine.active_queue)
        path, body = client.posts[0]
        self.assertEqual(path, "/api/agent/queue/0/result")
        self.assertEqual(body["outcome"], "inconclusive")
        self.assertTrue(body["explicit_finding_updates_only"])
        self.assertEqual(body["finding_updates"], [])
        self.assertEqual(body["duplicate_review"]["reviewed_finding_ids"], ["daf_a", "daf_b"])

    def test_rejected_missing_or_wrong_queue_receipts_never_report_success(self):
        for response in [{"ok": False, "error": "rejected"}, {"status": "ok"},
                         {"id": 1, "status": "completed", "outcome": "inconclusive"},
                         HTTPError(400, {"error": "invalid_outcome"})]:
            with self.subTest(response=response):
                self.engine.active_queue = "0"
                result, finished = self.engine._tool(Client(response), "finish", {
                    "status": "completed", "summary": "Done", "reviewed_finding_ids": ["daf_a", "daf_b"]})
                self.assertFalse(result["ok"])
                self.assertTrue(finished)
                self.assertEqual(self.engine.state, "blocked")
                self.assertEqual(self.engine.active_queue, "0")

    def test_scope_enforcement_blocks_rogue_tools_unlinked_ids_and_nonduplicate_writes(self):
        client = Client()
        attempts = [("send_burp_request", {}), ("double_agent_post", {"path": "/api/agent/request"}),
                    ("get_linked_finding", {"finding_id": "daf_other"}),
                    ("triage_finding", {"finding_id": "daf_a", "status": "valid"}),
                    ("triage_finding", {"finding_id": "daf_a", "status": "duplicate", "duplicate_of": "daf_other"}),
                    ("triage_finding", {"finding_id": "daf_a", "status": "duplicate", "duplicate_of": "daf_a"})]
        for name, args in attempts:
            result, finished = self.engine._tool(client, name, args)
            self.assertFalse(result["ok"])
            self.assertFalse(finished)
        self.assertEqual(client.posts, [])

    def test_duplicate_verdict_requires_receipt_and_retains_match_metadata(self):
        args = {"finding_id": "daf_b", "status": "duplicate", "duplicate_of": "daf_a", "priority": "defer",
                "rationale": "Same endpoint, parameter and matching proof as canonical finding.",
                "duplicate_evidence_match": "Same endpoint and affected parameter with the same evidence."}
        result, _ = self.engine._tool(Client({"status": "ok"}), "triage_finding", args)
        self.assertFalse(result["ok"])
        self.assertEqual(self.engine.finding_verdict_updates, {})
        client = Client({"id": "daf_b", "stable_id": "daf_b", "deleted": True})
        result, _ = self.engine._tool(client, "triage_finding", args)
        self.assertIsNot(result.get("ok"), False)
        self.assertEqual(self.engine.finding_verdict_updates["daf_b"]["duplicate_of"], "daf_a")
        self.assertEqual(self.engine.finding_verdict_updates["daf_b"]["duplicate_evidence_match"], args["duplicate_evidence_match"])

    def test_documented_wrapped_receipt_is_accepted_and_wrong_identity_is_rejected(self):
        args = {"finding_id": "daf_b", "status": "duplicate", "duplicate_of": "daf_a",
                "rationale": "Same endpoint and parameter with matching evidence.",
                "duplicate_evidence_match": "Matching endpoint, parameter and root cause."}
        for receipt in [{"id": "daf_a", "deleted": True}, {"id": "daf_b", "deleted": False}, None]:
            result, _ = self.engine._tool(Client({"status": "ok", "finding": receipt}), "triage_finding", args)
            self.assertFalse(result["ok"])
            self.assertEqual(self.engine.finding_verdict_updates, {})
        result, _ = self.engine._tool(Client({"status": "ok", "finding": {"id": "daf_b", "stable_id": "daf_b", "deleted": True}}), "triage_finding", args)
        self.assertIsNot(result.get("ok"), False)
        self.assertEqual(self.engine.finding_verdict_updates["daf_b"]["duplicate_of"], "daf_a")

    def test_blocked_finish_never_posts_completed_review(self):
        client = Client()
        result, finished = self.engine._tool(client, "finish", {"status": "blocked", "summary": "Evidence missing"})
        self.assertTrue(finished)
        self.assertEqual(self.engine.state, "blocked")
        self.assertEqual(self.engine.active_queue, "0")
        self.assertEqual(client.posts, [])

    def test_a_retained_canonical_cannot_be_deleted_later_in_the_review(self):
        self.engine.duplicate_review_ids.append("daf_c")
        self.engine.finding_verdict_updates["daf_b"] = {"duplicate_of": "daf_a", "agent_status": "duplicate"}
        client = Client()
        result, _ = self.engine._tool(client, "triage_finding", {
            "finding_id": "daf_a", "status": "duplicate", "duplicate_of": "daf_c",
            "rationale": "Same endpoint and matching parameter evidence.",
            "duplicate_evidence_match": "Same endpoint and affected parameter evidence."})
        self.assertFalse(result["ok"])
        self.assertEqual(client.posts, [])

    def large_population(self):
        rows = [{'stable_id': 'daf_%02d' % i, 'title': 'Finding %d' % i,
                 'url': 'https://example.test/%d' % i, 'detail': 'saved detail ' * 100,
                 'evidence': 'saved evidence ' * 100} for i in range(20)]
        return dict(detail(), findings=rows, finding_ids=[row['stable_id'] for row in rows],
                    duplicate_review={'finding_count': len(rows)})

    def test_compacted_middle_ids_recover_read_only_and_finish_with_full_population(self):
        self.assertEqual(self.engine._prepare_duplicate_review(self.large_population()), '')
        table = json.dumps(self.engine.duplicate_review_snapshot)
        history = [{'role': 'system', 'content': 'Read and classify only.'},
                   {'role': 'user', 'content': table}]
        for i in range(12):
            history.extend([{'role': 'assistant', 'tool_calls': [{'id': str(i), 'type': 'function',
                            'function': {'name': 'get_linked_finding', 'arguments': '{}'}}]},
                            {'role': 'tool', 'tool_call_id': str(i), 'content': 'old evidence ' * 1000}])
        compacted = compact_model_history(history, {'duplicate_review': self.engine._duplicate_review_context()}, 14000)
        self.assertNotIn('daf_10', json.dumps(compacted))
        self.assertIn('get_duplicate_review_page', json.dumps(compacted))
        client = Client()
        offset, ids = 0, []
        while offset is not None:
            page, finished = self.engine._tool(client, 'get_duplicate_review_page', {'offset': offset})
            self.assertTrue(page['ok'])
            self.assertFalse(finished)
            ids.extend(row['id'] for row in page['findings_to_compare'])
            offset = page['next_offset']
        self.assertEqual(ids, self.engine.duplicate_review_ids)
        self.assertEqual(client.posts, [])
        result, finished = self.engine._tool(client, 'finish', {'status': 'completed', 'summary': 'Compared full saved table', 'reviewed_finding_ids': ids})
        self.assertTrue(result['ok'])
        self.assertTrue(finished)

    def test_restart_keeps_snapshot_and_accepted_deletion_without_repeating_write(self):
        args = {'finding_id': 'daf_b', 'status': 'duplicate', 'duplicate_of': 'daf_a',
                'rationale': 'Same endpoint and affected parameter with matching proof.',
                'duplicate_evidence_match': 'Matching endpoint, parameter and root cause.'}
        self.engine.resume_queue_id = '0'
        self.engine._tool(Client({'finding': {'id': 'daf_b', 'deleted': True}}), 'triage_finding', args)
        restored = Engine(Store(Path(self.directory.name) / 'store.sqlite3'))
        restored.resume_requested = True
        current = dict(detail(), findings=detail()['findings'][:1], linked_findings_resolution={
            'requested_count': 2, 'unresolved_stable_ids': ['daf_b']})
        self.assertEqual(restored._prepare_duplicate_review(current), '')
        client = Client()
        page, _ = restored._tool(client, 'get_duplicate_review_page', {'offset': 0})
        self.assertEqual(page['findings_to_compare'][1]['accepted_verdict']['duplicate_of'], 'daf_a')
        result, _ = restored._tool(client, 'triage_finding', args)
        self.assertFalse(result['ok'])
        self.assertEqual(client.posts, [])
        self.assertEqual(restored.duplicate_review_ids, ['daf_a', 'daf_b'])

    def test_resume_rejects_changed_population_and_unreceipted_missing_rows(self):
        self.engine.resume_requested = True
        for current in [dict(detail(), finding_ids=['daf_a', 'daf_other']),
                        dict(detail(), findings=detail()['findings'][:1])]:
            self.assertTrue(self.engine._prepare_duplicate_review(current))

    def test_recovery_denies_outside_claim_and_invalid_offsets_without_client_calls(self):
        client = Client()
        for offset in [-1, 2, True, '0', None]:
            result, _ = self.engine._tool(client, 'get_duplicate_review_page', {'offset': offset})
            self.assertFalse(result['ok'])
        self.engine.active_queue = 'different'
        result, _ = self.engine._tool(client, 'get_duplicate_review_page', {'offset': 0})
        self.assertFalse(result['ok'])
        self.engine._duplicate_review_active = False
        result, _ = self.engine._tool(client, 'get_duplicate_review_page', {'offset': 0})
        self.assertFalse(result['ok'])
        self.assertEqual(client.posts, [])


if __name__ == "__main__":
    unittest.main()
