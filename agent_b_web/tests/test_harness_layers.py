"""Tests for the six-layer harness additions:

- Layer 1: task contracts (contract.build_contract / render_contract)
- Layer 2: bounded investigation mode + recommend_route teammate tool
- Layer 3+: capability tiers driving autonomy/scaffolding (config)
- Layer 5: independent verifier gate on finding write-back
- Layer 6: durable run traces + lessons store

These exercise the deterministic, offline units only — no live model or
Double Agent traffic — so they run in the sandbox without network or sockets.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.config import (
    AUTONOMY_LEVELS,
    Config,
    capability_tier,
    effective_autonomy,
)
from agent_b_harness.contract import build_contract, render_contract
from agent_b_harness.engine import Engine, assessment_thinking, finding_validation_result, is_investigation
from agent_b_harness.store import Store


class FakeDoubleAgent:
    def __init__(self):
        self.posts = []

    def post(self, path, body):
        self.posts.append((path, body))
        return {"ok": True, "status": "ok", "path": path}

    def get(self, path):
        return {"ok": True, "path": path}


class CapabilityTierTests(unittest.TestCase):
    def test_bedrock_and_anthropic_are_frontier(self):
        connections = ({
            "id": "hosted-model", "provider": "bedrock", "model": "model-id",
        },)
        self.assertEqual(capability_tier("hosted-model", connections), "frontier")

    def test_cyberstrike_is_capable(self):
        self.assertEqual(capability_tier("cyberstrike", ()), "capable")

    def test_unknown_openai_compatible_local_is_weak(self):
        custom = ({
            "id": "local-qwen", "label": "Local", "provider": "openai_compatible",
            "model": "qwen", "url": "http://127.0.0.1:1234/v1", "api_key": "", "region": "",
        },)
        self.assertEqual(capability_tier("local-qwen", custom), "weak")

    def test_auto_autonomy_follows_tier(self):
        hosted = ({
            "id": "hosted-model", "provider": "anthropic", "model": "model-id",
        },)
        self.assertEqual(effective_autonomy("auto", "hosted-model", hosted), "autonomous")
        self.assertEqual(effective_autonomy("auto", "cyberstrike", ()), "guided")
        self.assertEqual(
            effective_autonomy("auto", "local-qwen", ({
                "id": "local-qwen", "label": "L", "provider": "openai_compatible",
                "model": "q", "url": "http://127.0.0.1:1/v1", "api_key": "", "region": "",
            },)),
            "directed",
        )

    def test_explicit_autonomy_is_respected(self):
        self.assertEqual(effective_autonomy("directed", "bedrock-opus-4-8", ()), "directed")
        self.assertIn("autonomous", AUTONOMY_LEVELS)

    def test_public_exposes_tier_and_autonomy(self):
        value = Config(model="cyberstrike").public()
        self.assertEqual(value["capability_tier"], "capable")
        self.assertEqual(value["effective_autonomy"], "guided")
        self.assertEqual(tuple(value["autonomy_levels"]), AUTONOMY_LEVELS)

    def test_load_normalizes_invalid_autonomy_to_auto(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"autonomy": "turbo"}')
            with patch.object(config, "SETTINGS", path):
                self.assertEqual(config.load().autonomy, "auto")
            path.write_text('{"autonomy": "DIRECTED"}')
            with patch.object(config, "SETTINGS", path):
                self.assertEqual(config.load().autonomy, "directed")


class ContractTests(unittest.TestCase):
    def test_full_app_contract_has_goal_done_and_deliverable(self):
        contract = build_contract("full_app", {"id": 42}, model="cyberstrike", autonomy="guided")
        self.assertEqual(contract["task_id"], "42")
        self.assertEqual(contract["kind"], "full_app")
        self.assertTrue(contract["goal"])
        self.assertTrue(contract["done_when"])
        self.assertTrue(contract["deliverable"])
        self.assertTrue(contract["constraints"])

    def test_duplicate_review_contract_sends_no_traffic(self):
        contract = build_contract("duplicate_review")
        joined = " ".join(contract["constraints"]).lower()
        self.assertIn("no target traffic", joined)
        self.assertIn("do not ask to reconfirm", joined)
        self.assertIn("uncertain findings visible", joined)
        self.assertNotIn("related but distinct", " ".join(contract["escalate_when"]))

    def test_investigation_contract_uses_subject(self):
        contract = build_contract("investigation", {"subject": "IDOR on /api/orders"}, autonomy="guided")
        self.assertIn("IDOR on /api/orders", contract["goal"])
        self.assertIn("recommend_route", " ".join(contract["done_when"]))

    def test_generated_task_id_is_stable_prefix(self):
        contract = build_contract("try_harder")
        self.assertTrue(contract["task_id"].startswith("try_harder-"))

    def test_render_is_empty_without_goal(self):
        self.assertEqual(render_contract({}), "")
        self.assertEqual(render_contract({"kind": "x"}), "")

    def test_render_contains_labels(self):
        text = render_contract(build_contract("full_app"))
        self.assertIn("TASK CONTRACT", text)
        self.assertIn("done_when", text)
        self.assertIn("escalate_when", text)

    def test_single_finding_auto_thinking_is_brief_without_overriding_operator(self):
        self.assertIs(assessment_thinking(None, True, "finding_validation", 1), False)
        self.assertIsNone(assessment_thinking(None, True, "finding_validation", 2))
        self.assertIsNone(assessment_thinking(None, True, "full_app", 1))
        self.assertIsNone(assessment_thinking(None, False, "finding_validation", 1))
        self.assertIs(assessment_thinking(True, True, "finding_validation", 1), True)
        self.assertIs(assessment_thinking(False, True, "finding_validation", 1), False)

    def test_large_finding_and_verdict_keep_decisive_fields_visible(self):
        finding = {"id": "daf_example", "legacy_numeric_id": 15, "title": "Example",
                   "url": "https://app.test/login", "request_data_preview": "GET /login HTTP/1.1",
                   "response_data_preview": "x" * 4000, "active_test_recipe": {"baseline_request": "y" * 6000}}
        view = finding_validation_result("get_linked_finding", finding, {})
        self.assertEqual(view["request_data_preview"], "GET /login HTTP/1.1")
        self.assertEqual(view["legacy_numeric_id"], 15)
        self.assertNotIn("active_test_recipe", view)
        self.assertLess(len(json.dumps(view)), 9000)
        update = {"15": {"agent_status": "needs_investigation"}}
        verdict = finding_validation_result("triage_finding", {"finding": {"response_data": "z" * 12000}}, update, "15")
        self.assertEqual(verdict["status"], "needs_investigation")
        self.assertTrue(verdict["accepted"])


class InvestigationDetectionTests(unittest.TestCase):
    def test_investigation_prefixes_match(self):
        self.assertTrue(is_investigation("investigate the login flow"))
        self.assertTrue(is_investigation("Look into finding #12"))

    def test_plain_chat_is_not_investigation(self):
        self.assertFalse(is_investigation("hello"))
        self.assertFalse(is_investigation("what does this parameter do?"))


class TraceAndLessonStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "store.sqlite3")

    def tearDown(self):
        self.directory.cleanup()

    def test_saved_validation_verdict_is_not_written_twice(self):
        engine = Engine(self.store)
        engine.contract = {"kind": "finding_validation"}
        engine.finding_verdict_updates = {"15": {"agent_status": "needs_investigation"}}
        client = FakeDoubleAgent()
        result, finished = engine._tool(client, "triage_finding", {
            "finding_id": "15", "status": "needs_investigation", "rationale": "A different rationale long enough to write"})
        self.assertTrue(result["already_recorded"])
        self.assertFalse(finished)
        self.assertEqual(client.posts, [])

    def test_transport_failure_limit_blocks_more_validation_traffic(self):
        engine = Engine(self.store)
        engine.contract = {"kind": "finding_validation"}
        engine.linked_finding_total = 1
        engine.active_queue = "0"
        class Client(FakeDoubleAgent):
            def post(self, path, body):
                self.posts.append((path, body))
                return {"status_code": 400, "url": "https://app.test/login", "headers": [], "body": "Bad Request"}
        client = Client()
        arguments = {"path": "/api/agent/request", "body": {
            "host": "app.test", "port": 443, "https": True,
            "request": "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n"}}
        for attempt in range(3):
            result, finished = engine._tool(client, "double_agent_post", arguments)
            self.assertEqual(result["status_code"], 400)
            self.assertEqual(engine.validation_bad_transport_attempts, attempt + 1)
        result, finished = engine._tool(client, "double_agent_post", arguments)
        self.assertFalse(result["ok"])
        self.assertIn("needs_investigation", result["directive"])
        self.assertFalse(finished)
        self.assertEqual(len(client.posts), 3)

    def test_trace_roundtrips_and_redacts(self):
        run_id = self.store.save_trace({
            "run_id": "run-1", "mode": "full_app",
            "contract": {"constraints": ["Authorization: Bearer sk-secret-token-value"]},
        })
        self.assertEqual(run_id, "run-1")
        traces = self.store.traces()
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]["run_id"], "run-1")
        self.assertNotIn("sk-secret-token-value", str(traces[0]))

    def test_lessons_dedupe_and_rank_by_hits(self):
        self.store.add_lesson("scope", "Always check scope before probing")
        self.store.add_lesson("scope", "Always check scope before probing")
        self.store.add_lesson("evidence", "Capture a negative control")
        lessons = self.store.lessons()
        self.assertEqual(lessons[0]["summary"], "Always check scope before probing")
        self.assertEqual(lessons[0]["hits"], 2)
        self.assertEqual(len(lessons), 2)

    def test_traces_and_lessons_survive_clear(self):
        self.store.save_trace({"run_id": "keep-me"})
        self.store.add_lesson("x", "durable lesson")
        self.store.clear()
        self.assertEqual(len(self.store.traces()), 1)
        self.assertEqual(len(self.store.lessons()), 1)


class LessonPromptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.directory.name) / "store.sqlite3"))

    def tearDown(self):
        self.directory.cleanup()

    def test_empty_when_no_lessons(self):
        self.assertEqual(self.engine._lesson_prompt(), "")

    def test_renders_ranked_lessons(self):
        self.engine.store.add_lesson("scope", "Check scope first", "detail here")
        block = self.engine._lesson_prompt()
        self.assertIn("LESSONS", block)
        self.assertIn("Check scope first", block)
        self.assertIn("[scope x1]", block)


class IndependentVerifierTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.directory.name) / "store.sqlite3"))
        self.engine.target_url = "https://example.test/"
        self.engine.run_id = "fixture-run"
        self.engine.active_queue = "12"
        self.claim = {"poc_request": "GET /?id=2 HTTP/1.1\r\nHost: example.test\r\n\r\n"}
        for value in ("1", "2", "1"):
            self.engine._capture_hypothesis_evidence(
                f"GET /?id={value} HTTP/1.1\r\nHost: example.test\r\n\r\n",
                {"status_code": 200, "url": "https://example.test/", "body": "fixture response"}, "test fixture")
        self.evidence_ids = [e["id"] for e in self.engine._hypothesis_registry().get(self.engine.active_hypothesis_id)["observations"]]

    def tearDown(self):
        self.directory.cleanup()

    def _patch_reviewer(self, content):
        try:
            reply = json.loads(content)
            if content in ('{"accept": true, "reason": "evidence is solid"}', '{"accept": false, "reason": "no control"}'):
                reply.update(evidence_ids=self.evidence_ids, alternative_explanation="A benign response difference was considered")
                content = json.dumps(reply)
        except (ValueError, TypeError):
            pass
        class FakeModel:
            def __init__(self, *a, **k):
                self.thinking = None

            def complete(self, messages, tools, on_delta=None, tool_choice="auto"):
                return {"role": "assistant", "content": content}

        return patch("agent_b_harness.engine.Model", FakeModel)

    def test_accepts_when_verifier_says_accept(self):
        with self._patch_reviewer('{"accept": true, "reason": "evidence is solid"}'):
            result = self.engine._independent_verifier("SQLi on id", self.claim, reference="finding:12")
        self.assertTrue(result["accept"])
        self.assertTrue(result["verified"])
        self.assertIn("finding:12", self.engine.verifier_reviews)

    def test_rejects_when_verifier_says_reject(self):
        with self._patch_reviewer('{"accept": false, "reason": "no control"}'):
            result = self.engine._independent_verifier("weak claim", self.claim, reference="finding:9")
        self.assertFalse(result["accept"])
        self.assertEqual(self.engine.verifier_reviews["finding:9"]["reason"], "no control")

    def test_fails_closed_on_unparseable_reply(self):
        with self._patch_reviewer("I cannot produce JSON"):
            result = self.engine._independent_verifier("x", self.claim, reference="finding:1")
        self.assertFalse(result["accept"])
        self.assertFalse(result["verified"])

    def test_fails_closed_on_model_error(self):
        class BoomModel:
            def __init__(self, *a, **k):
                self.thinking = None

            def complete(self, *a, **k):
                raise RuntimeError("sensitive provider response must not be persisted")

        with patch("agent_b_harness.engine.Model", BoomModel):
            result = self.engine._independent_verifier("x", self.claim, reference="finding:2")
        self.assertFalse(result["accept"])
        self.assertFalse(result["verified"])
        self.assertNotIn("sensitive provider", str(self.engine.store.events()))

    def test_rejects_malformed_schemas_and_wrapped_json(self):
        replies = [
            '{"accept": "false", "reason": "x"}',
            '{"accept": "true", "reason": "x"}',
            '{"accept": 1, "reason": "x"}',
            '{"accept": null, "reason": "x"}',
            '{"accept": true}', '{"accept": true, "reason": []}',
            '{"accept": true, "reason": " "}',
            '{"accept": false, "accept": true, "reason": "x"}',
            '```json\n{"accept": true, "reason": "x"}\n```',
            'refusal {"accept": true, "reason": "x"}',
            '[]', '',
        ]
        for reply in replies:
            with self.subTest(reply=reply), self._patch_reviewer(reply):
                result = self.engine._independent_verifier("claim", self.claim)
                self.assertFalse(result["accept"])
                self.assertFalse(result["verified"])

    def test_unknown_or_rejected_review_stops_writes_and_preserves_evidence(self):
        for reply in ('invalid', '{"accept": false, "reason": "insufficient evidence"}'):
            for tool, args in (
                ("record_finding", {"title": "fixture", "evidence": "retained evidence"}),
                ("triage_finding", {"finding_id": "12", "status": "valid",
                                    "rationale": "A benign test fixture rationale.",
                                    "poc_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}),
            ):
                with self.subTest(reply=reply, tool=tool), self._patch_reviewer(reply):
                    client = FakeDoubleAgent()
                    result, finished = self.engine._tool(client, tool, args)
                    self.assertFalse(result["ok"])
                    self.assertTrue(finished)
                    self.assertEqual(self.engine.state, "blocked")
                    self.assertEqual(client.posts, [])
                    events = self.engine.store.events()
                    expected_claim = args if tool == "record_finding" else {
                        "finding_id": "12", "rationale": args["rationale"],
                        "poc_request": args["poc_request"], "priority": "P2",
                    }
                    self.assertTrue(any(e["kind"].startswith("verifier_")
                                        and e["data"].get("claim") == expected_claim for e in events))

    def test_stop_during_review_cannot_accept(self):
        engine = self.engine

        class CancelModel:
            def __init__(self, *a, **k):
                pass

            def complete(self, *a, **k):
                self.active_at_review = engine.active_model is self
                engine.stop_event.set()
                return {"content": json.dumps({"accept": True, "reason": "ok", "evidence_ids": [e["id"] for e in engine._hypothesis_registry().get(engine.active_hypothesis_id)["observations"]], "alternative_explanation": "Benign alternative was considered"})}

        with patch("agent_b_harness.engine.Model", CancelModel):
            result = engine._independent_verifier("fixture", self.claim)
        self.assertFalse(result["accept"])
        self.assertFalse(result["verified"])
        self.assertIsNone(engine.active_model)


if __name__ == "__main__":
    unittest.main()
