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
from agent_b_harness.engine import Engine, is_investigation
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

    def tearDown(self):
        self.directory.cleanup()

    def _patch_reviewer(self, content):
        class FakeModel:
            def __init__(self, *a, **k):
                self.thinking = None

            def complete(self, messages, tools, on_delta=None, tool_choice="auto"):
                return {"role": "assistant", "content": content}

        return patch("agent_b_harness.engine.Model", FakeModel)

    def test_accepts_when_verifier_says_accept(self):
        with self._patch_reviewer('{"accept": true, "reason": "evidence is solid"}'):
            result = self.engine._independent_verifier("SQLi on id", {"poc": "..."}, reference="finding:12")
        self.assertTrue(result["accept"])
        self.assertTrue(result["verified"])
        self.assertIn("finding:12", self.engine.verifier_reviews)

    def test_rejects_when_verifier_says_reject(self):
        with self._patch_reviewer('{"accept": false, "reason": "no control"}'):
            result = self.engine._independent_verifier("weak claim", {"poc": "..."}, reference="finding:9")
        self.assertFalse(result["accept"])
        self.assertEqual(self.engine.verifier_reviews["finding:9"]["reason"], "no control")

    def test_fails_open_on_unparseable_reply(self):
        with self._patch_reviewer("I cannot produce JSON"):
            result = self.engine._independent_verifier("x", {"poc": "..."}, reference="finding:1")
        self.assertTrue(result["accept"])
        self.assertFalse(result["verified"])

    def test_fails_open_on_model_error(self):
        class BoomModel:
            def __init__(self, *a, **k):
                self.thinking = None

            def complete(self, *a, **k):
                raise RuntimeError("network down")

        with patch("agent_b_harness.engine.Model", BoomModel):
            result = self.engine._independent_verifier("x", {"poc": "..."}, reference="finding:2")
        self.assertTrue(result["accept"])
        self.assertFalse(result["verified"])


if __name__ == "__main__":
    unittest.main()
