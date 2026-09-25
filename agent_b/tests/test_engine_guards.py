import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from agent_b_harness.engine import (
    ASSESSMENT_FAMILIES,
    CHAT_SYSTEM,
    Engine,
    apply_latest_auth_headers,
    assessment_phase_request,
    authentication_failed,
    build_full_assessment_plan,
    compact_model_history,
    corrective_assessment_mutation,
    deterministic_track_review,
    discovery_candidate_url,
    assessment_phase_evidence,
    assessment_risk_hunt_goals,
    findings_target_url,
    full_assessment_step_limit,
    model_history_limit,
    payload_target_url,
    passive_candidate_tracks,
    select_queue_item,
    upstream_origin_unavailable,
    without_browseros,
    workspace_target_url,
)
from agent_b_harness.config import Config
from agent_b_harness.discovery import extract_application_surface
from agent_b_harness.store import Store


class FakeDoubleAgent:
    def __init__(self):
        self.posts = []

    def post(self, path, body):
        self.posts.append((path, body))
        if path == "/api/agent/request":
            return {"status_code": 200, "url": "https://example.test/", "body": "ok"}
        return {"status": "ok"}

    def get(self, path):
        return {"status": "ok", "path": path}


class AssessmentPhaseHelpersTests(unittest.TestCase):
    def test_passive_candidates_are_prioritized_filtered_and_bounded(self):
        queue = {
            "id": 7,
            "passive_finding_stable_ids": ["daf_high", "daf_noise", "daf_low"],
        }
        findings = {"findings": [
            {
                "stable_id": "daf_low", "title": "Cookie flag", "url": "https://example.test/",
                "severity": "Low", "confidence": "Firm", "source": "eternals_passive",
                "agent_status": "needs_investigation", "agent_validated_by": "A",
                "agent_candidate_type": "theory_only",
            },
            {
                "stable_id": "daf_noise", "title": "Static chunk metadata", "url": "https://example.test/a.js",
                "severity": "Information", "confidence": "Tentative", "source": "eternals_passive",
                "agent_status": "false_positive", "agent_validated_by": "A",
                "agent_candidate_type": "scanner_noise",
            },
            {
                "stable_id": "daf_high", "title": "Possible IDOR", "url": "https://example.test/api/account/7",
                "severity": "High", "confidence": "Firm", "source": "eternals_passive",
                "agent_status": "needs_investigation", "agent_validated_by": "A",
                "agent_candidate_type": "reportable_candidate",
                "request_data_preview": "GET /api/account/7 HTTP/1.1\r\nHost: example.test\r\n\r\n",
                "active_test_recipe": {"active_test_type": "idor", "mutation_hint": "Replace the object id."},
            },
        ]}

        result = passive_candidate_tracks(queue, findings, limit=1)

        self.assertEqual(result["scheduled_count"], 1)
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["deferred_count"], 1)
        self.assertEqual(result["ignored_noise_count"], 1)
        self.assertEqual(result["tracks"][0]["candidate_finding_ids"], ["daf_high"])
        self.assertEqual(result["tracks"][0]["family"], "authorization_objects")
        self.assertEqual(result["tracks"][0]["route"], "GET example.test /api/account/7")

    def test_passive_candidates_require_linkage_and_skip_existing_tracks(self):
        queue = {"id": 7, "passive_finding_stable_ids": ["daf_linked", "daf_existing"]}
        findings = {"findings": [
            {"stable_id": "daf_linked", "title": "Potential XSS", "url": "https://example.test/search",
             "agent_status": "untouched", "agent_validated_by": "A", "active_test_recipe": {"active_test_type": "xss"}},
            {"stable_id": "daf_existing", "title": "Potential CORS", "url": "https://example.test/api",
             "agent_status": "untouched", "agent_validated_by": "A"},
            {"stable_id": "daf_unlinked", "title": "Other", "url": "https://elsewhere.test/",
             "agent_status": "untouched", "agent_validated_by": "A"},
        ]}

        result = passive_candidate_tracks(queue, findings, existing_finding_ids=["daf_existing"])

        self.assertEqual([item["id"] for item in result["tracks"]], ["passive::daf_linked"])

    def test_discovery_skips_decorative_assets_but_keeps_scripts_and_routes(self):
        self.assertFalse(discovery_candidate_url("https://example.test/favicon.svg"))
        self.assertFalse(discovery_candidate_url("https://example.test/assets/app.css?v=1"))
        self.assertTrue(discovery_candidate_url("https://example.test/assets/app.js"))
        self.assertTrue(discovery_candidate_url("https://example.test/api/account"))

    def test_sql_phase_requests_are_distinct_and_family_specific(self):
        definition = {
            "id": "sql_nosql_injection::GET example.test /search",
            "family": "sql_nosql_injection",
            "route": "GET example.test /search",
            "url": "https://example.test/search?q=seed",
            "inputs": [{"name": "q", "type": "query"}],
        }

        baseline = assessment_phase_request(definition, "baseline")
        mutation = assessment_phase_request(definition, "focused_mutation")
        control = assessment_phase_request(definition, "negative_control")

        self.assertEqual(baseline["url"], "https://example.test/search?q=seed")
        self.assertIn("q=%27+OR+%271%27%3D%271%27--", mutation["url"])
        self.assertIn("agent_b_phase=mutation", mutation["url"])
        self.assertIn("q=agent_b_control_text", control["url"])
        self.assertIn("agent_b_phase=control", control["url"])
        self.assertEqual(len({baseline["url"], mutation["url"], control["url"]}), 3)

    def test_cors_phase_requests_use_untrusted_and_same_origin_controls(self):
        definition = {
            "id": "csrf_cors_browser::GET example.test /api/session",
            "family": "csrf_cors_browser",
            "route": "GET example.test /api/session",
            "url": "https://example.test/api/session",
        }

        mutation = assessment_phase_request(definition, "focused_mutation")
        control = assessment_phase_request(definition, "negative_control")

        self.assertEqual(mutation["headers"]["Origin"], "https://agent-b.invalid")
        self.assertEqual(control["headers"]["Origin"], "https://example.test")
        self.assertNotEqual(mutation["url"], control["url"])

    def test_corrective_cache_mutation_is_distinct_and_targeted(self):
        value = corrective_assessment_mutation({
            "id": "cache_host_protocol::GET example.test /",
            "family": "cache_host_protocol",
            "route": "GET example.test /",
            "url": "https://example.test/",
        })
        self.assertEqual(value["method"], "GET")
        self.assertIn("agent_b_probe=cache_host_protocol", value["url"])
        self.assertEqual(value["headers"]["X-Forwarded-Host"], "agent-b.invalid")

    def test_phase_evidence_uses_the_distinct_request_as_mutation(self):
        baseline = {"request": "GET / HTTP/1.1", "status_code": 200}
        repeated = {"request": "GET / HTTP/1.1", "status_code": 200}
        mutation = {"request": "GET /?probe=1 HTTP/1.1", "status_code": 200}
        selected = assessment_phase_evidence([baseline, repeated, mutation])
        self.assertIs(selected[0], baseline)
        self.assertIs(selected[1], mutation)
        self.assertIs(selected[2], repeated)

    def test_completed_assessment_tracks_become_result_goals(self):
        plan = {
            "attack_families": [
                {"id": "authorization_objects", "title": "Authorization", "reason": "Observed account API."},
                {"id": "csrf_cors_browser", "title": "CSRF and CORS", "reason": "Observed browser session."},
                {"id": "cache_host_protocol", "title": "Cache and Host", "reason": "Observed HTTP traffic."},
                {"id": "rate_limits_abuse", "title": "Rate Limits", "reason": "Observed login flow."},
            ]
        }
        progress = {
            "authz": {"family": "authorization_objects", "route": "GET example.test /api/account", "status": "tested", "note": "Control enforced access."},
            "cors": {"family": "csrf_cors_browser", "route": "GET example.test /api/session", "status": "tested", "note": "Origin mutation was compared."},
            "cache": {"family": "cache_host_protocol", "route": "GET example.test /", "status": "blocked", "note": "No cache fixture was exposed."},
            "rate": {"family": "rate_limits_abuse", "route": "POST example.test /login", "status": "tested", "note": "Bounded attempts were enforced."},
        }

        goals = assessment_risk_hunt_goals(plan, progress)

        self.assertEqual(len(goals), 4)
        self.assertEqual({goal["id"] for goal in goals}, {
            "harness-authorization_objects", "harness-csrf_cors_browser",
            "harness-cache_host_protocol", "harness-rate_limits_abuse",
        })
        cache_goal = next(goal for goal in goals if goal["id"] == "harness-cache_host_protocol")
        self.assertEqual(cache_goal["status"], "gated")
        self.assertIn("No cache fixture", cache_goal["blocker"])


class EngineGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.directory.name) / "store.sqlite3"))
        self.engine.queue_fetch_mode = True
        self.client = FakeDoubleAgent()

    def tearDown(self):
        self.directory.cleanup()

    def test_phase_controller_stops_after_rejected_final_write_back(self):
        rejected = {
            "ok": False,
            "error": "HTTP 409",
            "response": {"message": "Analyze Burp Traffic must be enabled."},
        }

        self.assertFalse(self.engine._stop_after_controller_rejection("refresh_assessment_state", True, rejected))
        self.assertFalse(self.engine._stop_after_controller_rejection("submit_active_queue_result", False, rejected))
        self.assertTrue(self.engine._stop_after_controller_rejection("submit_active_queue_result", True, rejected))
        self.assertEqual(self.engine.state, "blocked")
        self.assertIn("Analyze Burp Traffic", self.engine.store.messages(1)[0]["content"])

    def test_stop_enters_waiting_state_and_cancels_active_model(self):
        class ActiveModel:
            cancelled = False

            def cancel(self):
                self.cancelled = True

        model = ActiveModel()
        self.engine.state = "running"
        self.engine.active_model = model

        self.engine.stop()

        self.assertTrue(self.engine.stop_event.is_set())
        self.assertTrue(model.cancelled)
        self.assertEqual(self.engine.state, "stopping")
        self.assertEqual(self.engine.store.events(0, 20)[-1]["data"]["status"], "stopping")

    def test_explicit_bootstrap_loads_latest_burp_context(self):
        class BootstrapClient:
            def __init__(self, _url):
                pass

            def get(self, path):
                if path == "/api/agent/prompt":
                    return {"prompt": "Current Agent B prompt. " + ("testing context " * 12), "browseros_enabled": False}
                if path == "/api/agent/burp/workspace?compact=true":
                    return {"target": {"url": "https://example.test/"}}
                return {"findings": []}

        self.engine.store.message("user", "old conversation")
        with patch("agent_b_harness.engine.DoubleAgent", BootstrapClient):
            self.engine.connect_burp()

        messages = self.engine.store.messages(20)
        self.assertEqual(len(messages), 2)
        self.assertIn("testing context", messages[-1]["content"])
        self.assertTrue(self.engine.burp_prompt_loaded)
        self.assertEqual(self.engine.context[1]["role"], "user")
        self.assertIn("Current Agent B prompt", self.engine.context[1]["content"])

    def test_explicit_bootstrap_preserves_old_chat_when_fetch_fails(self):
        class FailedBootstrapClient:
            def __init__(self, _url):
                pass

            def get(self, _path):
                raise ValueError("Burp is unavailable")

        self.engine.store.message("user", "keep this conversation")
        with patch("agent_b_harness.engine.DoubleAgent", FailedBootstrapClient):
            with self.assertRaisesRegex(ValueError, "Burp is unavailable"):
                self.engine.connect_burp()

        messages = self.engine.store.messages(20)
        self.assertEqual(messages[0]["content"], "keep this conversation")

    def test_new_conversation_needs_no_burp(self):
        self.engine.burp_prompt_loaded = True
        self.engine.target_url = "https://example.test"
        with patch("agent_b_harness.engine.DoubleAgent", side_effect=AssertionError("No Burp call expected")):
            self.engine.clear()
        self.assertFalse(self.engine.burp_prompt_loaded)
        self.assertFalse(self.engine.queue_fetch_mode)
        self.assertIsNone(self.engine.active_queue)
        self.assertEqual(self.engine.target_url, "")
        self.assertEqual(self.engine.context, [{"role": "system", "content": CHAT_SYSTEM}])

    def test_regular_chat_has_no_assessment_tools_or_context(self):
        self.engine.clear()
        with patch("agent_b_harness.engine.Model") as model, patch("agent_b_harness.engine.DoubleAgent", side_effect=AssertionError("No Burp call expected")):
            model.return_value.complete.return_value = {"content": "Hello!"}
            self.engine._run("Hello")
            args = model.return_value.complete.call_args.args
            self.assertEqual(args[1], [])
            self.assertEqual(args[3], "none")
            self.assertEqual(args[0][0]["content"], CHAT_SYSTEM)
        self.assertEqual(self.engine.state, "completed")
        self.assertEqual(self.engine.context[-1]["content"], "Hello!")

    def test_full_assessment_keeps_tool_schema_stable_across_phase_change(self):
        captured_tools = []
        engine = self.engine

        class RecordingModel:
            calls = 0

            def __init__(self, *_args, **_kwargs):
                pass

            def complete(self, _messages, tools, _on_delta, _tool_choice):
                captured_tools.append(json.loads(json.dumps(tools, sort_keys=True)))
                self.calls += 1
                name = "run_application_discovery" if self.calls == 1 else "next_assessment_test"
                return {
                    "content": "",
                    "tool_calls": [{
                        "id": f"call-{self.calls}",
                        "type": "function",
                        "function": {"name": name, "arguments": "{}"},
                    }],
                }

        def execute_phase(_client, name, _args):
            if name == "run_application_discovery":
                engine.assessment_discovery["plan_finalized"] = True
                return {"ok": True, "plan_finalized": True}, False
            self.assertEqual(name, "next_assessment_test")
            return {"ok": True}, True

        self.engine.burp_prompt_loaded = True
        self.engine.active_queue = "7"
        self.engine.assessment_plan = {
            "planned_tests": [{"id": "track-1", "family": "authorization_objects"}],
        }
        self.engine.assessment_discovery = {"plan_finalized": False}
        self.engine.assessment_test_progress = {
            "track-1": {"test_id": "track-1", "status": "pending"},
        }
        detail = {"id": 7, "campaign_type": "full_app_assessment", "mode": "full_app_assessment"}
        cfg = Config(model="custom-qwen3-8-27b-splash-abliterated", max_steps=4)

        with (
            patch("agent_b_harness.engine.config.load", return_value=cfg),
            patch("agent_b_harness.engine.config.resolve_model_connection", return_value={
                "base_url": "http://127.0.0.1:8000/v1",
                "api_key": "key",
                "model": "audreyt/Qwen3.8-27B-Splash-abliterated",
                "provider": "openai_compatible",
            }),
            patch("agent_b_harness.engine.Model", RecordingModel),
            patch("agent_b_harness.engine.DoubleAgent", return_value=self.client),
            patch.object(self.engine, "_bootstrap_queue", return_value=detail),
            patch.object(self.engine, "_heartbeat", return_value=None),
            patch.object(self.engine, "_tool", side_effect=execute_phase),
        ):
            self.engine._run("Fetch Burp queue")

        self.assertEqual(len(captured_tools), 2)
        self.assertGreater(len(captured_tools[0]), 3)
        self.assertEqual(captured_tools[0], captured_tools[1])

    def test_reconcile_passive_candidates_adds_late_tracks_and_persists_snapshot(self):
        class PassiveClient(FakeDoubleAgent):
            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {"id": 7, "passive_finding_stable_ids": ["daf_passive"]}
                if path.startswith("/api/findings?"):
                    return {"findings": [{
                        "stable_id": "daf_passive", "title": "Potential IDOR",
                        "url": "https://example.test/api/account/7", "severity": "High", "confidence": "Firm",
                        "source": "eternals_passive", "agent_status": "needs_investigation",
                        "agent_validated_by": "A", "agent_candidate_type": "reportable_candidate",
                        "active_test_recipe": {"active_test_type": "idor", "mutation_hint": "Change the account id."},
                    }]}
                return super().get(path)

        client = PassiveClient()
        self.engine.active_queue = "7"
        self.engine.step = 130
        self.engine.run_step_limit = 144
        self.engine.assessment_plan = {"version": 3, "planned_tests": []}
        self.engine.assessment_discovery = {"plan_finalized": True}
        self.engine.assessment_test_progress = {}

        result, finished = self.engine._tool(client, "reconcile_passive_candidates", {})

        self.assertFalse(finished)
        self.assertTrue(result["ok"])
        self.assertEqual(result["scheduled_count"], 1)
        self.assertIn("passive::daf_passive", self.engine.assessment_test_progress)
        self.assertTrue(self.engine.passive_candidates_reconciled)
        self.assertGreater(self.engine.run_step_limit, 144)
        self.assertIn("/api/agent/knowledge", [path for path, _ in client.posts])
        restored = Engine(self.engine.store)
        self.assertTrue(restored.passive_candidates_reconciled)
        self.assertIn("passive::daf_passive", restored.assessment_test_progress)

    def test_run_checkpoint_restores_assessment_progress_without_secrets(self):
        self.engine.step = 37
        self.engine.state = "running"
        self.engine.active_queue = "9"
        self.engine.resume_queue_id = "9"
        self.engine.target_url = "https://example.test/"
        self.engine.target_evidence = [{
            "request": "GET / HTTP/1.1\r\nCookie: session=secret\r\n\r\n",
            "cache_key": "variant-a",
        }]
        self.engine.assessment_plan = {"planned_tests": [{"id": "cache-test"}]}
        self.engine.assessment_test_progress = {"cache-test": {"status": "in_progress"}}
        self.engine.active_assessment_test_id = "cache-test"
        self.engine._checkpoint()

        restored = Engine(self.engine.store)

        self.assertEqual(restored.state, "stopped")
        self.assertEqual(restored.step, 37)
        self.assertEqual(restored.resume_queue_id, "9")
        self.assertEqual(restored.active_assessment_test_id, "cache-test")
        self.assertEqual(restored.target_evidence[0]["cache_key"], "variant-a")
        self.assertNotIn("session=secret", json.dumps(restored.target_evidence))

    def test_queue_execution_and_finish_require_real_lifecycle(self):
        result, finished = self.engine._tool(self.client, "double_agent_post", {
            "path": "/api/agent/request",
            "body": {"host": "example.test", "request": "GET / HTTP/1.1\r\n\r\n"},
            "purpose": "baseline",
        })
        self.assertFalse(finished)
        self.assertIn("No queue claim", result["error"])
        self.assertEqual(self.client.posts, [])

        result, finished = self.engine._tool(self.client, "double_agent_post", {
            "path": "/api/agent/queue/7/claim", "body": {}, "purpose": "claim"
        })
        self.assertFalse(finished)
        self.assertEqual(self.engine.active_queue, "7")

        result, finished = self.engine._tool(self.client, "double_agent_post", {
            "path": "/api/agent/queue/7/result",
            "body": {"outcome": "not-vulnerable"},
            "purpose": "premature result",
        })
        self.assertFalse(finished)
        self.assertIn("at least two", result["error"])

        for suffix in ("baseline", "mutation"):
            result, finished = self.engine._tool(self.client, "double_agent_post", {
                "path": "/api/agent/request",
                "body": {"host": "example.test", "request": f"GET /{suffix} HTTP/1.1\r\n\r\n"},
                "purpose": suffix,
            })
            self.assertFalse(finished)

        result, finished = self.engine._tool(self.client, "finish", {
            "status": "completed", "summary": "done"
        })
        self.assertFalse(finished)
        self.assertIn("still claimed", result["error"])

        self.engine._tool(self.client, "double_agent_post", {
            "path": "/api/agent/queue/7/result",
            "body": {"outcome": "inconclusive", "assessment": "Control did not confirm impact."},
            "purpose": "submit result",
        })
        self.assertIsNone(self.engine.active_queue)

        result, finished = self.engine._tool(self.client, "finish", {
            "status": "completed", "summary": "done"
        })
        self.assertTrue(finished)
        self.assertEqual(result["status"], "completed")

    def test_queue_selection_resumes_claimed_before_pending(self):
        selected = select_queue_item({"queue": [
            {"id": 2, "status": "pending"},
            {"id": 7, "status": "claimed"},
        ]})
        self.assertEqual(selected["id"], 7)

    def test_bootstrap_claims_and_returns_concrete_detail(self):
        class QueueClient:
            def __init__(self):
                self.claimed = False

            def get(self, path):
                if path == "/api/agent/queue":
                    return {"queue": [{"id": 4, "status": "pending", "detail_endpoint": "/api/agent/queue/4"}]}
                if path == "/api/agent/queue/4":
                    return {"id": 4, "status": "claimed" if self.claimed else "pending", "summary": "Concrete test", "next_action": {"instruction": "Run baseline"}}
                raise AssertionError(path)

            def post(self, path, body):
                self.assert_body = body
                if path == "/api/agent/queue/4/claim":
                    self.claimed = True
                    return {"status": "claimed"}
                raise AssertionError(path)

        detail = self.engine._bootstrap_queue(QueueClient())
        self.assertEqual(detail["id"], 4)
        self.assertEqual(detail["status"], "claimed")
        self.assertEqual(self.engine.active_queue, "4")

    def test_bootstrap_resumes_claimed_summary_when_detail_status_is_stale(self):
        class ClaimedClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue":
                    return {"queue": [{"id": 9, "status": "claimed", "detail_endpoint": "/api/agent/queue/9"}]}
                if path == "/api/agent/queue/9":
                    return {"id": 9, "status": "queued", "summary": "Resume campaign"}
                raise AssertionError(path)

            def post(self, path, body):
                self.posts.append((path, body))
                raise AssertionError("A claimed item must not be claimed again")

        client = ClaimedClient()
        detail = self.engine._bootstrap_queue(client)

        self.assertEqual(detail["id"], 9)
        self.assertEqual(self.engine.active_queue, "9")
        self.assertEqual(client.posts, [])

    def test_send_burp_request_builds_scoped_raw_request_and_records_receipt(self):
        self.engine.active_queue = "7"
        result, finished = self.engine._tool(self.client, "send_burp_request", {
            "url": "https://example.test/api/customer?id=2",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "note": "IDOR baseline",
        })
        self.assertFalse(finished)
        self.assertEqual(result["status_code"], 200)
        path, body = self.client.posts[-1]
        self.assertEqual(path, "/api/agent/request")
        self.assertIn("GET /api/customer?id=2 HTTP/1.1", body["request"])
        self.assertEqual(len(self.engine.target_receipts), 1)

    def test_full_app_scheduler_requires_track_and_baseline_mutation_control(self):
        test_id = "authorization_objects::GET example.test /api/users/1"
        definition = {
            "id": test_id, "family": "authorization_objects",
            "route": "GET example.test /api/users/1", "url": "https://example.test/api/users/1",
            "test_sequence": ["baseline", "horizontal object substitution", "negative control"],
        }
        self.engine.active_queue = "7"
        self.engine.assessment_plan = {
            "planned_tests": [definition],
            "attack_families": [{"id": "authorization_objects", "disposition": "planned"}],
        }
        self.engine.assessment_test_progress = {
            test_id: {"test_id": test_id, "family": "authorization_objects", "route": definition["route"],
                      "url": definition["url"], "status": "pending", "receipt_start": 0,
                      "receipt_count": 0, "note": "", "evidence": [], "finding_ids": []},
        }
        self.engine.assessment_discovery = {"plan_finalized": True}

        blocked, finished = self.engine._tool(self.client, "send_burp_request", {
            "url": definition["url"], "method": "GET", "note": "request before assignment",
        })
        self.assertFalse(finished)
        self.assertIn("next_assessment_test", blocked["error"])

        assigned, _ = self.engine._tool(self.client, "next_assessment_test", {})
        self.assertEqual(assigned["assignment"]["id"], test_id)
        for suffix in ("baseline", "mutation"):
            self.engine._tool(self.client, "send_burp_request", {
                "url": definition["url"] + "?phase=" + suffix, "method": "GET", "note": suffix,
            })
        premature, _ = self.engine._tool(self.client, "complete_assessment_test", {
            "test_id": test_id, "status": "tested", "note": "Compared baseline and mutation with controls.",
            "evidence": [{"phase": "baseline"}, {"phase": "mutation"}, {"phase": "control"}],
        })
        self.assertIn("three fresh", premature["error"])

        invalid_na, _ = self.engine._tool(self.client, "complete_assessment_test", {
            "test_id": test_id, "status": "not_applicable",
            "note": "The two responses were inconclusive, so this needs more work.",
            "evidence": [{"phase": "baseline"}, {"phase": "mutation"}],
        })
        self.assertIn("cannot be marked not applicable", invalid_na["error"])

        self.engine._tool(self.client, "send_burp_request", {
            "url": definition["url"] + "?phase=control", "method": "GET", "note": "negative control",
        })
        invented, _ = self.engine._tool(self.client, "complete_assessment_test", {
            "test_id": test_id, "status": "tested", "note": "A vulnerability was confirmed by the mutation and control.",
            "evidence": [{"phase": "baseline"}, {"phase": "mutation"}, {"phase": "control"}],
            "finding_ids": ["invented-finding-id"],
        })
        self.assertIn("not present in Double Agent", invented["error"])
        completed, _ = self.engine._tool(self.client, "complete_assessment_test", {
            "test_id": test_id, "status": "tested", "note": "Compared baseline, mutation, and negative control responses.",
            "evidence": [{"phase": "baseline"}, {"phase": "mutation"}, {"phase": "control"}],
        })
        self.assertTrue(completed["ok"])
        self.assertEqual(completed["progress"]["remaining"], 0)

    def test_full_app_submission_waits_for_all_tracks_and_recovers_snapshot_alias(self):
        test_id = "xss_client_injection::GET example.test /search"
        self.engine.active_queue = "7"
        self.engine.assessment_plan = {"planned_tests": [{"id": test_id}]}
        self.engine.assessment_discovery = {"plan_finalized": True}
        self.engine.assessment_test_progress = {
            test_id: {"test_id": test_id, "status": "pending", "receipt_start": 0,
                      "receipt_count": 0, "note": "", "evidence": [], "finding_ids": []},
        }
        blocked, _ = self.engine._tool(self.client, "submit_active_queue_result", {
            "outcome": "not-vulnerable", "assessment": "Premature close",
        })
        self.assertIn("every planned test track", blocked["error"])
        self.assertEqual(self.client.posts, [])

        aliased, _ = self.engine._tool(self.client, "parameter_coverage_snapshot", {})
        self.assertIn("assessment_tests", aliased)
        self.assertEqual(aliased["assessment_tests"]["remaining"], 1)

    def test_triage_verdict_is_carried_into_final_finding_updates(self):
        self.engine.active_queue = "7"
        triage, finished = self.engine._tool(self.client, "triage_finding", {
            "finding_id": "12",
            "status": "false_positive",
            "priority": "defer",
            "rationale": "Baseline and focused control produced the same non-exploitable response.",
        })

        self.assertFalse(finished)
        self.assertEqual(triage["status"], "ok")
        result, finished = self.engine._tool(self.client, "submit_active_queue_result", {
            "outcome": "gated",
            "assessment": "Every linked finding received an explicit verdict.",
        })

        self.assertTrue(finished)
        self.assertEqual(result["status"], "ok")
        submitted = [body for path, body in self.client.posts if path == "/api/agent/queue/7/result"][0]
        self.assertEqual(submitted["finding_updates"][0]["id"], "12")
        self.assertEqual(submitted["finding_updates"][0]["agent_status"], "false_positive")

    def test_automated_testing_cannot_close_with_unaccounted_linked_findings(self):
        class LinkedClient(FakeDoubleAgent):
            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {"id": 7, "source": "risk_hunt", "mode": "automated_testing", "finding_ids": [0, 1]}
                if path.startswith("/api/findings?"):
                    return {"findings": [
                        {"id": 1, "stable_id": "daf-one", "agent_validated_by": "A", "agent_status": "untouched"},
                        {"id": 2, "stable_id": "daf-two", "agent_validated_by": "A", "agent_status": "untouched"},
                    ]}
                return super().get(path)

        self.engine.active_queue = "7"
        result, finished = self.engine._tool(LinkedClient(), "submit_active_queue_result", {
            "outcome": "gated",
            "assessment": "Premature result.",
            "finding_updates": [{
                "id": "1", "agent_status": "false_positive",
                "agent_rationale": "A complete baseline and control comparison disproved the candidate.",
            }],
        })

        self.assertFalse(finished)
        self.assertIn("1 linked finding", result["error"])
        self.assertEqual(result["missing_finding_ids"], ["2"])

    def test_full_app_submission_autofills_risk_hunt_goals(self):
        families = ["authorization_objects", "csrf_cors_browser", "cache_host_protocol", "rate_limits_abuse"]
        self.engine.active_queue = "7"
        self.engine.assessment_plan = {
            "attack_families": [{"id": family, "title": family} for family in families],
            "planned_tests": [{"id": family + "::GET example.test /", "family": family} for family in families],
        }
        self.engine.assessment_discovery = {"plan_finalized": True}
        self.engine.assessment_test_progress = {
            family: {"test_id": family, "family": family, "route": "GET example.test /", "status": "tested",
                     "note": "Baseline, mutation, and control were compared.", "finding_ids": []}
            for family in families
        }

        result, finished = self.engine._tool(self.client, "submit_active_queue_result", {
            "outcome": "failed", "assessment": "All planned tracks were dispositioned."
        })

        self.assertTrue(finished)
        self.assertEqual(self.engine.state, "completed")
        self.assertEqual(result["status"], "ok")
        submitted = self.client.posts[-1][1]
        self.assertEqual(len(submitted["risk_hunt_goals"]), 4)

    def test_completed_tracks_sync_to_double_agent_campaign_ledger(self):
        class CampaignLedgerClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {
                        "id": 7,
                        "campaign_type": "full_app_assessment",
                        "campaign_options": {"required_stable_passes": 2},
                        "campaign_state": {
                            "surface_snapshots": [{"snapshot": {"routes": 1, "parameters": 1}}],
                            "steps": [
                                {"key": key, "status": "pending"}
                                for key in (
                                    "browser_explore_public", "browser_explore_authenticated",
                                    "extract_client_routes", "surface_diff", "generate_hypotheses",
                                    "reconcile_findings", "security_baseline", "active_testing",
                                )
                            ],
                        },
                    }
                raise AssertionError(path)

            def post(self, path, body):
                self.posts.append((path, body))
                return {"status": "updated"}

        client = CampaignLedgerClient()
        test_id = "authorization_objects::GET example.test /api/account"
        self.engine.active_queue = "7"
        self.engine.browseros_enabled = False
        self.engine.assessment_plan = {
            "route_count": 4,
            "input_count": 2,
            "attack_families": [{"id": "authorization_objects", "title": "Authorization"}],
            "planned_tests": [{"id": test_id, "family": "authorization_objects", "inputs": [{"name": "user", "type": "query"}]}],
        }
        self.engine.assessment_discovery = {"stable_passes": 2, "plan_finalized": True}
        self.engine.assessment_test_progress = {
            test_id: {
                "test_id": test_id, "family": "authorization_objects", "route": "GET example.test /api/account",
                "url": "https://example.test/api/account", "status": "tested",
                "note": "Baseline, object mutation, and expected-deny control were compared.",
                "evidence": [{"phase": "focused mutation", "status_code": 403}, {"phase": "negative control", "status_code": 403}],
                "finding_ids": [],
            }
        }

        self.engine._sync_full_app_campaign_from_assessment(client)

        surface_posts = [body for path, body in client.posts if path == "/api/agent/attack-surface"]
        step_posts = [body for path, body in client.posts if path.endswith("/campaign/step")]
        self.assertEqual(surface_posts[0]["entries"][0]["status"], "tested")
        self.assertIn("authorization_object_scope", surface_posts[0]["entries"][0]["techniques"])
        self.assertIn("active_testing", {body["key"] for body in step_posts})
        public = next(body for body in step_posts if body["key"] == "browser_explore_public")
        self.assertEqual(public["status"], "completed")
        browser = next(body for body in step_posts if body["key"] == "browser_explore_authenticated")
        self.assertEqual(browser["status"], "blocked")
        self.assertGreaterEqual(sum(body["key"] == "surface_diff" for body in step_posts), 1)

    def test_full_app_submit_requires_ai_overwatch_and_review(self):
        class FinalPhaseClient(FakeDoubleAgent):
            def __init__(self, ai_status="pending", review_status="pending"):
                super().__init__()
                self.ai_status = ai_status
                self.review_status = review_status

            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {
                        "id": 7,
                        "campaign_type": "full_app_assessment",
                        "campaign_state": {"steps": [
                            {"key": "browser_explore_public", "status": "completed"},
                            {"key": "browser_explore_authenticated", "status": "blocked"},
                            {"key": "extract_client_routes", "status": "completed"},
                            {"key": "surface_diff", "status": "completed"},
                            {"key": "generate_hypotheses", "status": "completed"},
                            {"key": "reconcile_findings", "status": "completed"},
                            {"key": "security_baseline", "status": "completed"},
                            {"key": "active_testing", "status": "completed"},
                            {"key": "burp_active_scan", "status": "completed"},
                            {"key": "scanner_validation", "status": "completed"},
                            {"key": "ai_coverage_overwatch", "status": self.ai_status},
                            {"key": "overwatch_review", "status": self.review_status},
                        ]},
                    }
                if path.startswith("/api/findings?"):
                    return {"findings": []}
                return {"status": "ok"}

        self.engine.active_queue = "7"
        self.engine.assessment_plan = {"version": 3, "planned_tests": [{"id": "t1", "family": "authorization_objects"}]}
        self.engine.assessment_discovery = {"plan_finalized": True}
        self.engine.assessment_test_progress = {
            "t1": {"test_id": "t1", "status": "tested", "family": "authorization_objects", "route": "GET example.test /", "url": "https://example.test/"}
        }
        self.engine.passive_candidates_reconciled = True

        missing_ai, _ = self.engine._tool(FinalPhaseClient(), "submit_active_queue_result", {
            "outcome": "gated", "assessment": "Manual tracks and scanner are complete."
        })
        self.assertIn("coverage overwatch", missing_ai["error"])
        self.assertIn("coverage_overwatch", missing_ai["directive"])

        missing_review, _ = self.engine._tool(FinalPhaseClient(ai_status="completed"), "submit_active_queue_result", {
            "outcome": "gated", "assessment": "Manual tracks, scanner, and AI overwatch are complete."
        })
        self.assertIn("attack-surface review", missing_review["error"])
        self.assertIn("review_attack_surface", missing_review["directive"])

    def test_procedural_risk_goal_question_is_answered_by_harness(self):
        self.engine.assessment_plan = {
            "attack_families": [{"id": "authorization_objects", "title": "Authorization"}],
        }
        self.engine.assessment_test_progress = {
            "authz": {"family": "authorization_objects", "route": "GET example.test /api/account",
                      "status": "tested", "note": "Compared baseline and control."},
        }

        result, finished = self.engine._tool(self.client, "ask_user", {
            "question": "What is the planned risk hunt goal for this assessment?",
            "reason": "At least one risk hunt goal is required.",
        })

        self.assertFalse(finished)
        self.assertTrue(result["auto_generated"])
        self.assertIsNone(self.engine.store.pending())

    def test_track_cannot_dismiss_deterministic_vulnerability_signal_without_real_finding(self):
        test_id = "ssrf_oob_redirect::GET example.test /continue"
        definition = {"id": test_id, "family": "ssrf_oob_redirect", "route": "GET example.test /continue"}
        self.engine.active_queue = "7"
        self.engine.assessment_plan = {
            "planned_tests": [definition],
            "attack_families": [{"id": "ssrf_oob_redirect", "disposition": "planned"}],
        }
        self.engine.assessment_discovery = {"plan_finalized": True}
        self.engine.assessment_test_progress = {
            test_id: {"test_id": test_id, "family": "ssrf_oob_redirect", "status": "in_progress",
                      "receipt_start": 0, "evidence_start": 0, "receipt_count": 0},
        }
        self.engine.active_assessment_test_id = test_id
        self.engine.target_receipts = [{"ok": True}] * 3
        self.engine.target_evidence = [
            {"request": "GET /continue?next=/ HTTP/1.1", "status_code": 200, "headers": []},
            {"request": "GET /continue?next=https://outside.example/ HTTP/1.1", "status_code": 302,
             "headers": ["Location: https://outside.example/"]},
            {"request": "GET /continue?next=/control HTTP/1.1", "status_code": 200, "headers": []},
        ]
        result, _ = self.engine._tool(self.client, "complete_assessment_test", {
            "test_id": test_id, "status": "tested",
            "note": "The route is safe and the external redirect is not a vulnerability.",
            "evidence": [{"phase": "baseline"}, {"phase": "mutation"}, {"phase": "control"}],
            "finding_ids": [],
        })
        self.assertIn("high-confidence vulnerability signal", result["error"])
        self.assertEqual(result["deterministic_review"]["signal"], "confirmed_open_redirect")
        self.assertEqual(self.engine.active_assessment_test_id, test_id)

    def test_persistent_goal_is_reused_and_completed(self):
        first = self.engine.store.create_goal("Complete Try Harder queue #7", "7")
        second = self.engine.store.create_goal("Complete Try Harder queue #7", "7")
        self.assertEqual(first["id"], second["id"])
        completed = self.engine.store.update_goal("complete")
        self.assertEqual(completed["status"], "complete")
        self.assertIsNone(self.engine.store.active_goal())

    def test_try_harder_campaign_runs_probes_writes_steps_and_completes_goal(self):
        class CampaignClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {"id": 7, "mode": "try_harder"}
                if path == "/api/agent/burp/workspace?compact=true":
                    return {"scope": {"observed_urls": ["https://example.test/"]}}
                if path.startswith("/api/agent/auth/latest?"):
                    return {"recommended_auth": {"raw_header_lines": ["Cookie: session=test"]}}
                if path == "/api/coverage?in_scope_only=true&limit=500":
                    return {"tested": [{"path": "/"}], "untested": [{"path": "/api/account"}]}
                raise AssertionError(path)

            def post(self, path, body):
                self.posts.append((path, body))
                if path == "/api/agent/request":
                    return {"status_code": 200, "body": "application response", "headers": []}
                if path.endswith("/campaign/step"):
                    return {"status": "updated"}
                if path == "/api/agent/queue/7/result":
                    return {"status": "completed", "id": 7, "outcome": "gated", "queue_removed": True}
                raise AssertionError(path)

        client = CampaignClient()
        self.engine.active_queue = "7"
        self.engine.store.create_goal("Complete Try Harder queue #7", "7")

        result, finished = self.engine._run_try_harder_campaign(client)

        self.assertTrue(finished)
        self.assertTrue(result["ok"])
        self.assertIsNone(self.engine.active_queue)
        self.assertIsNone(self.engine.store.active_goal())
        request_posts = [item for item in client.posts if item[0] == "/api/agent/request"]
        step_posts = [item for item in client.posts if item[0].endswith("/campaign/step")]
        result_posts = [item for item in client.posts if item[0] == "/api/agent/queue/7/result"]
        self.assertEqual(len(request_posts), 14)
        self.assertEqual(len(step_posts), 4)
        self.assertEqual(len(result_posts), 1)
        submitted = result_posts[0][1]
        self.assertEqual(submitted["outcome"], "gated")
        self.assertEqual(len(submitted["risk_hunt_goals"]), 6)
        self.assertEqual(len(submitted["evidence"]), 13)
        self.assertTrue(submitted["discovery_blockers"])

    def test_try_harder_campaign_stops_after_confirmed_cloudfront_origin_failure(self):
        class UnavailableClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue/7":
                    return {"id": 7, "mode": "try_harder"}
                if path == "/api/agent/burp/workspace?compact=true":
                    return {"scope": {"observed_urls": ["https://example.test/"]}}
                if path.startswith("/api/agent/auth/latest?"):
                    return {"recommended_auth": {"raw_header_lines": []}}
                raise AssertionError(path)

            def post(self, path, body):
                self.posts.append((path, body))
                if path == "/api/agent/request":
                    return {
                        "status_code": 400,
                        "headers": ["Server: CloudFront", "X-Cache: Error from cloudfront"],
                        "body": "We can't connect to the server for this app or website at this time. Generated by cloudfront.",
                    }
                if path.endswith("/campaign/step"):
                    return {"status": "updated"}
                if path == "/api/agent/queue/7/result":
                    return {"status": "completed", "id": 7, "outcome": "gated", "queue_removed": True}
                raise AssertionError(path)

        client = UnavailableClient()
        self.engine.active_queue = "7"
        self.engine.store.create_goal("Complete Try Harder queue #7", "7")

        edge_failure = {
            "status_code": 400,
            "headers": ["Server: CloudFront", "X-Cache: Error from cloudfront"],
            "body": "We can't connect to the server for this app or website at this time. Generated by cloudfront.",
            "transport": "burp_proxy_curl_http2",
        }
        with patch("agent_b_harness.engine.proxied_curl_request", return_value=edge_failure):
            result, finished = self.engine._run_try_harder_campaign(client)

        self.assertTrue(finished)
        self.assertEqual(result["reason"], "target_origin_unavailable")
        requests = [item for item in client.posts if item[0] == "/api/agent/request"]
        self.assertEqual(len(requests), 1)
        self.assertIn("example.test", self.engine.http2_fallback_hosts)
        submitted = [item[1] for item in client.posts if item[0] == "/api/agent/queue/7/result"][0]
        self.assertEqual(submitted["outcome"], "gated")
        self.assertEqual({goal["status"] for goal in submitted["risk_hunt_goals"]}, {"gated"})
        self.assertIn("No endpoint was marked safe", submitted["notes"][0])

    def test_cloudfront_origin_failure_detection_requires_edge_and_origin_signals(self):
        self.assertTrue(upstream_origin_unavailable({
            "status_code": 400,
            "headers": ["X-Cache: Error from cloudfront"],
            "body": "We can't connect to the server for this app or website at this time.",
        }))
        self.assertFalse(upstream_origin_unavailable({
            "status_code": 400,
            "headers": ["Server: nginx"],
            "body": "Application rejected malformed input",
        }))

    def test_full_assessment_step_limit_scales_with_planned_tracks(self):
        self.assertEqual(full_assessment_step_limit(36, 10), 168)
        self.assertEqual(full_assessment_step_limit(36, 34), 456)

    def test_auth_failure_recognizes_status_and_login_redirect(self):
        self.assertTrue(authentication_failed({"status_code": 401, "headers": []}))
        self.assertTrue(authentication_failed({"status_code": 302, "headers": ["Location: /_gate/login"]}))
        self.assertFalse(authentication_failed({"status_code": 302, "headers": ["Location: /dashboard"]}))

    def test_latest_burp_auth_replaces_stale_session_header(self):
        class AuthClient:
            def get(self, path):
                return {
                    "recommended_auth": {
                        "usable": True,
                        "raw_header_lines": ["Cookie: session=fresh", "Authorization: Bearer current"],
                        "source_history_indices": [42],
                    }
                }

        headers, auth = apply_latest_auth_headers(
            AuthClient(), "example.test",
            {"Cookie": "session=stale", "Accept": "application/json"},
            "/api/account",
        )
        self.assertEqual(headers["Cookie"], "session=fresh")
        self.assertEqual(headers["Authorization"], "Bearer current")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(auth["recommended_auth"]["source_history_indices"], [42])

    def test_auth_rejection_refreshes_from_burp_and_retries_over_http2(self):
        class AuthRetryClient(FakeDoubleAgent):
            def get(self, path):
                if path.startswith("/api/agent/auth/latest?"):
                    return {
                        "recommended_auth": {
                            "usable": True,
                            "raw_header_lines": ["Cookie: session=fresh"],
                            "source_history_indices": [51],
                        }
                    }
                return super().get(path)

            def post(self, path, body):
                self.posts.append((path, body))
                if path == "/api/agent/request":
                    return {"status_code": 401, "url": "https://example.test/private", "body": "unauthorized"}
                return {"status": "ok"}

        self.engine.active_queue = "7"
        client = AuthRetryClient()
        successful = {
            "status_code": 200, "headers": ["Content-Type: application/json"],
            "body": '{"ok":true}', "url": "https://example.test/private",
            "http_version": "2", "transport": "burp_proxy_curl_http2", "executed": True,
        }
        with patch("agent_b_harness.engine.proxied_curl_request", return_value=successful) as retry:
            result, finished = self.engine._tool(client, "send_burp_request", {
                "url": "https://example.test/private", "method": "GET",
                "headers": {"Cookie": "session=stale"}, "note": "authenticated baseline",
            })
            unchanged, _ = self.engine._tool(client, "send_burp_request", {
                "url": "https://example.test/private", "method": "GET",
                "headers": {"Cookie": "session=stale"}, "note": "repeat authenticated baseline",
            })

        self.assertFalse(finished)
        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["auth_refreshed"])
        self.assertEqual(retry.call_args.args[2]["Cookie"], "session=fresh")
        self.assertEqual(len(self.engine.target_receipts), 1)
        self.assertIn("refreshed the latest session", self.engine.model_stream)
        self.assertEqual(retry.call_count, 1)
        self.assertTrue(unchanged["auth_refresh_checked"])
        self.assertIn("unchanged", unchanged["auth_retry_skipped"])

    def test_deterministic_review_recognizes_cross_origin_redirect(self):
        review = deterministic_track_review(
            {"family": "ssrf_oob_redirect", "route": "GET example.test /continue"},
            [{
                "request": "GET /continue?next=https://outside.example/ HTTP/1.1",
                "status_code": 302,
                "headers": ["Location: https://outside.example/"],
            }],
        )
        self.assertEqual(review["signal"], "confirmed_open_redirect")
        self.assertEqual(review["confidence"], "high")

        traversal = deterministic_track_review(
            {"family": "files_paths_uploads", "route": "GET example.test /download"},
            [{"request": "GET /download?file=../../etc/passwd HTTP/1.1", "status_code": 200,
              "response_snippet": "root:x:0:0:root:/root:/bin/bash"}],
        )
        self.assertEqual(traversal["signal"], "confirmed_arbitrary_file_read")

        cors = deterministic_track_review(
            {"family": "csrf_cors_browser", "route": "GET example.test /api/me"},
            [{"request": "GET /api/me HTTP/1.1\r\nOrigin: https://attacker.example\r\n",
              "status_code": 200,
              "headers": ["Access-Control-Allow-Origin: https://attacker.example", "Access-Control-Allow-Credentials: true"]}],
        )
        self.assertEqual(cors["signal"], "confirmed_credentialed_cors_reflection")

    def test_raw_model_stream_is_complete_and_supports_incremental_reads(self):
        content = "x" * 150_000
        self.engine._model_delta({"content": content})

        initial = self.engine.public(0)
        incremental = self.engine.public(100_000)
        invalid_offset = self.engine.public(999_999)

        self.assertEqual(initial["model_stream_length"], 150_012)
        self.assertEqual(len(initial["model_stream"]), 150_012)
        self.assertEqual(incremental["model_stream_offset"], 100_000)
        self.assertEqual(len(incremental["model_stream"]), 50_012)
        self.assertEqual(invalid_offset["model_stream_offset"], 0)
        self.assertEqual(len(invalid_offset["model_stream"]), 150_012)

    def test_model_history_compaction_preserves_complete_tool_pairs(self):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "runtime queue item"},
        ]
        for index in range(10):
            call_id = f"call-{index}"
            messages.extend([
                {"role": "assistant", "content": "", "tool_calls": [{"id": call_id, "function": {"name": "probe", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": call_id, "content": str(index) + ("x" * 4_000)},
            ])

        compacted = compact_model_history(messages, {"discovery": {"passes": 10}}, 18_000)

        self.assertEqual(compacted[0], messages[0])
        self.assertIn("context checkpoint", compacted[2]["content"])
        self.assertLess(len(compacted), len(messages))
        assistant_ids = {
            call["id"]
            for item in compacted if item.get("role") == "assistant"
            for call in item.get("tool_calls", [])
        }
        tool_ids = {item["tool_call_id"] for item in compacted if item.get("role") == "tool"}
        self.assertEqual(assistant_ids, tool_ids)
        self.assertIn("call-9", tool_ids)

    def test_model_history_compaction_bounds_a_single_oversized_latest_result(self):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "queue context" + ("q" * 18_000)},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call-large",
                "type": "function",
                "function": {"name": "refresh_assessment_state", "arguments": "a" * 90_000},
            }], "reasoning_content": "z" * 70_000},
            {"role": "tool", "tool_call_id": "call-large", "content": "r" * 220_000},
        ]

        compacted = compact_model_history(messages, {"active_test": "cache"}, 28_000)

        self.assertLessEqual(sum(len(json.dumps(item, separators=(",", ":"))) for item in compacted), 28_000)
        assistant_ids = {
            call["id"]
            for item in compacted if item.get("role") == "assistant"
            for call in item.get("tool_calls", [])
        }
        tool_ids = {item["tool_call_id"] for item in compacted if item.get("role") == "tool"}
        self.assertEqual(assistant_ids, tool_ids)

    def test_splash_history_limit_does_not_compact_at_eighteen_thousand_tokens(self):
        self.assertEqual(
            model_history_limit(
                "custom-qwen3-8-27b-splash-abliterated",
                "audreyt/Qwen3.8-27B-Splash-abliterated",
            ),
            160_000,
        )
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "queue context"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call-1", "type": "function",
                "function": {"name": "probe", "arguments": "{}"},
            }]},
            {"role": "tool", "tool_call_id": "call-1", "content": "x" * 72_000},
        ]

        unchanged = compact_model_history(messages, {"step": 1}, 160_000)

        self.assertIs(unchanged, messages)

    def test_history_compaction_leaves_append_headroom_for_prefix_reuse(self):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "runtime queue item"},
        ]
        for index in range(10):
            call_id = f"call-{index}"
            messages.extend([
                {"role": "assistant", "content": "", "tool_calls": [{
                    "id": call_id,
                    "function": {"name": "probe", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": call_id, "content": str(index) + ("x" * 4_000)},
            ])

        compacted = compact_model_history(messages, {"step": 1}, 18_000)
        checkpoint = next(item for item in compacted if item.get("name") == "agent-b-context-checkpoint")
        appended = compacted + [
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "new-call", "function": {"name": "probe", "arguments": "{}"},
            }]},
            {"role": "tool", "tool_call_id": "new-call", "content": "new" * 300},
        ]

        next_turn = compact_model_history(appended, {"step": 2}, 18_000)

        self.assertIs(next_turn, appended)
        self.assertIs(next(item for item in next_turn if item.get("name") == "agent-b-context-checkpoint"), checkpoint)

    def test_model_stream_labels_channels_and_deduplicates_omlx_thinking(self):
        self.engine._model_delta({"reasoning_content": "Inspect scope", "content": "Inspect scope"})
        self.engine._model_delta({"content": "Ready."})

        public = self.engine.public()
        stream = public["model_stream"]
        self.assertEqual(stream.count("Inspect scope"), 1)
        self.assertIn("[Thinking]\nInspect scope", stream)
        self.assertIn("[Response]\nReady.", stream)
        self.assertTrue(public["model_reasoning_seen"])
        self.assertEqual(public["model_stream_channel"], "Response")
        self.assertEqual(public["model_reasoning_mode"], "provider-exposed reasoning")

    def test_model_stream_shows_tool_name_without_json_arguments(self):
        self.engine._model_delta({
            "content": "Claiming the next assessment test.",
            "tool_calls": [{
                "function": {
                    "name": "next_assessment_test",
                    "arguments": '{"commentary":"Claiming the next assessment test."}',
                },
            }],
            "finish_reason": "tool_calls",
        })

        stream = self.engine.public()["model_stream"]
        self.assertIn("[Response]\nClaiming the next assessment test.", stream)
        self.assertIn("[Tool call]\nnext_assessment_test", stream)
        self.assertNotIn("{\"commentary\"", stream)

    def test_workspace_target_url_uses_authoritative_non_loopback_scope(self):
        workspace = {
            "scope": {
                "observed_urls": ["http://127.0.0.1:8777/api", "https://example.test:443/login"],
            }
        }
        self.assertEqual(workspace_target_url(workspace), "https://example.test/login")

    def test_findings_target_url_recovers_assessment_origin(self):
        payload = {
            "findings": [
                {"url": "http://127.0.0.1:8777/api"},
                {"url": "https://example.test:443/a/deep/path?q=1"},
            ]
        }
        self.assertEqual(findings_target_url(payload), "https://example.test/")

    def test_starting_a_run_keeps_the_connected_target_link(self):
        self.engine.target_url = "https://example.test/"
        with patch("agent_b_harness.engine.threading.Thread") as thread_type:
            thread_type.return_value.is_alive.return_value = False
            self.engine.chat("Review this target")
        self.assertEqual(self.engine.target_url, "https://example.test/")

    def test_queue_payload_recovers_target_and_strips_disabled_browseros(self):
        payload = {
            "user_context": "Assess the app.\nSet up BrowserOS now.\nContinue through Burp.",
            "seed_url": "https://example.test/deep/path?q=1",
            "browseros_enabled": True,
            "steps": [{"key": "browseros_setup", "detail": "Launch BrowserOS"}, {"key": "inventory", "detail": "Read Burp history"}],
        }
        cleaned = without_browseros(payload)
        self.assertEqual(payload_target_url(payload), "https://example.test/")
        self.assertNotIn("browseros", str(cleaned).lower())
        self.assertEqual(cleaned["steps"], [{"key": "inventory", "detail": "Read Burp history"}])

    def test_typed_campaign_tools_supply_active_queue_paths(self):
        self.engine.active_queue = "7"
        result, finished = self.engine._tool(self.client, "update_campaign_step", {
            "key": "active_testing", "status": "completed", "note": "manual checks complete",
            "artifacts": [{"tested": 3}], "requests_used": 3,
        })
        self.assertFalse(finished)
        self.assertEqual(self.client.posts[-1][0], "/api/agent/queue/7/campaign/step")

        self.engine._tool(self.client, "coverage_overwatch", {})
        self.assertEqual(self.client.posts[-1][0], "/api/agent/attack-surface/overwatch")
        self.assertEqual(self.client.posts[-1][1]["queue_id"], 7)

        self.engine.assessment_plan = {"burp_action_catalog": [{"action": "history.http.search", "available": True}]}
        self.engine._tool(self.client, "burp_action", {
            "action": "history.http.search", "arguments": {"regex": "api"},
            "note": "Agent: queue #7 - enumerate API routes - collect observed inputs", "dry_run": True,
        })
        self.assertEqual(self.client.posts[-1][0], "/api/agent/burp/action/dry-run")

        self.engine.assessment_plan = {"burp_action_catalog": [{
            "action": "history.http.search", "available": True, "transport": "double_agent_api",
        }]}
        self.engine.assessment_discovery = {"plan_finalized": True}
        result, finished = self.engine._tool(self.client, "burp_action", {
            "action": "history.http.search", "arguments": {"regex": "api/.*", "count": 25},
            "note": "Agent: queue #7 - enumerate API routes - collect observed inputs",
        })
        self.assertFalse(finished)
        self.assertIn("regex=api%2F.%2A&count=25", result["path"])

        self.engine._tool(self.client, "submit_active_queue_result", {
            "outcome": "gated", "assessment": "Exact scope blocker",
        })
        self.assertEqual(self.client.posts[-1][0], "/api/agent/queue/7/result")

    def test_full_assessment_plan_maps_routes_inputs_and_every_attack_family(self):
        plan = build_full_assessment_plan({
            "coverage": {"tested": [
                {"method": "POST", "host": "example.test", "path": "/login", "url_example": "https://example.test/login"},
                {"method": "GET", "host": "example.test", "path": "/api/export", "url_example": "https://example.test/api/export?document=a"},
            ]},
            "parameters": {"meaningful_tested": [
                {"method": "POST", "host": "example.test", "path": "/login", "parameter": "password", "type": "body"},
                {"method": "GET", "host": "example.test", "path": "/api/export", "parameter": "document", "type": "query"},
                {"method": "GET", "host": "example.test", "path": "/api/continue", "parameter": "next", "type": "query", "url_example": "https://example.test/api/continue?next=/"},
            ]},
            "findings": {"findings": [{"method": "GET", "url": "https://example.test/api/export", "finding_ids": ["daf-1"]}]},
            "attack_surface": {"attack_surface": {"entries": []}},
            "capabilities": {"effective_actions": [
                {"action": "scanner.active.start", "available": True},
                {"action": "request.send.http2", "available": True},
            ]},
        })

        self.assertEqual(plan["route_count"], 3)
        self.assertEqual(plan["input_count"], 3)
        self.assertEqual(plan["input_locations"], ["body", "query"])
        self.assertEqual(plan["version"], 3)
        self.assertTrue(plan["planned_tests"])
        self.assertTrue(all(item["test_sequence"][0] == "baseline" for item in plan["planned_tests"]))
        export_tests = [item for item in plan["planned_tests"] if item["route"].endswith("/api/export")]
        self.assertTrue(export_tests)
        self.assertTrue(all("daf-1" in item["candidate_finding_ids"] for item in export_tests))
        first_routes = [item["route"] for item in plan["planned_tests"][:plan["route_count"]]]
        self.assertEqual(len(first_routes), len(set(first_routes)))
        self.assertEqual({item["id"] for item in plan["attack_families"]}, {item["id"] for item in ASSESSMENT_FAMILIES})
        families = {item["id"]: item for item in plan["attack_families"]}
        self.assertTrue(families["files_paths_uploads"]["matched_routes"])
        self.assertTrue(families["ssrf_oob_redirect"]["matched_routes"])
        self.assertEqual(families["websocket_realtime"]["disposition"], "applicability_pending")
        self.assertIn("crawl.start", plan["capability_gaps"])
        self.assertEqual(plan["application_model"]["api_surfaces"], ["GET example.test /api/continue", "GET example.test /api/export"])
        self.assertEqual(len(plan["ranked_hypotheses"]), len(ASSESSMENT_FAMILIES))

    def test_html_discovery_extracts_forms_routes_inputs_and_technology(self):
        surface = extract_application_surface(
            "https://example.test/",
            """<!doctype html><html data-reactroot><body>
            <a href='/account?id=4'>Account</a>
            <form method='post' action='/login'><input name='username'><input name='password'></form>
            <script>fetch('/api/orders?limit=10')</script></body></html>""",
            ["Server: CloudFront"],
        )
        routes = {(item["method"], urllib.parse.urlsplit(item["url"]).path): item for item in surface["entries"]}
        self.assertIn(("GET", "/account"), routes)
        self.assertIn(("POST", "/login"), routes)
        self.assertIn(("GET", "/api/orders"), routes)
        self.assertEqual({item["name"] for item in routes[("POST", "/login")]["parameters"]}, {"username", "password"})
        self.assertIn("React", surface["technologies"])
        self.assertIn("CloudFront", surface["technologies"])

    def test_discovery_locks_testing_until_two_stable_passes_then_finalizes_plan(self):
        class DiscoveryClient:
            def __init__(self):
                self.surface = []

            def get(self, path):
                if path.startswith("/api/agent/scope?url="):
                    return {"scope_guard": {"in_scope": True}}
                if path.startswith("/api/agent/auth/latest"):
                    return {"recommended_auth": {}}
                if path.startswith("/api/coverage/parameters"):
                    return {"meaningful_tested": []}
                if path.startswith("/api/coverage?"):
                    return {"tested": [{"method": "GET", "host": "example.test", "path": "/", "url_example": "https://example.test/"}], "untested": []}
                if path == "/api/agent/attack-surface":
                    return {"attack_surface": {"entries": list(self.surface)}}
                if path == "/api/findings?limit=500":
                    return {"findings": []}
                raise AssertionError(path)

            def post(self, path, body):
                if path == "/api/agent/request":
                    return {"status_code": 200, "headers": ["Server: CloudFront"], "body": "<a href='/api/items?id=1'>Items</a><form method='post' action='/login'><input name='username'></form>"}
                if path == "/api/agent/attack-surface":
                    by_key = {(item["method"], item["url"]): item for item in self.surface}
                    for item in body["entries"]:
                        by_key[(item["method"], item["url"])] = dict(item)
                    self.surface = list(by_key.values())
                    return {"status": "updated"}
                raise AssertionError(path)

        client = DiscoveryClient()
        inventory = {
            "coverage": client.get("/api/coverage?in_scope_only=true&limit=500"),
            "parameters": {"meaningful_tested": []}, "attack_surface": {"attack_surface": {"entries": []}},
            "findings": {"findings": []}, "capabilities": {"effective_actions": []},
        }
        self.engine.active_queue = "9"
        self.engine.assessment_inventory = inventory
        self.engine.assessment_plan = build_full_assessment_plan(inventory)
        self.engine.assessment_plan["scope_gate"] = {"ready": True}
        self.engine.assessment_discovery = {
            "status": "pending", "passes": 0, "stable_passes": 0, "required_stable_passes": 2,
            "fingerprint": "", "technologies": [], "plan_finalized": False, "blockers": [],
        }

        blocked, _ = self.engine._tool(client, "next_assessment_test", {})
        self.assertIn("run_application_discovery", blocked["error"])
        first, _ = self.engine._tool(client, "run_application_discovery", {"max_routes": 1})
        self.assertFalse(first["plan_finalized"])
        self.assertTrue(first["discovery"]["frontier_remaining"])
        second, _ = self.engine._tool(client, "run_application_discovery", {"max_routes": 1})
        self.assertFalse(second["plan_finalized"])
        third, _ = self.engine._tool(client, "run_application_discovery", {"max_routes": 1})
        if not third["plan_finalized"]:
            third, _ = self.engine._tool(client, "run_application_discovery", {"max_routes": 1})
        self.assertTrue(third["plan_finalized"])
        self.assertFalse(third["discovery"]["frontier_remaining"])
        self.assertTrue(self.engine.assessment_test_progress)
        self.assertIn("CloudFront", self.engine.assessment_plan["application_model"]["technologies"])
        self.assertEqual(self.engine.assessment_plan["plan_status"], "finalized")

    def test_full_assessment_preparation_persists_plan_before_active_testing(self):
        class FullClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue/9":
                    return {
                        "id": 9, "campaign_type": "full_app_assessment", "mode": "campaign_full_app_assessment",
                        "campaign_state": {"steps": [
                            {"key": "preflight", "status": "completed"},
                            {"key": "inventory", "status": "completed"},
                            {"key": "surface_baseline", "status": "completed"},
                        ]},
                    }
                if path.startswith("/api/coverage/parameters"):
                    return {"meaningful_tested": [{
                        "method": "GET", "host": "example.test", "path": "/search", "parameter": "q", "type": "query",
                    }]}
                if path.startswith("/api/coverage?"):
                    return {"tested": [{"method": "GET", "host": "example.test", "path": "/search"}], "untested": []}
                if path.startswith("/api/agent/burp/capabilities"):
                    return {"status": "ready_with_fallbacks", "effective_actions": [{"action": "scanner.active.start", "available": True}]}
                if path == "/api/findings?limit=500":
                    return {"findings": []}
                if path == "/api/agent/attack-surface":
                    return {"attack_surface": {"entries": []}}
                return {"status": "ok"}

            def post(self, path, body):
                self.posts.append((path, body))
                self.assert_no_target_traffic = path != "/api/agent/request"
                return {"status": "updated"}

        client = FullClient()
        self.engine.active_queue = "9"
        detail = {
            "id": 9,
            "campaign_type": "full_app_assessment",
            "mode": "campaign_full_app_assessment",
            "campaign_state": {"steps": [
                {"key": "preflight", "status": "pending"},
                {"key": "inventory", "status": "pending"},
                {"key": "surface_baseline", "status": "pending"},
            ]},
        }

        refreshed = self.engine._prepare_full_assessment(client, detail)

        self.assertEqual(refreshed["harness_assessment_plan"]["route_count"], 1)
        self.assertEqual(self.engine.assessment_plan["input_count"], 1)
        self.assertEqual([body["key"] for path, body in client.posts], ["preflight", "inventory", "surface_baseline"])
        self.assertFalse(any(path == "/api/agent/request" for path, _ in client.posts))
        baseline = client.posts[2][1]["artifacts"][0]
        self.assertEqual(len(baseline["attack_families"]), len(ASSESSMENT_FAMILIES))

    def test_full_assessment_blocks_before_traffic_when_burp_scope_is_empty(self):
        class EmptyScopeClient:
            def __init__(self):
                self.posts = []

            def get(self, path):
                if path == "/api/agent/queue/9":
                    return {"id": 9, "campaign_type": "full_app_assessment", "campaign_state": {"steps": []}}
                if path == "/api/agent/scope":
                    return {"authoritative": True, "in_scope_services": 0, "services": []}
                if path.startswith("/api/coverage?"):
                    return {"tested": [{"method": "GET", "host": "example.test", "path": "/", "url_example": "https://example.test/"}]}
                if path.startswith("/api/coverage/parameters"):
                    return {"meaningful_tested": []}
                if path.startswith("/api/agent/burp/capabilities"):
                    return {"status": "ready_with_fallbacks", "effective_actions": []}
                if path == "/api/findings?limit=500":
                    return {"findings": []}
                if path == "/api/agent/attack-surface":
                    return {"attack_surface": {"entries": []}}
                return {"status": "ok"}

            def post(self, path, body):
                self.posts.append((path, body))
                return {"status": "updated"}

        client = EmptyScopeClient()
        self.engine.active_queue = "9"
        detail = {"id": 9, "campaign_type": "full_app_assessment", "campaign_state": {"steps": []}}
        refreshed = self.engine._prepare_full_assessment(client, detail)

        self.assertIn("no in-scope services", refreshed["harness_scope_blocker"])
        self.assertFalse(self.engine.assessment_plan["scope_gate"]["ready"])
        self.assertFalse(any(path == "/api/agent/request" for path, _ in client.posts))
        preflight = next(body for path, body in client.posts if body.get("key") == "preflight")
        self.assertEqual(preflight["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
