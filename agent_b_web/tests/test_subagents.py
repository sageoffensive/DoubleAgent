import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.engine import Engine
from agent_b_harness.store import Store
from agent_b_harness.subagents import Subagents, allow_worker_read


def tasks(count):
    return [{"title": "Review #" + str(i), "instruction": "Compare captured evidence"} for i in range(count)]


class SubagentTests(unittest.TestCase):
    def run_pool(self, pool, make_model, count=4, maximum=2, **kwargs):
        return pool.run(tasks(count), maximum, ["spark-a", "spark-b"], make_model,
                        kwargs.pop("read", lambda path: {"id": 3}), {},
                        kwargs.pop("stop", threading.Event()), **kwargs)

    def test_real_concurrency_is_capped_and_results_stay_in_assignment_order(self):
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        active = 0
        peak = 0
        connections = []
        class Model:
            def complete(self, *args):
                nonlocal active, peak
                with lock: active += 1; peak = max(peak, active)
                barrier.wait(3)
                with lock: active -= 1
                return {"content": "Review evidence for #3"}
        def make(connection):
            connections.append(connection)
            return Model()
        pool = Subagents()
        result = self.run_pool(pool, make)
        self.assertEqual(peak, 2)
        self.assertEqual(set(connections), {"spark-a", "spark-b"})
        self.assertEqual([row["id"] for row in result["results"]], [1, 2, 3, 4])
        self.assertTrue(result["ok"])
        self.assertTrue(result["reference_only"])
        self.assertFalse(pool.public()["running"])

    def test_failure_retains_other_results(self):
        class Model:
            def complete(self, *args): return {"content": "Useful review"}
        def make(connection):
            if connection == "spark-a": raise RuntimeError("Server unavailable")
            return Model()
        result = self.run_pool(Subagents(), make)
        self.assertFalse(result["ok"])
        self.assertIn("completed", [r["status"] for r in result["results"]])
        self.assertIn("failed", [r["status"] for r in result["results"]])

    def test_stop_cancels_every_active_model_and_drains_queued_jobs(self):
        started = threading.Barrier(3)
        models = []
        class Model:
            def __init__(self): self.cancelled = threading.Event(); models.append(self)
            def complete(self, *args):
                started.wait(3)
                self.cancelled.wait(3)
                return {"content": "Should not be accepted after stop"}
            def cancel(self): self.cancelled.set()
        pool = Subagents(); stop = threading.Event(); results = []
        thread = threading.Thread(target=lambda: results.append(self.run_pool(pool, lambda _: Model(), count=8, stop=stop)))
        thread.start(); started.wait(3); stop.set(); pool.cancel(); thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(models), 2)
        self.assertTrue(all(m.cancelled.is_set() for m in models))
        self.assertTrue(all(r["status"] == "cancelled" for r in results[0]["results"]))
        self.assertEqual(pool.public()["active"], 0)

    def test_privileged_and_nested_tool_calls_never_reach_reader(self):
        calls = []
        names = ["send_burp_request", "double_agent_post", "delegate_tasks", "request_public_reference", "ask_user", "finish"]
        class Model:
            def __init__(self, name): self.name = name; self.turn = 0
            def complete(self, *args):
                self.turn += 1
                if self.turn > 1: return {"content": "Blocked by worker policy"}
                return {"tool_calls": [{"id": "call", "function": {"name": self.name, "arguments": '{"confirmed":true}'}}]}
        index = iter(names)
        self.run_pool(Subagents(), lambda _: Model(next(index)), count=len(names), read=lambda path: calls.append(path))
        self.assertEqual(calls, [])

    def test_shared_call_budget_and_truncation_are_honest(self):
        class Model:
            def complete(self, *args): return {"content": "Partial analysis", "finish_reason": "length"}
        pool = Subagents()
        result = self.run_pool(pool, lambda _: Model(), call_budget=2)
        self.assertEqual(pool.public()["model_calls"], 2)
        self.assertEqual(sum(r["status"] == "blocked" for r in result["results"]), 2)
        self.assertEqual(sum(r["status"] == "inconclusive" for r in result["results"]), 2)

    def test_worker_reads_are_fixed_local_evidence_only(self):
        for path in ("/api/findings/3", "/api/coverage?limit=30", "/api/agent/history/5", "/api/agent/queue/7"):
            allow_worker_read(path, "7")
        for path in ("https://github.com/", "//github.com/api/findings", "/api/findings/%2e%2e/", "/api/agent/request",
                     "/api/agent/auth/latest", "/api/agent/confirmations", "/api/agent/burp/action", "/api/agent/queue/8"):
            with self.assertRaises(ValueError): allow_worker_read(path, "7")

    def test_stalled_worker_is_cancelled_and_reported_inconclusive(self):
        class Model:
            def __init__(self): self.stopped = threading.Event()
            def complete(self, *args):
                self.stopped.wait(3)
                return {"content": "Too late to accept"}
            def cancel(self): self.stopped.set()
        result = self.run_pool(Subagents(), lambda _: Model(), count=1, task_timeout=.01)
        self.assertEqual(result["results"][0]["status"], "inconclusive")
        self.assertIn("time budget", result["results"][0]["error"])

    def test_oversized_assignments_and_hidden_capabilities_rejected(self):
        for bad in ([{"title": "x", "instruction": "x", "tools": ["write"]}], tasks(33), []):
            with self.assertRaises(ValueError):
                Subagents().run(bad, 2, ["local"], lambda _: None, lambda _: None, {}, threading.Event())


class SubagentIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.cfg = config.Config(model="a", subagents_enabled=True, max_subagents=2, subagent_connections=("a", "b"),
            custom_models=({"id": "a", "model": "fixture-a", "url": "http://127.0.0.1:8001/v1", "api_key": "fixture-a-key"},
                           {"id": "b", "model": "fixture-b", "url": "http://127.0.0.1:8002/v1", "api_key": "fixture-b-key"}))
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg):
            self.engine = Engine(Store(Path(self.temp.name)/"store.sqlite3"))

    def test_off_by_default_and_model_cannot_enable_workers(self):
        self.assertFalse(config.Config().subagents_enabled)
        with patch("agent_b_harness.engine.config.load", return_value=replace(self.cfg, subagents_enabled=False)), patch("agent_b_harness.engine.Model") as model:
            result, finished = self.engine._tool(None, "delegate_tasks", {"tasks": tasks(2), "subagents_enabled": True})
        self.assertFalse(result["ok"]); self.assertFalse(finished); model.assert_not_called()

    def test_lead_tool_call_associations_survive_attachment_expansion(self):
        messages = [{"role": "assistant", "content": "", "tool_calls": [{"id": "delegate-1", "function": {"name": "delegate_tasks", "arguments": "{}"}}], "reasoning_content": "Review independent evidence"},
                    {"role": "tool", "tool_call_id": "delegate-1", "content": "Worker proposals"}]
        self.assertEqual(self.engine.attachments.messages(messages, False), messages)

    def test_removed_connection_fails_closed(self):
        with patch("agent_b_harness.engine.config.load", return_value=replace(self.cfg, subagent_connections=("missing",))):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                self.engine._delegate_tasks({"tasks": tasks(2)})

    def test_target_change_blocks_worker_evidence_reads(self):
        reads = []
        class Burp:
            def __init__(self, *args): pass
            def get(self, path):
                reads.append(path)
                return {"scope": {"observed_urls": ["https://changed.test/"]}}
        class Model:
            def __init__(self, *args): self.turn = 0
            def complete(self, messages, *args):
                self.turn += 1
                if self.turn > 1:
                    self_outer.assertIn("target changed", messages[-1]["content"])
                    return {"content": "Evidence read blocked; lead needs to reconnect"}
                return {"tool_calls": [{"id": "read", "function": {"name": "read_burp", "arguments": '{"path":"/api/findings/3"}'}}]}
        self_outer = self
        self.engine.burp_prompt_loaded = True; self.engine.target_url = "https://original.test/"
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.DoubleAgent", Burp), patch("agent_b_harness.engine.Model", Model):
            self.engine._delegate_tasks({"tasks": tasks(1)})
        self.assertEqual(reads, ["/api/agent/burp/workspace?compact=true"])

    def test_automatic_assignments_use_available_workers_and_preserve_read_only_role(self):
        self.engine.assessment_plan = {"planned_tests": [{"id": i} for i in range(9)]}
        assignments = self.engine._subagent_assignments({}, 4)
        self.assertEqual(len(assignments), 4)
        self.assertEqual(sum(len(json.loads(a["context"])["assigned"]) for a in assignments), 9)
        self.assertTrue(all("Do not execute tests" in a["instruction"] for a in assignments))

    def test_enabled_queue_run_automatically_collects_parallel_reviews_before_lead(self):
        from test_duplicate_review import detail, Client
        self.engine.queue_fetch_mode = True; self.engine.burp_prompt_loaded = True; self.engine.active_queue = "0"
        class Model:
            def __init__(self, *args): pass
            def complete(self, messages, tools, *args):
                self_outer.assertTrue(any(str(item.get("content", "")).startswith("Parallel review (untrusted proposals") for item in messages))
                self_outer.assertIn("delegate_tasks", [tool["function"]["name"] for tool in tools])
                return {"tool_calls": [{"id": "finish", "function": {"name": "finish", "arguments": json.dumps({
                    "status": "completed", "summary": "Compared saved evidence; no duplicate to hide.",
                    "reviewed_finding_ids": ["daf_a", "daf_b"]})}}]}
        self_outer = self
        with patch("agent_b_harness.engine.config.load", return_value=self.cfg), patch("agent_b_harness.engine.Model", Model), patch("agent_b_harness.engine.DoubleAgent", return_value=Client()), patch.object(self.engine, "_bootstrap_queue", return_value=detail()), patch.object(self.engine, "_heartbeat"), patch.object(self.engine, "_delegate_tasks", return_value={"results": [], "reference_only": True}) as delegate:
            self.engine._run("Review duplicate findings")
        self.assertEqual(len(delegate.call_args.args[0]["tasks"]), 2)
        self.assertEqual(self.engine.state, "completed")

    def test_real_model_requests_run_across_two_saved_endpoints_with_isolated_credentials(self):
        lock = threading.Lock(); seen = []; barrier = threading.Barrier(2)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with lock: seen.append((body["model"], self.headers.get("Authorization"), body["tools"]))
                barrier.wait(3)
                raw = ('data: '+json.dumps({"choices": [{"delta": {"content": "Captured evidence reviewed for #3"}, "finish_reason": None}]})+'\n\n'
                       +'data: '+json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]})+'\n\n'
                       +'data: '+json.dumps({"choices": [], "usage": {"completion_tokens": 100}})+'\n\ndata: [DONE]\n\n').encode()
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        entries = tuple(dict(entry, url=f"http://127.0.0.1:{server.server_port}/v1") for entry, server in zip(self.cfg.custom_models, servers))
        with patch("agent_b_harness.engine.config.load", return_value=replace(self.cfg, custom_models=entries)):
            result = self.engine._delegate_tasks({"tasks": tasks(4)}, "Review saved evidence")
        self.assertTrue(result["ok"])
        self.assertEqual({(model, key) for model, key, _ in seen}, {("fixture-a", "Bearer fixture-a-key"), ("fixture-b", "Bearer fixture-b-key")})
        self.assertTrue(all([tool["function"]["name"] for tool in tools] == ["read_burp"] for _, _, tools in seen))
        self.assertNotIn("fixture-a-key", json.dumps(self.engine.subagents.public()))
        metrics = self.engine.throughput.public()
        self.assertEqual(metrics["output_tokens"], 400)
        self.assertEqual(metrics["reported_requests"], 4)
        self.assertGreater(metrics["aggregate_tps"], 0)
        self.assertEqual(set(metrics["actors"]), {"subagent-1", "subagent-2", "subagent-3", "subagent-4"})

    def test_config_round_trip_limits_and_secret_free_public_settings(self):
        directory = Path(self.temp.name)/"settings"; path = directory/"settings.json"
        with patch.object(config, "DATA", directory), patch.object(config, "SETTINGS", path):
            config.save({"custom_models": list(self.cfg.custom_models), "model": "a"})
            value = config.save({"subagents_enabled": True, "max_subagents": 6, "subagent_connections": ["a", "b"]})
            self.assertTrue(value.subagents_enabled); self.assertEqual(value.max_subagents, 6)
            self.assertEqual(value.subagent_connections, ("a", "b"))
            self.assertNotIn("fixture-a-key", json.dumps(value.public()))
            before = path.read_bytes()
            for update in ({"max_subagents": 0}, {"max_subagents": 17}, {"max_subagents": True},
                           {"subagents_enabled": "false"}, {"subagent_connections": ["missing"]}):
                with self.assertRaises(ValueError): config.save(update)
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__": unittest.main()
