import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from agent_b_harness.clients import Model, HTTPError
from agent_b_harness.telemetry import Throughput, output_tokens, union_seconds


class ThroughputTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.meter = Throughput(clock=lambda: self.now)

    def test_parallel_lead_workers_and_reviewer_share_wall_time_once(self):
        lead = self.meter.begin("lead", "a")
        self.now = 2; first = self.meter.begin("subagent-1", "a")
        self.now = 3; second = self.meter.begin("subagent-2", "b")
        self.meter.usage(lead, {"completion_tokens": 100, "prompt_tokens": 5000, "completion_tokens_details": {"reasoning_tokens": 50}})
        self.now = 4; self.meter.finish(lead, "completed")
        self.meter.usage(first, {"output_tokens": 80}); self.now = 6; self.meter.finish(first, "completed")
        self.meter.usage(second, {"outputTokens": 120}); self.now = 8; self.meter.finish(second, "completed")
        self.now = 10; reviewer = self.meter.begin("reviewer", "a")
        self.meter.usage(reviewer, {"completion_tokens": 60}); self.now = 12; self.meter.finish(reviewer, "completed")
        stats = self.meter.public()
        self.assertEqual(stats["model_wall_seconds"], 10)  # [0,8] + [10,12], not 15 summed request seconds.
        self.assertEqual(stats["output_tokens"], 360)
        self.assertEqual(stats["aggregate_tps"], 36)
        self.assertEqual(stats["actors"]["lead"]["aggregate_tps"], 25)
        self.assertEqual(len(stats["actors"]), 4)

    def test_usage_frames_are_cumulative_not_added_and_finish_is_idempotent(self):
        request = self.meter.begin("lead", "a")
        self.meter.usage(request, {"completion_tokens": 10})
        self.meter.usage(request, {"completion_tokens": 20})
        self.now = 2; self.meter.finish(request, "completed"); self.now = 9; self.meter.finish(request, "completed")
        self.assertEqual(self.meter.public()["aggregate_tps"], 10)
        self.assertEqual(self.meter.public()["output_tokens"], 20)

    def test_missing_usage_makes_whole_aggregate_unavailable(self):
        known = self.meter.begin("lead", "a"); unknown = self.meter.begin("subagent-1", "b")
        self.meter.usage(known, {"completion_tokens": 100}); self.now = 4
        self.meter.finish(known, "completed"); self.meter.finish(unknown, "completed")
        stats = self.meter.public()
        self.assertIsNone(stats["aggregate_tps"])
        self.assertEqual(stats["missing_usage"], 1); self.assertEqual(stats["reported_requests"], 1)
        self.assertEqual(stats["state"], "unavailable")

    def test_inflight_requests_are_not_presented_as_measured(self):
        request = self.meter.begin("lead", "a"); self.now = 10
        self.assertIsNone(self.meter.public()["aggregate_tps"])
        self.assertEqual(self.meter.public()["active_requests"], 1)
        self.assertEqual(self.meter.public()["state"], "awaiting_usage")
        self.meter.usage(request, {"completion_tokens": 0}); self.meter.finish(request, "completed")
        self.assertEqual(self.meter.public()["aggregate_tps"], 0)

    def test_invalid_or_decreasing_counts_cannot_produce_a_fake_speed(self):
        for value in (True, -3, 2.4, "10", None): self.assertIsNone(output_tokens({"completion_tokens": value}))
        request = self.meter.begin("lead", "a")
        self.meter.usage(request, {"completion_tokens": 12}); self.meter.usage(request, {"completion_tokens": 8})
        self.now = 2; self.meter.finish(request, "completed")
        self.assertIsNone(self.meter.public()["aggregate_tps"])

    def test_reset_drops_previous_run_and_cancelled_usage_is_unknown(self):
        request = self.meter.begin("lead", "a"); self.now = 5; self.meter.finish(request, "cancelled")
        self.assertEqual(self.meter.public()["state"], "unavailable")
        self.meter.reset(); self.assertEqual(self.meter.public()["requests"], 0)
        self.meter.finish(request, "completed"); self.assertEqual(self.meter.public()["requests"], 0)

    def test_union_handles_nested_disjoint_and_zero_duration_intervals(self):
        self.assertEqual(union_seconds([(0, 10), (1, 2), (9, 12), (15, 18), (18, 18)]), 15)


class UsageHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.bodies.append(body)
        if self.server.reject or (self.server.unsupported and "stream_options" in body):
            raw = json.dumps({"error": "stream_options unsupported" if self.server.unsupported else "context too long"}).encode()
            self.send_response(400); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if self.server.anthropic:
            raw = json.dumps({"content": [{"type": "text", "text": "Done"}], "stop_reason": "end_turn", "usage": {"output_tokens": 13}}).encode()
            mime = "application/json"
        elif self.server.plain:
            raw = json.dumps({"choices": [{"message": {"role": "assistant", "content": "Done"}}], "usage": {"completion_tokens": 9}}).encode()
            mime = "application/json"
        else:
            frames = [{"choices": [{"delta": {"content": "chunk"}}]} for _ in range(10)]
            if self.server.usage:
                frames[1]["usage"] = {"completion_tokens": 5}
            frames.append({"choices": [{"delta": {}, "finish_reason": "stop"}]})
            if self.server.usage:
                frames.append({"choices": [], "usage": {"completion_tokens": 11, "prompt_tokens": 200, "completion_tokens_details": {"reasoning_tokens": 4}}})
            raw = (''.join('data: '+json.dumps(frame)+'\n\n' for frame in frames)+'data: [DONE]\n\n').encode()
            mime = "text/event-stream"
        self.send_response(200); self.send_header("Content-Type", mime); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)


class ProviderUsageTests(unittest.TestCase):
    def model(self, **flags):
        server = ThreadingHTTPServer(("127.0.0.1", 0), UsageHandler)
        for name in ("unsupported", "reject", "plain", "anthropic", "usage"): setattr(server, name, flags.get(name, False))
        server.bodies = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        model = Model(f"http://127.0.0.1:{server.server_port}/v1", "fixture-key", "fixture", 3, 512,
                      "anthropic" if flags.get("anthropic") else "openai_compatible")
        model.telemetry = Throughput()
        return model, server

    def test_usage_only_final_sse_frame_is_counted_exactly_once(self):
        model, server = self.model(usage=True)
        model.complete([], [], None, "none")
        stats = model.telemetry.public()
        self.assertEqual(server.bodies[0]["stream_options"], {"include_usage": True})
        self.assertEqual(stats["output_tokens"], 11)
        self.assertEqual(stats["reported_requests"], 1)
        self.assertGreater(stats["aggregate_tps"], 0)

    def test_chunks_without_provider_counts_are_never_token_estimates(self):
        model, _ = self.model()
        model.complete([], [], None, "none")
        self.assertEqual(model.telemetry.public()["missing_usage"], 1)
        self.assertIsNone(model.telemetry.public()["aggregate_tps"])

    def test_unsupported_usage_option_falls_back_without_breaking_connection(self):
        model, server = self.model(unsupported=True)
        model.complete([], [], None, "none"); model.complete([], [], None, "none")
        self.assertEqual(len(server.bodies), 3)
        self.assertNotIn("stream_options", server.bodies[-1])
        self.assertEqual(model.telemetry.public()["requests"], 2)
        self.assertIsNone(model.telemetry.public()["aggregate_tps"])

    def test_unrelated_errors_are_not_retried_for_metrics(self):
        model, server = self.model(reject=True)
        with self.assertRaises(HTTPError): model.complete([], [], None, "none")
        self.assertEqual(len(server.bodies), 1)
        self.assertEqual(model.telemetry.public()["active_requests"], 0)

    def test_nonstream_and_anthropic_usage(self):
        for flags, expected in (({"plain": True}, 9), ({"anthropic": True}, 13)):
            model, _ = self.model(**flags); model.complete([], [], None, "none")
            self.assertEqual(model.telemetry.public()["output_tokens"], expected)

    def test_bedrock_converse_usage(self):
        model = Model("https://bedrock-runtime.example.test", "fixture-key", "fixture", 3, 512, "bedrock")
        model.telemetry = Throughput()
        response = Mock(status=200)
        response.read.return_value = json.dumps({"output": {"message": {"content": [{"text": "Done"}]}},
                                                "usage": {"outputTokens": 15, "inputTokens": 500}, "stopReason": "end_turn"}).encode()
        with patch("agent_b_harness.clients.http.client.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value = response
            model.complete([], [], None, "none")
        self.assertEqual(model.telemetry.public()["output_tokens"], 15)

    def test_cancelled_request_closes_measurement_without_inventing_usage(self):
        model = Model("http://127.0.0.1:1", "", "fixture", 1, 512); model.telemetry = Throughput()
        def cancelled(*args):
            model.cancel()
            return {"content": "Partial"}
        with patch.object(model, "_complete_impl", side_effect=cancelled): model.complete([], [])
        self.assertEqual(model.telemetry.public()["active_requests"], 0)
        self.assertEqual(model.telemetry.public()["state"], "unavailable")


if __name__ == "__main__": unittest.main()
