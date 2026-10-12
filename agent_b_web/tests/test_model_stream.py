import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent_b_harness.clients import (
    Model,
    _from_bedrock_response,
    _to_bedrock_messages,
    _to_bedrock_tools,
    recover_xml_tool_calls,
)


class StreamHandler(BaseHTTPRequestHandler):
    last_request = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"data": [{"id": "cyberstrike"}, {"id": "qwen3-coder-30b-6bit"}]}).encode())

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))
        StreamHandler.last_request = request
        if request.get("stream") is not True:
            self.send_error(400)
            return
        if request.get("tool_choice") != "required":
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        frames = [
            {"choices": [{"delta": {"analysis": "Reason briefly. "}}]},
            {"choices": [{"delta": {"content": "Checking "}}]},
            {"choices": [{"delta": {"content": "now."}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "finish", "arguments": "{\"status\":"}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"completed\"}"}}]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
        ]
        for frame in frames:
            self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *_):
        pass


class AnthropicHandler(BaseHTTPRequestHandler):
    last_request = None
    last_headers = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"data": [{"id": "claude-sonnet-test"}]}).encode())

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        AnthropicHandler.last_request = json.loads(self.rfile.read(size))
        AnthropicHandler.last_headers = dict(self.headers)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "tool-1", "name": "finish", "input": {"status": "completed"}},
            ],
            "stop_reason": "tool_use",
        }).encode())

    def log_message(self, *_):
        pass


class ModelStreamTests(unittest.TestCase):
    def test_recovers_cyberstrike_xml_tool_call_returned_as_content(self):
        tools = [{"type": "function", "function": {"name": "execute_queue_request"}}]
        content = """<function=execute_queue_request>
<parameter=commentary>Running the control request.</parameter>
<parameter=request_id>9</parameter>
</function>
</tool_call>"""

        calls = recover_xml_tool_calls(content, tools)

        self.assertEqual(calls[0]["function"]["name"], "execute_queue_request")
        self.assertEqual(json.loads(calls[0]["function"]["arguments"]), {
            "commentary": "Running the control request.",
            "queue_id": 9,
        })

    def test_does_not_recover_unadvertised_xml_tool(self):
        self.assertEqual(recover_xml_tool_calls(
            "<function=unknown><parameter=x>1</parameter></function>",
            [{"type": "function", "function": {"name": "finish"}}],
        ), [])

    def test_lists_available_models(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), StreamHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            model = Model(f"http://127.0.0.1:{server.server_port}/v1", "key", "cyberstrike", 5, 512)
            self.assertEqual(model.available_models(), ["cyberstrike", "qwen3-coder-30b-6bit"])
        finally:
            server.shutdown()
            server.server_close()

    def test_streams_and_reassembles_content_and_tool_calls(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), StreamHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        deltas = []
        try:
            model = Model(f"http://127.0.0.1:{server.server_port}/v1", "key", "cyberstrike", 5, 512)
            message = model.complete([{"role": "user", "content": "test"}], [], deltas.append, "required")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(message["content"], "Checking now.")
        self.assertEqual(message["reasoning_content"], "Reason briefly. ")
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "finish")
        self.assertEqual(json.loads(message["tool_calls"][0]["function"]["arguments"]), {"status": "completed"})
        self.assertEqual(len(deltas), 6)
        self.assertEqual(deltas[0]["reasoning_content"], "Reason briefly. ")
        self.assertEqual(deltas[-1]["finish_reason"], "tool_calls")
        self.assertEqual(StreamHandler.last_request["temperature"], 0.1)
        self.assertEqual(StreamHandler.last_request["chat_template_kwargs"], {"enable_thinking": True})

    def test_qwen_uses_official_non_thinking_sampling_profile(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), StreamHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            model = Model(f"http://127.0.0.1:{server.server_port}/v1", "key", "qwen3-coder-30b-6bit", 5, 8192)
            model.complete([{"role": "user", "content": "test"}], [], tool_choice="required")
        finally:
            server.shutdown()
            server.server_close()
        request = StreamHandler.last_request
        self.assertEqual(request["temperature"], 0.7)
        self.assertEqual(request["top_p"], 0.8)
        self.assertEqual(request["top_k"], 20)
        self.assertEqual(request["repetition_penalty"], 1.05)
        self.assertEqual(request["chat_template_kwargs"], {"enable_thinking": False})
        self.assertEqual(request["max_tokens"], 4096)

    def test_anthropic_native_messages_and_tool_translation(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), AnthropicHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        tools = [{"type": "function", "function": {
            "name": "finish", "description": "Finish", "parameters": {"type": "object"},
        }}]
        try:
            model = Model(f"http://127.0.0.1:{server.server_port}/v1", "anthropic-key", "claude-sonnet-test", 5, 512, "anthropic")
            self.assertEqual(model.available_models(), ["claude-sonnet-test"])
            message = model.complete([
                {"role": "system", "content": "Be precise."},
                {"role": "user", "content": "Finish this."},
            ], tools, tool_choice="required")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(AnthropicHandler.last_request["system"], "Be precise.")
        self.assertEqual(AnthropicHandler.last_request["tool_choice"], {"type": "any"})
        self.assertEqual(AnthropicHandler.last_headers["x-api-key"], "anthropic-key")
        self.assertEqual(message["tool_calls"][0]["function"]["name"], "finish")

    def test_bedrock_converse_translation_is_provider_neutral(self):
        system, messages = _to_bedrock_messages([
            {"role": "system", "content": "System prompt"},
            {"role": "user", "content": "Investigate"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call-1", "type": "function", "function": {"name": "inspect", "arguments": "{\"id\": 7}"},
            }]},
            {"role": "tool", "tool_call_id": "call-1", "content": "done"},
        ])
        tools = _to_bedrock_tools([{"type": "function", "function": {
            "name": "inspect", "description": "Inspect item", "parameters": {"type": "object"},
        }}])
        response = _from_bedrock_response({"output": {"message": {"content": [
            {"text": "Working"},
            {"toolUse": {"toolUseId": "call-2", "name": "inspect", "input": {"id": 8}}},
        ]}}})
        self.assertEqual(system, [{"text": "System prompt"}])
        self.assertEqual(messages[1]["content"][0]["toolUse"]["name"], "inspect")
        self.assertEqual(messages[2]["content"][0]["toolResult"]["toolUseId"], "call-1")
        self.assertEqual(tools[0]["toolSpec"]["inputSchema"]["json"], {"type": "object"})
        self.assertEqual(json.loads(response["tool_calls"][0]["function"]["arguments"]), {"id": 8})


if __name__ == "__main__":
    unittest.main()
