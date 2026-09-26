import base64
import http.client
import importlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.attachments import Attachments, MAX_FILE, image_dimensions
from agent_b_harness.clients import _to_anthropic_messages, _to_bedrock_messages
from agent_b_harness.engine import Engine
from agent_b_harness.store import Store


PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aX1cAAAAASUVORK5CYII=")


class CollaborationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "chat.sqlite3")
        self.engine = Engine(self.store)
        self.files = self.engine.attachments

    def upload(self, name, data):
        return self.files.add(name, base64.b64encode(data).decode())

    def test_text_is_redacted_and_filename_cannot_escape(self):
        item = self.upload("../../notes.md", b"API_key=example-secret-value\nUseful reference")
        row = self.files.get(item["id"])
        self.assertEqual(row[1], "notes.md")
        self.assertNotIn(b"example-secret-value", row[3])
        self.assertEqual(self.files.path.stat().st_mode & 0o777, 0o600)

    def test_bad_file_inputs_are_rejected(self):
        for name, data in [("x.html", b"<script>alert(1)</script>"), ("x.png", b"not a png"), ("x.txt", b"\x00"), ("x.txt", b"x" * 120001), ("x.jpg", b"x" * (MAX_FILE + 1))]:
            with self.subTest(name=name, size=len(data)), self.assertRaises(ValueError):
                self.upload(name, data)
        with self.assertRaises(ValueError):
            self.files.add("x.txt", "!invalid!")

    def test_images_require_explicit_capability_and_translate_across_providers(self):
        item = self.upload("screen.png", PNG)
        with self.assertRaisesRegex(ValueError, "vision-capable"):
            self.files.validate([item["id"]], False)
        self.files.validate([item["id"]], True)
        history = [{"role": "user", "content": "What is visible?", "attachments": [item["id"]]}]
        messages = self.files.messages(history, True)
        self.assertNotIn("attachments", messages[0])
        self.assertEqual(messages[0]["content"][-1]["type"], "image_url")
        _, anthropic = _to_anthropic_messages(messages)
        self.assertEqual(anthropic[0]["content"][-1]["source"]["media_type"], "image/png")
        self.assertEqual(base64.b64decode(anthropic[0]["content"][-1]["source"]["data"]), PNG)
        _, bedrock = _to_bedrock_messages(messages)
        self.assertEqual(bedrock[0]["content"][-1]["image"]["format"], "png")
        self.assertEqual(base64.b64decode(bedrock[0]["content"][-1]["image"]["source"]["bytes"]), PNG)
        self.assertNotIn("image_url", json.dumps(self.files.messages(history, False)))
        self.assertNotIn("base64", json.dumps(history))

    def test_file_limits_and_clear(self):
        ids = [self.upload(f"note{i}.txt", b"x" * 90000)["id"] for i in range(2)]
        with self.assertRaisesRegex(ValueError, "160 KB"):
            self.files.validate(ids, True)
        with self.assertRaises(ValueError):
            self.files.validate(ids * 3, True)
        self.engine.clear()
        with self.assertRaises(ValueError):
            self.files.get(ids[0])

    def test_image_dimensions_are_bounded_without_decoding(self):
        self.assertEqual(image_dimensions(PNG, "image/png"), (1, 1))
        huge = PNG[:16] + (9000).to_bytes(4, "big") + PNG[20:]
        with self.assertRaises(ValueError):
            self.upload("huge.png", huge)
        with self.assertRaises(ValueError):
            self.upload("truncated.png", PNG[:12])
        jpeg = b"\xff\xd8\xff\xc0\x00\x08\x08\x00\x02\x00\x03\x01"
        self.assertEqual(image_dimensions(jpeg, "image/jpeg"), (3, 2))
        webp = b"RIFF" + b"\x00" * 4 + b"WEBPVP8L" + b"\x00" * 4 + b"\x2f" + b"\x00" * 4
        self.assertEqual(image_dimensions(webp, "image/webp"), (1, 1))

    def test_approval_requires_exact_choice_and_cannot_be_chat(self):
        qid = self.store.ask("Approve action?", "A decision is required", ["Approve once", "Do not approve"], "approval")
        for answer in ["", "Approve later after I check", "approve once"]:
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                self.engine.answer(qid, answer)
        with self.assertRaisesRegex(ValueError, "card"):
            self.engine.chat("Approve once", discussion=True)
        self.engine.answer(qid, "Do not approve")
        self.assertEqual(self.store.question(qid)["answer"], "Do not approve")
        with self.assertRaises(ValueError):
            self.engine.answer(qid, "Approve once")

    def test_stop_and_restart_cancel_questions(self):
        qid = self.store.ask("Question", "Reason", [])
        self.engine.stop()
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.question(qid)["status"], "cancelled")
        with self.assertRaises(ValueError):
            self.engine.answer(qid, "yes")
        qid = self.store.ask("Old question", "Reason", [])
        Engine(self.store)
        self.assertEqual(self.store.question(qid)["status"], "cancelled")

    def test_discuss_cannot_silently_steer_an_assessment(self):
        self.engine.burp_prompt_loaded = True
        self.engine.thread = type("LiveWorker", (), {"is_alive": lambda self: True})()
        with self.assertRaisesRegex(ValueError, "assessment is running"):
            self.engine.chat("Explain these notes", discussion=True)
        self.assertEqual(self.engine.steering, [])

    def test_suggestion_decisions_survive_recreation(self):
        self.engine.route_recommendations = [{"subject": "Clarify requirements", "route": "needs-info", "rationale": "Context missing"}]
        self.engine._save_suggestion(self.engine.route_recommendations[0])
        item = self.engine.suggestions()[0]
        self.store.decide_suggestion(item["id"], "saved")
        self.engine.run_id = "another-discussion"
        self.assertEqual(self.engine.suggestions()[0]["decision"], "saved")
        self.assertEqual(Store(self.store.path).suggestion_decisions()[item["id"]], "saved")
        self.assertEqual(Engine(self.store).suggestions()[0]["decision"], "saved")

    def test_discussion_attachments_use_no_tools_even_with_bootstrap(self):
        item = self.upload("notes.txt", b"This is reference material.")
        cfg = config.Config(model="local", custom_models=({"id": "local", "model": "example", "url": "http://127.0.0.1:8000/v1"},))
        self.engine.burp_prompt_loaded = True
        with patch("agent_b_harness.engine.config.load", return_value=cfg), patch("agent_b_harness.engine.Model") as model:
            model.return_value.complete.return_value = {"content": "I can discuss the reference material."}
            self.engine.chat("Review these notes", attachment_ids=[item["id"]], discussion=True)
            self.engine.thread.join(3)
            self.assertFalse(self.engine.thread.is_alive())
            self.assertEqual(self.engine.state, "completed")
            args = model.return_value.complete.call_args.args
            self.assertEqual(args[1], [])
            self.assertEqual(args[3], "none")
            self.assertIn("reference material", json.dumps(args[0]))
            self.assertEqual(self.engine.discussion_context[0]["attachments"], [item["id"]])
            self.assertNotIn("base64", json.dumps(self.store.messages()))

    def test_image_capability_roundtrip_preserves_other_settings(self):
        with patch.object(config, "DATA", Path(self.temp.name)), patch.object(config, "SETTINGS", Path(self.temp.name) / "settings.json"):
            saved = config.add_custom_model("Vision", "example", "http://127.0.0.1:8000/v1", supports_images=True)
            ident = saved.model
            self.assertTrue(saved.public()["model_options"][0]["supports_images"])
            saved = config.edit_custom_model(ident, "Renamed", "example", "http://127.0.0.1:8000/v1")
            self.assertTrue(saved.public()["model_options"][0]["supports_images"])
            saved = config.edit_custom_model(ident, "Renamed", "example", "http://127.0.0.1:8000/v1", supports_images=False)
            self.assertFalse(saved.public()["model_options"][0]["supports_images"])


class FileHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with patch.object(config, "DATA", Path(self.temp.name)):
            server = importlib.import_module("agent_b_harness.server")
        self.store = Store(Path(self.temp.name) / "http.sqlite3")
        self.engine = Engine(self.store)
        for name, obj in [("STORE", self.store), ("ENGINE", self.engine)]:
            p = patch.object(server, name, obj)
            p.start()
            self.addCleanup(p.stop)
        self.http = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.http.server_port)
        conn.request(method, path, json.dumps(body) if body is not None else None, {"Content-Type": "application/json", **(headers or {})})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_upload_download_and_missing_file(self):
        status, _, body = self.request("POST", "/api/files", {"name": "notes.md", "data": base64.b64encode(b"hello").decode()})
        self.assertEqual(status, 201)
        status, headers, body = self.request("GET", "/api/files/" + json.loads(body)["id"])
        self.assertEqual((status, body), (200, b"hello"))
        self.assertTrue(headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.request("GET", "/api/files/../../settings.json")[0], 404)

    def test_cross_origin_and_bad_host_requests_rejected(self):
        self.assertEqual(self.request("POST", "/api/files", {}, {"Origin": "https://example.test"})[0], 403)
        self.assertEqual(self.request("GET", "/api/export", headers={"Host": "example.test"})[0], 403)
        self.assertEqual(self.request("GET", "/api/export", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("GET", "/api/export", headers={"Host": "[bad"})[0], 403)

    def test_preview_is_image_only(self):
        item = self.engine.attachments.add("screen.png", base64.b64encode(PNG).decode())
        status, headers, body = self.request("GET", "/api/files/" + item["id"] + "/preview")
        self.assertEqual((status, body), (200, PNG))
        self.assertEqual(headers["Content-Type"], "image/png")
        item = self.engine.attachments.add("notes.txt", base64.b64encode(b"plain text").decode())
        self.assertEqual(self.request("GET", "/api/files/" + item["id"] + "/preview")[0], 404)

    def test_download_response_and_export_are_redacted(self):
        self.store.message("assistant", "API_key=example-secret-value\nA useful response.")
        ident = self.store.messages()[0]["id"]
        for path in ["/api/export", f"/api/messages/{ident}/download"]:
            status, _, body = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn(b"A useful response", body)
            self.assertNotIn(b"example-secret-value", body)


if __name__ == "__main__":
    unittest.main()
