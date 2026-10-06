"""Catalogue reads never require a model, save drafts or move stored keys."""
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from agent_b_harness import config
from agent_b_harness.clients import Model, _json_request


class ModelCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Path(self.temp.name) / "settings.json"
        p = patch.object(config, "SETTINGS", self.settings)
        p.start()
        self.addCleanup(p.stop)

    def test_unsaved_draft_needs_no_name_or_model_and_does_not_save(self):
        candidate = config.model_catalog_candidate({"url": "http://127.0.0.1:8080/v1"})
        self.assertEqual(candidate["model"], "")
        self.assertEqual(candidate["api_key"], "")
        self.assertFalse(self.settings.exists())
        with self.assertRaises(ValueError):
            config.connection_candidate({"url": candidate["url"]})

    def test_saved_key_is_reused_only_for_its_provider_and_endpoint(self):
        self.settings.write_text(json.dumps({"custom_models": [{"id": "saved", "label": "Server", "model": "prior", "provider": "openai_compatible", "url": "http://localhost:8080/v1", "api_key": "private-fixture"}]}))
        before = self.settings.read_bytes()
        candidate = config.model_catalog_candidate({"id": "saved", "url": "http://localhost:8080/v1/"})
        self.assertEqual(candidate["api_key"], "private-fixture")
        for url in ("http://other.invalid/v1", "http://localhost:8080/other"):
            with self.assertRaisesRegex(ValueError, "changed server"):
                config.model_catalog_candidate({"id": "saved", "url": url})
        candidate = config.model_catalog_candidate({"id": "saved", "provider": "openai_compatible", "url": "http://other.invalid/v1", "api_key": "explicit-fixture"})
        self.assertEqual(candidate["api_key"], "explicit-fixture")
        candidate = config.model_catalog_candidate({"id": "saved", "provider": "anthropic", "url": "https://api.anthropic.com/v1", "api_key": "separate-fixture"})
        self.assertEqual(candidate["api_key"], "separate-fixture")
        self.assertEqual(self.settings.read_bytes(), before)

    def test_invalid_urls_missing_hosted_keys_and_bedrock_are_rejected(self):
        for body in ({"url": ""}, {"url": "file:///tmp/models"}, {"url": "http://user:pass@localhost/v1"}, {"url": "http://localhost/v1?key=value"}, {"url": "http://localhost/v1#fragment"}, {"provider": "openai", "url": "http://api.openai.com/v1", "api_key": "fixture"}, {"provider": "openai", "url": "https://api.openai.com/v1"}, {"provider": "bedrock", "api_key": "fixture"}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                config.model_catalog_candidate(body)

    def test_real_catalogue_gets_exact_path_with_optional_auth_and_no_inference(self):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.path, self.headers.get("Authorization")))
                raw = json.dumps({"data": [{"id": "model-a"}, {"id": "model-b"}]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        self.addCleanup(http.server_close)
        self.addCleanup(http.shutdown)
        base = "http://127.0.0.1:%d/v1" % http.server_port
        for key in ("", "fixture"):
            self.assertEqual(Model(base, key, "", 10, 16).available_models(), ["model-a", "model-b"])
        self.assertEqual(calls, [("/v1/models", None), ("/v1/models", "Bearer fixture")])

    def test_json_catalogue_response_size_is_bounded(self):
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit):
                self.limit = limit
                return b"x" * limit
        reply = Reply()
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = reply
            with self.assertRaisesRegex(ValueError, "too large"):
                _json_request("http://localhost/v1/models", max_response_bytes=100)
        self.assertEqual(reply.limit, 101)


if __name__ == "__main__":
    unittest.main()
