"""Offline analyzer boundaries, redaction, persistence and Discuss integration."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_b_harness.attachments import Attachments
from agent_b_harness.config import Config
from agent_b_harness.engine import Engine
from agent_b_harness.javascript import MAX_FINDINGS, analyze_javascript, redact_javascript
from agent_b_harness.skills import public_catalog, render_skill_prompt
from agent_b_harness.store import Store


class JavaScriptAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = Attachments(self.root / "files.sqlite3")
        self.key = "AKIA" + "7M9Q2D4R8W6N3P5Z"

    def upload(self, name, text):
        return self.files.add(name, base64.b64encode(text.encode()).decode())

    def test_all_six_categories_locations_and_secret_masking(self):
        text = '\n'.join([
            'const route = "/api/v1/profile";',
            'const site = "https://service.acme.invalid/account";',
            'const credential = "' + self.key + '";',
            'const mail = "security@acme.invalid";',
            'const backup = "/archive/database.sql";',
            '/* webpack@5.88.2 */',
        ])
        report = analyze_javascript(text, "bundle.js")
        self.assertTrue(all(report["summary"][category] == 1 for category in report["findings"]))
        self.assertEqual(report["findings"]["endpoints"][0]["position"], {"line": 1, "column": 16})
        self.assertEqual(report["findings"]["secrets"][0]["position"]["line"], 3)
        self.assertEqual(report["findings"]["secrets"][0]["value"], "[REDACTED]")
        self.assertNotIn(self.key, json.dumps(report))
        self.assertNotIn(self.key[:10], json.dumps(report))
        self.assertFalse(report["truncated"])

    def test_short_tokens_database_urls_query_values_and_private_keys_are_removed(self):
        short = "xoxb-" + "a7b3c9d4e8"
        database = "postgres://operator:sensitive-pass@database.acme.invalid/app"
        query = "unpublished-query-value"
        password = "short-private"
        pem = "-----BEGIN PRIVATE KEY-----\nfixture-key-material\n-----END PRIVATE KEY-----"
        text = f'const a="{short}"; const b="{database}"; const c="https://service.acme.invalid/?token={query}"; const password="{password}";\n{pem}'
        for result in (redact_javascript(text), json.dumps(analyze_javascript(text, "source.js"))):
            for secret in (short, database, query, password, "fixture-key-material"):
                self.assertNotIn(secret, result)
        self.assertGreaterEqual(analyze_javascript(text, "source.js")["summary"]["secrets"], 5)

    def test_report_survives_restart_and_locations_refer_to_original_upload(self):
        item = self.upload("source.jsx", f'const key = "{self.key}"; const path="/api/v1/account";')
        original = self.files.javascript_report(item["id"])
        restarted = Attachments(self.files.path)
        self.assertEqual(restarted.javascript_report(item["id"]), original)
        self.assertNotIn(self.key.encode(), restarted.get(item["id"])[3])
        self.assertNotIn(self.key.encode(), self.files.path.read_bytes())
        self.assertTrue(item["javascript"])
        self.files.clear()
        with self.assertRaises(ValueError):
            restarted.javascript_report(item["id"])

    def test_limits_deduplication_and_noise(self):
        text = '\n'.join(f'const a{i}="/api/v1/route{i}";' for i in range(MAX_FINDINGS + 5))
        text += '\nconst key="' + self.key + '";'
        report = analyze_javascript(text, "large.mjs")
        self.assertTrue(report["truncated"])
        self.assertEqual(report["summary"]["total"], MAX_FINDINGS)
        self.assertEqual(report["summary"]["secrets"], 1)
        noise = analyze_javascript('const a="/api/v1/users"; const b="/api/v1/users"; const c="./lib/helper.js"; const d="https://www.w3.org/schema";', "small.js")
        self.assertEqual(noise["summary"]["endpoints"], 1)
        self.assertEqual(noise["summary"]["urls"], 0)
        with self.assertRaises(ValueError):
            analyze_javascript("a" * 120_001, "too-large.js")
        for text in ("a" * 120_001, "\x00binary"):
            with self.assertRaises(ValueError):
                self.upload("invalid.js", text)

    def test_supplied_javascript_is_data_and_non_js_files_cannot_be_analyzed(self):
        source = 'throw new Error("must not execute"); fetch("https://service.acme.invalid/collect");'
        with patch("urllib.request.urlopen", side_effect=AssertionError("No network")), patch("subprocess.run", side_effect=AssertionError("No shell")), patch.object(Path, "read_text", side_effect=AssertionError("No file reads")):
            report = analyze_javascript(source, "script.js")
        self.assertEqual(report["summary"]["urls"], 1)
        item = self.upload("notes.txt", source)
        with self.assertRaises(ValueError):
            self.files.javascript_report(item["id"])
        with self.assertRaises(ValueError):
            self.files.javascript_report("../../settings.json")

    def test_skill_is_available_but_only_selected_discuss_receives_report(self):
        engine = Engine(Store(self.root / "chat.sqlite3"))
        item = engine.attachments.add("bundle.js", base64.b64encode(b'const route="/api/v1/profile";').decode())
        catalog = public_catalog(self.root)
        self.assertIn("analyze-js", {entry["id"] for entry in catalog})
        self.assertIn("cannot override Burp scope", render_skill_prompt(self.root, ["analyze-js"]))
        for selected in ((), ("analyze-js",)):
            engine.clear()
            item = engine.attachments.add("bundle.js", base64.b64encode(b'const route="/api/v1/profile";').decode())
            cfg = Config(model="local", selected_skills=selected, custom_models=({"id":"local", "model":"fixture", "url":"http://127.0.0.1:8000/v1"},))
            with patch("agent_b_harness.engine.config.load", return_value=cfg), patch("agent_b_harness.engine.Model") as model, patch("agent_b_harness.engine.DoubleAgent", side_effect=AssertionError("No Burp actions")):
                model.return_value.complete.return_value = {"content":"Static reference only."}
                engine.chat("Review the supplied JavaScript", attachment_ids=[item["id"]], discussion=True)
                engine.thread.join(3)
                self.assertFalse(engine.thread.is_alive())
                args = model.return_value.complete.call_args.args
                self.assertEqual([t["function"]["name"] for t in args[1]], ["request_public_reference"])
                self.assertEqual(args[3], "auto")
                self.assertEqual(engine.state, "completed")
                self.assertEqual("Offline JavaScript analysis" in json.dumps(args[0]), bool(selected))
                self.assertEqual("analyze-js static review methodology" in args[0][0]["content"], bool(selected))


if __name__ == "__main__":
    unittest.main()
