"""Offline release smoke check, using only the app's bundled Python.

Run: python3 tests/smoke_macos_bundle.py 'dist/Agent B.app'
This is a fresh-settings check, not a replacement for a clean-Mac UI install.
"""
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


@contextmanager
def burp_fixture():
    """Synthetic local API: any write or unexpected read fails the smoke check."""
    calls = []

    class FixtureHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append(("GET", self.path))
            path = self.path.split("?", 1)[0]
            payloads = {
                "/api/health": {"status": "ok"},
                "/api/agent/prompt": {"prompt": "Synthetic read-only release fixture. " * 12},
                "/api/agent/burp/workspace": {"scope": {"observed_urls": ["https://example.test/"]}},
                "/api/findings": {"findings": [{"id": "daf_bundle_fixture", "legacy_numeric_id": 3, "title": "Captured fixture finding",
                    "url": "https://example.test/", "evidence_preview": "Synthetic captured evidence"}], "total": 1},
                "/api/agent/queue": {"queue": []},
            }
            self.send_response(200 if path in payloads else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payloads.get(path, {"ok": False})).encode())

        def do_POST(self):
            calls.append(("POST", self.path))
            self.send_error(405)

    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    app = Path(sys.argv[1]).resolve()
    resources = app / "Contents/Resources"
    runtime = resources / "python/bin/python3"
    assert runtime.is_file(), "Missing bundled runtime"
    assert not (resources / "model-auth.json").exists(), "Credentials must not be bundled"
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with burp_fixture() as (burp_url, burp_calls), tempfile.TemporaryDirectory(prefix="agent-b-bundle-smoke-") as data:
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "AGENT_B_DATA_DIR": data,
            "DOUBLE_AGENT_URL": burp_url,
            "SSL_CERT_FILE": str(resources / "python/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem"),
        }
        process = subprocess.Popen(
            [str(runtime), "-E", "-s", "-B", "-m", "agent_b_harness.server",
             "--no-browser", "--port", str(port)],
            cwd=resources / "harness", env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "Bundled server exited before startup"
                try:
                    with urllib.request.urlopen(base + "/api/settings", timeout=1) as reply:
                        settings = json.load(reply)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Bundled server failed to start")
                    time.sleep(0.1)
            assert settings["model_options"] == [], "Fresh install must have no built-in connections"
            with urllib.request.urlopen(base, timeout=2) as reply:
                page = reply.read()
                assert b"Attach files" in page
                assert b'id="settings-tab-models"' in page
                assert b'id="settings-tab-skills"' in page
                assert b'aria-label="Agent B version">v' in page
                assert b"{{AGENT_B_VERSION}}" not in page
                assert b'id="javascript-dialog"' in page
                assert b'id="pane-conversation"' in page
                assert b'id="tab-notebook"' not in page and b'id="tab-assessment"' not in page
                assert b'id="validate-a"' not in page
            with urllib.request.urlopen(base + "/api/notebook", timeout=2) as reply:
                notebook = json.load(reply)
            assert notebook["burp_context_enabled"] is False
            update = urllib.request.Request(base + "/api/notebook", data=json.dumps({
                "revision": notebook["revision"], "objective": "Harmless notebook smoke check",
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(update, timeout=2) as reply:
                assert json.load(reply)["objective"] == "Harmless notebook smoke check"
            with urllib.request.urlopen(base + "/api/notebook/export", timeout=2) as reply:
                assert b"Harmless notebook smoke check" in reply.read()
            request = urllib.request.Request(base + "/api/connect/burp", data=b"{}",
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as reply:
                connection = json.load(reply)
            assert connection["connected"] and connection["findings_available"]
            assert connection["read_only_status"] == "ready"
            with urllib.request.urlopen(base + "/api/notebook", timeout=2) as reply:
                notebook = json.load(reply)
            assert notebook["burp_context_enabled"] is True
            assert notebook["objective"] == "Harmless notebook smoke check"
            assert notebook["snapshot"]["findings"]["items"][0]["id"] == "daf_bundle_fixture"
            assert notebook["snapshot"]["captured_at"] > 0
            assert len(burp_calls) == 5
            assert all(method == "GET" for method, _ in burp_calls)
            assert {path.split("?")[0] for _, path in burp_calls} == {
                "/api/agent/prompt", "/api/agent/burp/workspace", "/api/findings", "/api/agent/queue"}
            with urllib.request.urlopen(base + "/api/export", timeout=2) as reply:
                assert b"Would you like me to verify Agent A's findings, or what else would you like me to do?" in reply.read()
            with urllib.request.urlopen(base + "/research.html", timeout=2) as reply:
                page = reply.read()
                assert reply.url == base + "/", "Legacy research page must return to chat"
                assert b'id="source-review-panel"' not in page
                assert b'id="target-link"' in page
                assert b'aria-label="Agent B version">v' in page
                assert b"{{AGENT_B_VERSION}}" not in page
                assert b'id="pane-conversation"' in page
                assert b'id="tab-notebook"' not in page and b'id="tab-assessment"' not in page
            with urllib.request.urlopen(base + "/api/research", timeout=2) as reply:
                assert json.load(reply)["notes"] == [], "Fresh research notebook must be empty"
            source_request = urllib.request.Request(base + "/api/research/start", data=json.dumps({
                "kind": "upload", "files": [{"name": "example.py", "data": base64.b64encode(b"value = 42").decode()}],
            }).encode(), headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(source_request, timeout=2)
                raise AssertionError("Removed research endpoint must not start work")
            except urllib.error.HTTPError as error:
                assert error.code == 410
            fixture = b"Harmless release smoke-test note."
            request = urllib.request.Request(base + "/api/files", data=json.dumps({
                "name": "smoke.txt", "data": base64.b64encode(fixture).decode(),
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as reply:
                assert reply.status == 201
                file_id = json.load(reply)["id"]
            with urllib.request.urlopen(base + "/api/files/" + file_id, timeout=2) as reply:
                assert reply.read() == fixture
                assert reply.headers["Content-Disposition"].startswith("attachment;")
                assert reply.headers["X-Content-Type-Options"] == "nosniff"
            with urllib.request.urlopen(base + "/api/skills", timeout=2) as reply:
                assert any(item["id"] == "analyze-js" for item in json.load(reply)["skills"])
            javascript = b'const route="/api/v1/profile"; throw new Error("never execute uploaded source");'
            request = urllib.request.Request(base + "/api/files", data=json.dumps({
                "name": "bundle.js", "data": base64.b64encode(javascript).decode(),
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as reply:
                javascript_id = json.load(reply)["id"]
            report_path = base + "/api/files/" + javascript_id + "/javascript"
            with urllib.request.urlopen(report_path, timeout=2) as reply:
                report = json.load(reply)
                assert report["summary"]["endpoints"] == 1
                assert report["findings"]["endpoints"][0]["value"] == "/api/v1/profile"
            with urllib.request.urlopen(report_path + "/download", timeout=2) as reply:
                assert json.load(reply) == report
                assert reply.headers["Content-Disposition"].startswith("attachment;")
            print("PASS: bundle signature, isolated runtime, empty settings, UI, automatic read-only findings on connect, notebook persistence/export, local uploads/downloads, removed research endpoint, offline JavaScript report/export")
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    main()
