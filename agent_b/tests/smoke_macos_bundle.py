"""Offline release smoke check, using only the app's bundled Python.

Run: python3 tests/smoke_macos_bundle.py 'dist/Agent B.app'
This is a fresh-settings check, not a replacement for a clean-Mac UI install.
"""
import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


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
    with tempfile.TemporaryDirectory(prefix="agent-b-bundle-smoke-") as data:
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "AGENT_B_DATA_DIR": data,
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
                assert b'id="settings-tab-connections"' in page
                assert b'id="settings-tab-skills"' in page
                assert b'aria-label="Agent B version">v' in page
                assert b"{{AGENT_B_VERSION}}" not in page
            with urllib.request.urlopen(base + "/research.html", timeout=2) as reply:
                page = reply.read()
                assert reply.url == base + "/", "Legacy research page must return to chat"
                assert b'id="source-review-panel"' in page
                assert b'id="target-link-main"' not in page
                assert b'aria-label="Agent B version">v' in page
                assert b"{{AGENT_B_VERSION}}" not in page
            with urllib.request.urlopen(base + "/api/research", timeout=2) as reply:
                assert json.load(reply)["notes"] == [], "Fresh research notebook must be empty"
            source_request = urllib.request.Request(base + "/api/research/start", data=json.dumps({
                "kind": "upload", "files": [{"name": "example.py", "data": base64.b64encode(b"value = 42").decode()}],
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(source_request, timeout=2) as reply:
                research_id = json.load(reply)["id"]
            for attempt in range(30):
                with urllib.request.urlopen(base + "/api/research/" + research_id, timeout=2) as reply:
                    research_note = json.load(reply)
                if research_note["status"] != "running":
                    break
                time.sleep(0.1)
            assert research_note["status"] == "complete", "Research source import failed"
            with urllib.request.urlopen(base + "/api/research/" + research_id + "/download", timeout=2) as reply:
                assert b"value = 42" in reply.read()
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
            print("PASS: bundle signature, isolated runtime, empty settings, UI, local uploads/downloads, research import/export")
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    main()
