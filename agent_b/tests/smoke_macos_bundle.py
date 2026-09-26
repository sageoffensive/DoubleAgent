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
                assert b"Attach files" in reply.read()
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
            print("PASS: bundle signature, isolated runtime, empty settings, UI, local upload/download")
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    main()
