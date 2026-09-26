from __future__ import annotations

import argparse
import json
import mimetypes
import os
import signal
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import config
from .clients import Model
from .engine import Engine
from .skills import create_skill, public_catalog
from .store import Store


ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
STORE = Store(config.DATA / "agent-b.sqlite3")
ENGINE = Engine(STORE)


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentB/3.0"

    def do_GET(self) -> None:
        if not self.local_request():
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/api/files/"):
            try:
                file_path = parsed.path[len("/api/files/"):]
                preview = file_path.endswith("/preview")
                ident, name, mime, data = ENGINE.attachments.get(file_path[:-8] if preview else file_path)
                if preview:
                    if not mime.startswith("image/"):
                        raise ValueError("Only images have a preview")
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Content-Security-Policy", "default-src 'none'")
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.download(name, data)
            except ValueError as exc:
                self.json({"error": str(exc)}, 404)
            return
        if parsed.path == "/api/export":
            text = "# Agent B conversation\n\n" + "\n\n".join(
                "## " + m["role"].title() + "\n\n" + m["content"] for m in STORE.messages(10000)
                if not m.get("metadata", {}).get("intermediate")
            )
            self.download("agent-b-conversation.md", text.encode("utf-8"))
            return
        if parsed.path.startswith("/api/messages/") and parsed.path.endswith("/download"):
            ident = parsed.path.split("/")[3]
            message = next((m for m in STORE.messages(10000) if str(m["id"]) == ident), None)
            if message is None:
                self.json({"error": "Message not found"}, 404)
            else:
                self.download("agent-b-response-" + ident + ".md", message["content"].encode("utf-8"))
            return
        if parsed.path == "/api/state":
            query = urllib.parse.parse_qs(parsed.query)
            after = int(query.get("after", ["0"])[0])
            stream_after = int(query.get("stream_after", ["0"])[0])
            self.json({
                **ENGINE.public(stream_after),
                "messages": STORE.messages(150),
                "events": STORE.events(after, 250),
                "health": ENGINE.health(),
            })
            return
        if parsed.path == "/api/health":
            self.json({"status": "ok", **ENGINE.health()})
            return
        if parsed.path == "/api/settings":
            self.json(config.load().public())
            return
        if parsed.path == "/api/skills":
            self.json({"skills": public_catalog(config.DATA)})
            return
        if parsed.path == "/api/traces":
            query = urllib.parse.parse_qs(parsed.query)
            limit = max(1, min(200, int(query.get("limit", ["50"])[0])))
            self.json({"traces": STORE.traces(limit)})
            return
        if parsed.path == "/api/lessons":
            query = urllib.parse.parse_qs(parsed.query)
            limit = max(1, min(200, int(query.get("limit", ["50"])[0])))
            self.json({"lessons": STORE.lessons(limit)})
            return
        self.static(parsed.path)

    def do_POST(self) -> None:
        if not self.local_request():
            return
        parsed = urllib.parse.urlsplit(self.path)
        try:
            if self.headers.get_content_type() != "application/json":
                raise ValueError("Requests must use application/json")
            body = self.body()
            if parsed.path == "/api/files":
                self.json(ENGINE.attachments.add(str(body.get("name", "")), str(body.get("data", ""))), 201)
                return
            if parsed.path == "/api/suggestions/decide":
                ident = str(body.get("id", ""))
                if not any(s["id"] == ident for s in ENGINE.suggestions()):
                    raise ValueError("Suggestion is no longer available")
                STORE.decide_suggestion(ident, str(body.get("decision", "")))
                self.json({"ok": True})
                return
            if parsed.path == "/api/chat":
                self.json(ENGINE.chat(str(body.get("message", "")), body.get("thinking"), body.get("attachments", []), body.get("discussion") is True), 202)
                return
            if parsed.path == "/api/run/validate-findings":
                self.json(ENGINE.validate_findings(), 202)
                return
            if parsed.path == "/api/seed":
                self.json(ENGINE.seed_surface(str(body.get("text", "")), str(body.get("kind", "auto"))))
                return
            if parsed.path == "/api/connect/burp":
                self.json(ENGINE.connect_burp())
                return
            if parsed.path.startswith("/api/questions/") and parsed.path.endswith("/answer"):
                qid = parsed.path[len("/api/questions/"):-len("/answer")]
                ENGINE.answer(qid, str(body.get("answer", "")))
                self.json({"ok": True})
                return
            if parsed.path == "/api/run/stop":
                ENGINE.stop()
                self.json({"ok": True}, 202)
                return
            if parsed.path == "/api/run/clear":
                ENGINE.clear()
                self.json({"ok": True})
                return
            if parsed.path == "/api/settings":
                saved = ENGINE.save_settings(body)
                self.json(saved.public())
                return
            if parsed.path == "/api/skills":
                created = create_skill(config.DATA, body)
                self.json({"skill": {key: created[key] for key in ("id", "name", "description", "builtin")}}, 201)
                return
            if parsed.path == "/api/models":
                if ENGINE.thread and ENGINE.thread.is_alive():
                    raise ValueError("Stop the current run before adding a model")
                saved = config.add_custom_model(
                    str(body.get("label", "")), str(body.get("model", "")), str(body.get("url", "")),
                    body.get("supports_thinking") is True, str(body.get("provider", "openai_compatible")),
                    str(body.get("api_key", "")), str(body.get("region", "")),
                    supports_images=body.get("supports_images") is True,
                )
                ENGINE.health_cache = None
                self.json(saved.public(), 201)
                return
            if parsed.path == "/api/models/test":
                if ENGINE.thread and ENGINE.thread.is_alive():
                    raise ValueError("Stop the current run before testing another model connection")
                candidate = config.connection_candidate(body)
                client = Model(
                    candidate["base_url"], candidate["api_key"], candidate["model"],
                    min(config.load().request_timeout, 45), 16, candidate["provider"],
                )
                self.json({**client.test_connection(), "provider": candidate["provider"], "model": candidate["model"]})
                return
            if parsed.path == "/api/models/edit":
                if ENGINE.thread and ENGINE.thread.is_alive():
                    raise ValueError("Stop the current run before editing a model")
                saved = config.edit_custom_model(
                    str(body.get("id", "")), str(body.get("label", "")), str(body.get("model", "")),
                    str(body.get("url", "")), body.get("supports_thinking") if isinstance(body.get("supports_thinking"), bool) else None,
                    str(body.get("provider", "openai_compatible")), str(body.get("api_key", "")), str(body.get("region", "")),
                    supports_images=body.get("supports_images") if isinstance(body.get("supports_images"), bool) else None,
                )
                ENGINE.health_cache = None
                self.json(saved.public())
                return
            if parsed.path == "/api/models/delete":
                if ENGINE.thread and ENGINE.thread.is_alive():
                    raise ValueError("Stop the current run before removing a model")
                saved = config.remove_custom_model(str(body.get("id", "")))
                ENGINE.health_cache = None
                self.json(saved.public())
                return
            self.json({"error": "not found"}, 404)
        except ValueError as exc:
            self.json({"error": str(exc)}, 400)
        except Exception as exc:
            self.json({"error": str(exc)}, 500)

    def body(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length", "0"))
        limit = 4_300_000 if self.path == "/api/files" else 1_000_000
        if size < 0 or size > limit:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(size).decode("utf-8", "replace") if size else "{}"
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def local_request(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            parsed = urllib.parse.urlsplit("http://" + host)
            allowed = parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port == self.server.server_port
        except ValueError:
            allowed = False
        origin = self.headers.get("Origin")
        if not allowed or (origin and origin != "http://" + host) or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.json({"error": "Open Agent B from its local address"}, 403)
            return False
        return True

    def download(self, name: str, data: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(name, safe=""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def json(self, value: Any, status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def static(self, path: str) -> None:
        name = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC / name).resolve()
        if STATIC.resolve() not in target.parents and target != STATIC.resolve():
            self.json({"error": "not found"}, 404)
            return
        if not target.is_file():
            self.json({"error": "not found"}, 404)
            return
        data = target.read_bytes()
        kind = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", kind + ("; charset=utf-8" if kind.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, pattern: str, *args: Any) -> None:
        if os.environ.get("AGENT_B_HTTP_LOG"):
            super().log_message(pattern, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent B harness")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    cfg = config.load()
    port = args.port or cfg.listen_port
    server = ThreadingHTTPServer((cfg.listen_host, port), Handler)
    server.daemon_threads = True

    def stop(*_: Any) -> None:
        ENGINE.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    url = f"http://{cfg.listen_host}:{port}/"
    print(f"Agent B listening at {url}", flush=True)
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
