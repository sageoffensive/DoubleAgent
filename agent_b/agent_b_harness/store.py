from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[\x27\"]?[A-Za-z0-9._~-]+[\x27\"]?"),
    re.compile(r"(?i)(bearer\s*:\s*)[\x27\"]?[A-Za-z0-9._~-]+[\x27\"]?"),
    re.compile(r"(?i)((?:api[_ -]?token|api[_ -]?key)\s*[:=]\s*)[\x27\"]?\S+[\x27\"]?"),
    re.compile(r"\b[a-fA-F0-9]{32,}\b"),
    re.compile(r"(?im)^(\s*cookie\s*:\s*)[^\r\n]+"),
)


def redact_text(value: str) -> str:
    text = str(value)
    for index, pattern in enumerate(SECRET_PATTERNS):
        if index < 3:
            text = pattern.sub(lambda match: match.group(1) + "[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if "token" in str(key).lower() or "key" in str(key).lower() else redact_value(item)) for key, item in value.items()}
    return value


def redact_checkpoint_value(value: Any) -> Any:
    """Redact checkpoint secrets without destroying structural fields such as cache_key."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_checkpoint_value(item) for item in value]
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            name = str(key).lower().replace("-", "_").replace(" ", "_")
            secret_field = (
                name in {"token", "api_token", "api_key", "authorization", "cookie", "password", "secret"}
                or name.endswith("_api_token") or name.endswith("_api_key")
            )
            cleaned[key] = "[REDACTED]" if secret_field else redact_checkpoint_value(item)
        return cleaned
    return value


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.RLock()
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS messages (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  role TEXT NOT NULL,
                  content TEXT NOT NULL,
                  metadata TEXT NOT NULL DEFAULT '{}',
                  created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  kind TEXT NOT NULL,
                  data TEXT NOT NULL,
                  created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS questions (
                  id TEXT PRIMARY KEY,
                  question TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  options TEXT NOT NULL,
                  status TEXT NOT NULL,
                  answer TEXT NOT NULL DEFAULT '',
                  created REAL NOT NULL,
                  answered REAL
                );
                CREATE TABLE IF NOT EXISTS goals (
                  id TEXT PRIMARY KEY,
                  objective TEXT NOT NULL,
                  status TEXT NOT NULL,
                  queue_id TEXT NOT NULL DEFAULT '',
                  created REAL NOT NULL,
                  updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_checkpoint (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  data TEXT NOT NULL,
                  updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_traces (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  run_id TEXT NOT NULL,
                  data TEXT NOT NULL,
                  created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lessons (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  kind TEXT NOT NULL,
                  summary TEXT NOT NULL,
                  detail TEXT NOT NULL DEFAULT '',
                  hits INTEGER NOT NULL DEFAULT 1,
                  created REAL NOT NULL,
                  updated REAL NOT NULL
                );
                """
            )
        self._redact_existing()

    def _redact_existing(self) -> None:
        with self.lock, self._connect() as db:
            for row in db.execute("SELECT id,content FROM messages").fetchall():
                clean = redact_text(row["content"])
                if clean != row["content"]:
                    db.execute("UPDATE messages SET content=? WHERE id=?", (clean, row["id"]))
            for row in db.execute("SELECT id,data FROM events").fetchall():
                clean = redact_text(row["data"])
                if clean != row["data"]:
                    db.execute("UPDATE events SET data=? WHERE id=?", (clean, row["id"]))
            for row in db.execute("SELECT id,question,reason,answer FROM questions").fetchall():
                values = tuple(redact_text(row[name]) for name in ("question", "reason", "answer"))
                if values != (row["question"], row["reason"], row["answer"]):
                    db.execute("UPDATE questions SET question=?,reason=?,answer=? WHERE id=?", (*values, row["id"]))

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def message(self, role: str, content: str, metadata: dict[str, Any] | None = None) -> int:
        with self.lock, self._connect() as db:
            row = db.execute(
                "INSERT INTO messages(role,content,metadata,created) VALUES(?,?,?,?)",
                (role, redact_text(content), json.dumps(redact_value(metadata or {})), time.time()),
            )
            return int(row.lastrowid)

    def event(self, kind: str, data: dict[str, Any] | str) -> int:
        payload = redact_text(data) if isinstance(data, str) else json.dumps(redact_value(data))
        with self.lock, self._connect() as db:
            row = db.execute(
                "INSERT INTO events(kind,data,created) VALUES(?,?,?)",
                (kind, payload, time.time()),
            )
            return int(row.lastrowid)

    def messages(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._message(row) for row in reversed(rows)]

    def events(self, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        with self.lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (after, limit)
            ).fetchall()
        return [self._event(row) for row in rows]

    def ask(self, question: str, reason: str, options: list[str]) -> str:
        qid = uuid.uuid4().hex
        question = redact_text(question)
        reason = redact_text(reason)
        options = [redact_text(item) for item in options]
        with self.lock, self._connect() as db:
            db.execute(
                "INSERT INTO questions(id,question,reason,options,status,created) VALUES(?,?,?,?,?,?)",
                (qid, question, reason, json.dumps(options), "pending", time.time()),
            )
        self.event("question", {"id": qid, "question": question, "reason": reason, "options": options})
        return qid

    def answer(self, qid: str, answer: str) -> bool:
        with self.lock, self._connect() as db:
            row = db.execute(
                "UPDATE questions SET status='answered',answer=?,answered=? WHERE id=? AND status='pending'",
                (answer, time.time(), qid),
            )
            changed = row.rowcount == 1
        if changed:
            self.event("answer", {"id": qid, "answer": answer})
        return changed

    def pending(self) -> dict[str, Any] | None:
        with self.lock, self._connect() as db:
            row = db.execute(
                "SELECT * FROM questions WHERE status='pending' ORDER BY created DESC LIMIT 1"
            ).fetchone()
        return self._question(row) if row else None

    def question(self, qid: str) -> dict[str, Any] | None:
        with self.lock, self._connect() as db:
            row = db.execute("SELECT * FROM questions WHERE id=?", (qid,)).fetchone()
        return self._question(row) if row else None

    def clear(self) -> None:
        with self.lock, self._connect() as db:
            db.execute("DELETE FROM messages")
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM questions")
            db.execute("DELETE FROM run_checkpoint")

    def save_checkpoint(self, value: dict[str, Any]) -> None:
        payload = json.dumps(redact_checkpoint_value(value), ensure_ascii=False, separators=(",", ":"))
        with self.lock, self._connect() as db:
            db.execute(
                "INSERT INTO run_checkpoint(id,data,updated) VALUES(1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated=excluded.updated",
                (payload, time.time()),
            )

    def load_checkpoint(self) -> dict[str, Any] | None:
        with self.lock, self._connect() as db:
            row = db.execute("SELECT data FROM run_checkpoint WHERE id=1").fetchone()
        if not row:
            return None
        try:
            value = json.loads(row["data"])
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def clear_checkpoint(self) -> None:
        with self.lock, self._connect() as db:
            db.execute("DELETE FROM run_checkpoint WHERE id=1")

    def save_trace(self, trace: dict[str, Any]) -> str:
        """Persist a first-class run trace. Traces and lessons are cross-run
        infrastructure and are intentionally kept when the session is cleared."""
        run_id = str(trace.get("run_id") or uuid.uuid4().hex)
        trace = {**trace, "run_id": run_id}
        payload = json.dumps(redact_checkpoint_value(trace), ensure_ascii=False, separators=(",", ":"))
        with self.lock, self._connect() as db:
            db.execute(
                "INSERT INTO run_traces(run_id,data,created) VALUES(?,?,?)",
                (run_id, payload, time.time()),
            )
        return run_id

    def traces(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM run_traces ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        result = []
        for row in rows:
            try:
                data = json.loads(row["data"])
            except ValueError:
                data = {}
            result.append({"id": row["id"], "run_id": row["run_id"], "created": row["created"], **data})
        return result

    def add_lesson(self, kind: str, summary: str, detail: str = "") -> dict[str, Any]:
        """Record a durable lesson. A repeat of the same (kind, summary) bumps a
        hit counter instead of duplicating, so recurring failures rank higher."""
        kind = redact_text(str(kind)).strip()[:60] or "general"
        summary = redact_text(str(summary)).strip()[:300]
        detail = redact_text(str(detail)).strip()[:1000]
        if not summary:
            raise ValueError("A lesson needs a summary")
        now = time.time()
        with self.lock, self._connect() as db:
            row = db.execute(
                "SELECT id,hits FROM lessons WHERE kind=? AND summary=?", (kind, summary)
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE lessons SET hits=hits+1,updated=?,detail=CASE WHEN ?<>'' THEN ? ELSE detail END WHERE id=?",
                    (now, detail, detail, row["id"]),
                )
                lid = row["id"]
            else:
                cur = db.execute(
                    "INSERT INTO lessons(kind,summary,detail,hits,created,updated) VALUES(?,?,?,1,?,?)",
                    (kind, summary, detail, now, now),
                )
                lid = int(cur.lastrowid)
        self.event("lesson", {"kind": kind, "summary": summary})
        return {"id": lid, "kind": kind, "summary": summary, "detail": detail}

    def lessons(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM lessons ORDER BY hits DESC, updated DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"id": row["id"], "kind": row["kind"], "summary": row["summary"],
             "detail": row["detail"], "hits": row["hits"], "updated": row["updated"]}
            for row in rows
        ]

    def active_goal(self) -> dict[str, Any] | None:
        with self.lock, self._connect() as db:
            row = db.execute(
                "SELECT * FROM goals WHERE status='active' ORDER BY updated DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def create_goal(self, objective: str, queue_id: str = "") -> dict[str, Any]:
        objective = redact_text(objective).strip()
        if not objective:
            raise ValueError("Goal objective is required")
        existing = self.active_goal()
        if existing:
            if existing["objective"] == objective:
                return existing
            raise ValueError("A different persistent goal is already active")
        goal_id = uuid.uuid4().hex
        now = time.time()
        with self.lock, self._connect() as db:
            db.execute(
                "INSERT INTO goals(id,objective,status,queue_id,created,updated) VALUES(?,?,?,?,?,?)",
                (goal_id, objective, "active", str(queue_id), now, now),
            )
        return self.active_goal() or {}

    def update_goal(self, status: str) -> dict[str, Any]:
        if status not in {"complete", "blocked"}:
            raise ValueError("Goal status must be complete or blocked")
        goal = self.active_goal()
        if not goal:
            raise ValueError("No active persistent goal")
        with self.lock, self._connect() as db:
            db.execute("UPDATE goals SET status=?,updated=? WHERE id=?", (status, time.time(), goal["id"]))
            row = db.execute("SELECT * FROM goals WHERE id=?", (goal["id"],)).fetchone()
        return dict(row)

    @staticmethod
    def _message(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "role": row["role"], "content": row["content"],
            "metadata": json.loads(row["metadata"]), "created": row["created"],
        }

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        try:
            data = json.loads(row["data"])
        except ValueError:
            data = row["data"]
        return {"id": row["id"], "kind": row["kind"], "data": data, "created": row["created"]}

    @staticmethod
    def _question(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "question": row["question"], "reason": row["reason"],
            "options": json.loads(row["options"]), "status": row["status"],
            "answer": row["answer"], "created": row["created"],
        }
