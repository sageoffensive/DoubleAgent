"""Provider-reported output throughput; never infer tokens from stream chunks."""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any


def output_tokens(usage: Any) -> int | None:
    if not isinstance(usage, dict):
        return None
    for key in ("completion_tokens", "output_tokens", "outputTokens"):
        count = usage.get(key)
        if type(count) is int and count >= 0:
            return count
    return None


def union_seconds(intervals: list[tuple[float, float]]) -> float:
    total = 0.0
    end = None
    for start, stop in sorted(intervals):
        if stop <= start:
            continue
        total += max(0.0, stop - max(start, end if end is not None else start))
        end = max(stop, end if end is not None else stop)
    return total


class Throughput:
    def __init__(self, on_record=None, clock=time.monotonic):
        self.lock = threading.RLock()
        self.clock = clock
        self.on_record = on_record
        self.reset()

    def reset(self):
        with self.lock:
            self.run = uuid.uuid4().hex[:12]
            self.requests: dict[str, dict] = {}

    def begin(self, actor: str, connection: str) -> str:
        with self.lock:
            ident = self.run + "-" + str(len(self.requests) + 1)
            self.requests[ident] = {"actor": actor, "connection": connection,
                                    "start": self.clock(), "end": None,
                                    "output_tokens": None, "invalid_usage": False, "status": "running"}
            return ident

    def usage(self, ident: str, usage: Any):
        count = output_tokens(usage)
        if count is None:
            return
        with self.lock:
            row = self.requests.get(ident)
            if row is None or row["end"] is not None:
                return
            previous = row["output_tokens"]
            if previous is not None and count < previous:
                row["invalid_usage"] = True
            row["output_tokens"] = count

    def finish(self, ident: str, status: str):
        with self.lock:
            row = self.requests.get(ident)
            if row is None or row["end"] is not None:
                return
            row.update(end=self.clock(), status=status)
            if row["invalid_usage"]:
                row["output_tokens"] = None
            record = {"request_id": ident, "actor": row["actor"], "connection": row["connection"],
                      "status": status, "output_tokens": row["output_tokens"],
                      "duration_seconds": round(max(0, row["end"] - row["start"]), 6)}
        if self.on_record:
            try:
                self.on_record(record)
            except Exception:
                pass  # A metrics sink must never interrupt assessment/model work.

    @staticmethod
    def _summary(rows: list[dict]) -> dict:
        finished = [row for row in rows if row["end"] is not None]
        known = [row for row in finished if row["output_tokens"] is not None]
        seconds = union_seconds([(row["start"], row["end"]) for row in finished])
        tokens = sum(row["output_tokens"] for row in known)
        missing = len(finished) - len(known)
        return {"requests": len(rows), "active_requests": len(rows) - len(finished),
                "finished_requests": len(finished), "reported_requests": len(known), "missing_usage": missing,
                "output_tokens": tokens, "model_wall_seconds": round(seconds, 6),
                "aggregate_tps": round(tokens / seconds, 3) if finished and not missing and seconds > 0 else None,
                "state": "unavailable" if missing else "measured" if finished and seconds > 0 else "awaiting_usage" if rows else "idle"}

    def public(self) -> dict:
        with self.lock:
            rows = list(self.requests.values())
            actors = {actor: dict(self._summary([row for row in rows if row["actor"] == actor]),
                                  connection=next(row["connection"] for row in rows if row["actor"] == actor))
                      for actor in dict.fromkeys(row["actor"] for row in rows)}
            return {**self._summary(rows), "actors": actors, "basis": "completed_model_requests",
                    "definition": "Server-reported output tokens / union of completed model request wall times. Includes prefill and network time; overlapping calls count once. No chunk/token estimates. In-flight calls are excluded until finished; missing final usage makes the aggregate unavailable."}
