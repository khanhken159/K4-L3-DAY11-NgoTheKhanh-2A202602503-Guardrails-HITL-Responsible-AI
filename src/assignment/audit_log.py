"""
Assignment 11 — Audit log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and start a latency timer for the matching output."""
        key = request_id or user_id
        self._open[key] = time.perf_counter()
        self.logs.append({
            "timestamp": utc_now_iso(), "request_id": request_id,
            "user_id": user_id, "input": text, "output": None,
            "blocked": False, "layer": None,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the corresponding audit record and capture elapsed time."""
        key = request_id or user_id
        started = self._open.pop(key, None)
        entry = next((item for item in reversed(self.logs)
                      if item.get("request_id") == request_id
                      and item.get("user_id") == user_id
                      and item.get("output") is None), None)
        if entry is None:
            entry = {"timestamp": utc_now_iso(), "request_id": request_id,
                     "user_id": user_id, "input": None}
            self.logs.append(entry)
        entry.update({"output": text, "blocked": bool(blocked), "layer": layer,
                      "latency_seconds": max(0.0, time.perf_counter() - started)
                      if started is not None else None})

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as audit_file:
            json.dump(self.logs, audit_file, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
