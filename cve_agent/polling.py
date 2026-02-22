from __future__ import annotations

import json
import threading
import time
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .runner import CVEWatcher


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class PollController:
    def __init__(
        self,
        watcher: CVEWatcher,
        output_dir: Path,
        interval_minutes: int,
        enabled: bool,
    ) -> None:
        self.watcher = watcher
        self.status_path = output_dir / "poll_status.json"
        self._lock = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._enabled = bool(enabled)
        self._interval_minutes = max(1, int(interval_minutes))
        self._is_polling = False
        self._last_cycle_started: str | None = None
        self._last_cycle_completed: str | None = None
        self._last_cycle_error: str | None = None
        self._last_new_findings = 0
        self._next_run_at_monotonic = 0.0
        self._force_run = bool(enabled)
        self._history_limit = 25
        self._history: list[dict[str, Any]] = []

        self._load()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="poll-controller", daemon=True)
            self._thread.start()
            self._persist_locked()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()

    def update_config(self, enabled: bool, interval_minutes: int) -> dict[str, Any]:
        with self._lock:
            self._enabled = bool(enabled)
            self._interval_minutes = max(1, int(interval_minutes))
            if self._enabled:
                self._force_run = True
                self._next_run_at_monotonic = 0.0
            self._persist_locked()
        self._wake_event.set()
        return self.status()

    def trigger_now(self) -> dict[str, Any]:
        trigger_result = "queued"
        message = "poll queued"
        with self._lock:
            if self._is_polling:
                trigger_result = "already_running"
                message = "poll already in progress"
            elif self._force_run:
                trigger_result = "already_queued"
                message = "poll already queued"
            else:
                self._force_run = True
                self._persist_locked()
        if trigger_result == "queued":
            self._wake_event.set()
        data = self.status()
        data["trigger_result"] = trigger_result
        data["message"] = message
        return data

    def status(self) -> dict[str, Any]:
        with self._lock:
            data = self._status_dict_locked()
        runtime = self.watcher.get_poll_runtime_status()
        data["sources"] = runtime.get("sources", {})
        return data

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            should_run = False
            wait_seconds = 1.0

            with self._lock:
                now = time.monotonic()
                if self._force_run:
                    should_run = True
                    self._force_run = False
                elif self._enabled and now >= self._next_run_at_monotonic:
                    should_run = True
                elif self._enabled:
                    wait_seconds = max(1.0, min(5.0, self._next_run_at_monotonic - now))
                else:
                    wait_seconds = 5.0

            if should_run:
                self._run_cycle()
                continue

            self._wake_event.wait(wait_seconds)
            self._wake_event.clear()

    def _run_cycle(self) -> None:
        with self._lock:
            self._is_polling = True
            self._last_cycle_started = _utc_now_iso()
            self._last_cycle_error = None
            self._persist_locked()

        try:
            new_count = self.watcher.run_once()
        except Exception as exc:
            completed = _utc_now_iso()
            duration_ms = self._cycle_duration_ms(self._last_cycle_started, completed)
            with self._lock:
                self._last_cycle_error = str(exc)
                self._last_cycle_completed = completed
                self._is_polling = False
                self._append_history_locked(
                    status="error",
                    started=self._last_cycle_started,
                    completed=completed,
                    duration_ms=duration_ms,
                    new_findings=0,
                    error=str(exc),
                )
                self._schedule_next_locked()
                self._persist_locked()
            return

        completed = _utc_now_iso()
        duration_ms = self._cycle_duration_ms(self._last_cycle_started, completed)
        with self._lock:
            self._last_new_findings = int(new_count)
            self._last_cycle_completed = completed
            self._last_cycle_error = None
            self._is_polling = False
            self._append_history_locked(
                status="ok",
                started=self._last_cycle_started,
                completed=completed,
                duration_ms=duration_ms,
                new_findings=int(new_count),
                error="",
            )
            self._schedule_next_locked()
            self._persist_locked()

    def _schedule_next_locked(self) -> None:
        if self._enabled:
            self._next_run_at_monotonic = time.monotonic() + (self._interval_minutes * 60)
        else:
            self._next_run_at_monotonic = 0.0

    def _append_history_locked(
        self,
        *,
        status: str,
        started: str | None,
        completed: str | None,
        duration_ms: int | None,
        new_findings: int,
        error: str,
    ) -> None:
        sources = self.watcher.get_poll_runtime_status().get("sources", {})
        failed_sources = sorted([name for name, row in sources.items() if (row or {}).get("status") == "error"])
        source_counts = {name: int((row or {}).get("records") or 0) for name, row in sources.items()}
        entry = {
            "started": started,
            "completed": completed,
            "status": status,
            "duration_ms": duration_ms,
            "new_findings": int(new_findings),
            "error": error,
            "failed_sources": failed_sources,
            "source_counts": source_counts,
        }
        self._history.insert(0, entry)
        if len(self._history) > self._history_limit:
            del self._history[self._history_limit :]

    def _cycle_duration_ms(self, started: str | None, completed: str | None) -> int | None:
        if not started or not completed:
            return None
        try:
            a = datetime.fromisoformat(started)
            b = datetime.fromisoformat(completed)
            return max(0, int((b - a).total_seconds() * 1000))
        except ValueError:
            return None

    def _status_dict_locked(self) -> dict[str, Any]:
        next_run_in_seconds: int | None = None
        if self._enabled and self._next_run_at_monotonic > 0:
            delta = self._next_run_at_monotonic - time.monotonic()
            next_run_in_seconds = max(0, int(delta))

        return {
            "enabled": self._enabled,
            "interval_minutes": self._interval_minutes,
            "is_polling": self._is_polling,
            "last_cycle_started": self._last_cycle_started,
            "last_cycle_completed": self._last_cycle_completed,
            "last_cycle_error": self._last_cycle_error,
            "last_new_findings": self._last_new_findings,
            "next_run_in_seconds": next_run_in_seconds,
            "history": list(self._history),
        }

    def _persist_locked(self) -> None:
        payload = deepcopy(self._status_dict_locked())
        payload["sources"] = self.watcher.get_poll_runtime_status().get("sources", {})
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> None:
        try:
            payload = json.loads(self.status_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return

        if not isinstance(payload, dict):
            return

        enabled = payload.get("enabled")
        interval = payload.get("interval_minutes")
        if isinstance(enabled, bool):
            self._enabled = enabled
        if isinstance(interval, int):
            self._interval_minutes = max(1, interval)

        history = payload.get("history")
        if isinstance(history, list):
            normalized: list[dict[str, Any]] = []
            for item in history[: self._history_limit]:
                if not isinstance(item, dict):
                    continue
                normalized.append(
                    {
                        "started": item.get("started"),
                        "completed": item.get("completed"),
                        "status": str(item.get("status", "unknown")),
                        "duration_ms": item.get("duration_ms"),
                        "new_findings": int(item.get("new_findings", 0) or 0),
                        "error": str(item.get("error", "") or ""),
                        "failed_sources": [str(x) for x in item.get("failed_sources", []) if str(x)],
                        "source_counts": item.get("source_counts", {}) if isinstance(item.get("source_counts"), dict) else {},
                    }
                )
            self._history = normalized
