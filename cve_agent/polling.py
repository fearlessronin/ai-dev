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
        self._queued_source_runs: list[str] = []
        self._source_cooldown_seconds = 60
        self._source_last_manual_trigger: dict[str, str] = {}

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

    def trigger_now(self, origin: str = "manual_api") -> dict[str, Any]:
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
        data["trigger_origin"] = origin
        return data

    def trigger_source(self, source: str, origin: str = "manual_api") -> dict[str, Any]:
        source_name = str(source or "").strip().lower()
        valid_sources = set(self.watcher.supported_poll_sources())
        if source_name not in valid_sources:
            data = self.status()
            data["trigger_result"] = "invalid_source"
            data["message"] = f"unsupported source: {source_name or source}"
            return data

        trigger_result = "queued"
        message = f"source poll queued: {source_name}"
        with self._lock:
            cooldown_remaining = self._cooldown_remaining_locked(source_name)
            if self._is_polling:
                trigger_result = "already_running"
                message = "poll already in progress"
            elif cooldown_remaining > 0:
                trigger_result = "cooldown_active"
                message = f"source cooldown active: {source_name} ({cooldown_remaining}s)"
            elif source_name in self._queued_source_runs:
                trigger_result = "already_queued"
                message = f"source already queued: {source_name}"
            else:
                self._queued_source_runs.append({"source": source_name, "origin": origin})
                self._mark_manual_source_trigger_locked(source_name)
                self._persist_locked()
        if trigger_result == "queued":
            self._wake_event.set()
        data = self.status()
        data["trigger_result"] = trigger_result
        data["message"] = message
        data["requested_source"] = source_name
        data["trigger_origin"] = origin
        return data

    def retry_history_entry(self, history_index: int, origin: str = "manual_ui_retry") -> dict[str, Any]:
        with self._lock:
            if history_index < 0 or history_index >= len(self._history):
                data = self._status_dict_locked()
                data["trigger_result"] = "invalid_history_index"
                data["message"] = f"invalid history index: {history_index}"
                return data
            entry = dict(self._history[history_index])
        if entry.get("poll_kind") == "source" and entry.get("source"):
            return self.trigger_source(str(entry.get("source")), origin=origin)
        failed_sources = [str(x) for x in entry.get("failed_sources", []) if str(x)]
        if failed_sources:
            return self.trigger_source(failed_sources[0], origin=origin)
        return self.trigger_now(origin=origin)

    def status(self) -> dict[str, Any]:
        with self._lock:
            data = self._status_dict_locked()
        runtime = self.watcher.get_poll_runtime_status()
        with self._lock:
            data["sources"] = self._annotate_sources_with_controls_locked(runtime.get("sources", {}))
        return data

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            should_run = False
            source_run: str | None = None
            source_origin = "manual_api"
            wait_seconds = 1.0

            with self._lock:
                now = time.monotonic()
                source_run = None
                if self._force_run:
                    should_run = True
                    self._force_run = False
                elif self._queued_source_runs:
                    queued_source = self._queued_source_runs.pop(0)
                    if isinstance(queued_source, dict):
                        source_run = str(queued_source.get("source", "")).strip().lower() or None
                        source_origin = str(queued_source.get("origin", "manual_api") or "manual_api")
                    else:
                        source_run = str(queued_source).strip().lower() or None
                        source_origin = "manual_api"
                    should_run = False
                elif self._enabled and now >= self._next_run_at_monotonic:
                    should_run = True
                elif self._enabled:
                    wait_seconds = max(1.0, min(5.0, self._next_run_at_monotonic - now))
                else:
                    wait_seconds = 5.0

            if should_run:
                self._run_cycle()
                continue
            if source_run:
                self._run_source_cycle(source_run, trigger_origin=source_origin)
                continue

            self._wake_event.wait(wait_seconds)
            self._wake_event.clear()

    def _run_source_cycle(self, source_name: str, trigger_origin: str = "manual_api") -> None:
        with self._lock:
            self._is_polling = True
            self._last_cycle_started = _utc_now_iso()
            self._last_cycle_error = None
            self._persist_locked()

        try:
            records = self.watcher.poll_source(source_name)
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
                    poll_kind="source",
                    source=source_name,
                    trigger_origin=trigger_origin,
                )
                self._persist_locked()
            return

        completed = _utc_now_iso()
        duration_ms = self._cycle_duration_ms(self._last_cycle_started, completed)
        with self._lock:
            self._last_new_findings = 0
            self._last_cycle_completed = completed
            self._last_cycle_error = None
            self._is_polling = False
            self._append_history_locked(
                status="ok",
                started=self._last_cycle_started,
                completed=completed,
                duration_ms=duration_ms,
                new_findings=0,
                error="",
                poll_kind="source",
                source=source_name,
                records_polled=int(records),
                trigger_origin=trigger_origin,
            )
            self._persist_locked()

    def _run_cycle(self) -> None:
        with self._lock:
            self._is_polling = True
            self._last_cycle_started = _utc_now_iso()
            self._last_cycle_error = None
            self._persist_locked()

        inferred_full_origin = "auto_schedule"
        with self._lock:
            if self._last_cycle_completed is None and self._enabled:
                inferred_full_origin = "startup_auto"
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
                    poll_kind="full",
                    trigger_origin=inferred_full_origin,
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
                poll_kind="full",
                trigger_origin=inferred_full_origin,
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
        poll_kind: str = "full",
        source: str | None = None,
        records_polled: int | None = None,
        trigger_origin: str | None = None,
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
            "poll_kind": poll_kind,
            "source": source,
            "records_polled": records_polled,
            "trigger_origin": trigger_origin,
            "failed_sources": failed_sources,
            "source_counts": source_counts,
        }
        self._history.insert(0, entry)
        if len(self._history) > self._history_limit:
            del self._history[self._history_limit :]

    def _cooldown_remaining_locked(self, source: str) -> int:
        last = self._source_last_manual_trigger.get(source)
        if not last:
            return 0
        try:
            last_dt = datetime.fromisoformat(last)
            now_dt = datetime.now(UTC).replace(microsecond=0)
            elapsed = int((now_dt - last_dt).total_seconds())
        except ValueError:
            return 0
        return max(0, self._source_cooldown_seconds - max(0, elapsed))

    def _mark_manual_source_trigger_locked(self, source: str) -> None:
        self._source_last_manual_trigger[source] = _utc_now_iso()

    def _annotate_sources_with_controls_locked(self, runtime_sources: dict[str, Any]) -> dict[str, Any]:
        annotated: dict[str, Any] = {}
        for name, row in runtime_sources.items():
            payload = dict(row or {})
            cooldown = self._cooldown_remaining_locked(str(name))
            payload["cooldown_remaining_seconds"] = cooldown
            payload["last_manual_trigger"] = self._source_last_manual_trigger.get(str(name))
            payload["queued"] = str(name) in self._queued_source_runs
            annotated[str(name)] = payload
        return annotated

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
            "source_cooldown_seconds": self._source_cooldown_seconds,
            "queued_sources": [q.get("source") if isinstance(q, dict) else q for q in self._queued_source_runs],
            "history": list(self._history),
        }

    def _persist_locked(self) -> None:
        payload = deepcopy(self._status_dict_locked())
        payload["sources"] = self._annotate_sources_with_controls_locked(
            self.watcher.get_poll_runtime_status().get("sources", {})
        )
        payload["source_last_manual_trigger"] = dict(self._source_last_manual_trigger)
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
                        "poll_kind": str(item.get("poll_kind", "full") or "full"),
                        "source": (str(item.get("source")) if item.get("source") is not None else None),
                        "records_polled": item.get("records_polled"),
                        "trigger_origin": item.get("trigger_origin"),
                        "failed_sources": [str(x) for x in item.get("failed_sources", []) if str(x)],
                        "source_counts": item.get("source_counts", {})
                        if isinstance(item.get("source_counts"), dict)
                        else {},
                    }
                )
            self._history = normalized

        cooldown = payload.get("source_cooldown_seconds")
        if isinstance(cooldown, int):
            self._source_cooldown_seconds = max(0, cooldown)

        source_last_manual_trigger = payload.get("source_last_manual_trigger")
        if isinstance(source_last_manual_trigger, dict):
            self._source_last_manual_trigger = {str(k): str(v) for k, v in source_last_manual_trigger.items() if str(k)}

        queued_sources = payload.get("queued_sources")
        if isinstance(queued_sources, list):
            self._queued_source_runs = [
                {"source": str(x).strip().lower(), "origin": "manual_api"} for x in queued_sources if str(x).strip()
            ]
