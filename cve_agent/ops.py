from __future__ import annotations

import csv
import json
import threading
import time
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any

FINDINGS_CSV_FIELDS = [
    "cve_id",
    "published",
    "priority_score",
    "evidence_score",
    "change_type",
    "kev_status",
    "epss_score",
    "has_fix",
    "asset_in_scope",
    "triage_state",
    "regional_signal_count",
    "regional_sources",
    "source_corroboration_score",
    "source_confidence_label",
    "source_corroboration_count",
    "regional_escalation_badges",
    "asset_mapping_score",
    "asset_mapping_hits",
    "asset_priority_boost",
    "asset_owners",
    "asset_business_services",
    "asset_routing_summary",
    "patch_availability_summary",
]

POLL_HISTORY_CSV_FIELDS = [
    "started",
    "completed",
    "status",
    "poll_kind",
    "source",
    "trigger_origin",
    "duration_ms",
    "new_findings",
    "records_polled",
    "failed_sources",
    "error",
]


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


class OpsController:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)
        self.exports_dir = self.output_dir / "exports"
        self.config_path = self.output_dir / "ops_config.json"
        self.status_path = self.output_dir / "ops_ops_status.json"
        self.poll_status_path = self.output_dir / "poll_status.json"
        self.findings_path = self.output_dir / "findings.jsonl"

        self._lock = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._config: dict[str, Any] = self._default_config()
        self._is_running = False
        self._last_run_started: str | None = None
        self._last_run_completed: str | None = None
        self._last_run_error: str | None = None
        self._last_run_outputs: list[str] = []
        self._history_limit = 20
        self._history: list[dict[str, Any]] = []
        self._next_run_at_monotonic = 0.0
        self._force_export = False
        self._last_manual_trigger: str | None = None

        self._load()
        with self._lock:
            self._schedule_next_locked()
            self._persist_status_locked()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="ops-controller", daemon=True)
            self._thread.start()
            self._persist_status_locked()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()

    def status(self) -> dict[str, Any]:
        with self._lock:
            data = self._status_dict_locked()
        return data

    def update_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            cfg = deepcopy(self._config)
            notifications = payload.get("notifications")
            if isinstance(notifications, dict):
                n = cfg.setdefault("notifications", {})
                if "enabled" in notifications:
                    n["enabled"] = bool(notifications.get("enabled"))
                channels = notifications.get("channels")
                if isinstance(channels, list):
                    normalized_channels = []
                    for ch in channels:
                        if not isinstance(ch, dict):
                            continue
                        normalized_channels.append(
                            {
                                "type": str(ch.get("type", "webhook") or "webhook"),
                                "name": str(ch.get("name", "default") or "default"),
                                "url": str(ch.get("url", "") or ""),
                                "enabled": bool(ch.get("enabled", True)),
                            }
                        )
                    n["channels"] = normalized_channels
                rules = notifications.get("rules")
                if isinstance(rules, dict):
                    nr = n.setdefault("rules", {})
                    for key in ("high_corroboration_in_scope", "newly_fixed_in_scope", "source_unhealthy"):
                        row = rules.get(key)
                        if not isinstance(row, dict):
                            continue
                        target = nr.setdefault(key, {})
                        if "enabled" in row:
                            target["enabled"] = bool(row.get("enabled"))
                        for num_key in (
                            "min_corroboration_score",
                            "cooldown_minutes",
                            "min_consecutive_failures",
                            "stale_threshold_minutes",
                        ):
                            if num_key in row and row.get(num_key) is not None:
                                try:
                                    target[num_key] = max(0, int(row.get(num_key)))
                                except (TypeError, ValueError):
                                    pass
                        if "require_in_scope" in row:
                            target["require_in_scope"] = bool(row.get("require_in_scope"))

            exports = payload.get("exports")
            if isinstance(exports, dict):
                e = cfg.setdefault("exports", {})
                if "enabled" in exports:
                    e["enabled"] = bool(exports.get("enabled"))
                if "frequency" in exports:
                    freq = str(exports.get("frequency", "daily") or "daily").lower()
                    if freq in {"hourly", "daily"}:
                        e["frequency"] = freq
                for key, default_val, min_val, max_val in (
                    ("hour_utc", e.get("hour_utc", 1), 0, 23),
                    ("minute_utc", e.get("minute_utc", 0), 0, 59),
                ):
                    if key in exports and exports.get(key) is not None:
                        try:
                            val = int(exports.get(key))
                            e[key] = min(max_val, max(min_val, val))
                        except (TypeError, ValueError):
                            e[key] = default_val
                if "formats" in exports and isinstance(exports.get("formats"), list):
                    allowed = {"csv", "json"}
                    selected = [str(x).lower() for x in exports.get("formats", []) if str(x).lower() in allowed]
                    e["formats"] = sorted(set(selected)) or ["json"]
                datasets = exports.get("datasets")
                if isinstance(datasets, dict):
                    d = e.setdefault("datasets", {})
                    for key in ("findings", "poll_history"):
                        if key in datasets:
                            d[key] = bool(datasets.get(key))
                if "output_subdir" in exports:
                    subdir = str(exports.get("output_subdir") or "exports").strip().strip("/\\")
                    e["output_subdir"] = subdir or "exports"

            self._config = cfg
            self._schedule_next_locked()
            self._persist_config_locked()
            self._persist_status_locked()

        self._wake_event.set()
        return self.status()

    def trigger_export_now(self, origin: str = "manual_api") -> dict[str, Any]:
        with self._lock:
            if self._is_running:
                data = self._status_dict_locked()
                data.update({"trigger_result": "already_running", "message": "scheduled export job already running"})
                return data
            if self._force_export:
                data = self._status_dict_locked()
                data.update({"trigger_result": "already_queued", "message": "scheduled export job already queued"})
                return data
            self._force_export = True
            self._last_manual_trigger = origin
            self._persist_status_locked()
        self._wake_event.set()
        data = self.status()
        data.update({"trigger_result": "queued", "message": "scheduled export job queued", "trigger_origin": origin})
        return data

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            should_run = False
            wait_seconds = 5.0
            with self._lock:
                now = time.monotonic()
                if self._force_export:
                    should_run = True
                    self._force_export = False
                elif (
                    self._config.get("exports", {}).get("enabled")
                    and self._next_run_at_monotonic > 0
                    and now >= self._next_run_at_monotonic
                ):
                    should_run = True
                elif self._config.get("exports", {}).get("enabled") and self._next_run_at_monotonic > 0:
                    wait_seconds = max(1.0, min(15.0, self._next_run_at_monotonic - now))
                else:
                    wait_seconds = 15.0
            if should_run:
                self._run_export_cycle()
                continue
            self._wake_event.wait(wait_seconds)
            self._wake_event.clear()

    def _run_export_cycle(self) -> None:
        started_iso = _utc_now_iso()
        with self._lock:
            self._is_running = True
            self._last_run_started = started_iso
            self._last_run_error = None
            self._last_run_outputs = []
            self._persist_status_locked()

        outputs: list[str] = []
        err = ""
        status = "ok"
        try:
            outputs = self._write_scheduled_exports()
        except Exception as exc:  # noqa: BLE001
            status = "error"
            err = str(exc)

        completed_iso = _utc_now_iso()
        duration_ms = self._duration_ms(started_iso, completed_iso)
        with self._lock:
            self._is_running = False
            self._last_run_completed = completed_iso
            self._last_run_error = err or None
            self._last_run_outputs = list(outputs)
            self._append_history_locked(
                {
                    "started": started_iso,
                    "completed": completed_iso,
                    "status": status,
                    "duration_ms": duration_ms,
                    "outputs": list(outputs),
                    "error": err,
                    "trigger_origin": self._last_manual_trigger
                    or ("schedule" if self._config.get("exports", {}).get("enabled") else "manual_api"),
                }
            )
            self._last_manual_trigger = None
            self._schedule_next_locked()
            self._persist_status_locked()

    def _append_history_locked(self, entry: dict[str, Any]) -> None:
        self._history.insert(0, entry)
        if len(self._history) > self._history_limit:
            del self._history[self._history_limit :]

    def _write_scheduled_exports(self) -> list[str]:
        cfg = deepcopy(self._config.get("exports", {}))
        formats = [str(x).lower() for x in cfg.get("formats", ["json"]) if str(x).lower() in {"csv", "json"}]
        formats = sorted(set(formats)) or ["json"]
        datasets = cfg.get("datasets", {}) if isinstance(cfg.get("datasets"), dict) else {}
        include_findings = bool(datasets.get("findings", True))
        include_history = bool(datasets.get("poll_history", True))
        subdir = str(cfg.get("output_subdir", "exports") or "exports").strip().strip("/\\") or "exports"

        ts = _utc_now().strftime("%Y%m%dT%H%M%SZ")
        run_dir = self.output_dir / subdir / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        outputs: list[str] = []

        findings = self._read_findings()
        history = self._read_poll_history()

        if include_findings:
            if "json" in formats:
                path = run_dir / "findings.json"
                path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
                outputs.append(str(path))
            if "csv" in formats:
                path = run_dir / "findings.csv"
                path.write_text(self._findings_to_csv(findings), encoding="utf-8")
                outputs.append(str(path))

        if include_history:
            if "json" in formats:
                path = run_dir / "poll_history.json"
                path.write_text(json.dumps({"history": history}, indent=2), encoding="utf-8")
                outputs.append(str(path))
            if "csv" in formats:
                path = run_dir / "poll_history.csv"
                path.write_text(self._poll_history_to_csv(history), encoding="utf-8")
                outputs.append(str(path))

        if not outputs:
            raise RuntimeError("No export outputs were enabled in ops_config exports.datasets/formats")
        return outputs

    def _read_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not self.findings_path.exists():
            return findings
        with self.findings_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    findings.append(row)
        return findings

    def _read_poll_history(self) -> list[dict[str, Any]]:
        if not self.poll_status_path.exists():
            return []
        try:
            payload = json.loads(self.poll_status_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []
        history = payload.get("history", [])
        return [h for h in history if isinstance(h, dict)] if isinstance(history, list) else []

    def _findings_to_csv(self, findings: list[dict[str, Any]]) -> str:
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=FINDINGS_CSV_FIELDS)
        writer.writeheader()
        for f in findings:
            row = {k: f.get(k) for k in FINDINGS_CSV_FIELDS}
            for key in ("regional_sources", "regional_escalation_badges", "asset_owners", "asset_business_services"):
                if isinstance(row.get(key), list):
                    row[key] = ";".join(str(x) for x in row[key])
            if isinstance(row.get("asset_mapping_hits"), list):
                row["asset_mapping_hits"] = ";".join(
                    str((x or {}).get("matched_value") or (x or {}).get("target") or "")
                    for x in row["asset_mapping_hits"]
                    if isinstance(x, dict)
                )
            writer.writerow(row)
        return out.getvalue()

    def _poll_history_to_csv(self, history: list[dict[str, Any]]) -> str:
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=POLL_HISTORY_CSV_FIELDS)
        writer.writeheader()
        for h in history:
            row = {k: h.get(k) for k in POLL_HISTORY_CSV_FIELDS}
            if isinstance(row.get("failed_sources"), list):
                row["failed_sources"] = ";".join(str(x) for x in row["failed_sources"])
            writer.writerow(row)
        return out.getvalue()

    def _schedule_next_locked(self) -> None:
        exports_cfg = self._config.get("exports", {}) if isinstance(self._config.get("exports"), dict) else {}
        if not exports_cfg.get("enabled"):
            self._next_run_at_monotonic = 0.0
            return

        now = _utc_now()
        frequency = str(exports_cfg.get("frequency", "daily") or "daily").lower()
        hour = int(exports_cfg.get("hour_utc", 1) or 1)
        minute = int(exports_cfg.get("minute_utc", 0) or 0)
        if frequency == "hourly":
            next_dt = (now.replace(second=0, microsecond=0) + timedelta(hours=1)).replace(minute=minute % 60)
            if next_dt <= now:
                next_dt = next_dt + timedelta(hours=1)
        else:
            next_dt = now.replace(hour=max(0, min(23, hour)), minute=max(0, min(59, minute)), second=0, microsecond=0)
            if next_dt <= now:
                next_dt = next_dt + timedelta(days=1)
        delta_seconds = max(1, int((next_dt - now).total_seconds()))
        self._next_run_at_monotonic = time.monotonic() + delta_seconds

    def _status_dict_locked(self) -> dict[str, Any]:
        next_run_in_seconds: int | None = None
        if self._next_run_at_monotonic > 0:
            next_run_in_seconds = max(0, int(self._next_run_at_monotonic - time.monotonic()))
        config_copy = deepcopy(self._config)
        for ch in config_copy.get("notifications", {}).get("channels", []):
            if isinstance(ch, dict) and ch.get("url"):
                ch["url"] = "***redacted***"
        return {
            "config": config_copy,
            "runtime": {
                "is_running": self._is_running,
                "last_run_started": self._last_run_started,
                "last_run_completed": self._last_run_completed,
                "last_run_error": self._last_run_error,
                "last_run_outputs": list(self._last_run_outputs),
                "next_run_in_seconds": next_run_in_seconds,
                "notifications_engine": "config_only",
                "scheduler": "exports",
            },
            "history": list(self._history),
        }

    def _persist_config_locked(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(self._config, indent=2), encoding="utf-8")

    def _persist_status_locked(self) -> None:
        payload = self._status_dict_locked()
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> None:
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            self._config = self._merge_config(self._default_config(), payload)

        try:
            status_payload = json.loads(self.status_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            status_payload = None
        if isinstance(status_payload, dict):
            runtime = status_payload.get("runtime", {}) if isinstance(status_payload.get("runtime"), dict) else {}
            self._last_run_started = runtime.get("last_run_started")
            self._last_run_completed = runtime.get("last_run_completed")
            self._last_run_error = runtime.get("last_run_error")
            outputs = runtime.get("last_run_outputs")
            if isinstance(outputs, list):
                self._last_run_outputs = [str(x) for x in outputs if str(x)]
            history = status_payload.get("history")
            if isinstance(history, list):
                self._history = [dict(x) for x in history[: self._history_limit] if isinstance(x, dict)]

    def _merge_config(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = deepcopy(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self._merge_config(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _default_config(self) -> dict[str, Any]:
        return {
            "notifications": {
                "enabled": False,
                "channels": [{"type": "webhook", "name": "default", "url": "", "enabled": False}],
                "rules": {
                    "high_corroboration_in_scope": {
                        "enabled": False,
                        "min_corroboration_score": 3,
                        "require_in_scope": True,
                        "cooldown_minutes": 60,
                    },
                    "newly_fixed_in_scope": {
                        "enabled": False,
                        "require_in_scope": True,
                        "cooldown_minutes": 120,
                    },
                    "source_unhealthy": {
                        "enabled": False,
                        "min_consecutive_failures": 2,
                        "stale_threshold_minutes": 240,
                        "cooldown_minutes": 30,
                    },
                },
            },
            "exports": {
                "enabled": False,
                "frequency": "daily",
                "hour_utc": 1,
                "minute_utc": 0,
                "formats": ["csv", "json"],
                "datasets": {"findings": True, "poll_history": True},
                "output_subdir": "exports",
            },
        }

    def _duration_ms(self, started_iso: str | None, completed_iso: str | None) -> int | None:
        if not started_iso or not completed_iso:
            return None
        try:
            a = datetime.fromisoformat(started_iso)
            b = datetime.fromisoformat(completed_iso)
            return max(0, int((b - a).total_seconds() * 1000))
        except ValueError:
            return None
