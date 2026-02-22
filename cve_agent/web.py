from __future__ import annotations

import csv
import json
import mimetypes
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

if TYPE_CHECKING:
    from .polling import PollController

DOC_MAP = {
    "overview": "APP_OVERVIEW.md",
    "runbook": "RUNBOOK.md",
    "analyst": "ANALYST_GUIDE.md",
    "optimize": "OPTIMIZATION_GUIDE.md",
}

VALID_TRIAGE_STATES = {"new", "investigating", "mitigated", "accepted_risk"}


def _find_listeners_for_port(port: int) -> list[tuple[str, int]]:
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    listeners: list[tuple[str, int]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "LISTEN" not in line.upper():
            continue

        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue

        local_addr = parts[1]
        pid_text = parts[-1]

        try:
            local_port = int(local_addr.rsplit(":", 1)[-1])
            pid = int(pid_text)
        except ValueError:
            continue

        if local_port == port:
            listeners.append((local_addr, pid))

    return listeners


def _warn_existing_listeners(host: str, port: int) -> None:
    current_pid = os.getpid()
    listeners = _find_listeners_for_port(port)
    others = [(addr, pid) for addr, pid in listeners if pid != current_pid]
    if not others:
        return

    print(f"WARNING: Existing listener(s) already detected on TCP port {port} before startup:")
    for addr, pid in sorted(set(others), key=lambda x: x[1]):
        print(f"  - PID {pid} listening on {addr}")
    print(
        "WARNING: This can cause stale responses or route mismatches if multiple dashboard processes run concurrently."
    )
    print(f"WARNING: Intended bind target is {host}:{port}\n")


def _triage_file(output_dir: Path) -> Path:
    return output_dir / "triage.json"


def _read_triage(output_dir: Path) -> dict[str, dict[str, str]]:
    path = _triage_file(output_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    normalized: dict[str, dict[str, str]] = {}
    for cve_id, payload in data.items():
        if not isinstance(payload, dict):
            continue
        state = str(payload.get("state", "new")).strip().lower()
        note = str(payload.get("note", "")).strip()
        if state not in VALID_TRIAGE_STATES:
            state = "new"
        normalized[str(cve_id).upper()] = {"state": state, "note": note}
    return normalized


def _write_triage(output_dir: Path, triage_map: dict[str, dict[str, str]]) -> None:
    path = _triage_file(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(triage_map, indent=2), encoding="utf-8")


def _to_csv(findings: list[dict]) -> str:
    fields = [
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
    ]
    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for f in findings:
        writer.writerow({k: f.get(k) for k in fields})
    return out.getvalue()


def serve(
    frontend_dir: Path,
    output_dir: Path,
    docs_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8080,
    poll_controller: PollController | None = None,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = unquote(self.path.split("?", 1)[0])
            if path in {"/", "/index.html"}:
                return self._send_file(frontend_dir / "index.html")
            if path.startswith("/assets/"):
                rel = path[len("/assets/") :]
                return self._send_file(frontend_dir / rel)
            if path == "/api/findings":
                return self._send_findings()
            if path == "/api/export.csv":
                return self._send_export_csv()
            if path == "/api/poll/status":
                return self._send_poll_status()
            if path.startswith("/api/report/"):
                cve_id = path.rsplit("/", 1)[-1]
                return self._send_report(cve_id)
            if path.startswith("/api/docs/"):
                doc_id = path.rsplit("/", 1)[-1]
                return self._send_doc(doc_id)

            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            path = unquote(self.path.split("?", 1)[0])
            if path.startswith("/api/triage/"):
                cve_id = path.rsplit("/", 1)[-1].strip().upper()
                return self._update_triage(cve_id)
            if path == "/api/poll/config":
                return self._update_poll_config()
            if path == "/api/poll/run":
                return self._run_poll_now()

            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:
            return

        def _read_findings(self) -> list[dict]:
            source = output_dir / "findings.jsonl"
            findings: list[dict] = []
            if source.exists():
                with source.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            triage_map = _read_triage(output_dir)
            for finding in findings:
                cve_id = str(finding.get("cve_id", "")).upper()
                triage = triage_map.get(cve_id, {"state": "new", "note": ""})
                finding["triage_state"] = triage.get("state", finding.get("triage_state", "new"))
                finding["triage_note"] = triage.get("note", finding.get("triage_note", ""))

            findings.sort(key=lambda x: x.get("published", ""), reverse=True)
            return findings

        def _send_findings(self) -> None:
            payload = json.dumps(self._read_findings()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _send_export_csv(self) -> None:
            csv_payload = _to_csv(self._read_findings()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=findings.csv")
            self.send_header("Content-Length", str(len(csv_payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(csv_payload)

        def _send_poll_status(self) -> None:
            if poll_controller is None:
                return self._send_json({"error": "poll controller unavailable"}, status=503)
            return self._send_json(poll_controller.status())

        def _update_poll_config(self) -> None:
            if poll_controller is None:
                return self._send_json({"error": "poll controller unavailable"}, status=503)

            payload = self._read_json_body()
            if payload is None:
                return self._send_json({"error": "invalid JSON body"}, status=400)

            enabled = bool(payload.get("enabled", False))
            interval_raw = payload.get("interval_minutes", 30)
            try:
                interval_minutes = max(1, int(interval_raw))
            except (TypeError, ValueError):
                return self._send_json({"error": "interval_minutes must be an integer"}, status=400)

            status_payload = poll_controller.update_config(enabled=enabled, interval_minutes=interval_minutes)
            return self._send_json(status_payload)

        def _run_poll_now(self) -> None:
            if poll_controller is None:
                return self._send_json({"error": "poll controller unavailable"}, status=503)
            status_payload = poll_controller.trigger_now()
            return self._send_json(status_payload)

        def _update_triage(self, cve_id: str) -> None:
            if not cve_id:
                self.send_response(400)
                self.end_headers()
                return

            payload = self._read_json_body()
            if payload is None:
                self.send_response(400)
                self.end_headers()
                return

            state = str(payload.get("state", "new")).strip().lower()
            note = str(payload.get("note", "")).strip()
            if state not in VALID_TRIAGE_STATES:
                self.send_response(400)
                self.end_headers()
                return

            triage_map = _read_triage(output_dir)
            triage_map[cve_id] = {"state": state, "note": note}
            _write_triage(output_dir, triage_map)

            result = {"ok": True, "cve_id": cve_id, "state": state, "note": note}
            self._send_json(result)

        def _read_json_body(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0

            body = self.rfile.read(max(0, length))
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return None
            return payload if isinstance(payload, dict) else None

        def _send_report(self, cve_id: str) -> None:
            target = output_dir / "reports" / f"{cve_id}.md"
            if not target.exists():
                self.send_response(404)
                self.end_headers()
                return
            self._send_file(target, content_type="text/markdown; charset=utf-8")

        def _send_doc(self, doc_id: str) -> None:
            doc_name = DOC_MAP.get(doc_id)
            if not doc_name:
                self.send_response(404)
                self.end_headers()
                return

            target = docs_dir / doc_name
            if not target.exists():
                self.send_response(404)
                self.end_headers()
                return

            self._send_file(target, content_type="text/markdown; charset=utf-8")

        def _send_file(self, path: Path, content_type: str | None = None) -> None:
            if not path.exists() or not path.is_file():
                self.send_response(404)
                self.end_headers()
                return

            data = path.read_bytes()
            guessed = content_type or (mimetypes.guess_type(path.name)[0] or "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", guessed)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, payload: dict, status: int = 200) -> None:
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

    _warn_existing_listeners(host, port)

    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        raise RuntimeError(
            f"Unable to bind dashboard server to {host}:{port}. Another process may already be listening on that port."
        ) from exc

    print(f"Dashboard running at http://{host}:{port}")
    server.serve_forever()
