from __future__ import annotations

import json
import mimetypes
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


DOC_MAP = {
    "overview": "APP_OVERVIEW.md",
    "runbook": "RUNBOOK.md",
}


def _find_listeners_for_port(port: int) -> list[tuple[str, int]]:
    """Return (local_address, pid) tuples for listeners on the requested TCP port."""
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


def serve(
    frontend_dir: Path,
    output_dir: Path,
    docs_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = unquote(self.path.split("?", 1)[0])
            if path in {"/", "/index.html"}:
                return self._send_file(frontend_dir / "index.html")
            if path.startswith("/assets/"):
                rel = path[len("/assets/"):]
                return self._send_file(frontend_dir / rel)
            if path == "/api/findings":
                return self._send_findings()
            if path.startswith("/api/report/"):
                cve_id = path.rsplit("/", 1)[-1]
                return self._send_report(cve_id)
            if path.startswith("/api/docs/"):
                doc_id = path.rsplit("/", 1)[-1]
                return self._send_doc(doc_id)

            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:
            return

        def _send_findings(self) -> None:
            source = output_dir / "findings.jsonl"
            findings = []
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

            findings.sort(key=lambda x: x.get("published", ""), reverse=True)
            payload = json.dumps(findings).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

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

    _warn_existing_listeners(host, port)

    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        raise RuntimeError(
            f"Unable to bind dashboard server to {host}:{port}. "
            f"Another process may already be listening on that port."
        ) from exc

    print(f"Dashboard running at http://{host}:{port}")
    server.serve_forever()
