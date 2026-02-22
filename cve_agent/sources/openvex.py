from __future__ import annotations

import json
from pathlib import Path


def load_openvex_map(path: str | None) -> dict[str, str]:
    if not path:
        return {}

    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return {}

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

    statements = payload.get("statements", []) if isinstance(payload, dict) else []
    mapped: dict[str, str] = {}

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        status = str(stmt.get("status", "")).strip().lower()
        if not status:
            continue

        for vuln in stmt.get("vulnerabilities", []):
            cve_id = str(vuln).strip().upper()
            if not cve_id:
                continue
            mapped[cve_id] = status

    return mapped
