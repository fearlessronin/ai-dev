from __future__ import annotations

import json
from pathlib import Path


class StateStore:
    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_file.exists():
            self._write({"seen": []})

    def seen_ids(self) -> set[str]:
        data = self._read()
        return set(data.get("seen", []))

    def mark_seen(self, cve_id: str) -> None:
        data = self._read()
        seen = set(data.get("seen", []))
        seen.add(cve_id)
        self._write({"seen": sorted(seen)})

    def _read(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            return {"seen": []}

    def _write(self, data: dict) -> None:
        self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
