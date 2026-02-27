from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class AppPaths:
    root: Path
    runtime: Path
    generated: Path
    runs: Path
    state_file: Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def get_paths() -> AppPaths:
    root = repo_root()
    runtime = root / "runtime"
    generated = runtime / "generated"
    runs = runtime / "runs"
    state = runtime / "state.json"
    return AppPaths(root=root, runtime=runtime, generated=generated, runs=runs, state_file=state)


def ensure_paths(paths: AppPaths) -> None:
    paths.runtime.mkdir(parents=True, exist_ok=True)
    paths.generated.mkdir(parents=True, exist_ok=True)
    paths.runs.mkdir(parents=True, exist_ok=True)
    if not paths.state_file.exists():
        paths.state_file.write_text(
            json.dumps({"created_at": utc_now(), "last_render": None, "last_sync": None}, indent=2),
            encoding="utf-8",
        )


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def read_state(paths: AppPaths) -> dict:
    if not paths.state_file.exists():
        return {}
    try:
        return json.loads(paths.state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_state(paths: AppPaths, payload: dict) -> None:
    paths.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
