from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Profile


@dataclass
class RunPlan:
    ansible_command: list[str]
    run_record_path: Path


def build_ansible_command(
    profile: Profile,
    inventory_path: Path,
    generated_vars_path: Path,
    limit: str | None,
    check_mode: bool,
) -> list[str]:
    cmd = [
        "ansible-playbook",
        "-i",
        str(inventory_path),
        profile.playbook,
        "-e",
        f"@{generated_vars_path}",
    ]
    effective_limit = limit or profile.ansible_limit
    if effective_limit:
        cmd.extend(["--limit", effective_limit])
    if check_mode:
        cmd.append("--check")
    return cmd


def write_run_plan(run_dir: Path, git_cmd: list[str], ansible_cmd: list[str], metadata: dict) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "run_plan.json"
    payload = {
        "git_command": git_cmd,
        "ansible_command": ansible_cmd,
        "metadata": metadata,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def execute_ansible(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, check=False)


def shell_preview(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)
