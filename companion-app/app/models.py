from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


@dataclass
class Host:
    name: str
    host: str
    user: str
    port: int = 22
    groups: list[str] = field(default_factory=list)
    ssh_key_path: str | None = None
    enabled: bool = True
    vars: dict[str, Any] = field(default_factory=dict)


@dataclass
class Profile:
    name: str
    repo_url: str
    repo_branch: str
    repo_cache_path: str
    playbook: str
    remote_app_path: str
    python_bin: str = "python3"
    service_mode: str = "serve"
    health_url: str = "http://127.0.0.1:8080/api/poll/status"
    inventory_template: str = "templates/inventory.yml.j2"
    vars_template: str = "templates/group_vars_all.yml.j2"
    extra_vars: dict[str, Any] = field(default_factory=dict)
    ansible_limit: str | None = None
    check_mode_default: bool = True


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_hosts(path: Path) -> list[Host]:
    raw = _read_json(path)
    items = raw.get("hosts", []) if isinstance(raw, dict) else []
    hosts: list[Host] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        hosts.append(
            Host(
                name=str(item.get("name", "")).strip(),
                host=str(item.get("host", "")).strip(),
                user=str(item.get("user", "")).strip(),
                port=int(item.get("port", 22)),
                groups=[str(g) for g in item.get("groups", []) if str(g).strip()],
                ssh_key_path=(str(item["ssh_key_path"]).strip() if item.get("ssh_key_path") else None),
                enabled=bool(item.get("enabled", True)),
                vars=item.get("vars", {}) if isinstance(item.get("vars", {}), dict) else {},
            )
        )
    return [h for h in hosts if h.name and h.host and h.user]


def load_profile(path: Path) -> Profile:
    raw = _read_json(path)
    return Profile(
        name=str(raw.get("name", "cve-radar-satellite")),
        repo_url=str(raw.get("repo_url", "")),
        repo_branch=str(raw.get("repo_branch", "main")),
        repo_cache_path=str(raw.get("repo_cache_path", "runtime/cache/automation-repo")),
        playbook=str(raw.get("playbook", "playbooks/cve_radar_sync.yml")),
        remote_app_path=str(raw.get("remote_app_path", "/opt/ai-dev")),
        python_bin=str(raw.get("python_bin", "python3")),
        service_mode=str(raw.get("service_mode", "serve")),
        health_url=str(raw.get("health_url", "http://127.0.0.1:8080/api/poll/status")),
        inventory_template=str(raw.get("inventory_template", "templates/inventory.yml.j2")),
        vars_template=str(raw.get("vars_template", "templates/group_vars_all.yml.j2")),
        extra_vars=raw.get("extra_vars", {}) if isinstance(raw.get("extra_vars", {}), dict) else {},
        ansible_limit=(str(raw["ansible_limit"]) if raw.get("ansible_limit") else None),
        check_mode_default=bool(raw.get("check_mode_default", True)),
    )

