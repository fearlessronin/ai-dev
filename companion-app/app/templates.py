from __future__ import annotations

from pathlib import Path
import json

from .models import Host, Profile


def _read_template(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _indent(lines: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join((pad + line) if line else line for line in lines.splitlines())


def build_hosts_yaml(hosts: list[Host]) -> str:
    lines: list[str] = []
    for host in hosts:
        groups = host.groups or ["satellites"]
        group_line = json.dumps(groups)
        lines.append(f"{host.name}:")
        lines.append(f"  ansible_host: {host.host}")
        lines.append(f"  ansible_user: {host.user}")
        lines.append(f"  ansible_port: {host.port}")
        if host.ssh_key_path:
            lines.append(f"  ansible_ssh_private_key_file: {host.ssh_key_path}")
        lines.append(f"  companion_groups: {group_line}")
        for k, v in sorted(host.vars.items()):
            value = json.dumps(v) if not isinstance(v, str) else v
            lines.append(f"  {k}: {value}")
    return "\n".join(lines)


def build_group_vars_yaml(profile: Profile) -> str:
    payload = {
        "app_name": "ai-cve-watcher",
        "repo_url": profile.repo_url,
        "repo_branch": profile.repo_branch,
        "remote_app_path": profile.remote_app_path,
        "python_bin": profile.python_bin,
        "service_mode": profile.service_mode,
        "health_url": profile.health_url,
        "playbook": profile.playbook,
        "extra_vars": profile.extra_vars,
    }
    return json.dumps(payload, indent=2)


def render_templates(
    templates_root: Path,
    inventory_template_rel: str,
    vars_template_rel: str,
    output_dir: Path,
    hosts: list[Host],
    profile: Profile,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    inventory_tpl = _read_template(templates_root / Path(inventory_template_rel).name)
    vars_tpl = _read_template(templates_root / Path(vars_template_rel).name)

    inventory_text = (
        inventory_tpl
        .replace("{{PROFILE_NAME}}", profile.name)
        .replace("{{HOSTS_YAML}}", _indent(build_hosts_yaml(hosts), 6))
    )
    vars_text = (
        vars_tpl
        .replace("{{PROFILE_NAME}}", profile.name)
        .replace("{{PROFILE_JSON_VARS}}", _indent(build_group_vars_yaml(profile), 2))
    )

    inventory_out = output_dir / "inventory.generated.yml"
    vars_out = output_dir / "group_vars.all.generated.yml"
    inventory_out.write_text(inventory_text, encoding="utf-8")
    vars_out.write_text(vars_text, encoding="utf-8")
    return {"inventory": inventory_out, "group_vars": vars_out}
