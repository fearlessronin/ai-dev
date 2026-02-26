from __future__ import annotations

import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from .config import ensure_paths, get_paths, read_state, utc_now, write_state
from .gitops import plan_git_sync
from .models import load_hosts, load_profile
from .runner import build_ansible_command, write_run_plan
from .templates import render_templates

MAX_RECENT = 20


def _json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _text_response(
    handler: BaseHTTPRequestHandler,
    text: str,
    content_type: str = "text/plain; charset=utf-8",
    status: int = 200,
) -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def _list_recent_dirs(path: Path) -> list[Path]:
    if not path.exists():
        return []
    dirs = [p for p in path.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.name, reverse=True)
    return dirs[:MAX_RECENT]


def _load_run_plan(path: Path) -> dict[str, Any] | None:
    plan_file = path / "run_plan.json"
    if not plan_file.exists():
        return None
    try:
        payload = _read_json(plan_file)
    except Exception:
        return None
    payload["_dir"] = path.name
    payload["_path"] = str(plan_file)
    return payload


def _example_paths(root: Path) -> dict[str, Path]:
    cfg = root / "config"
    return {
        "hosts_example": cfg / "hosts.example.json",
        "profile_example": cfg / "profile.cve-radar.example.json",
        "satellite_spec_json": cfg / "satellite-spec.sample.json",
        "satellite_spec_yml": cfg / "satellite-spec.sample.yml",
    }


def _path_meta(path: Path) -> dict[str, Any]:
    meta = {"path": str(path), "exists": path.exists()}
    if path.exists():
        st = path.stat()
        meta["size_bytes"] = st.st_size
        meta["modified_utc"] = utc_now() if False else None
        meta["modified_epoch_ns"] = st.st_mtime_ns
    return meta


def _selected_hosts(hosts_path: Path, include_disabled: bool = False):
    hosts = load_hosts(hosts_path)
    return hosts if include_disabled else [h for h in hosts if h.enabled]


def _infer_environment(groups: list[str]) -> str | None:
    lowered = [g.lower() for g in groups]
    for env in ("prod", "production", "staging", "stage", "dev", "qa", "test"):
        if env in lowered:
            return env
    return None


def _registry_satellite_rows(hosts_path: Path) -> list[dict[str, Any]]:
    if not hosts_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for h in load_hosts(hosts_path):
        groups = list(h.groups or [])
        rows.append(
            {
                "source": "hosts_registry",
                "name": h.name,
                "enabled": h.enabled,
                "host": h.host,
                "user": h.user,
                "port": h.port,
                "groups": groups,
                "environment": _infer_environment(groups),
                "os_family": None,
                "os_distribution": None,
                "transport": "ssh",
                "auth_type": "ssh_key" if h.ssh_key_path else None,
                "ssh_key_path": h.ssh_key_path,
                "remote_app_path": (h.vars or {}).get("remote_app_path"),
                "app_port": (h.vars or {}).get("app_port"),
                "service_manager": (h.vars or {}).get("service_manager"),
            }
        )
    return rows


def _spec_json_satellite_rows(spec_json_path: Path) -> list[dict[str, Any]]:
    if not spec_json_path.exists():
        return []
    try:
        payload = _read_json(spec_json_path)
    except Exception:
        return []
    items = payload.get("satellite_hosts", []) if isinstance(payload, dict) else []
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        conn = item.get("connection", {}) if isinstance(item.get("connection"), dict) else {}
        vars_map = item.get("vars", {}) if isinstance(item.get("vars"), dict) else {}
        groups = [str(g) for g in item.get("groups", []) if str(g).strip()]
        rows.append(
            {
                "source": "satellite_spec_json",
                "name": str(item.get("name", "")).strip() or None,
                "enabled": bool(item.get("enabled", True)),
                "host": conn.get("host"),
                "user": conn.get("user"),
                "port": conn.get("port"),
                "groups": groups,
                "environment": _infer_environment(groups) or (payload.get("project", {}) or {}).get("environment"),
                "os_family": item.get("os_family"),
                "os_distribution": item.get("os_distribution"),
                "transport": conn.get("transport"),
                "auth_type": conn.get("auth_type"),
                "ssh_key_path": conn.get("ssh_key_path"),
                "remote_app_path": vars_map.get("remote_app_path"),
                "app_port": vars_map.get("app_port"),
                "service_manager": vars_map.get("service_manager"),
            }
        )
    return [r for r in rows if r.get("name")]


def _summarize_satellites(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    enabled = sum(1 for r in rows if r.get("enabled") is not False)
    disabled = total - enabled
    groups = Counter()
    envs = Counter()
    transports = Counter()
    auth_types = Counter()
    os_families = Counter()
    names = []
    for r in rows:
        names.append(str(r.get("name") or ""))
        for g in r.get("groups") or []:
            groups[str(g)] += 1
        if r.get("environment"):
            envs[str(r["environment"])] += 1
        if r.get("transport"):
            transports[str(r["transport"])] += 1
        if r.get("auth_type"):
            auth_types[str(r["auth_type"])] += 1
        if r.get("os_family"):
            os_families[str(r["os_family"])] += 1
    duplicates = [name for name, count in Counter([n for n in names if n]).items() if count > 1]
    return {
        "total": total,
        "enabled": enabled,
        "disabled": disabled,
        "group_counts": dict(groups),
        "environment_counts": dict(envs),
        "transport_counts": dict(transports),
        "auth_type_counts": dict(auth_types),
        "os_family_counts": dict(os_families),
        "duplicate_names": duplicates,
    }


def _satellite_snapshot(ex: dict[str, Path]) -> dict[str, Any]:
    registry_rows = _registry_satellite_rows(ex["hosts_example"])
    spec_json_rows = _spec_json_satellite_rows(ex["satellite_spec_json"])
    merged = sorted(
        registry_rows + spec_json_rows,
        key=lambda r: (str(r.get("name") or ""), str(r.get("source") or "")),
    )
    return {
        "files": {
            "hosts_registry": _path_meta(ex["hosts_example"]),
            "satellite_spec_json": _path_meta(ex["satellite_spec_json"]),
            "satellite_spec_yml": _path_meta(ex["satellite_spec_yml"]),
        },
        "registry": {
            "summary": _summarize_satellites(registry_rows),
            "rows": registry_rows,
        },
        "spec_json": {
            "summary": _summarize_satellites(spec_json_rows),
            "rows": spec_json_rows,
        },
        "combined": {
            "summary": _summarize_satellites(merged),
            "rows": merged,
        },
    }


def _render_with_examples() -> dict[str, Any]:
    paths = get_paths()
    ensure_paths(paths)
    ex = _example_paths(paths.root)
    profile = load_profile(ex["profile_example"])
    hosts = _selected_hosts(ex["hosts_example"])
    if not hosts:
        raise RuntimeError("No enabled hosts in hosts.example.json")

    stamp = utc_now().replace(":", "-")
    out_dir = paths.generated / stamp
    rendered = render_templates(
        templates_root=paths.root / "templates",
        inventory_template_rel=profile.inventory_template,
        vars_template_rel=profile.vars_template,
        output_dir=out_dir,
        hosts=hosts,
        profile=profile,
    )
    state = read_state(paths)
    state["last_render"] = {"at": utc_now(), "output_dir": str(out_dir)}
    write_state(paths, state)
    return {
        "profile_name": profile.name,
        "hosts": [h.name for h in hosts],
        "rendered": {k: str(v) for k, v in rendered.items()},
    }


def _plan_with_examples() -> dict[str, Any]:
    paths = get_paths()
    bundle = _render_with_examples()
    ex = _example_paths(paths.root)
    profile = load_profile(ex["profile_example"])
    git_cmd = plan_git_sync(profile, paths.root)
    ansible_cmd = build_ansible_command(
        profile=profile,
        inventory_path=Path(bundle["rendered"]["inventory"]),
        generated_vars_path=Path(bundle["rendered"]["group_vars"]),
        limit=None,
        check_mode=profile.check_mode_default,
    )
    run_stamp = utc_now().replace(":", "-")
    run_dir = paths.runs / run_stamp
    plan_path = write_run_plan(
        run_dir,
        git_cmd,
        ansible_cmd,
        metadata={
            "profile": profile.name,
            "hosts": bundle["hosts"],
            "created_at": utc_now(),
            "source": "ui_plan_example",
        },
    )
    return {
        "git_command": git_cmd,
        "ansible_command": ansible_cmd,
        "run_plan_path": str(plan_path),
        "rendered": bundle["rendered"],
        "hosts": bundle["hosts"],
        "profile_name": profile.name,
    }

def _overview() -> dict[str, Any]:
    paths = get_paths()
    ensure_paths(paths)
    ex = _example_paths(paths.root)
    state = read_state(paths)
    generated_dirs = _list_recent_dirs(paths.generated)
    run_dirs = _list_recent_dirs(paths.runs)
    run_plans = [p for p in (_load_run_plan(d) for d in run_dirs) if p is not None]

    samples: dict[str, Any] = {}
    for key, path in ex.items():
        item: dict[str, Any] = {"path": str(path), "exists": path.exists()}
        if path.exists():
            if path.suffix.lower() == ".json":
                try:
                    item["json"] = _read_json(path)
                except Exception as exc:
                    item["error"] = str(exc)
            else:
                item["text"] = _read_text(path)
        samples[key] = item

    return {
        "app": {
            "name": "companion-app-ui",
            "root": str(paths.root),
            "runtime": str(paths.runtime),
            "now_utc": utc_now(),
        },
        "state": state,
        "recent_generated": [str(d) for d in generated_dirs],
        "recent_run_plans": run_plans,
        "samples": samples,
        "satellites": _satellite_snapshot(ex),
    }


def serve_ui(host: str = "127.0.0.1", port: int = 8091) -> None:
    paths = get_paths()
    ensure_paths(paths)
    web_dir = paths.root / "web"
    index_path = web_dir / "index.html"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            route = unquote(self.path.split("?", 1)[0])
            if route in {"/", "/index.html"}:
                if not index_path.exists():
                    return _text_response(self, "UI file not found", status=404)
                return _text_response(self, _read_text(index_path), content_type="text/html; charset=utf-8")
            if route == "/api/overview":
                try:
                    return _json_response(self, _overview())
                except Exception as exc:
                    return _json_response(self, {"error": str(exc)}, status=500)
            if route == "/api/run-plan":
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                dir_name = (qs.get("dir") or [""])[0]
                plan_path = paths.runs / dir_name / "run_plan.json"
                if not dir_name or not plan_path.exists():
                    return _json_response(self, {"error": "run plan not found"}, status=404)
                return _json_response(self, _read_json(plan_path))
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            route = unquote(self.path.split("?", 1)[0])
            try:
                if route == "/api/actions/init":
                    ensure_paths(paths)
                    return _json_response(
                        self,
                        {"ok": True, "runtime": str(paths.runtime), "state_file": str(paths.state_file)},
                    )
                if route == "/api/actions/render-example":
                    return _json_response(self, {"ok": True, "result": _render_with_examples()})
                if route == "/api/actions/plan-example":
                    return _json_response(self, {"ok": True, "result": _plan_with_examples()})
            except Exception as exc:
                return _json_response(self, {"ok": False, "error": str(exc)}, status=500)
            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Companion UI listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve thin UI for companion-app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)
    serve_ui(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


