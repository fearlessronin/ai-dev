from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ensure_paths, get_paths, read_state, utc_now, write_state
from .gitops import execute_git_sync, plan_git_sync
from .models import load_hosts, load_profile
from .runner import build_ansible_command, shell_preview, write_run_plan
from .templates import render_templates


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Companion app for satellite Git+Ansible orchestration")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create runtime folders and state file")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--hosts", type=Path, required=True, help="Path to hosts json")
    common.add_argument("--profile", type=Path, required=True, help="Path to profile json")
    common.add_argument("--limit", type=str, default=None, help="Ansible --limit override")
    common.add_argument("--all-hosts", action="store_true", help="Include disabled hosts")

    sub.add_parser("render", parents=[common], help="Render inventory and vars to runtime/generated")

    plan = sub.add_parser("plan-run", parents=[common], help="Render + print Git and ansible commands")
    plan.add_argument("--no-check", action="store_true", help="Disable ansible --check mode")

    sync = sub.add_parser("sync-repo", parents=[common], help="Plan or execute automation repo sync")
    sync.add_argument("--execute", action="store_true", help="Actually run git sync command")

    return p


def _load_enabled_hosts(hosts_path: Path, include_disabled: bool) -> list:
    hosts = load_hosts(hosts_path)
    return hosts if include_disabled else [h for h in hosts if h.enabled]


def cmd_init() -> int:
    paths = get_paths()
    ensure_paths(paths)
    print(f"Initialized runtime at {paths.runtime}")
    print(f"State file: {paths.state_file}")
    return 0


def _render_bundle(args: argparse.Namespace) -> tuple[dict[str, Path], object, list]:
    paths = get_paths()
    ensure_paths(paths)
    profile = load_profile(args.profile)
    hosts = _load_enabled_hosts(args.hosts, args.all_hosts)
    if not hosts:
        raise SystemExit("No hosts selected (all disabled or invalid).")
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
    return rendered, profile, hosts


def cmd_render(args: argparse.Namespace) -> int:
    rendered, profile, hosts = _render_bundle(args)
    print(f"Rendered profile: {profile.name}")
    print(f"Hosts: {', '.join(h.name for h in hosts)}")
    print(f"Inventory: {rendered['inventory']}")
    print(f"Group vars: {rendered['group_vars']}")
    return 0


def cmd_plan_run(args: argparse.Namespace) -> int:
    paths = get_paths()
    rendered, profile, hosts = _render_bundle(args)
    git_cmd = plan_git_sync(profile, paths.root)
    check_mode = not args.no_check if args.no_check is not None else profile.check_mode_default
    ansible_cmd = build_ansible_command(
        profile=profile,
        inventory_path=rendered["inventory"],
        generated_vars_path=rendered["group_vars"],
        limit=args.limit,
        check_mode=check_mode,
    )
    run_stamp = utc_now().replace(":", "-")
    run_dir = paths.runs / run_stamp
    plan_path = write_run_plan(
        run_dir,
        git_cmd,
        ansible_cmd,
        metadata={"profile": profile.name, "hosts": [h.name for h in hosts], "created_at": utc_now()},
    )
    print("Git sync command:")
    print(f"  {shell_preview(git_cmd)}")
    print("Ansible command:")
    print(f"  {shell_preview(ansible_cmd)}")
    print(f"Run plan written to: {plan_path}")
    return 0


def cmd_sync_repo(args: argparse.Namespace) -> int:
    paths = get_paths()
    ensure_paths(paths)
    profile = load_profile(args.profile)
    _ = _load_enabled_hosts(args.hosts, args.all_hosts)
    git_cmd = plan_git_sync(profile, paths.root)
    print("Git sync command:")
    print(f"  {shell_preview(git_cmd)}")
    if not args.execute:
        print("Dry-run only. Pass --execute to run git sync.")
        return 0
    result = execute_git_sync(git_cmd, cwd=paths.root)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode
    state = read_state(paths)
    state["last_sync"] = {"at": utc_now(), "command": git_cmd}
    write_state(paths, state)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        return cmd_init()
    if args.command == "render":
        return cmd_render(args)
    if args.command == "plan-run":
        return cmd_plan_run(args)
    if args.command == "sync-repo":
        return cmd_sync_repo(args)
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
