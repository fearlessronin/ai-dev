from __future__ import annotations

from pathlib import Path
import subprocess

from .models import Profile


class GitSyncError(RuntimeError):
    pass


def plan_git_sync(profile: Profile, workspace_root: Path) -> list[str]:
    repo_cache = (workspace_root / profile.repo_cache_path).resolve()
    if repo_cache.exists():
        return [
            "git",
            "-C",
            str(repo_cache),
            "pull",
            "origin",
            profile.repo_branch,
        ]
    return [
        "git",
        "clone",
        "--branch",
        profile.repo_branch,
        profile.repo_url,
        str(repo_cache),
    ]


def execute_git_sync(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, check=False)
    except OSError as exc:
        raise GitSyncError(str(exc)) from exc
