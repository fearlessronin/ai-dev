from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def http_status(url: str) -> int:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return int(resp.status)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    temp_output = Path(tempfile.mkdtemp(prefix="cve-watch-smoke-"))

    env = dict(os.environ)
    env["OUTPUT_DIR"] = str(temp_output)
    env["STATE_FILE"] = str(temp_output / "state.json")

    subprocess.run(["python", "-m", "cve_agent.cli", "demo"], cwd=str(root), env=env, check=True)

    cmd = [
        "python",
        "-m",
        "cve_agent.cli",
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        "8099",
    ]

    proc = subprocess.Popen(cmd, cwd=str(root), env=env)

    try:
        for _ in range(30):
            try:
                if http_status("http://127.0.0.1:8099/") == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("Dashboard did not start on 127.0.0.1:8099")

        if http_status("http://127.0.0.1:8099/api/findings") != 200:
            raise RuntimeError("/api/findings did not return 200")
        if http_status("http://127.0.0.1:8099/api/docs/runbook") != 200:
            raise RuntimeError("/api/docs/runbook did not return 200")

        with urllib.request.urlopen("http://127.0.0.1:8099/api/findings", timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            if not isinstance(payload, list):
                raise RuntimeError("/api/findings payload is not a list")
            if len(payload) < 1:
                raise RuntimeError("/api/findings returned no records after demo seeding")

        print("Smoke test passed")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(temp_output, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
