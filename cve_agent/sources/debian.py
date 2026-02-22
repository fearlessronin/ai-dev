from __future__ import annotations

import time
from typing import Any

import requests

DEBIAN_TRACKER_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"


class DebianTrackerClient:
    def __init__(self, timeout_seconds: int = 20, cache_ttl_minutes: int = 30) -> None:
        self._timeout = timeout_seconds
        self._ttl_seconds = max(60, cache_ttl_minutes * 60)
        self._cached_at = 0.0
        self._cached_payload: dict[str, Any] = {}

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        normalized = sorted({c.strip().upper() for c in cve_ids if c})
        if not normalized:
            return {}

        payload = self._load_tracker()
        if not payload:
            return {}

        out: dict[str, dict[str, Any]] = {}
        wanted = set(normalized)
        for package_name, package_data in payload.items():
            if not isinstance(package_data, dict):
                continue
            for cve_id, cve_data in package_data.items():
                cve_norm = str(cve_id).upper()
                if cve_norm not in wanted or not isinstance(cve_data, dict):
                    continue
                row = out.setdefault(cve_norm, {"packages": set(), "fixed_versions": set(), "releases": []})
                row["packages"].add(str(package_name))
                releases = cve_data.get("releases", {})
                if isinstance(releases, dict):
                    for rel_name, rel_data in releases.items():
                        if not isinstance(rel_data, dict):
                            continue
                        status = str(rel_data.get("status", "")).strip()
                        fixed_version = str(rel_data.get("fixed_version", "")).strip()
                        if fixed_version and fixed_version not in {"<not-affected>", "0"}:
                            row["fixed_versions"].add(f"{rel_name}:{fixed_version}")
                        row["releases"].append(
                            {
                                "release": str(rel_name),
                                "status": status,
                                "fixed_version": fixed_version,
                            }
                        )

        for _cve_id, row in list(out.items()):
            row["packages"] = sorted(row["packages"])
            row["fixed_versions"] = sorted(row["fixed_versions"])
        return out

    def _load_tracker(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._cached_payload and (now - self._cached_at) < self._ttl_seconds:
            return self._cached_payload

        try:
            r = requests.get(DEBIAN_TRACKER_JSON_URL, timeout=self._timeout)
            if r.status_code != 200:
                return self._cached_payload
            data = r.json()
            if isinstance(data, dict):
                self._cached_payload = data
                self._cached_at = now
        except (requests.RequestException, ValueError):
            return self._cached_payload

        return self._cached_payload


def extract_debian_context(entry: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    sources = ["Debian Security Tracker"]
    packages = [str(x) for x in entry.get("packages", []) if str(x).strip()]
    fixed_versions = [str(x) for x in entry.get("fixed_versions", []) if str(x).strip()]
    return sources, sorted(set(packages)), sorted(set(fixed_versions))
