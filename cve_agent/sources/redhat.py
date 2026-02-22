from __future__ import annotations

import time
from typing import Any

import requests

REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"


class RedHatSecurityClient:
    def __init__(self, timeout_seconds: int = 12) -> None:
        self._timeout = timeout_seconds

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for cve_id in sorted({c.strip().upper() for c in cve_ids if c}):
            payload = self._get_json(REDHAT_CVE_URL.format(cve_id=cve_id))
            if isinstance(payload, dict) and payload:
                out[cve_id] = payload
        return out

    def _get_json(self, url: str) -> dict[str, Any] | None:
        delay = 0.2
        for attempt in range(2):
            try:
                r = requests.get(url, timeout=self._timeout)
                if r.status_code != 200:
                    return None
                data = r.json()
                return data if isinstance(data, dict) else None
            except (requests.RequestException, ValueError):
                if attempt == 1:
                    return None
                time.sleep(delay)
                delay *= 2
        return None


def extract_redhat_context(entry: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    sources = ["Red Hat Security Data API"]
    packages: list[str] = []
    fixed_versions: list[str] = []

    for item in entry.get("package_state", []):
        if not isinstance(item, dict):
            continue
        pkg = str(item.get("package_name", "")).strip()
        fix_state = str(item.get("fix_state", "")).strip()
        product = str(item.get("product_name", "")).strip()
        if pkg:
            packages.append(pkg)
        if product:
            packages.append(product)
        if fix_state and fix_state.lower() not in {"", "affected"}:
            fixed_versions.append(f"{pkg or product}: {fix_state}".strip())

    for rel in entry.get("affected_release", []):
        if not isinstance(rel, dict):
            continue
        package = str(rel.get("package", "")).strip()
        advisory = str(rel.get("advisory", "")).strip()
        product = str(rel.get("product_name", "")).strip()
        if package:
            packages.append(package)
        if product:
            packages.append(product)
        if advisory:
            fixed_versions.append(advisory)

    dedup_sources = sorted(set(filter(None, sources)))
    dedup_packages = sorted(set(filter(None, packages)))
    dedup_fixed_versions = sorted(set(filter(None, fixed_versions)))
    return dedup_sources, dedup_packages, dedup_fixed_versions
