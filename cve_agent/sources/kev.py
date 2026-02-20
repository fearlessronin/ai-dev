from __future__ import annotations

from typing import Any

import requests


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient:
    def __init__(self, timeout_seconds: int = 30) -> None:
        self._timeout = timeout_seconds

    def fetch_catalog(self) -> dict[str, dict[str, Any]]:
        response = requests.get(KEV_URL, timeout=self._timeout)
        response.raise_for_status()
        payload = response.json()

        mapped: dict[str, dict[str, Any]] = {}
        for vuln in payload.get("vulnerabilities", []):
            cve_id = str(vuln.get("cveID", "")).strip().upper()
            if not cve_id:
                continue
            mapped[cve_id] = vuln

        return mapped
