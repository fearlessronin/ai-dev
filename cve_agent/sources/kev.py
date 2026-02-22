from __future__ import annotations

import time
from typing import Any

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient:
    def __init__(self, timeout_seconds: int = 30, cache_ttl_minutes: int = 15) -> None:
        self._timeout = timeout_seconds
        self._cache_ttl_seconds = max(60, cache_ttl_minutes * 60)
        self._cached_at = 0.0
        self._cached_catalog: dict[str, dict[str, Any]] = {}

    def fetch_catalog(self) -> dict[str, dict[str, Any]]:
        now = time.monotonic()
        if self._cached_catalog and (now - self._cached_at) < self._cache_ttl_seconds:
            return self._cached_catalog

        payload = self._get_json_with_retry(KEV_URL)
        if not isinstance(payload, dict):
            return self._cached_catalog

        mapped: dict[str, dict[str, Any]] = {}
        for vuln in payload.get("vulnerabilities", []):
            cve_id = str(vuln.get("cveID", "")).strip().upper()
            if not cve_id:
                continue
            mapped[cve_id] = vuln

        if mapped:
            self._cached_catalog = mapped
            self._cached_at = now

        return self._cached_catalog

    def _get_json_with_retry(self, url: str) -> dict[str, Any] | None:
        delay = 0.2
        for attempt in range(3):
            try:
                response = requests.get(url, timeout=self._timeout)
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict):
                    return data
                return None
            except requests.RequestException:
                if attempt == 2:
                    return None
                time.sleep(delay)
                delay *= 2
        return None
