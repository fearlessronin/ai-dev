from __future__ import annotations

import time

import requests


GHSA_URL = "https://api.github.com/advisories"


class GHSAClient:
    def __init__(self, token: str | None = None, timeout_seconds: int = 20) -> None:
        self._token = token
        self._timeout = timeout_seconds

    def fetch_by_cves(self, cve_ids: list[str]) -> dict[str, list[dict]]:
        mapped: dict[str, list[dict]] = {}
        for cve_id in sorted({c.strip().upper() for c in cve_ids if c}):
            advisories = self._fetch_single(cve_id)
            if advisories:
                mapped[cve_id] = advisories
        return mapped

    def _fetch_single(self, cve_id: str) -> list[dict]:
        headers = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        for key in ("cve_id", "cve"):
            payload = self._get_json_with_retry(headers=headers, params={key: cve_id})
            if isinstance(payload, list) and payload:
                return [row for row in payload if isinstance(row, dict)]
        return []

    def _get_json_with_retry(self, headers: dict[str, str], params: dict[str, str]) -> list | dict | None:
        delay = 0.2
        for attempt in range(3):
            try:
                response = requests.get(GHSA_URL, headers=headers, params=params, timeout=self._timeout)
                if response.status_code != 200:
                    return None
                return response.json()
            except requests.RequestException:
                if attempt == 2:
                    return None
                time.sleep(delay)
                delay *= 2
        return None
