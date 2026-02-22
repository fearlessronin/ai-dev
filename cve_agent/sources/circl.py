from __future__ import annotations

import time

import requests

CIRCL_CVE_URL = "https://vulnerability.circl.lu/api/cve"


class CIRCLClient:
    def __init__(self, timeout_seconds: int = 20) -> None:
        self._timeout = timeout_seconds

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict]:
        mapped: dict[str, dict] = {}
        for cve_id in sorted({c.strip().upper() for c in cve_ids if c}):
            payload = self._get_json_with_retry(f"{CIRCL_CVE_URL}/{cve_id}")
            if isinstance(payload, dict):
                mapped[cve_id] = payload
        return mapped

    def _get_json_with_retry(self, url: str) -> dict | None:
        delay = 0.2
        for attempt in range(3):
            try:
                response = requests.get(url, timeout=self._timeout)
                if response.status_code != 200:
                    return None
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
