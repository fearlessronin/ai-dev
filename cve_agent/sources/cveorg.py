from __future__ import annotations

import requests


CVE_ORG_URL = "https://cveawg.mitre.org/api/cve"


class CVEOrgClient:
    def __init__(self, timeout_seconds: int = 30) -> None:
        self._timeout = timeout_seconds

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict]:
        records: dict[str, dict] = {}
        for cve_id in sorted({c.strip().upper() for c in cve_ids if c}):
            try:
                response = requests.get(f"{CVE_ORG_URL}/{cve_id}", timeout=self._timeout)
                if response.status_code != 200:
                    continue
                payload = response.json()
                records[cve_id] = payload
            except requests.RequestException:
                continue
        return records
