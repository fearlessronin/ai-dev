from __future__ import annotations

import time

import requests


OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class OSVClient:
    def __init__(self, timeout_seconds: int = 30) -> None:
        self._timeout = timeout_seconds

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict]:
        normalized = sorted({c.strip().upper() for c in cve_ids if c})
        if not normalized:
            return {}

        records = self._fetch_records_batch(normalized)
        missing = [cve_id for cve_id in normalized if cve_id not in records]
        if missing:
            records.update(self._fetch_records_single(missing))
        return records

    def _fetch_records_batch(self, cve_ids: list[str]) -> dict[str, dict]:
        records: dict[str, dict] = {}
        batch_size = 100
        for idx in range(0, len(cve_ids), batch_size):
            batch = cve_ids[idx : idx + batch_size]
            payload = {"queries": [{"cve": cve_id} for cve_id in batch]}
            data = self._request_json_with_retry("post", OSV_QUERY_BATCH_URL, json_payload=payload)
            if not data:
                continue

            results = data.get("results", [])
            for cve_id, row in zip(batch, results):
                vulns = row.get("vulns", []) if isinstance(row, dict) else []
                if vulns:
                    records[cve_id] = vulns[0]
        return records

    def _fetch_records_single(self, cve_ids: list[str]) -> dict[str, dict]:
        records: dict[str, dict] = {}
        for cve_id in cve_ids:
            data = self._request_json_with_retry("get", f"{OSV_VULN_URL}/{cve_id}")
            if data:
                records[cve_id] = data
        return records

    def _request_json_with_retry(
        self,
        method: str,
        url: str,
        json_payload: dict | None = None,
    ) -> dict | None:
        delay = 0.2
        for attempt in range(3):
            try:
                if method == "post":
                    response = requests.post(url, json=json_payload, timeout=self._timeout)
                else:
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
