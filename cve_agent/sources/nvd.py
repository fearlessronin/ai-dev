from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from ..models import CVEItem


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    def __init__(self, api_key: str | None = None, timeout_seconds: int = 30) -> None:
        self._api_key = api_key
        self._timeout = timeout_seconds

    def fetch_last_days(self, days: int) -> list[CVEItem]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

        params = {
            "pubStartDate": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "pubEndDate": end.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "resultsPerPage": 2000,
        }
        headers = {"User-Agent": "ai-cve-watcher/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        response = requests.get(NVD_URL, params=params, headers=headers, timeout=self._timeout)
        response.raise_for_status()
        payload = response.json()

        vulnerabilities = payload.get("vulnerabilities", [])
        return [self._parse_entry(v) for v in vulnerabilities]

    def _parse_entry(self, entry: dict[str, Any]) -> CVEItem:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        descriptions = cve.get("descriptions", [])
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        cwes: list[str] = []
        for weak in cve.get("weaknesses", []):
            for desc in weak.get("description", []):
                value = desc.get("value", "")
                if value:
                    cwes.append(value)

        metrics = cve.get("metrics", {})
        cvss_v31 = None
        cvss_vector = None
        if metrics.get("cvssMetricV31"):
            metric = metrics["cvssMetricV31"][0]
            cvss_data = metric.get("cvssData", {})
            cvss_v31 = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")

        return CVEItem(
            cve_id=cve_id,
            published=published,
            last_modified=modified,
            description=description,
            references=refs,
            cwes=cwes,
            cvss_v31_base=cvss_v31,
            cvss_v31_vector=cvss_vector,
            raw=entry,
        )
