from __future__ import annotations

import json
import time
from typing import Any

import requests

MSRC_API_CVE_URLS = [
    "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{cve_id}",
    "https://api.msrc.microsoft.com/cvrf/v3.0/cve/{cve_id}",
]
MSRC_HTML_URL = "https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"


class MSRCClient:
    def __init__(self, timeout_seconds: int = 12) -> None:
        self._timeout = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json, text/html;q=0.8"})

    def fetch_records(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for cve_id in sorted({c.strip().upper() for c in cve_ids if c}):
            record = self._fetch_one(cve_id)
            if record:
                out[cve_id] = record
        return out

    def _fetch_one(self, cve_id: str) -> dict[str, Any] | None:
        for template in MSRC_API_CVE_URLS:
            url = template.format(cve_id=cve_id)
            payload = self._get_json(url)
            if isinstance(payload, dict) and payload:
                return {"source": "MSRC", "url": url, "kind": "api", "payload": payload}

        html_url = MSRC_HTML_URL.format(cve_id=cve_id)
        text = self._get_text(html_url)
        if text and cve_id in text.upper():
            return {"source": "MSRC", "url": html_url, "kind": "html", "payload": {}}
        return None

    def _get_json(self, url: str) -> dict[str, Any] | None:
        delay = 0.2
        for attempt in range(2):
            try:
                r = self._session.get(url, timeout=self._timeout)
                if r.status_code != 200:
                    return None
                try:
                    data = r.json()
                except json.JSONDecodeError:
                    return None
                return data if isinstance(data, dict) else None
            except requests.RequestException:
                if attempt == 1:
                    return None
                time.sleep(delay)
                delay *= 2
        return None

    def _get_text(self, url: str) -> str | None:
        try:
            r = self._session.get(url, timeout=self._timeout)
            if r.status_code != 200:
                return None
            return r.text
        except requests.RequestException:
            return None
