from __future__ import annotations

import re
import time
from urllib.parse import urlparse

import requests

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class RegionalIntelClient:
    def __init__(
        self,
        csaf_feed_urls: list[str],
        rss_urls: list[str],
        jvn_api_template: str,
        timeout_seconds: int = 12,
    ) -> None:
        self._csaf_urls = csaf_feed_urls
        self._rss_urls = rss_urls
        self._jvn_template = jvn_api_template
        self._timeout = timeout_seconds

    def fetch_signals(self, cve_ids: list[str]) -> dict[str, list[str]]:
        normalized = sorted({c.strip().upper() for c in cve_ids if c})
        if not normalized:
            return {}

        mapped: dict[str, set[str]] = {cve_id: set() for cve_id in normalized}

        self._merge_jvn(mapped)
        self._merge_rss(mapped)
        self._merge_csaf(mapped)

        return {k: sorted(v) for k, v in mapped.items() if v}

    def _merge_jvn(self, mapped: dict[str, set[str]]) -> None:
        if not self._jvn_template:
            return

        for cve_id in mapped:
            url = self._jvn_template.replace("{cve_id}", cve_id)
            payload = self._request_text_with_retry(url)
            if payload and cve_id in payload.upper():
                mapped[cve_id].add("JVN")

    def _merge_rss(self, mapped: dict[str, set[str]]) -> None:
        for url in self._rss_urls:
            payload = self._request_text_with_retry(url)
            if not payload:
                continue

            source_name = _source_name(url)
            found = {m.group(0).upper() for m in CVE_PATTERN.finditer(payload)}
            for cve_id in found:
                if cve_id in mapped:
                    mapped[cve_id].add(source_name)

    def _merge_csaf(self, mapped: dict[str, set[str]]) -> None:
        for url in self._csaf_urls:
            payload = self._request_text_with_retry(url)
            if not payload:
                continue

            source_name = _source_name(url)
            found = {m.group(0).upper() for m in CVE_PATTERN.finditer(payload)}
            for cve_id in found:
                if cve_id in mapped:
                    mapped[cve_id].add(source_name)

    def _request_text_with_retry(self, url: str) -> str | None:
        delay = 0.2
        for attempt in range(3):
            try:
                response = requests.get(url, timeout=self._timeout)
                if response.status_code != 200:
                    return None
                return response.text
            except requests.RequestException:
                if attempt == 2:
                    return None
                time.sleep(delay)
                delay *= 2
        return None


def _source_name(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
    except ValueError:
        netloc = url.lower()

    if "jvn" in netloc:
        return "JVN"
    if "cert.europa" in netloc or "certvde" in netloc:
        return "CERT-EU/CSAF"
    if "ncsc" in netloc:
        return "NCSC-NL"
    if "govcert" in netloc:
        return "GovCERT-HK"
    if "hkcert" in netloc:
        return "HKCERT"
    return netloc or "regional-source"
