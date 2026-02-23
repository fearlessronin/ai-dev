from __future__ import annotations

import re
import time
from dataclasses import dataclass

import requests

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class AdvisoryFeed:
    key: str
    label: str
    url: str


DEFAULT_ADVISORY_FEEDS = {
    "cisa_ics": AdvisoryFeed(
        key="cisa_ics",
        label="CISA ICS Advisory",
        url="https://www.cisa.gov/news-events/cybersecurity-advisories",
    ),
    "certfr": AdvisoryFeed(
        key="certfr",
        label="CERT-FR",
        url="https://www.cert.ssi.gouv.fr/avis/",
    ),
    "ubuntu_usn": AdvisoryFeed(
        key="ubuntu_usn",
        label="Ubuntu Security Notices",
        url="https://ubuntu.com/security/notices",
    ),
    "suse": AdvisoryFeed(
        key="suse",
        label="SUSE Security Advisories",
        url="https://www.suse.com/support/update/",
    ),
    "oracle_cpu": AdvisoryFeed(
        key="oracle_cpu",
        label="Oracle Critical Patch Update",
        url="https://www.oracle.com/security-alerts/",
    ),
    "cisco": AdvisoryFeed(
        key="cisco",
        label="Cisco Security Advisories",
        url="https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    ),
    "bsi": AdvisoryFeed(
        key="bsi",
        label="BSI/CERT-Bund",
        url=(
            "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/"
            "Cyber-Sicherheitslage/Technische-Sicherheitshinweise-und-Warnungen/"
            "Technische-Sicherheitshinweise/technische-sicherheitshinweise_node.html"
        ),
    ),
}


class PublicAdvisoryClient:
    def __init__(self, timeout_seconds: int = 12) -> None:
        self._timeout = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ai-cve-radar/1.0"})

    def fetch_feed_signals(self, cve_ids: list[str], feed_key: str) -> dict[str, list[str]]:
        normalized = sorted({c.strip().upper() for c in cve_ids if c})
        if not normalized:
            return {}

        feed = DEFAULT_ADVISORY_FEEDS.get(feed_key)
        if not feed:
            return {}

        payload = self._request_text_with_retry(feed.url)
        if not payload:
            return {}

        found = extract_cves_from_text(payload)
        mapped: dict[str, list[str]] = {}
        wanted = set(normalized)
        for cve_id in sorted(found & wanted):
            mapped[cve_id] = [feed.label]
        return mapped

    def _request_text_with_retry(self, url: str) -> str | None:
        delay = 0.25
        for attempt in range(3):
            try:
                response = self._session.get(url, timeout=self._timeout)
                if response.status_code != 200:
                    return None
                return response.text
            except requests.RequestException:
                if attempt == 2:
                    return None
                time.sleep(delay)
                delay *= 2
        return None


def extract_cves_from_text(text: str) -> set[str]:
    return {m.group(0).upper() for m in CVE_PATTERN.finditer(text or "")}
