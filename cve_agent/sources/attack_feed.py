from __future__ import annotations

import time

import requests


ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class AttackFeedClient:
    def __init__(self, timeout_seconds: int = 20) -> None:
        self._timeout = timeout_seconds

    def fetch_metadata(self) -> dict[str, str] | None:
        payload = self._get_json_with_retry(ATTACK_ENTERPRISE_URL)
        if not payload:
            return None

        latest_modified = ""
        attack_version = ""

        for obj in payload.get("objects", []):
            if not isinstance(obj, dict):
                continue
            modified = str(obj.get("modified", "")).strip()
            if modified and modified > latest_modified:
                latest_modified = modified
            if not attack_version:
                attack_version = str(obj.get("x_mitre_version", "")).strip()

        if not latest_modified and not attack_version:
            return None

        return {
            "latest_modified": latest_modified,
            "version": attack_version,
        }

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
