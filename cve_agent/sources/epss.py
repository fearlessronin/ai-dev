from __future__ import annotations

import requests


EPSS_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    def __init__(self, timeout_seconds: int = 30) -> None:
        self._timeout = timeout_seconds

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        normalized = sorted({cve.strip().upper() for cve in cve_ids if cve})
        if not normalized:
            return {}

        scores: dict[str, dict[str, float]] = {}
        batch_size = 100

        for idx in range(0, len(normalized), batch_size):
            batch = normalized[idx : idx + batch_size]
            params = {"cve": ",".join(batch)}
            response = requests.get(EPSS_URL, params=params, timeout=self._timeout)
            response.raise_for_status()
            payload = response.json()

            for row in payload.get("data", []):
                cve = str(row.get("cve", "")).strip().upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss", 0.0))
                except (TypeError, ValueError):
                    score = 0.0
                try:
                    percentile = float(row.get("percentile", 0.0))
                except (TypeError, ValueError):
                    percentile = 0.0

                scores[cve] = {
                    "epss_score": score,
                    "epss_percentile": percentile,
                }

        return scores
