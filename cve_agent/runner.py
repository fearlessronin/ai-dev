from __future__ import annotations

import logging
import time
from pathlib import Path

from .analyzer import analyze_candidate
from .config import Settings
from .correlator import MitreCorrelator
from .enrichment import apply_enrichment
from .reporter import Reporter
from .sources.epss import EPSSClient
from .sources.kev import KEVClient
from .sources.nvd import NVDClient
from .store import StateStore


class CVEWatcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = NVDClient(api_key=settings.nvd_api_key)
        self.kev_client = KEVClient()
        self.epss_client = EPSSClient()
        self.reporter = Reporter(settings.output_dir)
        self.store = StateStore(settings.state_file)
        mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
        self.correlator = MitreCorrelator(mappings_dir)

    def run_once(self) -> int:
        logging.info("Fetching CVEs from last %s days", self.settings.window_days)
        cves = self.client.fetch_last_days(self.settings.window_days)
        seen = self.store.seen_ids()

        unseen_cves = [cve for cve in cves if cve.cve_id not in seen]

        kev_map = self.kev_client.fetch_catalog()
        epss_map = self.epss_client.fetch_scores([c.cve_id for c in unseen_cves])

        new_count = 0
        for cve in unseen_cves:
            analysis = analyze_candidate(cve)
            if analysis is None:
                continue

            analysis = self.correlator.correlate(analysis)
            analysis = apply_enrichment(
                analysis,
                kev_entry=kev_map.get(cve.cve_id.upper()),
                epss_entry=epss_map.get(cve.cve_id.upper()),
            )

            self.reporter.write(analysis)
            self.store.mark_seen(cve.cve_id)
            new_count += 1
            logging.info(
                "Recorded %s (confidence=%.2f, priority=%.2f, kev=%s, epss=%s)",
                cve.cve_id,
                analysis.confidence,
                analysis.priority_score,
                analysis.kev_status,
                f"{analysis.epss_score:.3f}" if analysis.epss_score is not None else "n/a",
            )

        logging.info("Run complete. New findings: %s", new_count)
        return new_count

    def run_daemon(self) -> None:
        interval_seconds = self.settings.poll_interval_minutes * 60
        logging.info("Starting daemon mode. Poll interval: %s minutes", self.settings.poll_interval_minutes)

        while True:
            try:
                self.run_once()
            except Exception as exc:
                logging.exception("Run failed: %s", exc)

            logging.info("Sleeping for %s seconds", interval_seconds)
            time.sleep(interval_seconds)
