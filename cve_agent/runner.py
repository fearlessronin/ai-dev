from __future__ import annotations

import logging
import time
from pathlib import Path

from .analyzer import analyze_candidate
from .config import Settings
from .correlator import MitreCorrelator
from .reporter import Reporter
from .sources.nvd import NVDClient
from .store import StateStore


class CVEWatcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = NVDClient(api_key=settings.nvd_api_key)
        self.reporter = Reporter(settings.output_dir)
        self.store = StateStore(settings.state_file)
        mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
        self.correlator = MitreCorrelator(mappings_dir)

    def run_once(self) -> int:
        logging.info("Fetching CVEs from last %s days", self.settings.window_days)
        cves = self.client.fetch_last_days(self.settings.window_days)
        seen = self.store.seen_ids()

        new_count = 0
        for cve in cves:
            if cve.cve_id in seen:
                continue

            analysis = analyze_candidate(cve)
            if analysis is None:
                continue

            analysis = self.correlator.correlate(analysis)
            self.reporter.write(analysis)
            self.store.mark_seen(cve.cve_id)
            new_count += 1
            logging.info(
                "Recorded %s (confidence=%.2f, atlas=%s, attack=%s)",
                cve.cve_id,
                analysis.confidence,
                len(analysis.atlas_matches),
                len(analysis.attack_matches),
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
