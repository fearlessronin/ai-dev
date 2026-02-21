from __future__ import annotations

import logging
import time
from pathlib import Path

from .analyzer import analyze_candidate
from .config import Settings
from .correlator import MitreCorrelator
from .enrichment import apply_enrichment
from .reporter import Reporter
from .sources.cveorg import CVEOrgClient
from .sources.epss import EPSSClient
from .sources.kev import KEVClient
from .sources.nvd import NVDClient
from .sources.osv import OSVClient
from .store import StateStore


class CVEWatcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = NVDClient(api_key=settings.nvd_api_key)
        self.kev_client = KEVClient(timeout_seconds=12)
        self.epss_client = EPSSClient(timeout_seconds=12)
        self.cveorg_client = CVEOrgClient(timeout_seconds=10)
        self.osv_client = OSVClient(timeout_seconds=10)
        self.reporter = Reporter(settings.output_dir)
        self.store = StateStore(settings.state_file)
        mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
        self.correlator = MitreCorrelator(mappings_dir)

    def run_once(self) -> int:
        logging.info("Fetching CVEs from last %s days", self.settings.window_days)
        cves = self.client.fetch_last_days(self.settings.window_days)
        seen = self.store.seen_ids()

        candidates = []
        for cve in cves:
            if cve.cve_id in seen:
                continue
            analysis = analyze_candidate(cve)
            if analysis is None:
                continue
            candidates.append((cve, analysis))

        candidate_ids = [cve.cve_id for cve, _ in candidates]
        kev_map = self.kev_client.fetch_catalog()
        epss_map = self.epss_client.fetch_scores(candidate_ids)
        cveorg_map = self.cveorg_client.fetch_records(candidate_ids)
        osv_map = self.osv_client.fetch_records(candidate_ids)

        new_count = 0
        for cve, analysis in candidates:
            analysis = self.correlator.correlate(analysis)
            analysis = apply_enrichment(
                analysis,
                kev_entry=kev_map.get(cve.cve_id.upper()),
                epss_entry=epss_map.get(cve.cve_id.upper()),
                cveorg_entry=cveorg_map.get(cve.cve_id.upper()),
                osv_entry=osv_map.get(cve.cve_id.upper()),
            )

            self.reporter.write(analysis)
            self.store.mark_seen(cve.cve_id)
            new_count += 1
            logging.info(
                "Recorded %s (priority=%.2f, kev=%s, epss=%s, fix=%s)",
                cve.cve_id,
                analysis.priority_score,
                analysis.kev_status,
                f"{analysis.epss_score:.3f}" if analysis.epss_score is not None else "n/a",
                analysis.has_fix,
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
