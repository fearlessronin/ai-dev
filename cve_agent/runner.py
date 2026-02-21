from __future__ import annotations

import logging
import time
from pathlib import Path

from .analyzer import analyze_candidate
from .config import Settings
from .correlation_v2 import apply_phase3_correlation
from .correlator import MitreCorrelator
from .enrichment import apply_enrichment
from .reporter import Reporter
from .sources.attack_feed import AttackFeedClient
from .sources.circl import CIRCLClient
from .sources.cveorg import CVEOrgClient
from .sources.epss import EPSSClient
from .sources.ghsa import GHSAClient
from .sources.kev import KEVClient
from .sources.nvd import NVDClient
from .sources.openvex import load_openvex_map
from .sources.osv import OSVClient
from .store import StateStore


class CVEWatcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = NVDClient(api_key=settings.nvd_api_key)
        self.kev_client = KEVClient(timeout_seconds=12, cache_ttl_minutes=settings.source_cache_ttl_minutes)
        self.epss_client = EPSSClient(timeout_seconds=12)
        self.cveorg_client = CVEOrgClient(timeout_seconds=10)
        self.osv_client = OSVClient(timeout_seconds=10)
        self.ghsa_client = GHSAClient(token=settings.github_token, timeout_seconds=12)
        self.circl_client = CIRCLClient(timeout_seconds=12)
        self.attack_feed_client = AttackFeedClient(timeout_seconds=12)
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
            if (cve.cve_id in seen) and (not self.settings.reprocess_seen):
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
        ghsa_map = self.ghsa_client.fetch_by_cves(candidate_ids)
        circl_map = self.circl_client.fetch_records(candidate_ids)
        openvex_map = load_openvex_map(self.settings.openvex_path)
        attack_feed_meta = self.attack_feed_client.fetch_metadata() or {}

        new_count = 0
        for cve, analysis in candidates:
            cve_id = cve.cve_id.upper()
            kev_entry = kev_map.get(cve_id)
            epss_entry = epss_map.get(cve_id)
            cveorg_entry = cveorg_map.get(cve_id)
            osv_entry = osv_map.get(cve_id)
            ghsa_entries = ghsa_map.get(cve_id, [])
            circl_entry = circl_map.get(cve_id)
            openvex_status = openvex_map.get(cve_id)

            analysis = self.correlator.correlate(analysis)
            analysis = apply_enrichment(
                analysis,
                kev_entry=kev_entry,
                epss_entry=epss_entry,
                cveorg_entry=cveorg_entry,
                osv_entry=osv_entry,
                ghsa_entries=ghsa_entries,
                circl_entry=circl_entry,
                openvex_status=openvex_status,
            )
            analysis.attack_feed_version = attack_feed_meta.get("version") or attack_feed_meta.get("latest_modified")
            analysis = apply_phase3_correlation(
                analysis,
                kev_entry=kev_entry,
                epss_entry=epss_entry,
                cveorg_entry=cveorg_entry,
                osv_entry=osv_entry,
                target_ecosystems=self.settings.target_ecosystems,
                target_packages=self.settings.target_packages,
                target_cpes=self.settings.target_cpes,
            )

            self.reporter.write(analysis)
            if cve.cve_id not in seen:
                self.store.mark_seen(cve.cve_id)
            new_count += 1
            logging.info(
                "Recorded %s (priority=%.2f, evidence=%.2f, change=%s, scope=%s, kev=%s, epss=%s, fix=%s)",
                cve.cve_id,
                analysis.priority_score,
                analysis.evidence_score,
                analysis.change_type,
                analysis.asset_in_scope,
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
