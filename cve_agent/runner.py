from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analyzer import analyze_candidate
from .config import Settings
from .correlator import MitreCorrelator
from .corroboration_patch_context import apply_corroboration_patch_context
from .enrichment import apply_enrichment
from .evidence_correlation import apply_evidence_correlation
from .reporter import Reporter
from .sources.attack_feed import AttackFeedClient
from .sources.circl import CIRCLClient
from .sources.cveorg import CVEOrgClient
from .sources.debian import DebianTrackerClient, extract_debian_context
from .sources.epss import EPSSClient
from .sources.ghsa import GHSAClient
from .sources.kev import KEVClient
from .sources.msrc import MSRCClient
from .sources.nvd import NVDClient
from .sources.openvex import load_openvex_map
from .sources.osv import OSVClient
from .sources.public_advisories import PublicAdvisoryClient
from .sources.redhat import RedHatSecurityClient, extract_redhat_context
from .sources.regional import RegionalIntelClient
from .store import StateStore

SOURCE_NAMES = [
    "nvd",
    "kev",
    "epss",
    "cveorg",
    "osv",
    "ghsa",
    "circl",
    "regional",
    "msrc",
    "redhat",
    "debian",
    "cisa_ics",
    "certfr",
    "bsi",
    "ubuntu_usn",
    "suse",
    "oracle_cpu",
    "cisco",
    "certcc",
    "paloalto",
    "fortinet",
    "vmware_broadcom",
    "apple_security",
    "android_bulletins",
    "openvex",
    "attack_feed",
]


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
        self.regional_client = RegionalIntelClient(
            csaf_feed_urls=settings.csaf_feed_urls,
            rss_urls=settings.regional_rss_urls,
            jvn_api_template=settings.jvn_api_template,
            timeout_seconds=12,
        )
        self.msrc_client = MSRCClient(timeout_seconds=12)
        self.redhat_client = RedHatSecurityClient(timeout_seconds=12)
        self.debian_client = DebianTrackerClient(timeout_seconds=20, cache_ttl_minutes=30)
        self.public_advisory_client = PublicAdvisoryClient(timeout_seconds=12)
        self.reporter = Reporter(settings.output_dir)
        self.store = StateStore(settings.state_file)
        mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
        self.correlator = MitreCorrelator(mappings_dir)
        self._source_status = {name: self._empty_source_status() for name in SOURCE_NAMES}
        self._last_candidate_ids: list[str] = []

    def run_once(self) -> int:
        logging.info("Fetching CVEs from last %s days", self.settings.window_days)

        cves = self._call_source("nvd", lambda: self.client.fetch_last_days(self.settings.window_days))
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
        self._last_candidate_ids = list(candidate_ids)
        kev_map = self._call_source("kev", self.kev_client.fetch_catalog)
        epss_map = self._call_source("epss", lambda: self.epss_client.fetch_scores(candidate_ids))
        cveorg_map = self._call_source("cveorg", lambda: self.cveorg_client.fetch_records(candidate_ids))
        osv_map = self._call_source("osv", lambda: self.osv_client.fetch_records(candidate_ids))
        ghsa_map = self._call_source("ghsa", lambda: self.ghsa_client.fetch_by_cves(candidate_ids))
        circl_map = self._call_source("circl", lambda: self.circl_client.fetch_records(candidate_ids))
        regional_map = self._call_source("regional", lambda: self.regional_client.fetch_signals(candidate_ids))
        msrc_map = self._call_source("msrc", lambda: self.msrc_client.fetch_records(candidate_ids))
        redhat_map = self._call_source("redhat", lambda: self.redhat_client.fetch_records(candidate_ids))
        debian_map = self._call_source("debian", lambda: self.debian_client.fetch_records(candidate_ids))
        cisa_ics_map = self._call_source(
            "cisa_ics", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "cisa_ics")
        )
        certfr_map = self._call_source(
            "certfr", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "certfr")
        )
        bsi_map = self._call_source("bsi", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "bsi"))
        ubuntu_usn_map = self._call_source(
            "ubuntu_usn", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "ubuntu_usn")
        )
        suse_map = self._call_source(
            "suse", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "suse")
        )
        oracle_cpu_map = self._call_source(
            "oracle_cpu", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "oracle_cpu")
        )
        cisco_map = self._call_source(
            "cisco", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "cisco")
        )
        certcc_map = self._call_source(
            "certcc", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "certcc")
        )
        paloalto_map = self._call_source(
            "paloalto", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "paloalto")
        )
        fortinet_map = self._call_source(
            "fortinet", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "fortinet")
        )
        vmware_broadcom_map = self._call_source(
            "vmware_broadcom", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "vmware_broadcom")
        )
        apple_security_map = self._call_source(
            "apple_security", lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "apple_security")
        )
        android_bulletins_map = self._call_source(
            "android_bulletins",
            lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "android_bulletins"),
        )
        openvex_map = self._call_source("openvex", lambda: load_openvex_map(self.settings.openvex_path))
        attack_feed_meta = self._call_source("attack_feed", self.attack_feed_client.fetch_metadata) or {}

        new_count = 0
        for cve, analysis in candidates:
            cve_id = cve.cve_id.upper()
            kev_entry = kev_map.get(cve_id)
            epss_entry = epss_map.get(cve_id)
            cveorg_entry = cveorg_map.get(cve_id)
            osv_entry = osv_map.get(cve_id)
            ghsa_entries = ghsa_map.get(cve_id, [])
            circl_entry = circl_map.get(cve_id)
            regional_sources = list(regional_map.get(cve_id, []))
            regional_sources.extend(cisa_ics_map.get(cve_id, []))
            regional_sources.extend(certfr_map.get(cve_id, []))
            regional_sources.extend(bsi_map.get(cve_id, []))
            regional_sources.extend(ubuntu_usn_map.get(cve_id, []))
            regional_sources.extend(suse_map.get(cve_id, []))
            regional_sources.extend(oracle_cpu_map.get(cve_id, []))
            regional_sources.extend(cisco_map.get(cve_id, []))
            regional_sources.extend(certcc_map.get(cve_id, []))
            regional_sources.extend(paloalto_map.get(cve_id, []))
            regional_sources.extend(fortinet_map.get(cve_id, []))
            regional_sources.extend(vmware_broadcom_map.get(cve_id, []))
            regional_sources.extend(apple_security_map.get(cve_id, []))
            regional_sources.extend(android_bulletins_map.get(cve_id, []))
            openvex_status = openvex_map.get(cve_id)

            vendor_sources, vendor_packages, vendor_fixed_versions = self._vendor_context_for_cve(
                cve_id,
                msrc_entry=msrc_map.get(cve_id),
                redhat_entry=redhat_map.get(cve_id),
                debian_entry=debian_map.get(cve_id),
            )
            regional_sources.extend(vendor_sources)

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
                regional_sources=regional_sources,
            )
            analysis.packages.extend(vendor_packages)
            analysis.fixed_versions.extend(vendor_fixed_versions)
            analysis.affected_products.extend(vendor_packages)
            analysis.attack_feed_version = attack_feed_meta.get("version") or attack_feed_meta.get("latest_modified")
            analysis = apply_enrichment(
                analysis,
                kev_entry=None,
                epss_entry=None,
                cveorg_entry=None,
                osv_entry=None,
            )
            analysis = apply_evidence_correlation(
                analysis,
                kev_entry=kev_entry,
                epss_entry=epss_entry,
                cveorg_entry=cveorg_entry,
                osv_entry=osv_entry,
                target_ecosystems=self.settings.target_ecosystems,
                target_packages=self.settings.target_packages,
                target_cpes=self.settings.target_cpes,
                inventory_context=self.settings.asset_inventory_context,
            )
            analysis = apply_corroboration_patch_context(
                analysis,
                cveorg_entry=cveorg_entry,
                osv_entry=osv_entry,
                msrc_entry=msrc_map.get(cve_id),
                redhat_entry=redhat_map.get(cve_id),
                debian_entry=debian_map.get(cve_id),
                target_ecosystems=self.settings.target_ecosystems,
                target_packages=self.settings.target_packages,
                target_cpes=self.settings.target_cpes,
            )

            self.reporter.write(analysis)
            if cve.cve_id not in seen:
                self.store.mark_seen(cve.cve_id)
            new_count += 1
            logging.info(
                "Recorded %s (priority=%.2f, evidence=%.2f, regional=%s, change=%s, scope=%s)",
                cve.cve_id,
                analysis.priority_score,
                analysis.evidence_score,
                analysis.regional_signal_count,
                analysis.change_type,
                analysis.asset_in_scope,
            )

        logging.info("Run complete. New findings: %s", new_count)
        return new_count

    def supported_poll_sources(self) -> list[str]:
        return list(SOURCE_NAMES)

    def poll_source(self, name: str) -> int:
        source = str(name or "").strip().lower()
        if source not in SOURCE_NAMES:
            raise ValueError(f"Unsupported source: {name}")

        candidate_sources = {
            "epss",
            "cveorg",
            "osv",
            "ghsa",
            "circl",
            "regional",
            "msrc",
            "redhat",
            "debian",
            "cisa_ics",
            "certfr",
            "bsi",
            "ubuntu_usn",
            "suse",
            "oracle_cpu",
            "cisco",
            "certcc",
            "paloalto",
            "fortinet",
            "vmware_broadcom",
            "apple_security",
            "android_bulletins",
        }
        candidate_ids = list(self._last_candidate_ids)
        if source in candidate_sources and not candidate_ids:
            raise ValueError("No cached candidate IDs available. Run a full poll first.")

        loaders: dict[str, Callable[[], Any]] = {
            "nvd": lambda: self.client.fetch_last_days(self.settings.window_days),
            "kev": self.kev_client.fetch_catalog,
            "epss": lambda: self.epss_client.fetch_scores(candidate_ids),
            "cveorg": lambda: self.cveorg_client.fetch_records(candidate_ids),
            "osv": lambda: self.osv_client.fetch_records(candidate_ids),
            "ghsa": lambda: self.ghsa_client.fetch_by_cves(candidate_ids),
            "circl": lambda: self.circl_client.fetch_records(candidate_ids),
            "regional": lambda: self.regional_client.fetch_signals(candidate_ids),
            "msrc": lambda: self.msrc_client.fetch_records(candidate_ids),
            "redhat": lambda: self.redhat_client.fetch_records(candidate_ids),
            "debian": lambda: self.debian_client.fetch_records(candidate_ids),
            "cisa_ics": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "cisa_ics"),
            "certfr": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "certfr"),
            "bsi": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "bsi"),
            "ubuntu_usn": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "ubuntu_usn"),
            "suse": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "suse"),
            "oracle_cpu": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "oracle_cpu"),
            "cisco": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "cisco"),
            "certcc": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "certcc"),
            "paloalto": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "paloalto"),
            "fortinet": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "fortinet"),
            "vmware_broadcom": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "vmware_broadcom"),
            "apple_security": lambda: self.public_advisory_client.fetch_feed_signals(candidate_ids, "apple_security"),
            "android_bulletins": lambda: self.public_advisory_client.fetch_feed_signals(
                candidate_ids, "android_bulletins"
            ),
            "openvex": lambda: load_openvex_map(self.settings.openvex_path),
            "attack_feed": self.attack_feed_client.fetch_metadata,
        }
        result = self._call_source(source, loaders[source])
        return self._count_result(result)

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

    def get_poll_runtime_status(self) -> dict[str, Any]:
        return {"sources": {name: dict(data) for name, data in self._source_status.items()}}

    def _vendor_context_for_cve(
        self,
        cve_id: str,
        msrc_entry: dict[str, Any] | None,
        redhat_entry: dict[str, Any] | None,
        debian_entry: dict[str, Any] | None,
    ) -> tuple[list[str], list[str], list[str]]:
        sources: list[str] = []
        packages: list[str] = []
        fixed_versions: list[str] = []

        if msrc_entry:
            sources.append("MSRC")

        if redhat_entry:
            src, pkgs, fixes = extract_redhat_context(redhat_entry)
            sources.extend(src)
            packages.extend(pkgs)
            fixed_versions.extend(fixes)

        if debian_entry:
            src, pkgs, fixes = extract_debian_context(debian_entry)
            sources.extend(src)
            packages.extend(pkgs)
            fixed_versions.extend(fixes)

        return sorted(set(sources)), sorted(set(packages)), sorted(set(fixed_versions))

    def _call_source(self, name: str, loader: Callable[[], Any]) -> Any:
        started = time.perf_counter()
        status = self._source_status.setdefault(name, self._empty_source_status())
        status["status"] = "running"
        status["last_polled"] = self._utc_now_iso()

        try:
            result = loader()
        except Exception as exc:
            status["status"] = "error"
            status["last_error"] = str(exc)
            status["duration_ms"] = int((time.perf_counter() - started) * 1000)
            status["records"] = 0
            raise

        status["status"] = "ok"
        status["last_error"] = ""
        status["last_success"] = self._utc_now_iso()
        status["duration_ms"] = int((time.perf_counter() - started) * 1000)
        status["records"] = self._count_result(result)
        return result

    def _empty_source_status(self) -> dict[str, Any]:
        return {
            "status": "never",
            "last_polled": None,
            "last_success": None,
            "last_error": "",
            "duration_ms": None,
            "records": 0,
        }

    def _utc_now_iso(self) -> str:
        return datetime.now(UTC).replace(microsecond=0).isoformat()

    def _count_result(self, result: Any) -> int:
        if result is None:
            return 0
        if isinstance(result, dict):
            return len(result)
        if isinstance(result, (list, tuple, set)):
            return len(result)
        return 1
