# App Overview

## Purpose

AI CVE Watcher continuously ingests newly published CVEs from NVD, identifies entries likely related to agentic AI risk, and produces remediation-focused documentation with evidence-weighted prioritization.

## End-to-end flow

1. `cve_agent.cli` starts the app in one of three modes:
- `once`: single ingestion/analyze/write cycle
- `daemon`: repeated cycle on a fixed interval
- `serve`: launches frontend dashboard server

2. `cve_agent.sources.nvd.NVDClient` fetches CVEs from NVD API for the configured rolling window (`WINDOW_DAYS`, default `30`) and extracts CPE applicability.

3. `cve_agent.analyzer.analyze_candidate` scores each CVE against AI/agentic keywords and maps likely categories.

4. Enrichment and correlation execute across multiple datasets:
- `cve_agent.sources.kev.KEVClient` (CISA KEV)
- `cve_agent.sources.epss.EPSSClient` (FIRST EPSS)
- `cve_agent.sources.cveorg.CVEOrgClient` (CVE.org + Vulnrichment ADP/SSVC)
- `cve_agent.sources.osv.OSVClient` (OSV ecosystem/package/fix context)
- `cve_agent.sources.ghsa.GHSAClient` (GitHub advisory context)
- `cve_agent.sources.circl.CIRCLClient` (sightings/lookup signals)
- `cve_agent.sources.attack_feed.AttackFeedClient` (ATT&CK feed freshness metadata)
- `cve_agent.sources.openvex.load_openvex_map` (local OpenVEX status overrides)

5. `cve_agent.correlation_v2.apply_phase3_correlation` computes evidence-weighted score and contradictions, with optional environment targeting (`TARGET_ECOSYSTEMS`, `TARGET_PACKAGES`, `TARGET_CPES`).

6. `cve_agent.reporter.Reporter` writes:
- append record to `output/findings.jsonl`
- create/update markdown report in `output/reports/<CVE-ID>.md`
- maintain latest snapshot for run-to-run change classification

7. `cve_agent.store.StateStore` deduplicates by CVE ID unless `REPROCESS_SEEN=true`.

8. `cve_agent.web` serves:
- static UI files in `frontend/`
- JSON API: `/api/findings`
- report API: `/api/report/<CVE-ID>`
- triage API: `POST /api/triage/<CVE-ID>`
- CSV export: `/api/export.csv`

## Project structure

- `cve_agent/cli.py`: command entrypoint (`once`, `daemon`, `serve`)
- `cve_agent/config.py`: env-driven settings loader
- `cve_agent/runner.py`: orchestration loop
- `cve_agent/sources/*.py`: external data clients/adapters
- `cve_agent/analyzer.py`: relevance scoring + remediation templates
- `cve_agent/correlator.py`: MITRE ATLAS/ATT&CK rule correlation
- `cve_agent/correlation_v2.py`: evidence-weighted correlation and scope boosting
- `cve_agent/enrichment.py`: normalized enrichment application
- `cve_agent/reporter.py`: JSONL + markdown writers + change tracking
- `cve_agent/store.py`: persistent seen-set state
- `cve_agent/web.py`: local dashboard server + triage/export endpoints
- `frontend/`: HTML/CSS/JS dashboard
- `output/`: generated findings/reports/state/triage

## Safety guidance

Generated remediation code is guidance, not drop-in patch code for every product/version. Validate with vendor advisories and test in staging before production rollout.

