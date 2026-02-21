# App Overview

## Purpose

AI CVE Watcher continuously ingests newly published CVEs from NVD, identifies entries likely related to agentic AI risk, and produces human-readable remediation documentation plus code-level hardening examples.

## End-to-end flow

1. `cve_agent.cli` starts the app in one of three modes:
- `once`: single ingestion/analyze/write cycle
- `daemon`: repeated cycle on a fixed interval
- `serve`: launches frontend dashboard server

2. `cve_agent.sources.nvd.NVDClient` fetches CVEs from NVD API for the configured rolling time window (`WINDOW_DAYS`, default 30).

3. `cve_agent.analyzer.analyze_candidate` scores each CVE against AI/agentic keywords and maps likely categories (for example prompt injection or unsafe tool execution).

4. Phase 2 enrichment runs before reporting:
- `cve_agent.sources.kev.KEVClient` for CISA KEV status
- `cve_agent.sources.epss.EPSSClient` for exploit probability
- `cve_agent.sources.cveorg.CVEOrgClient` for CNA metadata
- `cve_agent.sources.osv.OSVClient` for ecosystem/package/fix context

5. `cve_agent.reporter.Reporter` writes outputs:
- append record to `output/findings.jsonl`
- create/update markdown report in `output/reports/<CVE-ID>.md`

6. `cve_agent.store.StateStore` deduplicates by CVE ID so already processed findings are not repeatedly emitted.

7. `cve_agent.web` serves:
- static UI files in `frontend/`
- JSON API: `/api/findings`
- report API: `/api/report/<CVE-ID>`

## Project structure

- `cve_agent/cli.py`: command entrypoint (`once`, `daemon`, `serve`)
- `cve_agent/config.py`: env-driven settings loader
- `cve_agent/runner.py`: orchestration loop
- `cve_agent/sources/nvd.py`: NVD API client + parser
- `cve_agent/analyzer.py`: relevance scoring + remediation templates
- `cve_agent/sources/kev.py`: KEV enrichment client
- `cve_agent/sources/epss.py`: EPSS enrichment client
- `cve_agent/sources/cveorg.py`: CVE.org enrichment client
- `cve_agent/sources/osv.py`: OSV enrichment client
- `cve_agent/enrichment.py`: phase 1+2 enrichment + priority scoring
- `cve_agent/reporter.py`: JSONL + markdown writers
- `cve_agent/store.py`: persistent seen-set state
- `cve_agent/web.py`: local dashboard server
- `frontend/`: HTML/CSS/JS dashboard
- `output/`: generated findings/reports/state

## Current heuristic model

The analyzer is intentionally transparent and rule-based:
- keyword confidence scoring
- category inference via term matching
- category-specific remediation snippets

This makes it easy to tune for your environment, but it can still produce false positives/false negatives. Tune `AI_KEYWORDS` and `CATEGORY_RULES` in `cve_agent/analyzer.py` as you gather feedback.

## Safety guidance

The generated remediation code is guidance, not drop-in patch code for every product/version. Validate fixes against vendor advisories and test in staging before production rollout.

