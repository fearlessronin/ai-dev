# AI CVE Watcher

Continuously ingests CVEs from a configurable lookback window, enriches them with multi-source threat context, and produces analyst-ready prioritization for securing AI environments.

## What It Does

- Pulls CVEs from NVD
- Scores likely AI-agent / LLM ecosystem relevance
- Correlates findings with MITRE ATLAS and MITRE ATT&CK
- Enriches each finding with exploitability, fix, ecosystem, and regional/national intelligence signals
- Supports triage workflow and change tracking across runs
- Exposes findings in dashboard, JSONL, markdown, and CSV

## Data Feeds Included

| Source | Type | Usage in App |
|---|---|---|
| NVD CVE API | API | Base CVE ingest, CVSS/CWE metadata, CPE extraction |
| CISA KEV | Feed/API JSON | Known exploited status and KEV dates/action |
| FIRST EPSS | API | Exploit probability and percentile |
| CVE.org (CNA + ADP/Vulnrichment) | API | Affected/fixed metadata + SSVC-style signals |
| OSV | API | Package ecosystem and fix-version context |
| GitHub Security Advisories (GHSA) | API | Advisory linkage, severity, package/version context |
| CIRCL Vulnerability-Lookup | API | Sightings/external signal enrichment |
| MITRE ATT&CK feed metadata | Data source (JSON feed) | Feed freshness/version context |
| OpenVEX | Local data source (file path) | Not-affected/affected override signal |
| CSAF/global feeds | Data source/feed (configurable URLs) | Regional/national signal matching by CVE |
| Regional RSS feeds | Data source/feed (configurable URLs) | Regional/national signal matching by CVE |
| JVN (template-based request) | API/data source (configurable template) | Additional regional CVE signal matching |

## Benefits For Analysts

- Multi-signal prioritization reduces CVSS-only noise.
- Scope-aware ranking via `TARGET_ECOSYSTEMS`, `TARGET_PACKAGES`, and `TARGET_CPES`.
- Change tracking: `new`, `priority_changed`, `newly_fixed`, `unchanged`.
- Triage states and notes: `new`, `investigating`, `mitigated`, `accepted_risk`.
- Contradiction flags help resolve conflicting source data quickly.
- Regional/national signal matching helps surface geographically relevant alerts.

## Benefits For Researchers

- Unified cross-source record for pattern and trend analysis.
- Reprocessing support (`REPROCESS_SEEN=true`) for longitudinal comparisons.
- Structured JSONL for downstream analytics and experiments.
- Expanded context fields (SSVC-style, GHSA linkage, sightings, OpenVEX, regional feeds).

## Quick Start

1. Install via editable package metadata (recommended):

```bash
pip install -e .[dev]
```

Alternative requirements-based install:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

2. Create env file:

```bash
copy .env.example .env
```

3. Run once:

```bash
python -m cve_agent.cli once
```

4. Run daemon:

```bash
python -m cve_agent.cli daemon
```

5. Start dashboard:

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

Optional: start dashboard and background polling together on startup:

```bash
python -m cve_agent.cli serve --poll --poll-interval-minutes 30 --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

Serve polling flags:
- `--poll`: enable background polling while the dashboard is running.
- `--poll-interval-minutes`: override polling cadence at startup (applies to `daemon` and `serve --poll`).

## No-API Demo Mode

Seed a known-good local dataset and start the dashboard without API keys:

```bash
python -m cve_agent.cli demo
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

Demo data source:
- `demo/findings.demo.jsonl`

## Pre-commit

Install hooks:

```bash
pre-commit install
```

Run hooks manually:

```bash
pre-commit run --all-files
```

## Dev Workflow

- `just install`
- `just lint`
- `just format-check`
- `just test`
- `just smoke`
- `just validate`
- `just run-demo`

## Configuration

- `NVD_API_KEY`: optional NVD API key
- `GITHUB_TOKEN`: optional token for GHSA rate limits
- `OPENVEX_PATH`: optional path to local OpenVEX JSON
- `WINDOW_DAYS`: lookback window (default `30`)
- `POLL_INTERVAL_MINUTES`: daemon interval (default `60`)
- `OUTPUT_DIR`: output directory (default `output`)
- `STATE_FILE`: state file (default `output/state.json`)
- `LOG_LEVEL`: logging level (`INFO` default)
- `SOURCE_CACHE_TTL_MINUTES`: source cache TTL (default `15`)
- `TARGET_ECOSYSTEMS`: comma-separated ecosystem scope
- `TARGET_PACKAGES`: comma-separated package scope
- `TARGET_CPES`: comma-separated CPE fragment scope
- `REPROCESS_SEEN`: reprocess seen CVEs for change tracking (`false` default)
- `CSAF_FEED_URLS`: comma-separated CSAF/global feed URLs
- `REGIONAL_RSS_URLS`: comma-separated RSS feed URLs
- `JVN_API_TEMPLATE`: JVN request template containing `{cve_id}`

## Output

- `output/findings.jsonl`: enriched structured findings
- `output/reports/*.md`: detailed per-CVE reports
- `output/state.json`: seen CVE IDs
- `output/triage.json`: triage state/note overrides
- `output/findings_latest.json`: latest snapshot for change detection

## Data Contract

- `docs/DATA_CONTRACT.md`
- `schemas/findings.schema.json`

## Docs

- `docs/RUNBOOK.md`
- `docs/APP_OVERVIEW.md`
- `docs/ANALYST_GUIDE.md`
- `docs/OPTIMIZATION_GUIDE.md`
- `docs/DATA_CONTRACT.md`

## Maintenance Rule

When adding, removing, or changing a data source, update this README section:
- `Data Feeds Included`
- any related config variables in `Configuration`
- relevant analyst/researcher impact notes
