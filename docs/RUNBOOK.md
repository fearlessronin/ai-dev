# Runbook

## Prerequisites

- Python 3.11+
- Network access to configured upstream feeds/APIs

## Setup

1. Install dependencies (recommended path):

```bash
pip install -e .[dev]
```

Alternative:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

2. Configure environment:

```bash
copy .env.example .env
```

## Daily Usage

### One-time collection

```bash
python -m cve_agent.cli once
```

### Continuous collection

```bash
python -m cve_agent.cli daemon
```

### Dashboard only

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

### Dashboard + background polling on startup

```bash
python -m cve_agent.cli serve --poll --poll-interval-minutes 30 --host 127.0.0.1 --port 8080
```

## Polling Control (runtime)

Use the top-bar polling controls in the dashboard to:
- enable/disable auto-poll without restart
- change interval with the slider
- manually trigger a full-source refresh (`Poll Now`)
- inspect per-source freshness and errors

## Configuration Reference

- `NVD_API_KEY`: optional NVD API key
- `GITHUB_TOKEN`: optional GHSA token
- `OPENVEX_PATH`: optional OpenVEX JSON path
- `WINDOW_DAYS`: lookback window (default `30`)
- `POLL_INTERVAL_MINUTES`: daemon interval default (default `60`)
- `OUTPUT_DIR`: output root (default `output`)
- `STATE_FILE`: seen state path (default `output/state.json`)
- `LOG_LEVEL`: `DEBUG`, `INFO`, `WARNING`, `ERROR`
- `SOURCE_CACHE_TTL_MINUTES`: cache TTL for reusable source pulls
- `TARGET_ECOSYSTEMS`: comma-separated ecosystem scope
- `TARGET_PACKAGES`: comma-separated package scope
- `TARGET_CPES`: comma-separated CPE fragment scope
- `REPROCESS_SEEN`: reprocess seen CVEs for change tracking
- `CSAF_FEED_URLS`: comma-separated CSAF/global feed URLs
- `REGIONAL_RSS_URLS`: comma-separated RSS feed URLs
- `JVN_API_TEMPLATE`: template URL with `{cve_id}` placeholder

## Data Sources In Use

The app currently enriches with:
- NVD, CISA KEV, FIRST EPSS
- CVE.org (CNA + Vulnrichment), OSV, GHSA, CIRCL
- MSRC (Microsoft Security Response Center)
- Red Hat Security Data API
- Debian Security Tracker
- ATT&CK feed metadata, OpenVEX, regional/national RSS/CSAF/JVN sources
- Public advisory HTML sources: CISA ICS, CERT-FR, BSI/CERT-Bund (Phase 5 regional escalation signals)

## Polling API Endpoints

- `GET /api/poll/status`
- `POST /api/poll/config`
- `POST /api/poll/run`

## Output Files

- `output/findings.jsonl`
- `output/reports/*.md`
- `output/state.json`
- `output/triage.json`
- `output/findings_latest.json`
- `output/poll_status.json`

## Troubleshooting

- If dashboard routes fail, restart with a clean single process on the target port.
- If no findings appear in the UI, hard refresh the browser to clear cached JS/CSS.
- If ingestion is slow, reduce `WINDOW_DAYS` or tune feed lists.
- If GHSA calls are rate-limited, set `GITHUB_TOKEN`.
- If scope match quality is poor, refine `TARGET_*` lists.
- If a source freshness card shows repeated errors, inspect upstream availability and retry with `Poll Now`.


## Phase 5 UI Signals

The right-side detail panel now includes a `Phase 5 Correlation` section with:
- corroboration score + confidence label
- independent-source count and source-family presence
- regional escalation badges
- asset mapping hit summary (`TARGET_*`)
- patch availability matrix summary
