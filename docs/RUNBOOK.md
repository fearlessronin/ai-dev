# Runbook

## Prerequisites

- Python 3.11+
- Network access to configured upstream feeds/APIs

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
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

### Dashboard

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

## Configuration Reference

- `NVD_API_KEY`: optional NVD API key
- `GITHUB_TOKEN`: optional GHSA token
- `OPENVEX_PATH`: optional OpenVEX JSON path
- `WINDOW_DAYS`: lookback window (default `30`)
- `POLL_INTERVAL_MINUTES`: daemon interval (default `60`)
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

## Output Files

- `output/findings.jsonl`
- `output/reports/*.md`
- `output/state.json`
- `output/triage.json`
- `output/findings_latest.json`

## Troubleshooting

- If dashboard routes fail, restart with a clean single process on the target port.
- If ingestion is slow, reduce `WINDOW_DAYS` or tune feed lists.
- If GHSA calls are rate-limited, set `GITHUB_TOKEN`.
- If scope match quality is poor, refine `TARGET_*` lists.
