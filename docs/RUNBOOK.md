# Runbook

## Prerequisites

- Python 3.11+
- Internet access to NVD, CISA KEV, EPSS, CVE.org, OSV, GitHub Advisory, and CIRCL APIs

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure environment:

```bash
copy .env.example .env
```

Optional: set `NVD_API_KEY` in `.env` for better API throughput.

## Daily usage

### 1) Pull latest findings

```bash
python -m cve_agent.cli once
```

### 2) Run continuously

```bash
python -m cve_agent.cli daemon
```

Default poll interval is 60 minutes. Change via `POLL_INTERVAL_MINUTES`.

### 3) View dashboard

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

## Configuration reference

- `NVD_API_KEY`: optional NVD API key
- `GITHUB_TOKEN`: optional token for higher GHSA API quota
- `OPENVEX_PATH`: optional path to local OpenVEX JSON file
- `WINDOW_DAYS`: CVE lookback window (default `30`)
- `POLL_INTERVAL_MINUTES`: daemon interval (default `60`)
- `OUTPUT_DIR`: output root (default `output`)
- `STATE_FILE`: dedupe state file (default `output/state.json`)
- `LOG_LEVEL`: `DEBUG`, `INFO`, `WARNING`, `ERROR`
- `SOURCE_CACHE_TTL_MINUTES`: source-cache TTL in minutes (default `15`)
- `TARGET_ECOSYSTEMS`: comma-separated ecosystem names for in-scope boosting
- `TARGET_PACKAGES`: comma-separated package names for in-scope boosting
- `TARGET_CPES`: comma-separated CPE fragments for asset scope matching
- `REPROCESS_SEEN`: reprocess seen CVEs to detect changes (`false` by default)

## Output files

- `output/findings.jsonl`: one JSON object per finding (includes enrichment + evidence fields)
- `output/reports/*.md`: per-CVE remediation docs with operational + ecosystem/fix sections
- `output/state.json`: CVE IDs already processed
- `output/triage.json`: analyst triage state/note overrides

## Troubleshooting

### Dashboard not loading

- Confirm server process is running in terminal.
- Use `http://127.0.0.1:<port>` (not `https`).
- Try a different port:

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8090
```

### No new findings

- Run `once` and inspect logs.
- Increase `WINDOW_DAYS` temporarily.
- Check whether CVEs are already in `output/state.json`.

### Dependency/import errors

Reinstall packages:

```bash
python -m pip install -r requirements.txt
```
