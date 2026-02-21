# Runbook

## Prerequisites

- Python 3.11+
- Internet access to NVD, CISA KEV, EPSS, CVE.org, and OSV APIs

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
- `WINDOW_DAYS`: CVE lookback window (default `10`)
- `POLL_INTERVAL_MINUTES`: daemon interval (default `60`)
- `OUTPUT_DIR`: output root (default `output`)
- `STATE_FILE`: dedupe state file (default `output/state.json`)
- `LOG_LEVEL`: `DEBUG`, `INFO`, `WARNING`, `ERROR`

## Output files

- `output/findings.jsonl`: one JSON object per finding (includes KEV/EPSS/CVE.org/OSV context and priority score)
- `output/reports/*.md`: per-CVE remediation docs with operational + ecosystem/fix sections
- `output/state.json`: CVE IDs already processed

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

