# AI CVE Watcher

Continuously pulls CVEs from the last 10 days, filters likely agentic AI vulnerabilities, and generates remediation-focused documentation with code guidance.

## What it does

- Pulls CVEs from NVD (2.0 API)
- Keeps a rolling 10-day window
- Filters for likely AI agent / LLM ecosystem issues
- Correlates findings with MITRE ATLAS and MITRE ATT&CK via explainable rules
- Enriches findings with:
  - CISA KEV exploitation status
  - FIRST EPSS exploit probability
  - composite priority score
- Generates:
  - machine-readable JSON lines
  - per-CVE Markdown documentation
  - remediation code snippets (Python + JavaScript examples)
- Includes a local visual dashboard for analysts
- Supports one-shot mode and continuous polling mode

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy env template:

```bash
copy .env.example .env
```

4. Run once:

```bash
python -m cve_agent.cli once
```

5. Run continuously (default: every 60 minutes):

```bash
python -m cve_agent.cli daemon
```

6. Launch the dashboard:

```bash
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

Then open `http://127.0.0.1:8080`.

## Core docs

- Architecture and flow: `docs/APP_OVERVIEW.md`
- Setup/operations/troubleshooting: `docs/RUNBOOK.md`

## Correlation and enrichment

- MITRE rule files:
  - `mappings/atlas_rules.json`
  - `mappings/attack_rules.json`
- MITRE correlator:
  - `cve_agent/correlator.py`
- Phase 1 enrichment:
  - `cve_agent/sources/kev.py`
  - `cve_agent/sources/epss.py`
  - `cve_agent/enrichment.py`

## Configuration

Use `.env` or environment variables:

- `NVD_API_KEY`: optional API key for higher NVD throughput
- `WINDOW_DAYS`: lookback window (default: `10`)
- `POLL_INTERVAL_MINUTES`: daemon poll interval (default: `60`)
- `OUTPUT_DIR`: output directory (default: `output`)
- `STATE_FILE`: state file (default: `output/state.json`)
- `LOG_LEVEL`: logging level (default: `INFO`)

## Output structure

- `output/findings.jsonl`: includes MITRE + KEV + EPSS + `priority_score`
- `output/reports/CVE-YYYY-NNNN.md`: remediation report with operational risk section
- `output/state.json`: seen CVE tracking for deduplication

## Notes

- This tool identifies likely agentic AI issues using keyword/risk heuristics.
- Always confirm patch guidance with vendor advisories and official fix releases.
- For strongest signal quality, tune `AI_KEYWORDS`, `CATEGORY_RULES`, and mapping rules for your environment.
