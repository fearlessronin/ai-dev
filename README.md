# AI CVE Watcher

Continuously pulls CVEs from the configured lookback window, filters likely agentic AI vulnerabilities, and generates remediation-focused documentation with code guidance.

## What it does

- Pulls CVEs from NVD (2.0 API)
- Keeps a configurable rolling window (`WINDOW_DAYS`)
- Filters for likely AI agent / LLM ecosystem issues
- Correlates findings with MITRE ATLAS and MITRE ATT&CK via explainable rules
- Enriches findings with:
  - CISA KEV exploitation status
  - FIRST EPSS exploit probability
  - CVE.org CNA affected-product metadata
  - OSV ecosystem/package/fix-version context`r`n  - GitHub Security Advisories (GHSA) package context`r`n  - CISA Vulnrichment/SSVC signals via CVE.org ADP`r`n  - CIRCL sightings and OpenVEX status (optional)
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
- Enrichment sources:
  - `cve_agent/sources/kev.py`
  - `cve_agent/sources/epss.py`
  - `cve_agent/sources/cveorg.py`
  - `cve_agent/sources/osv.py`
- Enrichment logic:
  - `cve_agent/enrichment.py`

## Configuration

Use `.env` or environment variables:

- `NVD_API_KEY`: optional API key for higher NVD throughput
- `WINDOW_DAYS`: lookback window (default: `30`)
- `POLL_INTERVAL_MINUTES`: daemon poll interval (default: `60`)
- `OUTPUT_DIR`: output directory (default: `output`)
- `STATE_FILE`: state file (default: `output/state.json`)
- `LOG_LEVEL`: logging level (default: `INFO`)
- `SOURCE_CACHE_TTL_MINUTES`: source cache TTL in minutes (default: `15`)
- `TARGET_ECOSYSTEMS`: comma-separated ecosystem names for in-scope boosting
- `TARGET_PACKAGES`: comma-separated package names for in-scope boosting
- `REPROCESS_SEEN`: reprocess seen CVEs to detect change types (default: `false`)`r`n- `GITHUB_TOKEN`: optional token for higher GHSA API quota`r`n- `OPENVEX_PATH`: optional path to local OpenVEX JSON file`r`n- `TARGET_CPES`: comma-separated CPE fragments for asset scope matching

## Output structure

- `output/findings.jsonl`: includes MITRE + KEV + EPSS + ecosystem/fix context + `priority_score`
- `output/reports/CVE-YYYY-NNNN.md`: remediation report with operational and ecosystem sections
- `output/state.json`: seen CVE tracking for deduplication

## Notes

- This tool identifies likely agentic AI issues using keyword/risk heuristics.
- Always confirm patch guidance with vendor advisories and official fix releases.
- For strongest signal quality, tune `AI_KEYWORDS`, `CATEGORY_RULES`, and mapping rules for your environment.




