# AI CVE Watcher

Continuously ingests CVEs from a configurable lookback window, enriches them with exploitability and ecosystem context, and produces analyst-ready prioritization for securing AI environments.

## What It Does

- Pulls CVEs from NVD (2.0 API)
- Uses configurable rolling window (`WINDOW_DAYS`, default `30`)
- Scores likely AI-agent / LLM ecosystem relevance
- Correlates with MITRE ATLAS and MITRE ATT&CK
- Enriches findings with:
  - CISA KEV exploitation status
  - FIRST EPSS exploit probability
  - CVE.org CNA metadata + Vulnrichment/SSVC-style signals
  - OSV package/fix context
  - GHSA advisory context
  - CIRCL sightings signals
  - OpenVEX status (optional)
  - regional/national feeds (CSAF/RSS/JVN-style matching)
- Generates:
  - JSONL findings
  - per-CVE markdown reports
  - CSV export via UI/API
- Supports analyst triage workflow and change tracking across runs

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
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

Open `http://127.0.0.1:8080`.

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
- `CSAF_FEED_URLS`: comma-separated CSAF/feed URLs
- `REGIONAL_RSS_URLS`: comma-separated RSS URLs
- `JVN_API_TEMPLATE`: JVN request template containing `{cve_id}`

## Output

- `output/findings.jsonl`: enriched structured findings
- `output/reports/*.md`: detailed per-CVE reports
- `output/state.json`: seen CVE IDs
- `output/triage.json`: triage state/note overrides
- `output/findings_latest.json`: latest snapshot for change detection

## Docs

- `docs/RUNBOOK.md`
- `docs/APP_OVERVIEW.md`
- `docs/ANALYST_GUIDE.md`
- `docs/OPTIMIZATION_GUIDE.md`
