# AI CVE Watcher

Continuously ingests CVEs across a configurable lookback window, correlates them with open, vendor, and national advisory sources, and produces analyst-ready prioritization for securing AI and automation environments.

The application is designed for analysts and researchers who need more than CVSS-only triage: it combines exploitability signals, patch/fix context, source corroboration, regional escalation indicators, and asset-scope matching in a single workflow.

## What It Does

- Ingests CVEs from NVD and enriches them with supporting context from KEV, EPSS, CVE.org, OSV, GHSA, CIRCL, vendor advisories, distro trackers, and selected national/public advisory sources.
- Scores likely AI-agent / LLM ecosystem relevance and prioritizes findings using deterministic, evidence-weighted scoring and change classification.
- Correlates findings with MITRE ATLAS and MITRE ATT&CK to provide adversary-technique context for analyst triage.
- Adds patch and remediation intelligence, including package/fix-version context, vendor/distro corroboration signals (MSRC, Red Hat, Debian, Ubuntu, SUSE, Oracle, Cisco, Palo Alto, Fortinet, VMware/Broadcom, Apple, Android advisories), and a source-by-source patch availability matrix (NVD, CVE.org, OSV, MSRC, Red Hat, Debian).
- Computes corroboration metrics (confidence label, independent-source count, source-family presence) and highlights regional escalation patterns across national advisories.
- Supports asset-aware prioritization using `TARGET_*` scope settings and optional inventory-file matching (`ASSET_INVENTORY_PATH` for JSON/CSV inventory inputs).
- Provides an analyst workflow in the dashboard with filtering, sorting, saved views/presets, triage states/notes, contradiction flags, and detailed remediation context.
- Provides runtime polling operations: auto-poll controls, interval tuning, per-source manual polling, source freshness/reliability telemetry, cooldowns, poll history, retry, and audit exports.
- Adds a configurable operations scheduler for scheduled exports (findings and poll history) with runtime config/status APIs and export job history.
- Supports configurable notification rules/channels persistence (webhook-first config model) as groundwork for alert delivery automation.
- Exposes findings and operations data through the dashboard and file/API outputs (`JSONL`, markdown reports, CSV/JSON findings exports, and poll history CSV/JSON exports).

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
| Microsoft Security Response Center (MSRC) | API/HTML source (best-effort) | Vendor confirmation signal for Microsoft-covered CVEs |
| Red Hat Security Data API | API | Vendor product/package/advisory context and fix-state signals |
| Debian Security Tracker | API/JSON data source | Distro package/release fixed-version context |
| Ubuntu Security Notices (USN) | Public web advisory source (HTML parsed) | Vendor/distro corroboration and patch-availability support signals for Ubuntu estates |
| SUSE Security Advisories | Public web advisory source (HTML parsed) | Vendor/distro corroboration signals for SUSE-managed Linux environments |
| Oracle Critical Patch Update advisories | Public web advisory source (HTML parsed) | Vendor advisory corroboration for Oracle products and infrastructure components |
| Cisco Security Advisories | Public web advisory source (HTML parsed) | Vendor advisory corroboration for network/security appliance exposure |
| CERT/CC Vulnerability Notes | Public web advisory source (HTML parsed) | US CERT advisory corroboration and additional public-sector signal coverage |
| Palo Alto Networks Security Advisories | Public web advisory source (HTML parsed) | Vendor advisory corroboration for PAN-OS and security platform exposure |
| Fortinet PSIRT Advisories | Public web advisory source (HTML parsed) | Vendor advisory corroboration for Fortinet appliance/product exposure |
| VMware/Broadcom Security Advisories | Public web advisory source (HTML parsed) | Vendor advisory corroboration for VMware/Broadcom virtualization and infrastructure products |
| Apple Security Updates | Public web advisory source (HTML parsed) | Vendor advisory corroboration for Apple OS/platform security updates |
| Google Android Security Bulletins | Public web advisory source (HTML parsed) | Vendor/public bulletin corroboration for Android platform/device patch context |
| CISA ICS advisories | Public web advisory source (HTML parsed) | ICS/OT national advisory corroboration and escalation signals |
| CERT-FR advisories | Public web advisory source (HTML parsed) | French national advisory corroboration and regional escalation signals |
| BSI/CERT-Bund advisories | Public web advisory source (HTML parsed) | German national advisory corroboration and regional escalation signals |
| MITRE ATT&CK feed metadata | Data source (JSON feed) | Feed freshness/version context |
| OpenVEX | Local data source (file path) | Not-affected/affected override signal |
| CSAF/global feeds | Data source/feed (configurable URLs) | Regional/national signal matching by CVE |
| Regional RSS feeds | Data source/feed (configurable URLs) | Regional/national signal matching by CVE |
| JVN (template-based request) | API/data source (configurable template) | Additional regional CVE signal matching |

## Benefits For Analysts

- Multi-signal prioritization reduces CVSS-only noise.
- Scope-aware ranking via `TARGET_ECOSYSTEMS`, `TARGET_PACKAGES`, and `TARGET_CPES`.
- Vendor and distro corroboration (MSRC, Red Hat, Debian, Ubuntu, SUSE, Oracle, Cisco, Palo Alto, Fortinet, VMware/Broadcom, Apple, Android advisory signals) improves patch-context confidence.
- Change tracking: `new`, `priority_changed`, `newly_fixed`, `unchanged`.
- Triage states and notes: `new`, `investigating`, `mitigated`, `accepted_risk`.
- Contradiction flags help resolve conflicting source data quickly.
- Runtime polling controls and per-source freshness help analysts tune collection cadence and validate recency.
- Corroboration scoring quantifies independent source confirmation (core/open/vendor/national/telemetry).
- Regional escalation badges highlight multi-country / transatlantic advisory overlap (e.g., CISA + CERT-FR / BSI).
- Patch availability matrix summarizes patch/fix presence across NVD, CVE.org, OSV, and vendor/distro advisories.
- Patch matrix table in the finding detail panel makes source-by-source patch status easier to scan.
- Asset mapping by package/ecosystem/CPE improves prioritization against your configured environment scope.
- Richer inventory metadata (`owner`, `criticality`, `environment`, `business_service`, `internet_exposed`) enables weighted asset mapping and bounded priority boosts for operational routing.

## Benefits For Researchers

- Unified cross-source record for pattern and trend analysis.
- Reprocessing support (`REPROCESS_SEEN=true`) for longitudinal comparisons.
- Structured JSONL for downstream analytics and experiments.
- Expanded context fields (SSVC-style, GHSA linkage, sightings, OpenVEX, regional feeds, vendor/distro signals).
- Source freshness telemetry helps evaluate collection quality and source availability over time.

## Analyst Playbook

### 1. Daily Triage (High-Value First)

Use this workflow to reduce noise and focus on findings that are both relevant and actionable.

- Start with a saved view such as `High corroboration + in scope` or create one with:
  - `In target scope`
  - `High corroboration only`
  - `Has vendor corroboration`
  - `Has fix version` (optional if you want patch-ready items first)
- Sort by `Priority` or `Corroboration` depending on whether you want operational urgency or evidence strength first.
- Review the right-side detail panel for:
  - corroboration score and source-family presence
  - regional escalation badges
  - vendor/distro corroboration summary
  - patch matrix table
- Set triage state and add notes (`investigating`, `mitigated`, `accepted_risk`) directly in the dashboard.

Recommended outcome:
- A short list of in-scope, corroborated findings with triage state and owner notes.

### 2. Patch Watch / Remediation Planning

Use this workflow when the goal is patch execution readiness rather than broad monitoring.

- Filter for:
  - `Has fix version`
  - `Has vendor corroboration` and/or `Has distro fix context`
  - `In target scope`
- Sort by `Asset Mapping` (to prioritize environment impact) or `Priority`.
- Use the patch matrix table to compare patch/fix presence across `NVD`, `CVE.org`, `OSV`, and vendor/distro sources.
- Use vendor/distro corroboration details (MSRC, Red Hat, Debian, Ubuntu, SUSE, Oracle, Cisco, Palo Alto, Fortinet, VMware/Broadcom, Apple, Android) to validate patch guidance before routing tickets.
- Export findings (`CSV`/`JSON`) for patch teams or change-control workflows.

Recommended outcome:
- A remediation-ready queue with patch context, corroboration, and asset relevance.

### 3. Source Health / Collection Operations

Use this workflow to validate data freshness and troubleshoot source issues without stopping analyst work.

- In the top poll panel, monitor:
  - source freshness cards
  - reliability metrics (success rate, consecutive failures, average latency)
  - reliability alerts
- Use `Unhealthy sources only` to focus on stale/erroring feeds.
- Use `Poll Source` on a single stale/erroring feed instead of triggering a full poll cycle.
- Use `Recent Poll Runs` with `Errors only` and `Source` filters to troubleshoot ingestion failures.
- Use `Retry` on failed history entries to replay a failed source/full poll.
- Export poll history (`CSV`/`JSON`) for audit, handoff, or incident documentation.

Recommended outcome:
- Verified collection health and fresher data with minimal unnecessary upstream polling.

### 4. Research / Comparative Analysis

Use this workflow to study how the same CVE is represented across sources and over time.

- Reprocess historical findings after enrichment changes using `REPROCESS_SEEN=true` to backfill new fields.
- Compare corroboration score, patch matrix, and contradiction flags across findings.
- Export enriched findings JSON for notebooks, dashboards, or downstream analytics.
- Track source reliability telemetry to understand collection bias and availability effects on results.

Recommended outcome:
- Reproducible datasets with source-aware context for experiments and reporting.

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

Feed Analytics POC page:
- Open `http://127.0.0.1:8080/assets/feed-analytics-poc.html`
- The main dashboard and analytics POC include links to each other for quick navigation.

Serve polling flags:
- `--poll`: enable background polling while the dashboard is running.
- `--poll-interval-minutes`: override polling cadence at startup (applies to `daemon` and `serve --poll`).


Operations scheduler (configurable):
- Config is persisted in `output/ops_config.json` and runtime/job status in `output/ops_ops_status.json`.
- Scheduled exports can write findings and poll history to timestamped folders under `output/exports/`.
- Notifications config (rules/channels) is persisted now; alert delivery engine is the next implementation step.

Dashboard Poll Controls (top bar):
- Auto-poll toggle: enable/disable background polling without restart.
- Interval slider: set polling cadence at runtime.
- `Poll Now` button: trigger an immediate full-source refresh (returns a clear `already running` response if a poll is in progress).
- Reliability alerts: highlights stale/erroring/low-success-rate sources.
- `Unhealthy sources only` toggle: filters source cards to problem sources.
- Source freshness cards: per-source status, last polled time, last success time, duration, records, and last error.
- Source reliability metrics: per-source success rate, consecutive failures, average latency, stale status, and cooldown metadata.
- `Poll Source` buttons: manually refresh a single source when a source is stale/erroring without forcing a full poll.
- Source cooldowns: manual source polls enforce a short cooldown to avoid hammering upstream feeds.
- Recent Poll Runs: rolling audit trail of recent poll cycles (status, duration, new findings, failed sources, error summary).
- Poll history filters: `Errors only` and `Source` filters for fast troubleshooting.
- Retry from history: retry a failed/source poll directly from the `Recent Poll Runs` list.
- Poll history export: download poll audit history as CSV or JSON.

Dashboard Operations Controls (top bar):
- `Show Operations` / `Hide Operations` button: collapses the operations scheduler/alerts panel to keep the top area compact.
- Scheduled Exports panel: configure runtime export scheduler (`enabled`, `hourly`/`daily`, UTC time, formats, datasets).
- `Apply Ops Config` button: persists operations config to `output/ops_config.json`.
- `Run Export Now` button: queues an immediate export job using the scheduler pipeline.
- Export Job History: recent scheduled/manual export jobs with status, duration, output count, and errors.
- Alerts (Config) panel: webhook/rule settings are configurable and persisted (delivery engine is config-ready in this build).


## Corroboration, Patch Matrix, Asset Mapping, and Saved Views

- `Export CSV` / `Export JSON` buttons: download findings with analyst enrichment fields for sharing and offline analysis.
- Saved analyst views/presets (stored in browser local storage) support recurring filter/sort combinations such as `High corroboration + in scope` or `Vendor patch watch`.

The dashboard surfaces advanced corroboration and remediation context per finding:
- Source corroboration score + confidence label (`low` / `medium` / `high`)
- Independent corroborating source count and source-family presence (core/open/vendor/national/telemetry)
- Regional escalation badges (multi-national and transatlantic combinations)
- Asset mapping hits against `TARGET_PACKAGES`, `TARGET_ECOSYSTEMS`, `TARGET_CPES`, plus optional inventory metadata routing context
- Bounded inventory-based priority boost (when findings match high-value production assets in `ASSET_INVENTORY_PATH`)
- Patch availability matrix summary across `NVD`, `CVE.org`, `OSV`, `MSRC`, `Red Hat`, and `Debian`


## No-API Demo Mode

Seed a known-good local dataset and start the dashboard without API keys:

```bash
python -m cve_agent.cli demo
python -m cve_agent.cli serve --host 127.0.0.1 --port 8080
```

Demo data source:
- `demo/findings.demo.jsonl`

## Post-Upgrade Reprocess (Backfill New Fields)

After adding new enrichment/scoring fields (for example, corroboration and patch-matrix fields), existing rows in `output/findings.jsonl` will not automatically contain those fields.

Run a one-time reprocess pass to backfill existing findings:

```bash
# PowerShell
$env:REPROCESS_SEEN='true'
python -m cve_agent.cli once
Remove-Item Env:REPROCESS_SEEN
```

This re-evaluates previously seen CVEs and rewrites findings/reports with the latest enrichment logic.

## Asset Inventory Examples and Validation

Use the included examples to bootstrap inventory-driven matching:
- `examples/assets.inventory.json`
- `examples/assets.inventory.csv`

Supported inventory metadata fields (JSON assets or CSV columns):
- `asset_id`
- `owner`
- `criticality` (`low` / `medium` / `high` / `critical`)
- `environment` (`dev`, `staging`, `prod`, etc.)
- `business_service`
- `internet_exposed` (`true` / `false`)
- `tags`

These fields are used to improve asset routing context and apply a bounded inventory-based priority boost when a finding matches high-value production assets.

Validate inventory format before enabling `ASSET_INVENTORY_PATH`:

```bash
python -m cve_agent.cli validate-inventory --inventory-path examples/assets.inventory.json
just validate-inventory
just validate-inventory path=examples/assets.inventory.csv
```

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
- `just validate-inventory` (optionally `path=examples/assets.inventory.csv`)

## Polling API

Findings export endpoints:
- `GET /api/export.csv` (includes corroboration/asset/patch context columns)
- `GET /api/export.json`

Poll history export endpoints:
- `GET /api/poll/history.csv`
- `GET /api/poll/history.json`

Runtime polling endpoints:
- `GET /api/poll/status`: current polling state + per-source freshness telemetry
- `POST /api/poll/config`: update runtime polling config (`enabled`, `interval_minutes`)
- `POST /api/poll/run`: trigger an immediate manual polling cycle
- `POST /api/poll/run-source`: trigger a single-source polling cycle (`source`)
- `POST /api/poll/retry-history`: retry a poll based on a history entry (`history_index`)

Operations scheduler endpoints:
- `GET /api/ops/status`: scheduled export runtime status, config (redacted), and ops job history
- `POST /api/ops/config`: update notifications/exports ops config (persisted to `output/ops_config.json`)
- `POST /api/ops/run-export`: queue an immediate scheduled-export job


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
- `ASSET_INVENTORY_PATH`: optional JSON/CSV inventory file to augment `TARGET_*` matching inputs and provide asset metadata for routing/priority boosts
- `REPROCESS_SEEN`: reprocess seen CVEs for change tracking (`false` default)
- `CSAF_FEED_URLS`: comma-separated CSAF/global feed URLs
- `REGIONAL_RSS_URLS`: comma-separated RSS feed URLs
- `JVN_API_TEMPLATE`: JVN request template containing `{cve_id}`
- Operations scheduler/runtime config is persisted in `output/ops_config.json` (API-managed; no required env vars for first pass)

## Output

- `output/findings.jsonl`: enriched structured findings
- `output/reports/*.md`: detailed per-CVE reports
- `output/state.json`: seen CVE IDs
- `output/triage.json`: triage state/note overrides
- `output/findings_latest.json`: latest snapshot for change detection
- `output/poll_status.json`: persisted polling state and per-source freshness snapshot
- `output/ops_config.json`: persisted operations config (notifications + scheduled exports)
- `output/ops_ops_status.json`: persisted operations runtime status and export job history
- `output/exports/<timestamp>/...`: scheduled export artifacts (findings and/or poll history in configured formats)

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

