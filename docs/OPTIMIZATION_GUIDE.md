# Optimization Guide

## Goal

Maximize signal quality for AI environment defense while minimizing triage noise.

## Recommended Configuration

Set these in `.env`:
- `WINDOW_DAYS=30`
- `SOURCE_CACHE_TTL_MINUTES=15`
- `REPROCESS_SEEN=false` for normal operation
- `REPROCESS_SEEN=true` for periodic re-evaluation passes

Scope tuning:
- `TARGET_ECOSYSTEMS=PyPI,npm`
- `TARGET_PACKAGES=<critical internal or third-party AI packages>`
- `TARGET_CPES=<high-value infrastructure CPE fragments>`

Optional integrations:
- `GITHUB_TOKEN` for higher GHSA API quota
- `OPENVEX_PATH` for local VEX status overrides

## Polling and Freshness Tuning

- Run `serve --poll` for analyst-facing dashboards that need continuous freshness.
- Start at `--poll-interval-minutes 30` for balanced coverage and API load.
- Use shorter intervals (5-15 min) only when analysts actively triage new campaigns.
- Use the top-bar source freshness cards to identify slow/error-prone feeds before lowering intervals.
- Prefer `Poll Now` for ad hoc refreshes instead of permanently aggressive polling.

## Tuning Strategy

1. Start strict
- Keep target package/CPE lists narrow.
- Require stronger evidence in filters (`Min Evidence >= 0.35`).

2. Expand deliberately
- Add ecosystems/packages only when false negatives are confirmed.
- Track how many findings move to `investigating` vs `accepted_risk`.

3. Resolve contradictions
- Investigate records with `Has contradictions` first.
- Align vendor advisories with OSV/GHSA/CVE.org fix ranges.
- Use MSRC/Red Hat/Debian context as corroboration when package/version evidence is sparse.

4. Establish SLAs
- `priority >= 0.80`: same-day response
- `0.60 - 0.79`: this sprint
- `< 0.60`: backlog unless in-scope + high-impact

## Operations Cadence

Daily:
- Run `once` or keep `daemon` / `serve --poll` running.
- Triage new/high-priority in-scope issues.
- Check source freshness cards for stale or failed sources.

Weekly:
- Run reprocess pass with `REPROCESS_SEEN=true`.
- Export CSV and review trend deltas.
- Review poll telemetry (`output/poll_status.json`) for recurring source failures.

Monthly:
- Refresh target package/CPE inventories.
- Validate OpenVEX file currency.
- Revisit priority thresholds and SLA cutoffs.
- Review whether vendor/distro sources (MSRC, Red Hat, Debian) materially improve triage outcomes.

## Researcher Mode

Use broader scope and longer windows to discover emerging patterns:
- increase `WINDOW_DAYS` temporarily
- loosen target filters
- focus on change-type and contradiction clusters
- compare source freshness and availability when evaluating dataset coverage quality

Then convert findings back into tighter production rules.
