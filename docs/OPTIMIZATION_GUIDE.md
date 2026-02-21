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

4. Establish SLAs
- `priority >= 0.80`: same-day response
- `0.60 - 0.79`: this sprint
- `< 0.60`: backlog unless in-scope + high-impact

## Operations Cadence

Daily:
- Run `once` or keep `daemon` running.
- Triage new/high-priority in-scope issues.

Weekly:
- Run reprocess pass with `REPROCESS_SEEN=true`.
- Export CSV and review trend deltas.

Monthly:
- Refresh target package/CPE inventories.
- Validate OpenVEX file currency.
- Revisit priority thresholds and SLA cutoffs.

## Researcher Mode

Use broader scope and longer windows to discover emerging patterns:
- increase `WINDOW_DAYS` temporarily
- loosen target filters
- focus on change-type and contradiction clusters

Then convert findings back into tighter production rules.
