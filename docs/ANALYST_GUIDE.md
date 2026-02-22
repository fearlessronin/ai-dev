# Analyst Guide

## What This App Does

AI CVE Radar continuously monitors newly published CVEs and prioritizes issues that are likely relevant to agentic AI systems, copilots, LLM apps, and AI toolchains.

It combines multiple signals in one place:
- NVD baseline vulnerability data and CPE context
- CISA KEV and EPSS exploitability indicators
- CVE.org CNA + Vulnrichment (SSVC-style) data
- OSV and GHSA package/fix context
- CIRCL sightings and optional OpenVEX override status
- Vendor/distro context from MSRC, Red Hat Security Data API, and Debian Security Tracker
- MITRE ATLAS and ATT&CK mapping
- Regional/national feed matching (CSAF/RSS/JVN)

## Who Should Use It

- SOC analysts triaging AI-related exposure
- Application security engineers validating fix urgency
- AI platform teams securing model-serving stacks and tool integrations
- Threat researchers tracking emerging AI attack surfaces

## Daily Analyst Workflow

1. Start in `Radar` view and sort by `Priority`.
2. Review the polling bar at the top:
- confirm `Auto-poll` state
- confirm source freshness (last success / status / errors)
- run `Poll Now` when you need an immediate refresh
3. Apply filters:
- `In target scope`
- `KEV listed`
- `Has contradictions`
- `Min Evidence`
4. Open top findings and read:
- `change_type` (`new`, `priority_changed`, `newly_fixed`, `unchanged`)
- evidence rationale and contradictions
- recommended remediation and fixed versions
- vendor/distro package/fix context when present (MSRC/Red Hat/Debian corroboration)
5. Set triage state and note:
- `new`
- `investigating`
- `mitigated`
- `accepted_risk`
6. Export CSV for ticketing/reporting workflows.

## Interpreting Priority

Treat priority as evidence-weighted guidance, not an absolute truth.
Use this order of confidence:
1. KEV + high EPSS + in-scope asset match
2. Strong package/CPE applicability and fix availability (including vendor/distro corroboration)
3. Consistent metadata across CVE.org, OSV, GHSA, and vendor/distro sources
4. No contradiction flags

If OpenVEX marks a CVE as `not_affected`, validate quickly and downgrade unless other hard evidence contradicts it.

## Analyst Tips

- Use `REPROCESS_SEEN=true` periodically to refresh change-type signals.
- Keep `TARGET_ECOSYSTEMS`, `TARGET_PACKAGES`, and `TARGET_CPES` tightly scoped.
- Review contradiction flags early; they often reveal source drift or version ambiguity.
- Treat missing fix data as uncertainty, not safety.
- If a source card shows `error` or stale freshness, use `Poll Now` after network/API recovery.
