from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contract import REQUIRED_FINDING_FIELDS, SCHEMA_VERSION
from .models import AnalysisResult, MitreMatch


class Reporter:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.reports_dir = output_dir / "reports"
        self.jsonl_path = output_dir / "findings.jsonl"
        self.latest_path = output_dir / "findings_latest.json"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._previous_latest = self._load_latest()
        self._current_latest = dict(self._previous_latest)

    def write(self, finding: AnalysisResult) -> None:
        self._apply_change_tracking(finding)
        self._write_jsonl(finding)
        self._write_markdown(finding)
        self._current_latest[finding.cve.cve_id.upper()] = {
            "priority_score": finding.priority_score,
            "has_fix": finding.has_fix,
            "evidence_score": finding.evidence_score,
        }
        self._persist_latest()

    def _load_latest(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.latest_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k).upper(): v for k, v in data.items() if isinstance(v, dict)}
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return {}

    def _persist_latest(self) -> None:
        self.latest_path.write_text(json.dumps(self._current_latest, indent=2), encoding="utf-8")

    def _apply_change_tracking(self, finding: AnalysisResult) -> None:
        prev = self._previous_latest.get(finding.cve.cve_id.upper())
        if not prev:
            finding.change_type = "new"
            finding.change_reason = "first observation"
            return

        prev_priority = _safe_float(prev.get("priority_score"))
        prev_has_fix = bool(prev.get("has_fix"))

        if (not prev_has_fix) and finding.has_fix:
            finding.change_type = "newly_fixed"
            finding.change_reason = "fix information became available"
        elif abs(finding.priority_score - prev_priority) >= 0.10:
            finding.change_type = "priority_changed"
            finding.change_reason = f"priority changed from {prev_priority:.2f} to {finding.priority_score:.2f}"
        else:
            finding.change_type = "unchanged"
            finding.change_reason = "no material change vs prior snapshot"

    def _write_jsonl(self, finding: AnalysisResult) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "cve_id": finding.cve.cve_id,
            "published": finding.cve.published,
            "last_modified": finding.cve.last_modified,
            "confidence": finding.confidence,
            "matched_keywords": finding.matched_keywords,
            "categories": finding.categories,
            "summary": finding.summary,
            "remediation": finding.remediation,
            "references": finding.cve.references,
            "cwes": finding.cve.cwes,
            "cpes": finding.cve.cpes,
            "cvss_v31_base": finding.cve.cvss_v31_base,
            "cvss_v31_vector": finding.cve.cvss_v31_vector,
            "atlas_matches": self._serialize_matches(finding.atlas_matches),
            "attack_matches": self._serialize_matches(finding.attack_matches),
            "correlation_summary": finding.correlation_summary,
            "kev_status": finding.kev_status,
            "kev_date_added": finding.kev_date_added,
            "kev_due_date": finding.kev_due_date,
            "kev_required_action": finding.kev_required_action,
            "epss_score": finding.epss_score,
            "epss_percentile": finding.epss_percentile,
            "cna_org_id": finding.cna_org_id,
            "affected_products": finding.affected_products,
            "ecosystems": finding.ecosystems,
            "packages": finding.packages,
            "cpe_uris": finding.cpe_uris,
            "fixed_versions": finding.fixed_versions,
            "has_fix": finding.has_fix,
            "ssvc_decision": finding.ssvc_decision,
            "ssvc_role": finding.ssvc_role,
            "ghsa_ids": finding.ghsa_ids,
            "ghsa_severity": finding.ghsa_severity,
            "circl_sightings": finding.circl_sightings,
            "openvex_status": finding.openvex_status,
            "attack_feed_version": finding.attack_feed_version,
            "regional_sources": finding.regional_sources,
            "regional_signal_count": finding.regional_signal_count,
            "evidence_score": finding.evidence_score,
            "evidence_reason": finding.evidence_reason,
            "evidence_links": finding.evidence_links,
            "contradiction_flags": finding.contradiction_flags,
            "asset_in_scope": finding.asset_in_scope,
            "asset_scope_reason": finding.asset_scope_reason,
            "triage_state": finding.triage_state,
            "triage_note": finding.triage_note,
            "change_type": finding.change_type,
            "change_reason": finding.change_reason,
            "priority_score": finding.priority_score,
            "priority_reason": finding.priority_reason,
            "source_corroboration_score": finding.source_corroboration_score,
            "source_corroboration_count": finding.source_corroboration_count,
            "source_confidence_label": finding.source_confidence_label,
            "source_corroboration_sources": finding.source_corroboration_sources,
            "source_family_presence": finding.source_family_presence,
            "vendor_advisory_count": finding.vendor_advisory_count,
            "national_feed_count": finding.national_feed_count,
            "regional_escalation_badges": finding.regional_escalation_badges,
            "asset_mapping_hits": finding.asset_mapping_hits,
            "asset_mapping_score": finding.asset_mapping_score,
            "asset_mapping_summary": finding.asset_mapping_summary,
            "asset_priority_boost": finding.asset_priority_boost,
            "asset_owners": finding.asset_owners,
            "asset_business_services": finding.asset_business_services,
            "asset_routing_summary": finding.asset_routing_summary,
            "patch_availability_matrix": finding.patch_availability_matrix,
            "patch_availability_summary": finding.patch_availability_summary,
        }
        missing = [key for key in REQUIRED_FINDING_FIELDS if key not in payload]
        if missing:
            raise ValueError(f"findings contract violation: missing required fields {missing}")

        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _write_markdown(self, finding: AnalysisResult) -> None:
        cve = finding.cve
        target = self.reports_dir / f"{cve.cve_id}.md"

        refs = "\n".join(f"- {url}" for url in cve.references) if cve.references else "- None"
        cwes = ", ".join(cve.cwes) if cve.cwes else "N/A"
        cpes = ", ".join(cve.cpes) if cve.cpes else "N/A"
        atlas_lines = self._format_match_lines(finding.atlas_matches)
        attack_lines = self._format_match_lines(finding.attack_matches)
        evidence_lines = "\n".join(f"- {x}" for x in finding.evidence_links) if finding.evidence_links else "- None"
        contradiction_lines = (
            "\n".join(f"- {x}" for x in finding.contradiction_flags) if finding.contradiction_flags else "- None"
        )
        corroborating_sources_line = (
            ", ".join(finding.source_corroboration_sources) if finding.source_corroboration_sources else "N/A"
        )
        regional_escalation_badges_line = (
            ", ".join(finding.regional_escalation_badges) if finding.regional_escalation_badges else "N/A"
        )
        asset_business_services_line = (
            ", ".join(finding.asset_business_services) if finding.asset_business_services else "N/A"
        )

        content = f"""# {cve.cve_id}

## Summary
{finding.summary}

## CVE Metadata
- Published: {cve.published}
- Last modified: {cve.last_modified}
- Confidence (agentic AI relevance): {finding.confidence:.2f}
- Matched keywords: {", ".join(finding.matched_keywords)}
- Categories: {", ".join(finding.categories)}
- CWE: {cwes}
- CPEs: {cpes}
- CVSS v3.1 Base Score: {cve.cvss_v31_base if cve.cvss_v31_base is not None else "N/A"}
- CVSS v3.1 Vector: {cve.cvss_v31_vector or "N/A"}

## Operational Risk Signals
- Priority score: {finding.priority_score:.2f}
- Priority rationale: {finding.priority_reason or "N/A"}
- Change type: {finding.change_type}
- Change reason: {finding.change_reason}
- KEV listed: {"Yes" if finding.kev_status else "No"}
- KEV date added: {finding.kev_date_added or "N/A"}
- KEV due date: {finding.kev_due_date or "N/A"}
- EPSS score: {finding.epss_score if finding.epss_score is not None else "N/A"}
- EPSS percentile: {finding.epss_percentile if finding.epss_percentile is not None else "N/A"}
- SSVC decision: {finding.ssvc_decision or "N/A"}
- SSVC role: {finding.ssvc_role or "N/A"}
- GHSA IDs: {", ".join(finding.ghsa_ids) if finding.ghsa_ids else "N/A"}
- GHSA severity: {finding.ghsa_severity or "N/A"}
- CIRCL sightings: {finding.circl_sightings if finding.circl_sightings is not None else "N/A"}
- OpenVEX status: {finding.openvex_status or "N/A"}
- ATT&CK feed version: {finding.attack_feed_version or "N/A"}
- Regional/National sources: {", ".join(finding.regional_sources) if finding.regional_sources else "N/A"}
- Regional signal count: {finding.regional_signal_count}
- Source corroboration score: {finding.source_corroboration_score:.2f} ({finding.source_confidence_label})
- Source corroboration count: {finding.source_corroboration_count}
- Corroborating sources: {corroborating_sources_line}
- Regional escalation badges: {regional_escalation_badges_line}
- Patch availability matrix: {finding.patch_availability_summary or "N/A"}

## Ecosystem and Fix Context
- CNA org ID: {finding.cna_org_id or "N/A"}
- Affected products: {", ".join(finding.affected_products) if finding.affected_products else "N/A"}
- Ecosystems: {", ".join(finding.ecosystems) if finding.ecosystems else "N/A"}
- Packages: {", ".join(finding.packages) if finding.packages else "N/A"}
- Matching CPEs: {", ".join(finding.cpe_uris) if finding.cpe_uris else "N/A"}
- Has fix version: {"Yes" if finding.has_fix else "No"}
- Fixed versions: {", ".join(finding.fixed_versions) if finding.fixed_versions else "N/A"}
- Asset mapping score: {finding.asset_mapping_score:.2f}
- Asset mapping summary: {finding.asset_mapping_summary or "N/A"}
- Asset owners (inventory): {", ".join(finding.asset_owners) if finding.asset_owners else "N/A"}
- Business services (inventory): {asset_business_services_line}
- Inventory priority boost: {finding.asset_priority_boost:.2f}
- Asset routing summary: {finding.asset_routing_summary or "N/A"}

## Phase 3 Evidence Correlation
- Evidence score: {finding.evidence_score:.2f}
- Evidence rationale: {finding.evidence_reason or "N/A"}
- In target asset scope: {"Yes" if finding.asset_in_scope else "No"}
- Asset scope reason: {finding.asset_scope_reason or "N/A"}

### Evidence Links
{evidence_lines}

### Contradictions
{contradiction_lines}

## Triage
- State: {finding.triage_state}
- Note: {finding.triage_note or "N/A"}

## MITRE Correlation
- Summary: {finding.correlation_summary}

### MITRE ATLAS Matches
{atlas_lines}

### MITRE ATT&CK Matches
{attack_lines}

## Description
{cve.description or "No description provided by source."}

## Recommended Remediation
{finding.remediation}

## Code Guidance (Python)
```python
{finding.code_examples.get("python", "# no example")}
```

## Code Guidance (JavaScript)
```javascript
{finding.code_examples.get("javascript", "// no example")}
```

## References
{refs}
"""
        target.write_text(content, encoding="utf-8")

    def _serialize_matches(self, matches: list[MitreMatch]) -> list[dict[str, Any]]:
        return [
            {
                "framework": m.framework,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "score": m.score,
                "reasons": m.reasons,
            }
            for m in matches
        ]

    def _format_match_lines(self, matches: list[MitreMatch]) -> str:
        if not matches:
            return "- None"

        lines = []
        for m in matches:
            reasons = "; ".join(m.reasons) if m.reasons else "No reason provided"
            line = (
                f"- {m.technique_id} ({m.technique_name}) | tactic={m.tactic} "
                f"| confidence={m.confidence} | reason={reasons}"
            )
            lines.append(line)
        return "\n".join(lines)


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
