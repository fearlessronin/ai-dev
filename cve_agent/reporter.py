from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
            "fixed_versions": finding.fixed_versions,
            "has_fix": finding.has_fix,
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
        }
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _write_markdown(self, finding: AnalysisResult) -> None:
        cve = finding.cve
        target = self.reports_dir / f"{cve.cve_id}.md"

        refs = "\n".join(f"- {url}" for url in cve.references) if cve.references else "- None"
        cwes = ", ".join(cve.cwes) if cve.cwes else "N/A"
        atlas_lines = self._format_match_lines(finding.atlas_matches)
        attack_lines = self._format_match_lines(finding.attack_matches)
        evidence_lines = "\n".join(f"- {x}" for x in finding.evidence_links) if finding.evidence_links else "- None"
        contradiction_lines = (
            "\n".join(f"- {x}" for x in finding.contradiction_flags)
            if finding.contradiction_flags
            else "- None"
        )

        content = f"""# {cve.cve_id}

## Summary
{finding.summary}

## CVE Metadata
- Published: {cve.published}
- Last modified: {cve.last_modified}
- Confidence (agentic AI relevance): {finding.confidence:.2f}
- Matched keywords: {', '.join(finding.matched_keywords)}
- Categories: {', '.join(finding.categories)}
- CWE: {cwes}
- CVSS v3.1 Base Score: {cve.cvss_v31_base if cve.cvss_v31_base is not None else 'N/A'}
- CVSS v3.1 Vector: {cve.cvss_v31_vector or 'N/A'}

## Operational Risk Signals
- Priority score: {finding.priority_score:.2f}
- Priority rationale: {finding.priority_reason or 'N/A'}
- Change type: {finding.change_type}
- Change reason: {finding.change_reason}
- KEV listed: {'Yes' if finding.kev_status else 'No'}
- KEV date added: {finding.kev_date_added or 'N/A'}
- KEV due date: {finding.kev_due_date or 'N/A'}
- EPSS score: {finding.epss_score if finding.epss_score is not None else 'N/A'}
- EPSS percentile: {finding.epss_percentile if finding.epss_percentile is not None else 'N/A'}

## Ecosystem and Fix Context
- CNA org ID: {finding.cna_org_id or 'N/A'}
- Affected products: {', '.join(finding.affected_products) if finding.affected_products else 'N/A'}
- Ecosystems: {', '.join(finding.ecosystems) if finding.ecosystems else 'N/A'}
- Packages: {', '.join(finding.packages) if finding.packages else 'N/A'}
- Has fix version: {'Yes' if finding.has_fix else 'No'}
- Fixed versions: {', '.join(finding.fixed_versions) if finding.fixed_versions else 'N/A'}

## Phase 3 Evidence Correlation
- Evidence score: {finding.evidence_score:.2f}
- Evidence rationale: {finding.evidence_reason or 'N/A'}
- In target asset scope: {'Yes' if finding.asset_in_scope else 'No'}
- Asset scope reason: {finding.asset_scope_reason or 'N/A'}

### Evidence Links
{evidence_lines}

### Contradictions
{contradiction_lines}

## Triage
- State: {finding.triage_state}
- Note: {finding.triage_note or 'N/A'}

## MITRE Correlation
- Summary: {finding.correlation_summary}

### MITRE ATLAS Matches
{atlas_lines}

### MITRE ATT&CK Matches
{attack_lines}

## Description
{cve.description or 'No description provided by source.'}

## Recommended Remediation
{finding.remediation}

## Code Guidance (Python)
```python
{finding.code_examples.get('python', '# no example')}
```

## Code Guidance (JavaScript)
```javascript
{finding.code_examples.get('javascript', '// no example')}
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
            lines.append(
                f"- {m.technique_id} ({m.technique_name}) | tactic={m.tactic} | confidence={m.confidence} | reason={reasons}"
            )
        return "\n".join(lines)


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
