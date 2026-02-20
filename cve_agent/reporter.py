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
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def write(self, finding: AnalysisResult) -> None:
        self._write_jsonl(finding)
        self._write_markdown(finding)

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
