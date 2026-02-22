from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AnalysisResult, MitreMatch


class MitreCorrelator:
    def __init__(self, mappings_dir: Path) -> None:
        self.mappings_dir = mappings_dir
        self.atlas_rules = self._load_rules("atlas_rules.json")
        self.attack_rules = self._load_rules("attack_rules.json")

    def correlate(self, analysis: AnalysisResult) -> AnalysisResult:
        text = analysis.cve.description.lower()
        cwes = {c.strip().upper() for c in analysis.cve.cwes}
        tags = {t.lower() for t in analysis.categories + analysis.matched_keywords}
        cvss_vector = (analysis.cve.cvss_v31_vector or "").upper()

        analysis.atlas_matches = self._match_framework("ATLAS", self.atlas_rules, text, cwes, tags, cvss_vector)
        analysis.attack_matches = self._match_framework("ATTACK", self.attack_rules, text, cwes, tags, cvss_vector)

        atlas_count = len(analysis.atlas_matches)
        attack_count = len(analysis.attack_matches)
        if atlas_count == 0 and attack_count == 0:
            analysis.correlation_summary = "No confident MITRE correlation rules matched."
        else:
            analysis.correlation_summary = (
                f"Matched {atlas_count} ATLAS and {attack_count} ATT&CK techniques using rule-based evidence scoring."
            )

        return analysis

    def _load_rules(self, filename: str) -> list[dict[str, Any]]:
        path = self.mappings_dir / filename
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError:
            return []

    def _match_framework(
        self,
        framework: str,
        rules: list[dict[str, Any]],
        text: str,
        cwes: set[str],
        tags: set[str],
        cvss_vector: str,
    ) -> list[MitreMatch]:
        matches: list[MitreMatch] = []

        for rule in rules:
            score = 0.0
            reasons: list[str] = []

            rule_tags = {str(x).lower() for x in rule.get("tags", [])}
            matched_tags = sorted(tags & rule_tags)
            if matched_tags:
                score += 0.35
                reasons.append(f"tag match: {', '.join(matched_tags)}")

            rule_keywords = [str(x).lower() for x in rule.get("keywords", [])]
            matched_keywords = [kw for kw in rule_keywords if kw in text]
            if matched_keywords:
                score += min(0.35, 0.10 * len(matched_keywords))
                reasons.append(f"keyword match: {', '.join(matched_keywords[:3])}")

            rule_cwes = {str(x).upper() for x in rule.get("cwes", [])}
            matched_cwes = sorted(cwes & rule_cwes)
            if matched_cwes:
                score += min(0.25, 0.10 * len(matched_cwes))
                reasons.append(f"CWE overlap: {', '.join(matched_cwes)}")

            if "AV:N" in cvss_vector and "remote" in " ".join(rule_keywords):
                score += 0.05
                reasons.append("CVSS indicates network exposure (AV:N)")

            if score < 0.35:
                continue

            confidence = "low"
            if score >= 0.75:
                confidence = "high"
            elif score >= 0.50:
                confidence = "medium"

            matches.append(
                MitreMatch(
                    framework=framework,
                    technique_id=str(rule.get("technique_id", "UNKNOWN")),
                    technique_name=str(rule.get("technique_name", "Unknown Technique")),
                    tactic=str(rule.get("tactic", "Unknown")),
                    confidence=confidence,
                    score=round(min(score, 1.0), 2),
                    reasons=reasons,
                )
            )

        matches.sort(key=lambda m: m.score, reverse=True)
        return matches
