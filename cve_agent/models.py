from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CVEItem:
    cve_id: str
    published: str
    last_modified: str
    description: str
    references: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    cvss_v31_base: float | None = None
    cvss_v31_vector: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class MitreMatch:
    framework: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    cve: CVEItem
    confidence: float
    matched_keywords: list[str]
    categories: list[str]
    summary: str
    remediation: str
    code_examples: dict[str, str]
    atlas_matches: list[MitreMatch] = field(default_factory=list)
    attack_matches: list[MitreMatch] = field(default_factory=list)
    correlation_summary: str = "No MITRE correlations yet."

    kev_status: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None

    epss_score: float | None = None
    epss_percentile: float | None = None

    priority_score: float = 0.0
    priority_reason: str = ""
