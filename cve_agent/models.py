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
class AnalysisResult:
    cve: CVEItem
    confidence: float
    matched_keywords: list[str]
    categories: list[str]
    summary: str
    remediation: str
    code_examples: dict[str, str]
