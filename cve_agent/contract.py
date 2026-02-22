from __future__ import annotations

SCHEMA_VERSION = "1.0"

REQUIRED_FINDING_FIELDS = [
    "schema_version",
    "cve_id",
    "published",
    "confidence",
    "summary",
    "priority_score",
    "priority_reason",
    "evidence_score",
    "change_type",
    "triage_state",
]
