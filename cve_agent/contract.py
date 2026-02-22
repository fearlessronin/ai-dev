from __future__ import annotations

SCHEMA_VERSION = "1.1"

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
    "source_corroboration_score",
    "patch_availability_matrix",
]

