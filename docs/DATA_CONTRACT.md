# Findings JSONL Data Contract

`output/findings.jsonl` uses a line-delimited JSON format with schema versioning.

## Schema Version

- Field: `schema_version`
- Current value: `1.1`

## Required Fields (v1.1)

- `schema_version`
- `cve_id`
- `published`
- `confidence`
- `summary`
- `priority_score`
- `priority_reason`
- `evidence_score`
- `change_type`
- `triage_state`
- `source_corroboration_score`
- `patch_availability_matrix`

## Notes

- New fields may be added over time. Consumers should ignore unknown fields.
- Any breaking contract change increments `schema_version`.
- Reporter enforces required field presence before writing each record.


## Corroboration and Patch Context additive fields (selected)

Examples of corroboration/patch context fields now emitted:
- `source_corroboration_count`, `source_corroboration_score`, `source_confidence_label`
- `source_corroboration_sources`, `source_family_presence`
- `regional_escalation_badges`
- `asset_mapping_hits`, `asset_mapping_score`, `asset_mapping_summary`
- `patch_availability_matrix`, `patch_availability_summary`
