# Findings JSONL Data Contract

`output/findings.jsonl` uses a line-delimited JSON format with schema versioning.

## Schema Version

- Field: `schema_version`
- Current value: `1.0`

## Required Fields (v1.0)

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

## Notes

- New fields may be added over time. Consumers should ignore unknown fields.
- Any breaking contract change increments `schema_version`.
- Reporter enforces required field presence before writing each record.
