from __future__ import annotations

import json
from pathlib import Path


def seed_demo_dataset(output_dir: Path) -> Path:
    root_dir = Path(__file__).resolve().parent.parent
    source = root_dir / "demo" / "findings.demo.jsonl"
    if not source.exists():
        raise FileNotFoundError(f"Demo dataset not found at {source}")

    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "findings.jsonl"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    triage_path = output_dir / "triage.json"
    if not triage_path.exists():
        triage_path.write_text("{}\n", encoding="utf-8")

    latest: dict[str, dict[str, float | bool]] = {}
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        finding = json.loads(line)
        cve_id = str(finding.get("cve_id", "")).upper()
        if not cve_id:
            continue
        latest[cve_id] = {
            "priority_score": float(finding.get("priority_score", 0.0) or 0.0),
            "has_fix": bool(finding.get("has_fix", False)),
            "evidence_score": float(finding.get("evidence_score", 0.0) or 0.0),
        }

    (output_dir / "findings_latest.json").write_text(json.dumps(latest, indent=2), encoding="utf-8")
    return target
