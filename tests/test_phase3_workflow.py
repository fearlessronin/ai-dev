from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cve_agent.models import AnalysisResult, CVEItem
from cve_agent.reporter import Reporter
from cve_agent.web import _read_triage, _write_triage


class Phase3WorkflowTests(unittest.TestCase):
    def _analysis(self, cve_id: str, priority: float, has_fix: bool) -> AnalysisResult:
        cve = CVEItem(
            cve_id=cve_id,
            published="",
            last_modified="",
            description="",
        )
        return AnalysisResult(
            cve=cve,
            confidence=0.5,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
            priority_score=priority,
            has_fix=has_fix,
        )

    def test_reporter_change_tracking_marks_newly_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            latest_path = out / "findings_latest.json"
            latest_path.write_text(
                json.dumps({"CVE-TEST-9": {"priority_score": 0.40, "has_fix": False, "evidence_score": 0.2}}),
                encoding="utf-8",
            )

            reporter = Reporter(out)
            finding = self._analysis("CVE-TEST-9", priority=0.45, has_fix=True)
            reporter.write(finding)

            self.assertEqual(finding.change_type, "newly_fixed")
            self.assertIn("fix information", finding.change_reason)

    def test_triage_read_write_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            triage = {"CVE-TEST-10": {"state": "investigating", "note": "checking impact"}}
            _write_triage(out, triage)
            loaded = _read_triage(out)

            self.assertIn("CVE-TEST-10", loaded)
            self.assertEqual(loaded["CVE-TEST-10"]["state"], "investigating")
            self.assertEqual(loaded["CVE-TEST-10"]["note"], "checking impact")


if __name__ == "__main__":
    unittest.main()
