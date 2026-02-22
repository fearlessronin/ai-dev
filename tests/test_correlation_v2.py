from __future__ import annotations

import unittest

from cve_agent.correlation_v2 import apply_phase3_correlation
from cve_agent.models import AnalysisResult, CVEItem


class CorrelationV2Tests(unittest.TestCase):
    def _analysis(self) -> AnalysisResult:
        cve = CVEItem(
            cve_id="CVE-TEST-3",
            published="",
            last_modified="",
            description="",
            cvss_v31_base=7.5,
        )
        return AnalysisResult(
            cve=cve,
            confidence=0.8,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
            priority_score=0.60,
            priority_reason="baseline",
            has_fix=True,
            affected_products=["acme/agent-sdk"],
            packages=["agent-sdk"],
        )

    def test_phase3_adds_evidence_and_blends_priority(self) -> None:
        analysis = self._analysis()

        result = apply_phase3_correlation(
            analysis,
            kev_entry={"cveID": "CVE-TEST-3"},
            epss_entry={"epss_score": 0.91},
            cveorg_entry={
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "versions": [
                                    {"status": "fixed", "version": "2.3.1"},
                                ]
                            }
                        ]
                    }
                }
            },
            osv_entry={
                "affected": [
                    {
                        "ranges": [
                            {"events": [{"fixed": "2.3.1"}]},
                        ]
                    }
                ]
            },
        )

        self.assertGreater(result.evidence_score, 0.0)
        self.assertIn("KEV indicates known exploitation", result.evidence_reason)
        self.assertEqual(len(result.contradiction_flags), 0)
        self.assertGreater(result.priority_score, 0.60)

    def test_phase3_flags_conflicting_fix_versions(self) -> None:
        analysis = self._analysis()

        result = apply_phase3_correlation(
            analysis,
            kev_entry=None,
            epss_entry={"epss_score": 0.2},
            cveorg_entry={
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "versions": [
                                    {"status": "fixed", "version": "3.1.0"},
                                ]
                            }
                        ]
                    }
                }
            },
            osv_entry={
                "affected": [
                    {
                        "ranges": [
                            {"events": [{"fixed": "2.9.0"}]},
                        ]
                    }
                ]
            },
        )

        self.assertGreaterEqual(len(result.contradiction_flags), 1)
        self.assertIn("disagree", result.contradiction_flags[0])


if __name__ == "__main__":
    unittest.main()
