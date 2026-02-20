from __future__ import annotations

import unittest

from cve_agent.enrichment import apply_enrichment
from cve_agent.models import AnalysisResult, CVEItem


class EnrichmentTests(unittest.TestCase):
    def test_apply_enrichment_sets_kev_epss_and_priority(self) -> None:
        cve = CVEItem(
            cve_id="CVE-TEST-2",
            published="",
            last_modified="",
            description="",
            cvss_v31_base=8.0,
        )
        analysis = AnalysisResult(
            cve=cve,
            confidence=0.9,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
        )

        result = apply_enrichment(
            analysis,
            kev_entry={
                "dateAdded": "2026-01-10",
                "dueDate": "2026-02-01",
                "requiredAction": "Patch immediately",
            },
            epss_entry={
                "epss_score": 0.81,
                "epss_percentile": 0.97,
            },
        )

        self.assertTrue(result.kev_status)
        self.assertAlmostEqual(result.epss_score or 0.0, 0.81, places=3)
        self.assertGreater(result.priority_score, 0.0)
        self.assertIn("KEV listed", result.priority_reason)


if __name__ == "__main__":
    unittest.main()
