from __future__ import annotations

import unittest

from cve_agent.enrichment import apply_enrichment
from cve_agent.models import AnalysisResult, CVEItem


class EnrichmentTests(unittest.TestCase):
    def test_apply_enrichment_sets_phase1_and_phase2_fields(self) -> None:
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
            cveorg_entry={
                "containers": {
                    "cna": {
                        "providerMetadata": {"orgId": "ORG-123"},
                        "affected": [
                            {
                                "vendor": "acme",
                                "product": "agent-sdk",
                                "versions": [
                                    {"status": "fixed", "version": "2.3.1"},
                                ],
                            }
                        ],
                    }
                }
            },
            osv_entry={
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "agent-sdk"},
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "2.3.1"},
                                ]
                            }
                        ],
                    }
                ]
            },
        )

        self.assertTrue(result.kev_status)
        self.assertAlmostEqual(result.epss_score or 0.0, 0.81, places=3)
        self.assertEqual(result.cna_org_id, "ORG-123")
        self.assertIn("acme/agent-sdk", result.affected_products)
        self.assertIn("PyPI", result.ecosystems)
        self.assertIn("agent-sdk", result.packages)
        self.assertIn("2.3.1", result.fixed_versions)
        self.assertTrue(result.has_fix)
        self.assertGreater(result.priority_score, 0.0)
        self.assertIn("KEV listed", result.priority_reason)


if __name__ == "__main__":
    unittest.main()
