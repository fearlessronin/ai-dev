from __future__ import annotations

import unittest

from cve_agent.models import AnalysisResult, CVEItem
from cve_agent.sources.nvd import NVDClient
from cve_agent.enrichment import apply_enrichment


class IntegrationSignalsTests(unittest.TestCase):
    def test_nvd_extracts_cpes(self) -> None:
        client = NVDClient()
        entry = {
            "cve": {
                "id": "CVE-TEST-CPES",
                "published": "",
                "lastModified": "",
                "descriptions": [{"lang": "en", "value": "x"}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:acme:agent-sdk:*:*:*:*:*:python:*:*"},
                                ]
                            }
                        ]
                    }
                ],
            }
        }

        parsed = client._parse_entry(entry)  # noqa: SLF001 - test internal parser behavior
        self.assertIn("cpe:2.3:a:acme:agent-sdk:*:*:*:*:*:python:*:*", parsed.cpes)

    def test_enrichment_applies_ghsa_circl_and_openvex(self) -> None:
        cve = CVEItem(
            cve_id="CVE-TEST-EXT",
            published="",
            last_modified="",
            description="",
            cpes=["cpe:2.3:a:acme:agent-sdk:*:*:*:*:*:python:*:*"],
        )
        analysis = AnalysisResult(
            cve=cve,
            confidence=0.8,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
        )

        result = apply_enrichment(
            analysis,
            kev_entry=None,
            epss_entry=None,
            cveorg_entry={
                "containers": {
                    "adp": [
                        {"metrics": [{"ssvc": {"decision": "Act", "role": "CISA"}}]},
                    ]
                }
            },
            osv_entry=None,
            ghsa_entries=[
                {
                    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                    "severity": "high",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "pip", "name": "agent-sdk"},
                            "patched_versions": ">=2.3.1",
                        }
                    ],
                }
            ],
            circl_entry={"sightings": 7},
            openvex_status="not_affected",
        )

        self.assertEqual(result.ssvc_decision, "Act")
        self.assertEqual(result.ssvc_role, "CISA")
        self.assertIn("GHSA-aaaa-bbbb-cccc", result.ghsa_ids)
        self.assertEqual(result.ghsa_severity, "high")
        self.assertEqual(result.circl_sightings, 7)
        self.assertEqual(result.openvex_status, "not_affected")
        self.assertIn(">=2.3.1", result.fixed_versions)


if __name__ == "__main__":
    unittest.main()
