from __future__ import annotations

import unittest

from cve_agent.corroboration_patch_context import apply_corroboration_patch_context
from cve_agent.models import AnalysisResult, CVEItem


def _analysis() -> AnalysisResult:
    cve = CVEItem(
        cve_id="CVE-2026-0001",
        published="2026-02-20T00:00:00Z",
        last_modified="2026-02-20T00:00:00Z",
        description="agent prompt injection issue",
        references=[],
        cwes=["CWE-20"],
        cpes=["cpe:2.3:a:acme:agent-platform:1.0:*:*:*:*:*:*:*"],
    )
    result = AnalysisResult(
        cve=cve,
        confidence=0.8,
        matched_keywords=["agent", "prompt injection"],
        categories=["prompt_injection"],
        summary="test",
        remediation="test",
        code_examples={"python": "pass", "javascript": ""},
    )
    result.epss_score = 0.42
    result.kev_status = True
    result.packages = ["acme-agent", "python3-foo"]
    result.affected_products = ["Acme/Agent Platform"]
    result.ecosystems = ["PyPI"]
    result.cpe_uris = ["cpe:2.3:a:acme:agent-platform:1.0:*:*:*:*:*:*:*"]
    result.fixed_versions = ["1.2.3", "RHSA-2026:1234", "bookworm:1.2.4-1"]
    result.regional_sources = [
        "CISA ICS Advisory",
        "CERT-FR",
        "BSI/CERT-Bund",
        "MSRC",
        "Red Hat Security Data API",
        "Debian Security Tracker",
    ]
    result.ghsa_ids = ["GHSA-xxxx-yyyy-zzzz"]
    return result


class CorroborationPatchContextTests(unittest.TestCase):
    def test_derives_scores_badges_asset_mapping_and_patch_matrix(self) -> None:
        analysis = _analysis()
        cveorg_entry = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "Acme",
                            "product": "Agent Platform",
                            "versions": [{"status": "fixed", "version": "1.2.3"}],
                        }
                    ]
                }
            }
        }
        osv_entry = {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "acme-agent"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                }
            ]
        }

        out = apply_corroboration_patch_context(
            analysis,
            cveorg_entry=cveorg_entry,
            osv_entry=osv_entry,
            msrc_entry={"source": "MSRC"},
            redhat_entry={"package_state": []},
            debian_entry={"packages": ["python3-foo"], "fixed_versions": ["bookworm:1.2.4-1"]},
            target_ecosystems=["PyPI"],
            target_packages=["acme-agent", "agent platform"],
            target_cpes=["cpe:2.3:a:acme:agent-platform"],
            inventory_context={
                "assets": [
                    {
                        "asset_id": "prod-api-01",
                        "packages": ["acme-agent"],
                        "ecosystems": ["PyPI"],
                        "owner": "secops",
                        "criticality": "critical",
                        "environment": "prod",
                        "business_service": "ai-api",
                        "internet_exposed": True,
                    }
                ]
            },
        )

        self.assertGreaterEqual(out.source_corroboration_score, 0.8)
        self.assertEqual(out.source_confidence_label, "high")
        self.assertIn("transatlantic-escalation", out.regional_escalation_badges)
        self.assertGreaterEqual(out.asset_mapping_score, 0.25)
        self.assertTrue(out.asset_mapping_hits)
        self.assertGreater(out.asset_priority_boost, 0.0)
        self.assertIn("secops", out.asset_owners)
        self.assertIn("ai-api", out.asset_business_services)
        self.assertIn("nvd", out.patch_availability_matrix)
        self.assertIn("cveorg", out.patch_availability_matrix)
        self.assertTrue(out.patch_availability_matrix["cveorg"]["fix_available"])
        self.assertTrue(out.patch_availability_matrix["osv"]["fix_available"])


if __name__ == "__main__":
    unittest.main()
