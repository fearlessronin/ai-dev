from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cve_agent.correlator import MitreCorrelator
from cve_agent.models import AnalysisResult, CVEItem


class CorrelatorTests(unittest.TestCase):
    def test_correlate_returns_atlas_and_attack_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = Path(td)
            (mappings / "atlas_rules.json").write_text(
                json.dumps(
                    [
                        {
                            "technique_id": "AML.T0018",
                            "technique_name": "LLM Plugin Abuse",
                            "tactic": "Execution",
                            "tags": ["unsafe_tool_execution"],
                            "keywords": ["plugin"],
                            "cwes": ["CWE-862"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (mappings / "attack_rules.json").write_text(
                json.dumps(
                    [
                        {
                            "technique_id": "T1190",
                            "technique_name": "Exploit Public-Facing Application",
                            "tactic": "Initial Access",
                            "tags": ["unsafe_tool_execution"],
                            "keywords": ["remote", "plugin"],
                            "cwes": ["CWE-862"],
                        }
                    ]
                ),
                encoding="utf-8",
            )

            cve = CVEItem(
                cve_id="CVE-TEST-1",
                published="",
                last_modified="",
                description="Remote plugin execution vulnerability in agent framework.",
                cwes=["CWE-862"],
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
            analysis = AnalysisResult(
                cve=cve,
                confidence=0.8,
                matched_keywords=["agent", "plugin"],
                categories=["unsafe_tool_execution"],
                summary="",
                remediation="",
                code_examples={},
            )

            correlator = MitreCorrelator(mappings)
            result = correlator.correlate(analysis)

            self.assertGreaterEqual(len(result.atlas_matches), 1)
            self.assertGreaterEqual(len(result.attack_matches), 1)
            self.assertIn("Matched", result.correlation_summary)


if __name__ == "__main__":
    unittest.main()
