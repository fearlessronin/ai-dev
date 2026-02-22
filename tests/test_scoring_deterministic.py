from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cve_agent.analyzer import analyze_candidate
from cve_agent.correlation_v2 import apply_phase3_correlation
from cve_agent.models import AnalysisResult, CVEItem
from cve_agent.reporter import Reporter


class DeterministicScoringTests(unittest.TestCase):
    def test_relevance_scoring_is_deterministic(self) -> None:
        cve = CVEItem(
            cve_id="CVE-TEST-R1",
            published="2026-01-01",
            last_modified="2026-01-01",
            description="Agentic LLM prompt injection through tool calling plugin chain.",
        )

        result = analyze_candidate(cve)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.confidence, 1.0)
        self.assertIn("prompt_injection", result.categories)
        self.assertIn("unsafe_tool_execution", result.categories)

    def test_evidence_weighted_priority_is_deterministic(self) -> None:
        cve = CVEItem(cve_id="CVE-TEST-E1", published="", last_modified="", description="")
        analysis = AnalysisResult(
            cve=cve,
            confidence=0.8,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
            priority_score=0.50,
            has_fix=True,
            affected_products=["acme/agent-sdk"],
            packages=["agent-sdk"],
        )

        result = apply_phase3_correlation(
            analysis,
            kev_entry={"cveID": "CVE-TEST-E1"},
            epss_entry={"epss_score": 0.8},
            cveorg_entry={
                "containers": {"cna": {"affected": [{"versions": [{"status": "fixed", "version": "2.1.0"}]}]}}
            },
            osv_entry={"affected": [{"ranges": [{"events": [{"fixed": "2.1.0"}]}]}]},
        )

        self.assertEqual(result.evidence_score, 0.85)
        self.assertEqual(result.priority_score, 0.6)

    def test_contradiction_logic_is_deterministic(self) -> None:
        cve = CVEItem(cve_id="CVE-TEST-C1", published="", last_modified="", description="")
        analysis = AnalysisResult(
            cve=cve,
            confidence=0.7,
            matched_keywords=[],
            categories=[],
            summary="",
            remediation="",
            code_examples={},
            priority_score=0.55,
            has_fix=False,
            openvex_status="not_affected",
        )

        result = apply_phase3_correlation(
            analysis,
            kev_entry=None,
            epss_entry={"epss_score": 0.2},
            cveorg_entry={
                "containers": {"cna": {"affected": [{"versions": [{"status": "fixed", "version": "9.0.0"}]}]}}
            },
            osv_entry={"affected": [{"ranges": [{"events": [{"fixed": "8.1.0"}]}]}]},
        )

        joined = " | ".join(result.contradiction_flags)
        self.assertIn("CVE.org and OSV fixed-version data disagree", joined)
        self.assertIn("OpenVEX indicates not_affected", joined)
        self.assertEqual(result.evidence_score, 0.0)

    def test_change_type_classification_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "findings_latest.json").write_text(
                json.dumps(
                    {
                        "CVE-TEST-NEW": {"priority_score": 0.40, "has_fix": False, "evidence_score": 0.2},
                        "CVE-TEST-PRIO": {"priority_score": 0.30, "has_fix": True, "evidence_score": 0.3},
                        "CVE-TEST-SAME": {"priority_score": 0.52, "has_fix": True, "evidence_score": 0.4},
                    }
                ),
                encoding="utf-8",
            )
            reporter = Reporter(out)

            prio_change = _analysis("CVE-TEST-PRIO", 0.45, True)
            reporter.write(prio_change)
            self.assertEqual(prio_change.change_type, "priority_changed")

            unchanged = _analysis("CVE-TEST-SAME", 0.57, True)
            reporter.write(unchanged)
            self.assertEqual(unchanged.change_type, "unchanged")

            new_finding = _analysis("CVE-TEST-NOT-SEEN", 0.20, False)
            reporter.write(new_finding)
            self.assertEqual(new_finding.change_type, "new")

    def test_reporter_jsonl_contains_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            reporter = Reporter(out)
            finding = _analysis("CVE-TEST-CONTRACT", 0.30, False)
            reporter.write(finding)

            rows = (out / "findings.jsonl").read_text(encoding="utf-8").splitlines()
            payload = json.loads(rows[0])
            self.assertEqual(payload["schema_version"], "1.1")
            self.assertIn("cve_id", payload)
            self.assertIn("priority_score", payload)
            self.assertIn("change_type", payload)


def _analysis(cve_id: str, priority: float, has_fix: bool) -> AnalysisResult:
    return AnalysisResult(
        cve=CVEItem(cve_id=cve_id, published="", last_modified="", description=""),
        confidence=0.6,
        matched_keywords=["llm"],
        categories=["general_ai_security"],
        summary="demo",
        remediation="demo",
        code_examples={},
        priority_score=priority,
        has_fix=has_fix,
    )


if __name__ == "__main__":
    unittest.main()
