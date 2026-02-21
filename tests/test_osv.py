from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from cve_agent.sources.osv import OSVClient


class OSVClientTests(unittest.TestCase):
    @patch("cve_agent.sources.osv.requests.post")
    @patch("cve_agent.sources.osv.requests.get")
    def test_fetch_records_uses_querybatch_results(self, mock_get: Mock, mock_post: Mock) -> None:
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(
                return_value={
                    "results": [
                        {"vulns": [{"id": "CVE-2026-0001", "affected": []}]},
                        {"vulns": [{"id": "CVE-2026-0002", "affected": []}]},
                    ]
                }
            ),
        )

        client = OSVClient(timeout_seconds=5)
        result = client.fetch_records(["CVE-2026-0001", "cve-2026-0002"])

        self.assertEqual(sorted(result.keys()), ["CVE-2026-0001", "CVE-2026-0002"])
        mock_get.assert_not_called()

    @patch("cve_agent.sources.osv.requests.post")
    @patch("cve_agent.sources.osv.requests.get")
    def test_fetch_records_falls_back_to_single_for_missing_batch_entries(
        self,
        mock_get: Mock,
        mock_post: Mock,
    ) -> None:
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"results": [{"vulns": [{"id": "CVE-2026-0001"}]}, {}]}),
        )
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"id": "CVE-2026-0002", "affected": []}),
        )

        client = OSVClient(timeout_seconds=5)
        result = client.fetch_records(["CVE-2026-0001", "CVE-2026-0002"])

        self.assertIn("CVE-2026-0001", result)
        self.assertIn("CVE-2026-0002", result)
        mock_get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
