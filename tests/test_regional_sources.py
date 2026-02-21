from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from cve_agent.sources.regional import RegionalIntelClient


class RegionalClientTests(unittest.TestCase):
    @patch("cve_agent.sources.regional.requests.get")
    def test_fetch_signals_maps_multiple_sources(self, mock_get: Mock) -> None:
        def _resp(text: str, status: int = 200) -> Mock:
            m = Mock()
            m.status_code = status
            m.text = text
            return m

        mock_get.side_effect = [
            _resp("CVE-2026-1001"),  # JVN for first CVE
            _resp("no hit"),         # JVN for second CVE
            _resp("<item>CVE-2026-1001</item><item>CVE-2026-2002</item>"),  # RSS
            _resp('{"note":"CVE-2026-2002"}'),  # CSAF text body
        ]

        client = RegionalIntelClient(
            csaf_feed_urls=["https://aggregator.certvde.com/feed.json"],
            rss_urls=["https://www.govcert.gov.hk/en/rss.html"],
            jvn_api_template="https://jvn.example/api?cve={cve_id}",
            timeout_seconds=5,
        )

        result = client.fetch_signals(["CVE-2026-1001", "CVE-2026-2002"])

        self.assertIn("CVE-2026-1001", result)
        self.assertIn("JVN", result["CVE-2026-1001"])
        self.assertIn("GovCERT-HK", result["CVE-2026-1001"])
        self.assertIn("CVE-2026-2002", result)
        self.assertIn("CERT-EU/CSAF", result["CVE-2026-2002"])


if __name__ == "__main__":
    unittest.main()
