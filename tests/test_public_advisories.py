from __future__ import annotations

import unittest
from unittest.mock import patch

from cve_agent.sources.public_advisories import PublicAdvisoryClient, extract_cves_from_text


class PublicAdvisoryClientTests(unittest.TestCase):
    def test_extract_cves_from_text(self) -> None:
        text = "Mentions CVE-2026-1111 and cve-2025-22222 in advisory body."
        self.assertEqual(extract_cves_from_text(text), {"CVE-2026-1111", "CVE-2025-22222"})

    def test_fetch_feed_signals_filters_to_requested_ids(self) -> None:
        client = PublicAdvisoryClient(timeout_seconds=1)
        with patch.object(client, "_request_text_with_retry", return_value="CVE-2026-1111 CVE-2026-9999"):
            result = client.fetch_feed_signals(["CVE-2026-1111", "CVE-2026-2222"], "certfr")
        self.assertEqual(result, {"CVE-2026-1111": ["CERT-FR"]})


if __name__ == "__main__":
    unittest.main()
