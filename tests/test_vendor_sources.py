from __future__ import annotations

import unittest

from cve_agent.sources.debian import extract_debian_context
from cve_agent.sources.redhat import extract_redhat_context


class VendorSourcesTests(unittest.TestCase):
    def test_extract_redhat_context(self) -> None:
        entry = {
            "package_state": [
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "package_name": "python3-foo-1.2.3-1.el9",
                    "fix_state": "RHSA-2026:1234",
                }
            ],
            "affected_release": [
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "package": "python3-foo-1.2.4-1.el9",
                    "advisory": "RHSA-2026:1234",
                }
            ],
        }

        sources, packages, fixes = extract_redhat_context(entry)
        self.assertIn("Red Hat Security Data API", sources)
        self.assertTrue(any("python3-foo" in p for p in packages))
        self.assertIn("RHSA-2026:1234", fixes)

    def test_extract_debian_context(self) -> None:
        entry = {
            "packages": ["python-foo", "python-foo"],
            "fixed_versions": ["bookworm:1.2.3-1", "bullseye:1.2.2-1"],
        }

        sources, packages, fixes = extract_debian_context(entry)
        self.assertEqual(sources, ["Debian Security Tracker"])
        self.assertEqual(packages, ["python-foo"])
        self.assertIn("bookworm:1.2.3-1", fixes)


if __name__ == "__main__":
    unittest.main()
