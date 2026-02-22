from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cve_agent.demo import seed_demo_dataset


class DemoDatasetTests(unittest.TestCase):
    def test_seed_demo_dataset_writes_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            target = seed_demo_dataset(out)

            self.assertTrue(target.exists())
            self.assertTrue((out / "findings_latest.json").exists())

            rows = target.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(rows), 1)

            first = json.loads(rows[0])
            self.assertEqual(first.get("schema_version"), "1.0")
            self.assertIn("cve_id", first)


if __name__ == "__main__":
    unittest.main()
