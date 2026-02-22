from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cve_agent.inventory import load_inventory_targets


class InventoryTargetsTests(unittest.TestCase):
    def test_load_inventory_targets_json_dict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "packages": ["acme-agent"],
                        "ecosystems": ["PyPI"],
                        "cpes": ["cpe:2.3:a:acme:agent-platform"],
                    }
                ),
                encoding="utf-8",
            )
            out = load_inventory_targets(str(path))
            self.assertIn("acme-agent", out["packages"])
            self.assertIn("PyPI", out["ecosystems"])
            self.assertIn("cpe:2.3:a:acme:agent-platform", out["cpes"])

    def test_load_inventory_targets_csv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "assets.csv"
            path.write_text("package,ecosystem,cpe\nacme-agent,PyPI,cpe:2.3:a:acme:agent-platform\n", encoding="utf-8")
            out = load_inventory_targets(str(path))
            self.assertEqual(out["packages"], ["acme-agent"])
            self.assertEqual(out["ecosystems"], ["PyPI"])
            self.assertEqual(out["cpes"], ["cpe:2.3:a:acme:agent-platform"])


if __name__ == "__main__":
    unittest.main()
