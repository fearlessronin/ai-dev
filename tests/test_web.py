from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from cve_agent import web


class WebStartupChecksTest(unittest.TestCase):
    def test_find_listeners_for_port_parses_netstat_output(self) -> None:
        fake_output = """
  TCP    0.0.0.0:8080      0.0.0.0:0      LISTENING       1234
  TCP    127.0.0.1:8081    0.0.0.0:0      LISTENING       5678
"""

        class Result:
            stdout = fake_output

        with patch("subprocess.run", return_value=Result()):
            listeners = web._find_listeners_for_port(8080)

        self.assertEqual(listeners, [("0.0.0.0:8080", 1234)])

    def test_warn_existing_listeners_prints_warning(self) -> None:
        out = io.StringIO()
        with patch("os.getpid", return_value=1000), patch(
            "cve_agent.web._find_listeners_for_port",
            return_value=[("0.0.0.0:8080", 2000), ("127.0.0.1:8080", 1000)],
        ), patch("sys.stdout", out):
            web._warn_existing_listeners("127.0.0.1", 8080)

        rendered = out.getvalue()
        self.assertIn("WARNING: Existing listener(s)", rendered)
        self.assertIn("PID 2000", rendered)
        self.assertIn("127.0.0.1:8080", rendered)


if __name__ == "__main__":
    unittest.main()
