from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cve_agent.polling import PollController


class _FakeWatcher:
    def __init__(self) -> None:
        self.calls = 0
        self._runtime = {
            "sources": {
                "nvd": {"status": "ok", "records": 3},
                "osv": {"status": "error", "records": 0},
            }
        }

    def run_once(self) -> int:
        self.calls += 1
        return 2

    def get_poll_runtime_status(self) -> dict:
        return self._runtime


class PollControllerTests(unittest.TestCase):
    def test_trigger_now_returns_already_running_without_queueing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctl = PollController(_FakeWatcher(), Path(td), interval_minutes=30, enabled=False)
            with ctl._lock:
                ctl._is_polling = True
                ctl._force_run = False
            status = ctl.trigger_now()
            self.assertEqual(status["trigger_result"], "already_running")
            self.assertIn("already", status["message"])
            with ctl._lock:
                self.assertFalse(ctl._force_run)

    def test_run_cycle_appends_history_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            watcher = _FakeWatcher()
            ctl = PollController(watcher, Path(td), interval_minutes=30, enabled=False)
            ctl._run_cycle()
            status = ctl.status()
            self.assertEqual(watcher.calls, 1)
            self.assertTrue(status["history"])
            latest = status["history"][0]
            self.assertEqual(latest["status"], "ok")
            self.assertEqual(latest["new_findings"], 2)
            self.assertIn("osv", latest["failed_sources"])
            self.assertIn("source_counts", latest)


if __name__ == "__main__":
    unittest.main()
