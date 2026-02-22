from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cve_agent.polling import PollController


class _FakeWatcher:
    def __init__(self) -> None:
        self.calls = 0
        self.source_calls: list[str] = []
        self._runtime = {
            "sources": {
                "nvd": {"status": "ok", "records": 3},
                "osv": {"status": "error", "records": 0},
            }
        }

    def run_once(self) -> int:
        self.calls += 1
        return 2

    def poll_source(self, name: str) -> int:
        self.source_calls.append(name)
        return 5

    def supported_poll_sources(self) -> list[str]:
        return ["nvd", "osv"]

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

    def test_trigger_source_queues_and_reports_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            watcher = _FakeWatcher()
            ctl = PollController(watcher, Path(td), interval_minutes=30, enabled=False)
            status = ctl.trigger_source("osv")
            self.assertEqual(status["trigger_result"], "queued")
            self.assertEqual(status["requested_source"], "osv")
            self.assertIn("osv", status.get("queued_sources", []))
            ctl._run_source_cycle("osv")
            final = ctl.status()
            self.assertIn("osv", watcher.source_calls)
            latest = final["history"][0]
            self.assertEqual(latest["poll_kind"], "source")
            self.assertEqual(latest["source"], "osv")
            self.assertEqual(latest["records_polled"], 5)

    def test_trigger_source_returns_invalid_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctl = PollController(_FakeWatcher(), Path(td), interval_minutes=30, enabled=False)
            status = ctl.trigger_source("invalid")
            self.assertEqual(status["trigger_result"], "invalid_source")

    def test_trigger_source_cooldown_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ctl = PollController(_FakeWatcher(), Path(td), interval_minutes=30, enabled=False)
            first = ctl.trigger_source("osv", origin="manual_ui_source")
            self.assertEqual(first["trigger_result"], "queued")
            second = ctl.trigger_source("osv", origin="manual_ui_source")
            self.assertIn(second["trigger_result"], {"already_queued", "cooldown_active"})

    def test_retry_history_entry_uses_source_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            watcher = _FakeWatcher()
            ctl = PollController(watcher, Path(td), interval_minutes=30, enabled=False)
            ctl._append_history_locked(
                status="error",
                started=None,
                completed=None,
                duration_ms=None,
                new_findings=0,
                error="x",
                poll_kind="source",
                source="osv",
                records_polled=None,
                trigger_origin="manual_ui_source",
            )
            status = ctl.retry_history_entry(0)
            self.assertEqual(status["requested_source"], "osv")
            self.assertIn(status["trigger_result"], {"queued", "cooldown_active", "already_queued"})


if __name__ == "__main__":
    unittest.main()
