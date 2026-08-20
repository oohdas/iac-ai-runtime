import tempfile
import unittest
from pathlib import Path

from sean_os import EscalationRoute, SeanOSStore
from scripts.monitor_worker import run_monitor_loop


class MonitorWorkerTests(unittest.TestCase):
    def test_bounded_loop_records_repeated_evidence_without_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "monitor.db", scope_profile="IAC")
            try:
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                snapshots = []
                completed = run_monitor_loop(
                    store,
                    route,
                    interval_seconds=5,
                    wait=lambda _seconds: False,
                    sink=snapshots.append,
                    max_iterations=2,
                )
                self.assertEqual(completed, 2)
                self.assertEqual(len(snapshots), 2)
                self.assertTrue(all(not item["delivery_authorized"] for item in snapshots))
                self.assertTrue(
                    all(
                        observation["occurrence_count"] == 2
                        for observation in snapshots[-1]["recorded_observations"]
                    )
                )
            finally:
                store.close()

    def test_wait_interrupt_stops_before_next_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "monitor.db", scope_profile="IAC")
            try:
                snapshots = []
                completed = run_monitor_loop(
                    store,
                    EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    interval_seconds=5,
                    wait=lambda _seconds: True,
                    sink=snapshots.append,
                )
                self.assertEqual(completed, 1)
                self.assertEqual(len(snapshots), 1)
            finally:
                store.close()

    def test_invalid_interval_fails_before_snapshot(self):
        store = SeanOSStore(":memory:", scope_profile="IAC")
        try:
            with self.assertRaisesRegex(ValueError, "at least one second"):
                run_monitor_loop(
                    store,
                    EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    interval_seconds=0,
                    wait=lambda _seconds: False,
                    sink=lambda _snapshot: None,
                    max_iterations=1,
                )
        finally:
            store.close()

    def test_sink_failure_propagates_to_process_supervisor(self):
        store = SeanOSStore(":memory:", scope_profile="IAC")
        try:
            def fail(_snapshot):
                raise RuntimeError("synthetic sink failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic sink failure"):
                run_monitor_loop(
                    store,
                    EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    interval_seconds=5,
                    wait=lambda _seconds: False,
                    sink=fail,
                    max_iterations=1,
                )
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
