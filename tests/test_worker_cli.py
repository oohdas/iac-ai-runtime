import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sean_os import Actor, EscalationRoute, SeanOSStore, plan_alert_deliveries


ROOT = Path(__file__).resolve().parents[1]


class WorkerCliTests(unittest.TestCase):
    def test_integrated_monitoring_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable, "scripts/worker.py", "--once", "--database",
                    str(Path(directory) / "default.db"),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_partial_monitoring_contract_fails_startup(self):
        result = subprocess.run(
            [sys.executable, "scripts/worker.py", "--once", "--monitor-route-id", "iac"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("complete route contract", result.stderr)

    def test_complete_monitoring_contract_stays_non_delivering(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable, "scripts/worker.py", "--once", "--database",
                    str(Path(directory) / "enabled.db"), "--monitor-route-id",
                    "iac-operator", "--monitor-destination-kind", "EMAIL",
                    "--monitor-destination-ref", "iac-ops-alias",
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshot = json.loads(result.stdout)
            self.assertTrue(snapshot["healthy"])
            self.assertFalse(snapshot["delivery_authorized"])

    def test_explicit_synthetic_mode_processes_authorized_outbox_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Path(directory) / "delivery.db"
            store=SeanOSStore(database, scope_profile="IAC")
            try:
                monitor=Actor("monitor", frozenset({"IAC"}))
                plan=plan_alert_deliveries(
                    [{"code":"DEAD_LETTER", "severity":"CRITICAL", "summary":"failed"}],
                    route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    owner_scope="IAC",
                )[0]
                store.record_alert_observation(monitor, plan)
                delivery=store.stage_alert_delivery(monitor, plan["plan_id"])
                approval=store.create_approval(
                    Actor.sean(), action_type="DELIVER_ALERT", target=delivery["delivery_id"],
                    scope="IAC", max_impact="one synthetic alert", approver="sean",
                    expires_at="2099-01-01T00:00:00+00:00",
                )
                store.authorize_alert_delivery(
                    Actor.sean(), delivery["delivery_id"], approval_id=approval
                )
            finally:
                store.close()
            result=subprocess.run(
                [
                    sys.executable, "scripts/worker.py", "--once", "--synthetic-delivery",
                    "--database", str(database),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            store=SeanOSStore(database, scope_profile="IAC")
            try:
                completed=store.get_alert_delivery(
                    Actor("auditor", frozenset({"IAC"})), delivery["delivery_id"]
                )
                self.assertEqual(completed["status"], "SYNTHETIC_DELIVERED")
                self.assertEqual(completed["attempt_count"], 1)
                self.assertFalse(completed["receipt_payload"]["network_used"])
                self.assertFalse(completed["receipt_payload"]["external_effect"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
