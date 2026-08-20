import unittest

from sean_os import classify_alerts


class MonitoringTests(unittest.TestCase):
    def base_health(self):
        return {
            "healthy": True,
            "kill_switch": False,
            "integrity": {"ok": True},
            "queue": {},
            "workers": [{"worker_id": "worker-1", "stale": False}],
            "active_worker_count": 1,
        }

    def test_healthy_snapshot_has_no_alerts(self):
        self.assertEqual(classify_alerts(self.base_health(), backup_ok=True), [])

    def test_all_required_escalation_classes_are_deterministic(self):
        health = self.base_health()
        health.update(
            {
                "kill_switch": True,
                "integrity": {"ok": False},
                "queue": {
                    "DEAD_LETTER": 1,
                    "POLICY_BLOCKED": 2,
                    "BUDGET_BLOCKED": 3,
                    "APPROVAL_BLOCKED": 4,
                },
                "workers": [{"worker_id": "worker-1", "stale": True}],
                "active_worker_count": 0,
            }
        )
        alerts = classify_alerts(health, backup_ok=False)
        self.assertEqual(
            {alert["code"] for alert in alerts},
            {
                "DATABASE_INTEGRITY_FAILED",
                "KILL_SWITCH_ACTIVE",
                "STALE_WORKER",
                "DEAD_LETTER",
                "POLICY_BLOCKED",
                "BUDGET_BLOCKED",
                "APPROVAL_BLOCKED",
                "NO_ACTIVE_WORKER",
                "BACKUP_FAILED",
            },
        )
        self.assertTrue(all(set(alert) == {"code", "severity", "summary"} for alert in alerts))


if __name__ == "__main__":
    unittest.main()
