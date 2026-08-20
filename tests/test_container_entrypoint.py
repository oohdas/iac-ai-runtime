import unittest

from scripts.container_entrypoint import worker_arguments


class ContainerEntrypointTests(unittest.TestCase):
    def test_monitoring_is_disabled_when_environment_is_unset(self):
        self.assertEqual(
            worker_arguments({"SEAN_OS_DATABASE": "/data/iac-ai.db"}),
            ["scripts/worker.py", "--database", "/data/iac-ai.db"],
        )

    def test_complete_environment_adds_single_worker_monitoring(self):
        arguments = worker_arguments(
            {
                "SEAN_OS_DATABASE": "/data/iac-ai.db",
                "SEAN_OS_MONITOR_ROUTE_ID": "iac-operator",
                "SEAN_OS_MONITOR_DESTINATION_KIND": "EMAIL",
                "SEAN_OS_MONITOR_DESTINATION_REF": "iac-ops-alias",
                "SEAN_OS_MONITOR_INTERVAL_SECONDS": "30",
            }
        )
        self.assertEqual(arguments.count("scripts/worker.py"), 1)
        self.assertIn("--monitor-route-id", arguments)
        self.assertIn("30.0", arguments)

    def test_synthetic_delivery_requires_exact_no_network_mode(self):
        arguments=worker_arguments({
            "SEAN_OS_DATABASE":"/data/iac-ai.db",
            "SEAN_OS_ALERT_DELIVERY_MODE":"SYNTHETIC_ONLY",
        })
        self.assertIn("--synthetic-delivery", arguments)
        with self.assertRaisesRegex(ValueError, "SYNTHETIC_ONLY"):
            worker_arguments({"SEAN_OS_ALERT_DELIVERY_MODE":"LIVE"})

    def test_partial_environment_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "complete route contract"):
            worker_arguments({"SEAN_OS_MONITOR_ROUTE_ID": "iac-operator"})

    def test_interval_without_route_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "complete route contract"):
            worker_arguments({"SEAN_OS_MONITOR_INTERVAL_SECONDS": "30"})

    def test_invalid_kind_interval_and_control_characters_fail(self):
        base = {
            "SEAN_OS_MONITOR_ROUTE_ID": "iac-operator",
            "SEAN_OS_MONITOR_DESTINATION_KIND": "EMAIL",
            "SEAN_OS_MONITOR_DESTINATION_REF": "iac-ops-alias",
        }
        with self.assertRaisesRegex(ValueError, "destination kind"):
            worker_arguments({**base, "SEAN_OS_MONITOR_DESTINATION_KIND": "SMS"})
        with self.assertRaisesRegex(ValueError, "finite"):
            worker_arguments({**base, "SEAN_OS_MONITOR_INTERVAL_SECONDS": "nan"})
        with self.assertRaisesRegex(ValueError, "single-line"):
            worker_arguments({**base, "SEAN_OS_MONITOR_DESTINATION_REF": "bad\nvalue"})


if __name__ == "__main__":
    unittest.main()
