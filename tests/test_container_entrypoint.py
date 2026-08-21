import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.container_entrypoint import requested_restore_version, worker_arguments


class ContainerEntrypointTests(unittest.TestCase):
    def backup_environment(self):
        return {
            "SEAN_OS_DATABASE":"/data/iac-ai.db",
            "SEAN_OS_BACKUP_EXECUTION":"APPROVED",
            "SEAN_OS_BACKUP_PROVIDER":"BACKBLAZE_B2",
            "SEAN_OS_BACKUP_DATA_REGION":"CA_EAST",
            "SEAN_OS_BACKUP_ENDPOINT":"s3.ca-east-006.backblazeb2.com",
            "SEAN_OS_BACKUP_DESTINATION_REF":(
                "backblaze-b2-bucket:iac-sean-os-ca-east-20260820-v01-9k4m"
            ),
            "SEAN_OS_BACKUP_WRITER_IDENTITY_REF":(
                "railway-managed-value:sean-os-b2-writer-v1"
            ),
            "SEAN_OS_BACKUP_ENCRYPTION_KEY_REF":(
                "railway-managed-value:sean-os-aes256-v1"
            ),
            "SEAN_OS_BACKUP_MAX_BYTES":"10485760",
            "SEAN_OS_BACKUP_MAX_COST_CAD":"15",
            "SEAN_OS_BACKUP_BUCKET":"iac-sean-os-ca-east-20260820-v01-9k4m",
            "SEAN_OS_BACKUP_MANIFEST_PATH":"/data/backup-staging/approved.manifest.json",
            "SEAN_OS_BACKUP_OUTPUT_DIRECTORY":"/data/backup-staging/encrypted",
        }

    def test_direct_script_bootstraps_application_import_path(self):
        root=Path(__file__).resolve().parents[1]
        script=root / "scripts" / "container_entrypoint.py"
        check=(
            "import runpy,sys\n"
            "from pathlib import Path\n"
            f"root=Path({str(root)!r})\n"
            "sys.path=[str(root/'scripts')]+[item for item in sys.path "
            "if item and Path(item).resolve()!=root]\n"
            f"runpy.run_path({str(script)!r}, run_name='container_entrypoint_import_smoke')\n"
        )
        environment=dict(os.environ)
        environment.pop("PYTHONPATH", None)
        with tempfile.TemporaryDirectory() as isolated_directory:
            completed=subprocess.run(
                [sys.executable, "-c", check], cwd=isolated_directory,
                env=environment, text=True, capture_output=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

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

    def test_backup_worker_is_default_off_and_requires_complete_exact_contract(self):
        arguments=worker_arguments(self.backup_environment())
        self.assertIn("--backup-execution", arguments)
        self.assertIn("iac-sean-os-ca-east-20260820-v01-9k4m", arguments)
        self.assertIn("/data/backup-staging/approved.manifest.json", arguments)
        self.assertIn("/data/backup-staging/encrypted", arguments)
        partial=self.backup_environment()
        partial.pop("SEAN_OS_BACKUP_MANIFEST_PATH")
        with self.assertRaisesRegex(ValueError, "complete worker contract"):
            worker_arguments(partial)
        with self.assertRaisesRegex(ValueError, "Disabled backup execution"):
            worker_arguments({
                "SEAN_OS_BACKUP_OUTPUT_DIRECTORY":"/data/backup-staging/encrypted"
            })
        for key, value in (
            ("SEAN_OS_BACKUP_MANIFEST_PATH", "/tmp/outside.manifest.json"),
            ("SEAN_OS_BACKUP_OUTPUT_DIRECTORY", "relative/encrypted"),
        ):
            changed=self.backup_environment()
            changed[key]=value
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "inside the database volume"):
                    worker_arguments(changed)

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

    def test_restore_version_is_explicit_and_fails_closed(self):
        self.assertIsNone(requested_restore_version({}))
        self.assertIsNone(requested_restore_version({"SEAN_OS_RESTORE_SCHEMA_VERSION":""}))
        self.assertEqual(
            requested_restore_version({"SEAN_OS_RESTORE_SCHEMA_VERSION":"7"}), 7
        )
        for invalid in ("0", "-1", " 7", "7 ", "seven"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    requested_restore_version(
                        {"SEAN_OS_RESTORE_SCHEMA_VERSION":invalid}
                    )


if __name__ == "__main__":
    unittest.main()
