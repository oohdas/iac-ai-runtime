import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from sean_os import (
    BackupPilotError,
    build_supervised_backup_pilot_package,
    verify_supervised_backup_pilot_package,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1" * 40
START = "2026-08-21T09:00:00-04:00"
END = "2026-08-21T11:00:00-04:00"


class BackupPilotTests(unittest.TestCase):
    def package(self):
        return build_supervised_backup_pilot_package(
            candidate_commit=COMMIT, window_start=START, window_end=END
        )

    def test_package_binds_actual_resources_and_authorizes_nothing(self):
        package = self.package()
        self.assertEqual(package, self.package())
        self.assertEqual(verify_supervised_backup_pilot_package(package), package)
        self.assertEqual(package["data_mode"], "SYNTHETIC_IAC_DATABASE_ONLY")
        self.assertEqual(
            package["bucket_name"], "iac-sean-os-ca-east-20260820-v01-9k4m"
        )
        self.assertEqual(
            package["provider_endpoint"], "s3.ca-east-006.backblazeb2.com"
        )
        self.assertIn(COMMIT[:12], package["object_ref"])
        self.assertEqual(package["deployed_baseline_commit"], COMMIT)
        self.assertFalse(package["writer_key_approval_package"]["creation_authorized"])
        self.assertFalse(package["drill_approval_package"]["execution_authorized"])
        for field in (
            "key_creation_authorized",
            "secret_placement_authorized",
            "push_authorized",
            "deployment_authorized",
            "upload_authorized",
            "restore_authorized",
            "real_data_authorized",
            "network_enabled",
            "execution_authorized",
        ):
            self.assertFalse(package[field])

    def test_package_contains_only_variable_names_and_non_secret_configuration(self):
        package = self.package()
        self.assertEqual(len(package["managed_variable_names"]), 3)
        serialized = json.dumps(package)
        self.assertNotIn("synthetic-application-key-001", serialized)
        self.assertNotIn("source.db", serialized)
        self.assertNotIn("/data/sean-os.db", serialized)
        self.assertNotIn("SEAN_OS_BACKUP_MAX_BYTES", package["non_secret_runtime"])

    def test_tampering_wrong_commit_or_unbounded_window_fails_closed(self):
        modified = copy.deepcopy(self.package())
        modified["upload_authorized"] = True
        with self.assertRaises(BackupPilotError):
            verify_supervised_backup_pilot_package(modified)
        modified = copy.deepcopy(self.package())
        modified["deployed_baseline_commit"] = "9" * 40
        with self.assertRaises(BackupPilotError):
            verify_supervised_backup_pilot_package(modified)
        for commit, start, end in (
            ("short", START, END),
            (COMMIT, START, "2026-08-21T14:00:01-04:00"),
            (COMMIT, END, START),
        ):
            with self.subTest(commit=commit, start=start, end=end):
                with self.assertRaises(BackupPilotError):
                    build_supervised_backup_pilot_package(
                        candidate_commit=commit, window_start=start, window_end=end
                    )

    def test_cli_prints_verified_non_executing_package(self):
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/prepare_supervised_backup_pilot.py",
                COMMIT,
                START,
                "--duration-minutes",
                "120",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        package = json.loads(completed.stdout)
        self.assertEqual(verify_supervised_backup_pilot_package(package), package)
        self.assertFalse(package["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
