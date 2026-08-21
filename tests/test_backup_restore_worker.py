import tempfile
import unittest
from pathlib import Path

from scripts.restore_worker import (
    _new_restore_destination,
    _private_directory,
    process_backup_restore_once,
)
from sean_os import Actor, SeanOSStore


class BackupRestoreWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SeanOSStore(self.root / "iac.db", scope_profile="IAC")
        self.environment = {
            "SEAN_OS_BACKUP_RESTORE_EXECUTION":"APPROVED",
            "SEAN_OS_BACKUP_RESTORE_PROVIDER":"BACKBLAZE_B2",
            "SEAN_OS_BACKUP_RESTORE_DATA_REGION":"CA_EAST",
            "SEAN_OS_BACKUP_RESTORE_ENDPOINT":"s3.ca-east-006.backblazeb2.com",
            "SEAN_OS_BACKUP_RESTORE_DESTINATION_REF":(
                "backblaze-b2-bucket:synthetic-ca-east-backup-bucket"
            ),
            "SEAN_OS_BACKUP_RESTORE_IDENTITY_REF":(
                "managed-secret-store:synthetic-restore-v1"
            ),
            "SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY_REF":(
                "managed-secret-store:synthetic-aes256-v1"
            ),
            "SEAN_OS_BACKUP_RESTORE_MAX_BYTES":"1048576",
            "SEAN_OS_BACKUP_RESTORE_MAX_COST_CAD":"1",
        }

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_no_authorized_restore_returns_without_resolving_secrets_or_network(self):
        calls = []

        def forbidden_factory(*_args, **_kwargs):
            calls.append(True)
            raise AssertionError("secret or network factory must not run")

        result = process_backup_restore_once(
            self.store, Actor("restore-worker", frozenset({"IAC"})),
            "restore-worker-1", environment=self.environment,
            bucket_name="synthetic-ca-east-backup-bucket",
            download_directory=self.root / "downloads",
            restore_directory=self.root / "isolated",
            restore_destination=self.root / "isolated" / "restored.db",
            data_root=self.root, client_factory=forbidden_factory,
            resolver_factory=forbidden_factory,
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_disabled_partial_or_wrong_bucket_fails_before_claim(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            process_backup_restore_once(
                self.store, Actor("restore-worker", frozenset({"IAC"})),
                "restore-worker-1", environment={},
                bucket_name="synthetic-ca-east-backup-bucket",
                download_directory=self.root / "downloads",
                restore_directory=self.root / "isolated",
                restore_destination=self.root / "isolated" / "restored.db",
                data_root=self.root,
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            process_backup_restore_once(
                self.store, Actor("restore-worker", frozenset({"IAC"})),
                "restore-worker-1", environment=self.environment,
                bucket_name="different-ca-east-backup-bucket",
                download_directory=self.root / "downloads",
                restore_directory=self.root / "isolated",
                restore_destination=self.root / "isolated" / "restored.db",
                data_root=self.root,
            )

    def test_paths_remain_private_new_and_inside_data_volume(self):
        private = _private_directory(self.root / "isolated", self.root, "restore")
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        destination = _new_restore_destination(private / "restored.db", private)
        self.assertEqual(destination, (private / "restored.db").resolve())
        destination.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "must be new"):
            _new_restore_destination(destination, private)
        with self.assertRaisesRegex(ValueError, "inside the data volume"):
            _private_directory(Path(self.temp.name).parent / "outside", self.root, "restore")


if __name__ == "__main__":
    unittest.main()
