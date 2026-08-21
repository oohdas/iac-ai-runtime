from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from sean_os.migration_guard import (
    MigrationGuardError,
    backup_paths,
    ensure_pre_migration_backup,
    guarded_migrate,
    restore_pre_migration_backup,
)
from sean_os.store import Actor, SeanOSStore


V8_TO_V15_TABLES = (
    "coding_delivery_requests",
    "coding_deliveries",
    "alert_delivery_outbox",
    "alert_incidents",
    "alert_observations",
    "backup_transfer_outbox",
)


class MigrationGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "iac-ai.db"

    def tearDown(self):
        self.temporary.cleanup()

    def make_deployed_v7_database(self) -> str:
        store = SeanOSStore(self.database, scope_profile="IAC")
        record_id = store.create_record(
            Actor.sean(), "GOAL", "IAC", {"name": "Migration sentinel"}
        )
        store.close()
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("DELETE FROM schema_migrations WHERE version >= 8")
            for table in V8_TO_V15_TABLES:
                connection.execute(f"DROP TABLE {table}")
            connection.commit()
        return record_id

    def schema_version(self) -> int:
        with sqlite3.connect(self.database) as connection:
            return int(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            )

    def test_guard_backs_up_and_migrates_deployed_schema(self):
        record_id = self.make_deployed_v7_database()

        evidence = guarded_migrate(self.database, scope_profile="IAC")

        backup, manifest_path = backup_paths(self.database, 7)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(evidence["migration_required"])
        self.assertEqual(evidence["source_schema_version"], 7)
        self.assertEqual(evidence["schema_version"], 15)
        self.assertEqual(manifest["storage_scope"], "SAME_RAILWAY_VOLUME")
        self.assertEqual(manifest["schema_version"], 7)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        with sqlite3.connect(backup) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0],
                7,
            )
        migrated = SeanOSStore(self.database, scope_profile="IAC")
        try:
            self.assertEqual(
                migrated.get_record(Actor.sean(), record_id)["payload"]["name"],
                "Migration sentinel",
            )
            self.assertTrue(migrated.integrity_check()["ok"])
        finally:
            migrated.close()

    def test_failed_migration_restores_v7_and_denies_worker_start(self):
        record_id = self.make_deployed_v7_database()

        def failing_runner(database: Path, _scope_profile: str) -> None:
            with sqlite3.connect(database) as connection:
                connection.execute("DELETE FROM records WHERE id=?", (record_id,))
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES(8, 'failed')"
                )
                connection.commit()
            raise RuntimeError("synthetic migration failure")

        with self.assertRaisesRegex(MigrationGuardError, "restored.*worker start denied"):
            guarded_migrate(
                self.database, scope_profile="IAC", migration_runner=failing_runner
            )

        self.assertEqual(self.schema_version(), 7)
        with sqlite3.connect(self.database) as connection:
            self.assertIsNotNone(
                connection.execute("SELECT id FROM records WHERE id=?", (record_id,)).fetchone()
            )
        quarantined = list(Path(self.temporary.name).glob("iac-ai.db.failed-migration-v8-*"))
        self.assertTrue(quarantined)
        recovery = json.loads(
            self.database.with_name(
                f"{self.database.name}.migration-restore-evidence.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(recovery["worker_start_authorized"])

    def test_explicit_restore_after_success_enters_recovery_state(self):
        self.make_deployed_v7_database()
        guarded_migrate(self.database, scope_profile="IAC")
        self.assertEqual(self.schema_version(), 15)

        evidence = restore_pre_migration_backup(self.database, 7)

        self.assertTrue(evidence["restored"])
        self.assertFalse(evidence["worker_start_authorized"])
        self.assertEqual(self.schema_version(), 7)
        repeated = restore_pre_migration_backup(self.database, 7)
        self.assertTrue(repeated["already_restored"])

    def test_corrupt_existing_backup_fails_closed_before_migration(self):
        self.make_deployed_v7_database()
        backup, _manifest = backup_paths(self.database, 7)
        backup.write_bytes(b"not a sqlite database")
        os.chmod(backup, 0o600)

        with self.assertRaises((MigrationGuardError, sqlite3.DatabaseError)):
            guarded_migrate(self.database, scope_profile="IAC")

        self.assertEqual(self.schema_version(), 7)

    def test_modified_manifest_fails_closed_before_migration(self):
        self.make_deployed_v7_database()
        ensure_pre_migration_backup(self.database, 7)
        _backup, manifest_path = backup_paths(self.database, 7)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(MigrationGuardError, "does not match"):
            guarded_migrate(self.database, scope_profile="IAC")

        self.assertEqual(self.schema_version(), 7)


if __name__ == "__main__":
    unittest.main()
