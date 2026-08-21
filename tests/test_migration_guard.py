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
from sean_os.migrations import _upgrade_backup_transfer_outbox
from sean_os.store import Actor, SeanOSStore


V8_TO_V18_TABLES = (
    "coding_delivery_requests",
    "coding_deliveries",
    "alert_delivery_outbox",
    "alert_incidents",
    "alert_observations",
    "backup_activation_evidence",
    "backup_transfer_outbox",
    "backup_restore_outbox",
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
            for table in V8_TO_V18_TABLES:
                connection.execute(f"DROP TABLE {table}")
            connection.commit()
        return record_id

    def schema_version(self) -> int:
        with sqlite3.connect(self.database) as connection:
            return int(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            )

    def test_v15_backup_outbox_upgrade_preserves_rows_and_adds_reconciliation_state(self):
        with sqlite3.connect(":memory:") as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("CREATE TABLE approvals(record_id TEXT PRIMARY KEY)")
            connection.execute(
                """CREATE TABLE backup_transfer_outbox (
                    plan_sha256 TEXT PRIMARY KEY CHECK (length(plan_sha256) = 64),
                    owner_scope TEXT NOT NULL CHECK (owner_scope = 'IAC'),
                    approval_target TEXT NOT NULL,
                    proposal_sha256 TEXT NOT NULL CHECK (length(proposal_sha256) = 64),
                    plan_payload TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN (
                        'STAGED','PREFLIGHT_VALIDATED','AUTHORIZED','COMPLETED','FAILED'
                    )),
                    approval_id TEXT REFERENCES approvals(record_id),
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    last_error TEXT,
                    preflight_receipt_payload TEXT,
                    receipt_payload TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )"""
            )
            plan_sha="a" * 64
            connection.execute(
                """INSERT INTO backup_transfer_outbox
                   (plan_sha256, owner_scope, approval_target, proposal_sha256,
                    plan_payload, status, available_at, created_at, updated_at)
                   VALUES (?, 'IAC', 'synthetic-target', ?, '{}', 'STAGED', ?, ?, ?)""",
                (plan_sha, "b" * 64, "2030-01-01T00:00:00+00:00",
                 "2030-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00"),
            )
            connection.commit()

            _upgrade_backup_transfer_outbox(connection)

            row=connection.execute(
                "SELECT status, plan_payload FROM backup_transfer_outbox WHERE plan_sha256=?",
                (plan_sha,),
            ).fetchone()
            self.assertEqual(row, ("STAGED", "{}"))
            connection.execute(
                "UPDATE backup_transfer_outbox SET status='RECONCILIATION_REQUIRED' "
                "WHERE plan_sha256=?", (plan_sha,)
            )
            self.assertFalse(list(connection.execute("PRAGMA foreign_key_check")))

    def test_guard_backs_up_and_migrates_deployed_schema(self):
        record_id = self.make_deployed_v7_database()

        evidence = guarded_migrate(self.database, scope_profile="IAC")

        backup, manifest_path = backup_paths(self.database, 7)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(evidence["migration_required"])
        self.assertEqual(evidence["source_schema_version"], 7)
        self.assertEqual(evidence["schema_version"], 18)
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

    def test_guard_backs_up_deployed_v16_and_adds_activation_and_restore_tables(self):
        store=SeanOSStore(self.database, scope_profile="IAC")
        record_id=store.create_record(
            Actor.sean(), "KNOWLEDGE", "IAC", {"name":"v16 migration sentinel"}
        )
        store.close()
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TABLE backup_activation_evidence")
            connection.execute("DROP TABLE backup_restore_outbox")
            connection.execute("DELETE FROM schema_migrations WHERE version>=17")
            connection.commit()

        evidence=guarded_migrate(self.database, scope_profile="IAC")

        self.assertEqual(evidence["source_schema_version"], 16)
        self.assertEqual(evidence["schema_version"], 18)
        backup, _manifest=backup_paths(self.database, 16)
        with sqlite3.connect(backup) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0],
                16,
            )
        migrated=SeanOSStore(self.database, scope_profile="IAC")
        try:
            self.assertEqual(
                migrated.get_record(Actor.sean(), record_id)["payload"]["name"],
                "v16 migration sentinel",
            )
            table=migrated.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='backup_activation_evidence'"
            ).fetchone()
            self.assertIsNotNone(table)
            restore_table=migrated.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='backup_restore_outbox'"
            ).fetchone()
            self.assertIsNotNone(restore_table)
            self.assertTrue(migrated.integrity_check()["ok"])
        finally:
            migrated.close()

    def test_guard_backs_up_deployed_v17_and_adds_restore_outbox(self):
        store=SeanOSStore(self.database, scope_profile="IAC")
        record_id=store.create_record(
            Actor.sean(), "KNOWLEDGE", "IAC", {"name":"v17 migration sentinel"}
        )
        store.close()
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TABLE backup_restore_outbox")
            connection.execute("DELETE FROM schema_migrations WHERE version=18")
            connection.commit()

        evidence=guarded_migrate(self.database, scope_profile="IAC")

        self.assertEqual(evidence["source_schema_version"], 17)
        self.assertEqual(evidence["schema_version"], 18)
        backup, _manifest=backup_paths(self.database, 17)
        with sqlite3.connect(backup) as connection:
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0],
                17,
            )
        migrated=SeanOSStore(self.database, scope_profile="IAC")
        try:
            self.assertEqual(
                migrated.get_record(Actor.sean(), record_id)["payload"]["name"],
                "v17 migration sentinel",
            )
            table=migrated.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='backup_restore_outbox'"
            ).fetchone()
            self.assertIsNotNone(table)
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
        self.assertEqual(self.schema_version(), 18)

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
