from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


LATEST_SCHEMA_VERSION = 16


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
        (version, _stamp()),
    )
    connection.commit()


def _work_queue_supports_policy_states(connection: sqlite3.Connection) -> bool:
    row=connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='work_queue'"
    ).fetchone()
    return bool(row and "APPROVAL_BLOCKED" in row[0] and "POLICY_BLOCKED" in row[0])


def _upgrade_work_queue(connection: sqlite3.Connection) -> None:
    if _work_queue_supports_policy_states(connection):
        return
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE work_queue_new (
                id TEXT PRIMARY KEY,
                task_type TEXT NOT NULL,
                owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
                payload TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN (
                    'QUEUED','RUNNING','SUCCEEDED','FAILED','DEAD_LETTER',
                    'BUDGET_BLOCKED','APPROVAL_BLOCKED','POLICY_BLOCKED')),
                priority INTEGER NOT NULL DEFAULT 100,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                available_at TEXT NOT NULL,
                lease_owner TEXT,
                lease_expires_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        columns={row[1] for row in connection.execute("PRAGMA table_info(work_queue)")}
        required={"id","task_type","owner_scope","payload","status","priority","attempts",
                  "max_attempts","available_at","lease_owner","lease_expires_at","last_error",
                  "created_at","updated_at"}
        if not required.issubset(columns):
            raise sqlite3.DatabaseError("Legacy work_queue lacks required migration columns")
        names=",".join(sorted(required))
        connection.execute(f"INSERT INTO work_queue_new ({names}) SELECT {names} FROM work_queue")
        connection.execute("DROP TABLE work_queue")
        connection.execute("ALTER TABLE work_queue_new RENAME TO work_queue")
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_work_queue_claim
               ON work_queue(status, available_at, priority, created_at)"""
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def _add_column_if_missing(
    connection: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    columns={row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _backup_transfer_supports_reconciliation(connection: sqlite3.Connection) -> bool:
    row=connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='backup_transfer_outbox'"
    ).fetchone()
    return bool(row and "RECONCILIATION_REQUIRED" in row[0])


def _upgrade_backup_transfer_outbox(connection: sqlite3.Connection) -> None:
    """Add the manual-reconciliation terminal state without weakening existing rows."""
    if _backup_transfer_supports_reconciliation(connection):
        return
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    columns=(
        "plan_sha256", "owner_scope", "approval_target", "proposal_sha256",
        "plan_payload", "status", "approval_id", "attempt_count", "max_attempts",
        "available_at", "lease_owner", "lease_expires_at", "last_error",
        "preflight_receipt_payload", "receipt_payload", "created_at", "updated_at",
        "completed_at",
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE backup_transfer_outbox_new (
                plan_sha256 TEXT PRIMARY KEY CHECK (length(plan_sha256) = 64),
                owner_scope TEXT NOT NULL CHECK (owner_scope = 'IAC'),
                approval_target TEXT NOT NULL,
                proposal_sha256 TEXT NOT NULL CHECK (length(proposal_sha256) = 64),
                plan_payload TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN (
                    'STAGED','PREFLIGHT_VALIDATED','AUTHORIZED','COMPLETED','FAILED',
                    'RECONCILIATION_REQUIRED'
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
        existing={row[1] for row in connection.execute(
            "PRAGMA table_info(backup_transfer_outbox)"
        )}
        if not set(columns).issubset(existing):
            raise sqlite3.DatabaseError(
                "Legacy backup_transfer_outbox lacks required migration columns"
            )
        names=",".join(columns)
        connection.execute(
            f"INSERT INTO backup_transfer_outbox_new ({names}) SELECT {names} "
            "FROM backup_transfer_outbox"
        )
        connection.execute("DROP TABLE backup_transfer_outbox")
        connection.execute(
            "ALTER TABLE backup_transfer_outbox_new RENAME TO backup_transfer_outbox"
        )
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_backup_transfer_outbox_claim
               ON backup_transfer_outbox(status, available_at, lease_expires_at, created_at)"""
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def apply_migrations(connection: sqlite3.Connection) -> int:
    """Apply ordered, restart-safe migrations and return the current version."""
    versions={row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    if 1 not in versions:
        _record(connection, 1)
    if 2 not in versions:
        _upgrade_work_queue(connection)
        _record(connection, 2)
    if 3 not in versions:
        # v3 tables are additive and are created idempotently by schema.sql before this call.
        _record(connection, 3)
    if 4 not in versions:
        # v4 action execution receipts are additive and created by schema.sql.
        _record(connection, 4)
    if 5 not in versions:
        # v5 connector gates and provenance tables are additive and created by schema.sql.
        _record(connection, 5)
    if 6 not in versions:
        # v6 command intake records are additive and created by schema.sql.
        _record(connection, 6)
    if 7 not in versions:
        connection.execute(
            "UPDATE records SET effective_at=created_at WHERE effective_at IS NULL"
        )
        connection.execute(
            "UPDATE records SET confidence=CASE WHEN source='user' THEN 1.0 ELSE 0.5 END WHERE confidence IS NULL"
        )
        connection.commit()
        _record(connection, 7)
    if 8 not in versions:
        # v8 scoped alert observations are additive and created by schema.sql.
        _record(connection, 8)
    if 9 not in versions:
        # v9 alert incident lifecycle is additive and created by schema.sql.
        _record(connection, 9)
    if 10 not in versions:
        # v10 approval-gated alert delivery outbox is additive and created by schema.sql.
        _record(connection, 10)
    if 11 not in versions:
        _add_column_if_missing(connection, "alert_delivery_outbox", "max_attempts",
                               "INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10)")
        _add_column_if_missing(connection, "alert_delivery_outbox", "available_at", "TEXT")
        _add_column_if_missing(connection, "alert_delivery_outbox", "lease_owner", "TEXT")
        _add_column_if_missing(connection, "alert_delivery_outbox", "lease_expires_at", "TEXT")
        _add_column_if_missing(connection, "alert_delivery_outbox", "last_error", "TEXT")
        connection.execute(
            "UPDATE alert_delivery_outbox SET available_at=created_at WHERE available_at IS NULL"
        )
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_alert_delivery_outbox_claim
               ON alert_delivery_outbox(status, available_at, lease_expires_at, created_at)"""
        )
        connection.commit()
        _record(connection, 11)
    if 12 not in versions:
        # v12 synthetic coding-delivery ledger is additive and created by schema.sql.
        _record(connection, 12)
    if 13 not in versions:
        # v13 approval-gated independent-backup transfer outbox is additive.
        _record(connection, 13)
    if 14 not in versions:
        _add_column_if_missing(connection, "backup_transfer_outbox", "attempt_count",
                               "INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)")
        _add_column_if_missing(connection, "backup_transfer_outbox", "max_attempts",
                               "INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10)")
        _add_column_if_missing(connection, "backup_transfer_outbox", "available_at", "TEXT")
        _add_column_if_missing(connection, "backup_transfer_outbox", "lease_owner", "TEXT")
        _add_column_if_missing(connection, "backup_transfer_outbox", "lease_expires_at", "TEXT")
        _add_column_if_missing(connection, "backup_transfer_outbox", "last_error", "TEXT")
        connection.execute(
            "UPDATE backup_transfer_outbox SET available_at=created_at WHERE available_at IS NULL"
        )
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_backup_transfer_outbox_claim
               ON backup_transfer_outbox(status, available_at, lease_expires_at, created_at)"""
        )
        connection.commit()
        _record(connection, 14)
    if 15 not in versions:
        _add_column_if_missing(
            connection, "backup_transfer_outbox", "preflight_receipt_payload", "TEXT"
        )
        connection.execute(
            """UPDATE backup_transfer_outbox
               SET preflight_receipt_payload=receipt_payload, receipt_payload=NULL
               WHERE preflight_receipt_payload IS NULL AND receipt_payload IS NOT NULL
               AND status IN ('STAGED','PREFLIGHT_VALIDATED','AUTHORIZED','FAILED')"""
        )
        connection.commit()
        _record(connection, 15)
    if 16 not in versions:
        _upgrade_backup_transfer_outbox(connection)
        _record(connection, 16)
    version=connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    if version != LATEST_SCHEMA_VERSION:
        raise sqlite3.DatabaseError(
            f"Schema version {version} does not match supported {LATEST_SCHEMA_VERSION}"
        )
    return version
