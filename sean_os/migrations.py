from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


LATEST_SCHEMA_VERSION = 11


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
    version=connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    if version != LATEST_SCHEMA_VERSION:
        raise sqlite3.DatabaseError(
            f"Schema version {version} does not match supported {LATEST_SCHEMA_VERSION}"
        )
    return version
