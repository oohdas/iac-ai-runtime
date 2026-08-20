from __future__ import annotations

import gc
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .migrations import LATEST_SCHEMA_VERSION
from .store import SeanOSStore, ValidationError


class MigrationGuardError(RuntimeError):
    pass


MigrationRunner = Callable[[Path, str], None]


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _open_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _ledger_version(connection: sqlite3.Connection) -> int:
    table=connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if table is None:
        raise MigrationGuardError("Existing database has no schema migration ledger")
    versions=[int(row[0]) for row in connection.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    )]
    if not versions:
        raise MigrationGuardError("Existing database has an empty schema migration ledger")
    if versions != list(range(1, versions[-1] + 1)):
        raise MigrationGuardError("Existing database has a non-contiguous migration ledger")
    return versions[-1]


def _schema_version(path: Path) -> int:
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    with _open_read_only(path) as connection:
        return _ledger_version(connection)


def _verify(path: Path, expected_version: int) -> dict[str, Any]:
    with _open_read_only(path) as connection:
        integrity=connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys=[tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
        version=_ledger_version(connection)
    if integrity != "ok" or foreign_keys or version != expected_version:
        raise MigrationGuardError(
            f"Database verification failed for expected schema v{expected_version}"
        )
    return {
        "bytes":path.stat().st_size,
        "sha256":_sha256(path),
        "schema_version":int(version),
        "integrity_ok":True,
        "foreign_key_violations":0,
    }


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary=path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def backup_paths(
    database: str | Path, source_version: int, target_version: int = LATEST_SCHEMA_VERSION,
) -> tuple[Path, Path]:
    source=Path(database)
    backup=source.with_name(
        f"{source.name}.pre-migration-v{source_version}-to-v{target_version}.db"
    )
    return backup, backup.with_suffix(backup.suffix + ".manifest.json")


def ensure_pre_migration_backup(
    database: str | Path, source_version: int, target_version: int = LATEST_SCHEMA_VERSION,
) -> dict[str, Any]:
    source=Path(database)
    if source_version <= 0 or source_version >= target_version:
        raise MigrationGuardError("Pre-migration backup requires an older positive schema")
    if _schema_version(source) != source_version:
        raise MigrationGuardError("Source schema changed before pre-migration backup")
    backup, manifest_path=backup_paths(source, source_version, target_version)
    reused=backup.exists()
    if not reused:
        temporary=backup.with_name(f".{backup.name}.tmp-{uuid.uuid4().hex}")
        try:
            with _open_read_only(source) as source_connection:
                with sqlite3.connect(temporary) as destination_connection:
                    source_connection.backup(destination_connection)
            os.chmod(temporary, 0o600)
            _verify(temporary, source_version)
            os.replace(temporary, backup)
        finally:
            if temporary.exists():
                temporary.unlink()
    verified=_verify(backup, source_version)
    if manifest_path.exists():
        try:
            prior=json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MigrationGuardError("Pre-migration backup manifest is unreadable") from exc
        for key in (
            "format", "backup_file", "sha256", "bytes",
            "source_schema_version", "target_schema_version",
        ):
            expected={
                "format":"sean-os-pre-migration-backup/v1", "backup_file":backup.name,
                "sha256":verified["sha256"], "bytes":verified["bytes"],
                "source_schema_version":source_version, "target_schema_version":target_version,
            }[key]
            if prior.get(key) != expected:
                raise MigrationGuardError("Pre-migration backup manifest does not match backup")
        created_at=prior.get("created_at") or _stamp()
    else:
        created_at=_stamp()
    manifest={
        "format":"sean-os-pre-migration-backup/v1",
        "created_at":created_at,
        "source_schema_version":source_version,
        "target_schema_version":target_version,
        "backup_file":backup.name,
        **verified,
        "reused_existing":reused,
        "contains_record_content":True,
        "record_content_inspected":False,
        "storage_scope":"SAME_RAILWAY_VOLUME",
    }
    _write_json_atomic(manifest_path, manifest)
    return manifest


def _copy_verified_database(source: Path, destination: Path, expected_version: int) -> None:
    temporary=destination.with_name(f".{destination.name}.restore-{uuid.uuid4().hex}")
    try:
        with _open_read_only(source) as source_connection:
            with sqlite3.connect(temporary) as destination_connection:
                source_connection.backup(destination_connection)
        os.chmod(temporary, 0o600)
        _verify(temporary, expected_version)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def restore_pre_migration_backup(
    database: str | Path, source_version: int, target_version: int = LATEST_SCHEMA_VERSION,
) -> dict[str, Any]:
    destination=Path(database)
    backup, manifest_path=backup_paths(destination, source_version, target_version)
    if not backup.is_file() or not manifest_path.is_file():
        raise MigrationGuardError("Exact pre-migration backup and manifest are required")
    backup_evidence=_verify(backup, source_version)
    try:
        manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationGuardError("Exact pre-migration backup manifest is unreadable") from exc
    if (manifest.get("format") != "sean-os-pre-migration-backup/v1" or
            manifest.get("backup_file") != backup.name or
            manifest.get("sha256") != backup_evidence["sha256"] or
            manifest.get("source_schema_version") != source_version or
            manifest.get("target_schema_version") != target_version):
        raise MigrationGuardError("Exact pre-migration backup evidence does not match")

    current_version=_schema_version(destination)
    current_hash=_sha256(destination)
    if current_version == source_version and current_hash == backup_evidence["sha256"]:
        return {
            "restored":False, "already_restored":True,
            "schema_version":source_version, "backup_sha256":backup_evidence["sha256"],
        }
    if current_version < source_version or current_version > target_version:
        raise MigrationGuardError("Current schema is outside the approved recovery range")

    quarantine=destination.with_name(
        f"{destination.name}.failed-migration-v{current_version}-{_safe_stamp()}-{uuid.uuid4().hex[:8]}"
    )
    sidecars=[]
    quarantined=[]
    for suffix in ("", "-wal", "-shm"):
        item=Path(str(destination) + suffix)
        if item.exists():
            target=Path(str(quarantine) + suffix)
            os.replace(item, target)
            sidecars.append(target.name)
            quarantined.append((item, target))
    try:
        _copy_verified_database(backup, destination, source_version)
    except Exception:
        for original, quarantined_file in quarantined:
            if not original.exists() and quarantined_file.exists():
                os.replace(quarantined_file, original)
        raise
    evidence={
        "format":"sean-os-migration-restore/v1", "restored":True,
        "restored_at":_stamp(), "source_schema_version":source_version,
        "target_schema_version":target_version, "backup_sha256":backup_evidence["sha256"],
        "quarantine_files":sidecars, "worker_start_authorized":False,
    }
    _write_json_atomic(
        destination.with_name(f"{destination.name}.migration-restore-evidence.json"), evidence
    )
    return evidence


def _default_migration_runner(database: Path, scope_profile: str) -> None:
    store=SeanOSStore(database, scope_profile=scope_profile)
    try:
        if not store.integrity_check()["ok"]:
            raise ValidationError("Migrated database failed integrity verification")
    finally:
        store.close()


def guarded_migrate(
    database: str | Path, *, scope_profile: str = "IAC",
    migration_runner: MigrationRunner | None = None,
) -> dict[str, Any]:
    path=Path(database)
    if not path.exists() or path.stat().st_size == 0:
        (migration_runner or _default_migration_runner)(path, scope_profile)
        return {
            "migration_required":False, "backup_created":False,
            "schema_version":_schema_version(path),
        }
    source_version=_schema_version(path)
    if source_version > LATEST_SCHEMA_VERSION:
        raise MigrationGuardError("Database schema is newer than this runtime")
    if source_version == LATEST_SCHEMA_VERSION:
        _verify(path, LATEST_SCHEMA_VERSION)
        return {
            "migration_required":False, "backup_created":False,
            "schema_version":source_version,
        }
    manifest=ensure_pre_migration_backup(path, source_version)
    try:
        (migration_runner or _default_migration_runner)(path, scope_profile)
        migrated=_verify(path, LATEST_SCHEMA_VERSION)
    except Exception as exc:
        gc.collect()
        try:
            recovery=restore_pre_migration_backup(path, source_version)
        except Exception as recovery_exc:
            raise MigrationGuardError(
                "Migration and automatic restoration both failed; worker start denied"
            ) from recovery_exc
        raise MigrationGuardError(
            f"Migration failed; schema v{source_version} was restored and worker start denied"
        ) from exc
    return {
        "migration_required":True, "backup_created":True,
        "source_schema_version":source_version,
        "schema_version":LATEST_SCHEMA_VERSION,
        "backup_file":manifest["backup_file"],
        "backup_sha256":manifest["sha256"],
        "integrity_ok":migrated["integrity_ok"],
    }
