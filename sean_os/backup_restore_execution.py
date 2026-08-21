"""Default-off execution boundary for one approved isolated backup restore.

Provider download, key resolution, and decryption are injected ports.  This module
contains no SDK or secret lookup and cannot run with partial configuration, a stale
lease, a changed object version, or an overwrite-capable destination.
"""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .backup_encryption import DECRYPTED_ARTIFACT_FORMAT, DecryptedBackupArtifact
from .backup_restore import (
    build_isolated_backup_restore_receipt,
    verify_isolated_backup_restore_plan,
    verify_synthetic_backup_restore_preflight,
)
from .security import secret_findings


class BackupRestoreExecutionError(ValueError):
    pass


class BackupRestoreExecutionReconciliationRequired(BackupRestoreExecutionError):
    """A private plaintext artifact may exist and must not be retried blindly."""

    retry_permitted = False


RESTORE_EXECUTION_ENV_KEYS = frozenset({
    "SEAN_OS_BACKUP_RESTORE_EXECUTION",
    "SEAN_OS_BACKUP_RESTORE_PROVIDER",
    "SEAN_OS_BACKUP_RESTORE_DATA_REGION",
    "SEAN_OS_BACKUP_RESTORE_ENDPOINT",
    "SEAN_OS_BACKUP_RESTORE_DESTINATION_REF",
    "SEAN_OS_BACKUP_RESTORE_IDENTITY_REF",
    "SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY_REF",
    "SEAN_OS_BACKUP_RESTORE_MAX_BYTES",
    "SEAN_OS_BACKUP_RESTORE_MAX_COST_CAD",
})
FORBIDDEN_DIRECT_RESTORE_SECRET_KEYS = frozenset({
    "SEAN_OS_BACKUP_RESTORE_ACCESS_KEY_ID",
    "SEAN_OS_BACKUP_RESTORE_SECRET_ACCESS_KEY",
    "SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY",
})
DOWNLOADED_ARTIFACT_FORMAT = "sean-os-downloaded-encrypted-backup/v1"
DOWNLOADED_ARTIFACT_FIELDS = frozenset({
    "format", "restore_plan_sha256", "provider", "provider_region",
    "provider_endpoint", "provider_restore_identity_ref", "destination_ref",
    "object_ref", "provider_version_ref", "ciphertext_sha256", "ciphertext_bytes",
    "provider_encryption", "network_performed", "downloaded", "overwrite_performed",
    "object_lock_mode", "object_lock_verified", "retain_until",
    "credentials_persisted", "source_path_included",
})
DECRYPTED_ARTIFACT_FIELDS = frozenset({
    "format", "plan_sha256", "plaintext_sha256", "plaintext_bytes", "algorithm",
    "key_owner", "key_ref", "authenticated", "credentials_persisted",
    "source_path_included",
})
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class BackupRestoreRuntimeConfig:
    enabled: bool
    provider: str | None = None
    data_region: str | None = None
    endpoint: str | None = None
    destination_ref: str | None = None
    restore_identity_ref: str | None = None
    encryption_key_ref: str | None = None
    max_bytes: int | None = None
    max_cost_cad: float | None = None


@dataclass(frozen=True)
class DownloadedBackupArtifact:
    path: Path
    evidence: Mapping[str, Any]


class ObjectStorageDownloadPort(Protocol):
    def download_exact(
        self, *, plan: Mapping[str, Any], config: BackupRestoreRuntimeConfig,
    ) -> DownloadedBackupArtifact: ...


class ClientDecryptionPort(Protocol):
    def decrypt_to(
        self, encrypted: Path, destination: Path, *, key_ref: str,
        expected_plan_sha256: str,
    ) -> DecryptedBackupArtifact: ...


def _safe_ref(name: str, value: Any) -> str:
    if (
        not isinstance(value, str) or not value or value.strip() != value
        or len(value) > 200 or any(ord(character) < 32 for character in value)
        or secret_findings(value)
    ):
        raise BackupRestoreExecutionError(f"{name} must be one bounded non-secret reference")
    return value


def _hash_file(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_backup_restore_runtime_config(
    environment: Mapping[str, str],
) -> BackupRestoreRuntimeConfig:
    if any(environment.get(key) for key in FORBIDDEN_DIRECT_RESTORE_SECRET_KEYS):
        raise BackupRestoreExecutionError(
            "Raw restore secrets are prohibited in runtime configuration"
        )
    mode=environment.get("SEAN_OS_BACKUP_RESTORE_EXECUTION", "DISABLED")
    configured={
        key:environment.get(key) for key in RESTORE_EXECUTION_ENV_KEYS
        if key != "SEAN_OS_BACKUP_RESTORE_EXECUTION" and environment.get(key)
    }
    if mode == "DISABLED":
        if configured:
            raise BackupRestoreExecutionError(
                "Disabled backup restore cannot retain partial configuration"
            )
        return BackupRestoreRuntimeConfig(enabled=False)
    if mode != "APPROVED":
        raise BackupRestoreExecutionError(
            "Backup restore execution mode must be DISABLED or APPROVED"
        )
    required=RESTORE_EXECUTION_ENV_KEYS - {"SEAN_OS_BACKUP_RESTORE_EXECUTION"}
    if any(not environment.get(key) for key in required):
        raise BackupRestoreExecutionError(
            "Approved backup restore requires the complete configuration"
        )
    if environment["SEAN_OS_BACKUP_RESTORE_PROVIDER"] != "BACKBLAZE_B2":
        raise BackupRestoreExecutionError("Backup restore provider must be BACKBLAZE_B2")
    if environment["SEAN_OS_BACKUP_RESTORE_DATA_REGION"] != "CA_EAST":
        raise BackupRestoreExecutionError("Backup restore data region must be CA_EAST")
    endpoint=_safe_ref("provider_endpoint", environment["SEAN_OS_BACKUP_RESTORE_ENDPOINT"])
    if not endpoint.startswith("s3.ca-east-") or not endpoint.endswith(".backblazeb2.com"):
        raise BackupRestoreExecutionError("Backup restore endpoint must be exact Canada East")
    try:
        max_bytes=int(environment["SEAN_OS_BACKUP_RESTORE_MAX_BYTES"])
    except ValueError as exc:
        raise BackupRestoreExecutionError("Backup restore maximum bytes must be an integer") from exc
    if not 1 <= max_bytes <= 10 * 1024 * 1024 * 1024:
        raise BackupRestoreExecutionError("Backup restore maximum bytes is outside the safe range")
    try:
        max_cost=float(environment["SEAN_OS_BACKUP_RESTORE_MAX_COST_CAD"])
    except ValueError as exc:
        raise BackupRestoreExecutionError("Backup restore cost ceiling must be numeric") from exc
    if not math.isfinite(max_cost) or not 0 <= max_cost <= 15:
        raise BackupRestoreExecutionError("Backup restore cost ceiling must be CAD 0 to CAD 15")
    config=BackupRestoreRuntimeConfig(
        enabled=True,
        provider="BACKBLAZE_B2",
        data_region="CA_EAST",
        endpoint=endpoint,
        destination_ref=_safe_ref(
            "destination_ref", environment["SEAN_OS_BACKUP_RESTORE_DESTINATION_REF"]
        ),
        restore_identity_ref=_safe_ref(
            "restore_identity_ref", environment["SEAN_OS_BACKUP_RESTORE_IDENTITY_REF"]
        ),
        encryption_key_ref=_safe_ref(
            "encryption_key_ref", environment["SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY_REF"]
        ),
        max_bytes=max_bytes,
        max_cost_cad=max_cost,
    )
    if secret_findings(config.__dict__):
        raise BackupRestoreExecutionError(
            "Backup restore runtime configuration contains secret-like material"
        )
    return config


def validate_claimed_backup_restore(
    claimed: Mapping[str, Any], *, worker_id: str,
    config: BackupRestoreRuntimeConfig, at: datetime | None = None,
) -> dict[str, Any]:
    if not config.enabled:
        raise BackupRestoreExecutionError("Backup restore execution is disabled")
    if (
        claimed.get("status") != "AUTHORIZED" or not claimed.get("approval_id")
        or claimed.get("lease_owner") != worker_id or not claimed.get("lease_expires_at")
    ):
        raise BackupRestoreExecutionError("Backup restore requires an active approved lease")
    plan=verify_isolated_backup_restore_plan(claimed.get("plan_payload"))
    preflight=verify_synthetic_backup_restore_preflight(
        claimed.get("preflight_receipt_payload")
    )
    if (
        preflight["restore_plan_sha256"] != plan["plan_sha256"]
        or preflight["upload_receipt_sha256"] != plan["upload_receipt_sha256"]
    ):
        raise BackupRestoreExecutionError("Backup restore preflight does not match the lease")
    expected={
        "provider":plan["provider"], "data_region":plan["data_region"],
        "endpoint":plan["provider_endpoint"], "destination_ref":plan["destination_ref"],
        "restore_identity_ref":plan["provider_restore_identity_ref"],
        "encryption_key_ref":plan["client_encryption_key_ref"],
        "max_cost_cad":float(plan["max_cost_cad"]),
    }
    if any(getattr(config, field) != wanted for field, wanted in expected.items()):
        raise BackupRestoreExecutionError(
            "Backup restore runtime configuration does not match the exact plan"
        )
    if plan["ciphertext_bytes"] > int(config.max_bytes or 0):
        raise BackupRestoreExecutionError("Backup restore exceeds the byte ceiling")
    instant=at or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupRestoreExecutionError("Backup restore time must include a timezone")
    if not datetime.fromisoformat(plan["window_start"]) <= instant <= datetime.fromisoformat(
        plan["window_end"]
    ):
        raise BackupRestoreExecutionError("Backup restore is outside the exact approved window")
    if datetime.fromisoformat(claimed["lease_expires_at"]) <= instant:
        raise BackupRestoreExecutionError("Backup restore lease has expired")
    return plan


def _verify_download(
    artifact: DownloadedBackupArtifact, plan: Mapping[str, Any],
    config: BackupRestoreRuntimeConfig,
) -> dict[str, Any]:
    evidence=dict(artifact.evidence)
    required={
        "format":DOWNLOADED_ARTIFACT_FORMAT,
        "restore_plan_sha256":plan["plan_sha256"],
        "provider":plan["provider"],
        "provider_region":plan["data_region"],
        "provider_endpoint":plan["provider_endpoint"],
        "provider_restore_identity_ref":plan["provider_restore_identity_ref"],
        "destination_ref":plan["destination_ref"],
        "object_ref":plan["object_ref"],
        "provider_version_ref":plan["provider_version_ref"],
        "ciphertext_sha256":plan["ciphertext_sha256"],
        "ciphertext_bytes":plan["ciphertext_bytes"],
        "provider_encryption":"AES256",
        "object_lock_mode":"COMPLIANCE",
        "object_lock_verified":True,
        "retain_until":plan["retain_until"],
        "network_performed":True,
        "downloaded":True,
        "overwrite_performed":False,
        "credentials_persisted":False,
        "source_path_included":False,
    }
    if set(evidence) != DOWNLOADED_ARTIFACT_FIELDS or secret_findings(evidence) or any(
        evidence.get(field) != wanted for field, wanted in required.items()
    ):
        raise BackupRestoreExecutionError("Downloaded artifact evidence does not match the plan")
    path=Path(artifact.path)
    if (
        path.is_symlink() or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
        or path.stat().st_size != plan["ciphertext_bytes"]
        or _hash_file(path) != plan["ciphertext_sha256"]
        or plan["ciphertext_bytes"] > int(config.max_bytes or 0)
    ):
        raise BackupRestoreExecutionError("Downloaded encrypted artifact is unsafe or changed")
    return evidence


def _verify_decrypted(
    artifact: DecryptedBackupArtifact, plan: Mapping[str, Any],
) -> dict[str, Any]:
    evidence=dict(artifact.evidence)
    required={
        "format":DECRYPTED_ARTIFACT_FORMAT,
        "plan_sha256":plan["upload_plan_sha256"],
        "plaintext_sha256":plan["expected_plaintext_sha256"],
        "plaintext_bytes":plan["expected_plaintext_bytes"],
        "algorithm":"AES_256_GCM",
        "key_owner":"IAC",
        "key_ref":plan["client_encryption_key_ref"],
        "authenticated":True,
        "credentials_persisted":False,
        "source_path_included":False,
    }
    if set(evidence) != DECRYPTED_ARTIFACT_FIELDS or secret_findings(evidence) or any(
        evidence.get(field) != wanted for field, wanted in required.items()
    ):
        raise BackupRestoreExecutionError("Decrypted artifact evidence does not match the plan")
    path=Path(artifact.path)
    if (
        path.is_symlink() or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
        or path.stat().st_size != plan["expected_plaintext_bytes"]
        or _hash_file(path) != plan["expected_plaintext_sha256"]
    ):
        raise BackupRestoreExecutionError("Authenticated restore artifact is unsafe or changed")
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA query_only = ON")
            integrity=connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys=list(connection.execute("PRAGMA foreign_key_check"))
            schema_version=connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
            scope_profile=connection.execute(
                "SELECT value FROM runtime_state WHERE key='scope_profile'"
            ).fetchone()[0]
    except (sqlite3.Error, TypeError) as exc:
        raise BackupRestoreExecutionError("Restored database verification failed") from exc
    if (
        integrity != "ok" or foreign_keys
        or schema_version != plan["expected_schema_version"] or scope_profile != "IAC"
    ):
        raise BackupRestoreExecutionError("Restored database integrity or scope check failed")
    return evidence


def execute_claimed_backup_restore(
    claimed: Mapping[str, Any], *, worker_id: str,
    config: BackupRestoreRuntimeConfig, downloader: ObjectStorageDownloadPort,
    decryptor: ClientDecryptionPort, restore_destination: Path,
    guard: Callable[[str], None], at: datetime | None = None,
) -> dict[str, Any]:
    """Execute one exact restore through injected ports and return path-free evidence."""
    instant=at or datetime.now(timezone.utc)
    plan=validate_claimed_backup_restore(
        claimed, worker_id=worker_id, config=config, at=instant
    )
    destination=Path(restore_destination)
    if destination.exists() or destination.is_symlink():
        raise BackupRestoreExecutionError("Restore destination must be new and non-overwriting")
    guard("BEFORE_DOWNLOAD")
    downloaded=downloader.download_exact(plan=plan, config=config)
    _verify_download(downloaded, plan, config)
    guard("AFTER_DOWNLOAD")
    decrypted=decryptor.decrypt_to(
        downloaded.path, destination,
        key_ref=str(config.encryption_key_ref),
        expected_plan_sha256=plan["upload_plan_sha256"],
    )
    try:
        _verify_decrypted(decrypted, plan)
        guard("AFTER_DECRYPTION")
        evidence={
            "provider":plan["provider"],
            "provider_region":plan["data_region"],
            "provider_endpoint":plan["provider_endpoint"],
            "provider_restore_identity_ref":plan["provider_restore_identity_ref"],
            "object_ref":plan["object_ref"],
            "provider_version_ref":plan["provider_version_ref"],
            "ciphertext_sha256":plan["ciphertext_sha256"],
            "ciphertext_bytes":plan["ciphertext_bytes"],
            "client_encryption_key_ref":plan["client_encryption_key_ref"],
            "plaintext_sha256":plan["expected_plaintext_sha256"],
            "plaintext_bytes":plan["expected_plaintext_bytes"],
            "schema_version":plan["expected_schema_version"],
            "restore_target_ref":plan["restore_target_ref"],
            "object_lock_mode":"COMPLIANCE",
            "object_lock_verified":True,
            "retain_until":plan["retain_until"],
            "client_encryption_authenticated":True,
            "database_integrity_ok":True,
            "foreign_key_violations":0,
            "scope_profile":"IAC",
            "network_performed":True,
            "downloaded":True,
            "decrypted":True,
            "restored":True,
            "isolated_restore":True,
            "overwrite_performed":False,
            "credentials_persisted":False,
            "source_path_included":False,
        }
        return build_isolated_backup_restore_receipt(
            plan, evidence, restored_at=instant.isoformat()
        )
    except Exception as exc:
        raise BackupRestoreExecutionReconciliationRequired(
            "Published isolated restore requires manual reconciliation"
        ) from exc
