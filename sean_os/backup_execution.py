"""Default-off orchestration boundary for an approved independent backup upload.

This module deliberately contains no provider SDK, network client, or secret resolver.
The reviewed streaming encryption implementation and future provider ports are injected
separately; the orchestration here proves they cannot run with partial configuration,
the wrong region, an unleased transfer, or unverified evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .backup_adapter import (
    CLIENT_ENCRYPTION_ALGORITHMS,
    UPLOAD_RECEIPT_FORMAT,
    verify_backblaze_endpoint,
    verify_backup_upload_receipt,
    verify_local_iac_backup_manifest,
    verify_stored_backup_transfer_plan,
    verify_synthetic_backup_adapter_receipt,
)
from .security import secret_findings


class BackupExecutionError(ValueError):
    pass


EXECUTION_ENV_KEYS = frozenset({
    "SEAN_OS_BACKUP_EXECUTION",
    "SEAN_OS_BACKUP_PROVIDER",
    "SEAN_OS_BACKUP_DATA_REGION",
    "SEAN_OS_BACKUP_ENDPOINT",
    "SEAN_OS_BACKUP_DESTINATION_REF",
    "SEAN_OS_BACKUP_WRITER_IDENTITY_REF",
    "SEAN_OS_BACKUP_ENCRYPTION_KEY_REF",
    "SEAN_OS_BACKUP_MAX_BYTES",
    "SEAN_OS_BACKUP_MAX_COST_CAD",
})
FORBIDDEN_DIRECT_SECRET_ENV_KEYS = frozenset({
    "SEAN_OS_BACKUP_ACCESS_KEY_ID",
    "SEAN_OS_BACKUP_SECRET_ACCESS_KEY",
    "SEAN_OS_BACKUP_ENCRYPTION_KEY",
})
_SHA256 = re.compile(r"[0-9a-f]{64}")
ENCRYPTED_ARTIFACT_FORMAT = "sean-os-client-encrypted-backup-artifact/v1"
ENCRYPTED_ARTIFACT_FIELDS = frozenset({
    "format",
    "plan_sha256",
    "plaintext_sha256",
    "plaintext_bytes",
    "ciphertext_sha256",
    "ciphertext_bytes",
    "algorithm",
    "key_owner",
    "key_ref",
    "authenticated",
    "aad_plan_sha256",
    "credentials_persisted",
    "source_path_included",
})
PROVIDER_UPLOAD_FIELDS = frozenset({
    "provider",
    "provider_region",
    "provider_endpoint",
    "provider_writer_identity_ref",
    "plan_sha256",
    "destination_ref",
    "object_ref",
    "content_sha256",
    "content_bytes",
    "provider_request_ref",
    "provider_version_ref",
    "provider_encryption",
    "encryption_verified",
    "object_lock_mode",
    "object_lock_verified",
    "retention_days",
    "uploaded_at",
    "retain_until",
    "network_performed",
    "uploaded",
    "overwrite_performed",
    "restore_authorized",
    "credentials_persisted",
})


@dataclass(frozen=True)
class BackupRuntimeConfig:
    enabled: bool
    provider: str | None = None
    data_region: str | None = None
    endpoint: str | None = None
    destination_ref: str | None = None
    writer_identity_ref: str | None = None
    encryption_key_ref: str | None = None
    max_bytes: int | None = None
    max_cost_cad: float | None = None


@dataclass(frozen=True)
class EncryptedBackupArtifact:
    path: Path
    evidence: Mapping[str, Any]


class ClientEncryptionPort(Protocol):
    def encrypt(
        self, source: Path, *, plan: Mapping[str, Any], key_ref: str,
    ) -> EncryptedBackupArtifact: ...


class ObjectStorageUploadPort(Protocol):
    def upload_new(
        self, artifact: EncryptedBackupArtifact, *, plan: Mapping[str, Any],
        config: BackupRuntimeConfig,
    ) -> Mapping[str, Any]: ...


def _safe_ref(name: str, value: Any) -> str:
    if (not isinstance(value, str) or not value or value.strip() != value or
            len(value) > 200 or any(ord(character) < 32 for character in value)):
        raise BackupExecutionError(f"{name} must be one bounded non-secret reference")
    if secret_findings(value):
        raise BackupExecutionError(f"{name} must not contain secret-like material")
    return value


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_backup_runtime_config(environment: Mapping[str, str]) -> BackupRuntimeConfig:
    """Load only non-secret references; disabled is the complete default state."""
    if any(environment.get(key) for key in FORBIDDEN_DIRECT_SECRET_ENV_KEYS):
        raise BackupExecutionError("Raw backup secrets are prohibited in runtime configuration")
    mode = environment.get("SEAN_OS_BACKUP_EXECUTION", "DISABLED")
    configured = {
        key: environment.get(key) for key in EXECUTION_ENV_KEYS
        if key != "SEAN_OS_BACKUP_EXECUTION" and environment.get(key)
    }
    if mode == "DISABLED":
        if configured:
            raise BackupExecutionError("Disabled backup execution cannot retain partial configuration")
        return BackupRuntimeConfig(enabled=False)
    if mode != "APPROVED":
        raise BackupExecutionError("Backup execution mode must be DISABLED or APPROVED")
    required = EXECUTION_ENV_KEYS - {"SEAN_OS_BACKUP_EXECUTION"}
    missing = sorted(key for key in required if not environment.get(key))
    if missing:
        raise BackupExecutionError("Approved backup execution requires the complete configuration")
    provider = environment["SEAN_OS_BACKUP_PROVIDER"]
    region = environment["SEAN_OS_BACKUP_DATA_REGION"]
    endpoint = environment["SEAN_OS_BACKUP_ENDPOINT"]
    if provider != "BACKBLAZE_B2":
        raise BackupExecutionError("Backup provider must be BACKBLAZE_B2")
    try:
        endpoint = verify_backblaze_endpoint(endpoint, region)
    except ValueError as exc:
        raise BackupExecutionError(str(exc)) from exc
    try:
        max_bytes = int(environment["SEAN_OS_BACKUP_MAX_BYTES"])
    except ValueError as exc:
        raise BackupExecutionError("Backup maximum bytes must be an integer") from exc
    if not 1 <= max_bytes <= 10 * 1024 * 1024 * 1024:
        raise BackupExecutionError("Backup maximum bytes must be between 1 byte and 10 GiB")
    try:
        max_cost_cad = float(environment["SEAN_OS_BACKUP_MAX_COST_CAD"])
    except ValueError as exc:
        raise BackupExecutionError("Backup cost ceiling must be numeric") from exc
    if not math.isfinite(max_cost_cad) or not 0 <= max_cost_cad <= 15:
        raise BackupExecutionError("Backup cost ceiling must be between CAD 0 and CAD 15")
    config = BackupRuntimeConfig(
        enabled=True,
        provider=provider,
        data_region=region,
        endpoint=endpoint,
        destination_ref=_safe_ref(
            "destination_ref", environment["SEAN_OS_BACKUP_DESTINATION_REF"]
        ),
        writer_identity_ref=_safe_ref(
            "writer_identity_ref", environment["SEAN_OS_BACKUP_WRITER_IDENTITY_REF"]
        ),
        encryption_key_ref=_safe_ref(
            "encryption_key_ref", environment["SEAN_OS_BACKUP_ENCRYPTION_KEY_REF"]
        ),
        max_bytes=max_bytes,
        max_cost_cad=max_cost_cad,
    )
    if secret_findings(config.__dict__):
        raise BackupExecutionError("Backup runtime configuration contains secret-like material")
    return config


def _verify_encrypted_artifact(
    artifact: EncryptedBackupArtifact, plan: Mapping[str, Any], config: BackupRuntimeConfig,
    source_path: Path,
) -> dict[str, Any]:
    evidence = dict(artifact.evidence)
    if set(evidence) != ENCRYPTED_ARTIFACT_FIELDS or secret_findings(evidence):
        raise BackupExecutionError("Client encryption evidence is incomplete or unsafe")
    required = {
        "format": ENCRYPTED_ARTIFACT_FORMAT,
        "plan_sha256": plan["plan_sha256"],
        "plaintext_sha256": plan["backup_sha256"],
        "plaintext_bytes": plan["backup_bytes"],
        "key_owner": "IAC",
        "key_ref": config.encryption_key_ref,
        "authenticated": True,
        "aad_plan_sha256": plan["plan_sha256"],
        "credentials_persisted": False,
        "source_path_included": False,
    }
    if any(evidence.get(field) != expected for field, expected in required.items()):
        raise BackupExecutionError("Client encryption evidence does not match the exact plan")
    if evidence.get("algorithm") not in CLIENT_ENCRYPTION_ALGORITHMS:
        raise BackupExecutionError("Client encryption algorithm is unsupported")
    if (not isinstance(evidence.get("ciphertext_sha256"), str) or
            not _SHA256.fullmatch(evidence["ciphertext_sha256"])):
        raise BackupExecutionError("Client-encrypted artifact hash is malformed")
    if (isinstance(evidence.get("ciphertext_bytes"), bool) or
            not isinstance(evidence.get("ciphertext_bytes"), int) or
            evidence["ciphertext_bytes"] <= 0):
        raise BackupExecutionError("Client-encrypted artifact size is invalid")
    path = artifact.path
    if (path == source_path or path.is_symlink() or not path.is_file() or
            path.stat().st_size != evidence["ciphertext_bytes"] or
            _hash_file(path) != evidence["ciphertext_sha256"]):
        raise BackupExecutionError("Client-encrypted artifact does not match its evidence")
    return evidence


def _build_upload_receipt(
    provider_evidence: Mapping[str, Any], encryption_evidence: Mapping[str, Any],
    plan: Mapping[str, Any], config: BackupRuntimeConfig,
) -> dict[str, Any]:
    provider = dict(provider_evidence)
    if set(provider) != PROVIDER_UPLOAD_FIELDS or secret_findings(provider):
        raise BackupExecutionError("Provider upload evidence is incomplete or unsafe")
    required = {
        "provider": plan["provider"],
        "provider_region": plan["data_region"],
        "provider_endpoint": config.endpoint,
        "provider_writer_identity_ref": config.writer_identity_ref,
        "plan_sha256": plan["plan_sha256"],
        "destination_ref": plan["destination_ref"],
        "object_ref": plan["object_ref"],
        "content_sha256": encryption_evidence["ciphertext_sha256"],
        "content_bytes": encryption_evidence["ciphertext_bytes"],
        "provider_encryption": "AES256",
        "encryption_verified": True,
        "object_lock_mode": "COMPLIANCE",
        "object_lock_verified": True,
        "retention_days": plan["retention_days"],
        "network_performed": True,
        "uploaded": True,
        "overwrite_performed": False,
        "restore_authorized": False,
        "credentials_persisted": False,
    }
    if any(provider.get(field) != expected for field, expected in required.items()):
        raise BackupExecutionError("Provider upload evidence does not match the exact plan")
    receipt = {
        "format": UPLOAD_RECEIPT_FORMAT,
        "evidence_mode": "PRODUCTION",
        "provider": provider["provider"],
        "provider_region": provider["provider_region"],
        "provider_endpoint": provider["provider_endpoint"],
        "provider_writer_identity_ref": provider["provider_writer_identity_ref"],
        "plan_sha256": plan["plan_sha256"],
        "destination_ref": plan["destination_ref"],
        "object_ref": plan["object_ref"],
        "backup_sha256": plan["backup_sha256"],
        "backup_bytes": plan["backup_bytes"],
        "ciphertext_sha256": encryption_evidence["ciphertext_sha256"],
        "ciphertext_bytes": encryption_evidence["ciphertext_bytes"],
        "client_encryption_algorithm": encryption_evidence["algorithm"],
        "client_encryption_key_ref": encryption_evidence["key_ref"],
        "provider_request_ref": provider["provider_request_ref"],
        "provider_version_ref": provider["provider_version_ref"],
        "encryption_mode": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION_PLUS_PROVIDER_AES256",
        "encryption_verified": True,
        "object_lock_mode": provider["object_lock_mode"],
        "object_lock_verified": provider["object_lock_verified"],
        "retention_days": provider["retention_days"],
        "uploaded_at": provider["uploaded_at"],
        "retain_until": provider["retain_until"],
        "network_performed": provider["network_performed"],
        "uploaded": provider["uploaded"],
        "overwrite_performed": provider["overwrite_performed"],
        "restore_authorized": provider["restore_authorized"],
        "credentials_persisted": False,
        "source_path_included": False,
    }
    unsigned = dict(receipt)
    receipt["receipt_sha256"] = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()
    return verify_backup_upload_receipt(receipt, plan)


def execute_claimed_backup_transfer(
    claimed: Mapping[str, Any], backup_manifest: Mapping[str, Any], *, worker_id: str,
    config: BackupRuntimeConfig, encryptor: ClientEncryptionPort,
    uploader: ObjectStorageUploadPort, guard: Callable[[str], None],
    at: datetime | None = None,
) -> dict[str, Any]:
    """Execute only a leased exact approval through separately injected ports."""
    if not config.enabled:
        raise BackupExecutionError("Backup execution is disabled")
    if (claimed.get("status") != "AUTHORIZED" or not claimed.get("approval_id") or
            claimed.get("lease_owner") != worker_id or
            not claimed.get("lease_expires_at")):
        raise BackupExecutionError("Backup transfer requires an active approved worker lease")
    plan = verify_stored_backup_transfer_plan(claimed.get("plan_payload"))
    preflight = verify_synthetic_backup_adapter_receipt(
        claimed.get("preflight_receipt_payload")
    )
    if preflight["plan_sha256"] != plan["plan_sha256"]:
        raise BackupExecutionError("Backup preflight does not match the leased plan")
    if (config.provider != plan["provider"] or
            config.data_region != plan["data_region"] or
            config.endpoint != plan["provider_endpoint"] or
            config.destination_ref != plan["destination_ref"] or
            config.writer_identity_ref != plan["provider_writer_identity_ref"] or
            config.encryption_key_ref != plan["client_encryption_key_ref"] or
            config.max_cost_cad != float(plan["max_cost_cad"])):
        raise BackupExecutionError("Backup runtime configuration does not match the approved plan")
    instant = at or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupExecutionError("Backup execution time must include a timezone")
    window_start = datetime.fromisoformat(plan["window_start"])
    window_end = datetime.fromisoformat(plan["window_end"])
    if not window_start <= instant <= window_end:
        raise BackupExecutionError("Backup execution is outside the exact approved window")
    verified_source = verify_local_iac_backup_manifest(backup_manifest)
    if (verified_source["backup_sha256"] != plan["backup_sha256"] or
            verified_source["backup_bytes"] != plan["backup_bytes"] or
            verified_source["schema_version"] != plan["schema_version"]):
        raise BackupExecutionError("Backup source no longer matches the approved plan")
    if verified_source["backup_bytes"] > int(config.max_bytes or 0):
        raise BackupExecutionError("Backup source exceeds the configured maximum size")
    source_path = Path(str(backup_manifest["path"]))
    guard("BEFORE_ENCRYPTION")
    artifact = encryptor.encrypt(
        source_path, plan=plan, key_ref=str(config.encryption_key_ref)
    )
    encryption_evidence = _verify_encrypted_artifact(
        artifact, plan, config, source_path
    )
    guard("BEFORE_UPLOAD")
    provider_evidence = uploader.upload_new(artifact, plan=plan, config=config)
    guard("AFTER_UPLOAD")
    return _build_upload_receipt(provider_evidence, encryption_evidence, plan, config)
