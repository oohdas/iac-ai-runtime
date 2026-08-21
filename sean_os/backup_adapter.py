"""No-network transfer contract for independently stored IAC backups."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .backup_approval import DATA_REGIONS, verify_independent_backup_approval_package
from .migrations import LATEST_SCHEMA_VERSION
from .security import secret_findings


class BackupAdapterError(ValueError):
    pass


TRANSFER_PLAN_FORMAT = "sean-os-independent-backup-transfer-plan/v3"
SYNTHETIC_RECEIPT_FORMAT = "sean-os-synthetic-backup-adapter-receipt/v1"
UPLOAD_RECEIPT_FORMAT = "sean-os-independent-backup-upload-receipt/v3"
PROVIDER_INTERFACE = "S3_COMPATIBLE_OBJECT_STORAGE_V1"
CLIENT_ENCRYPTION_ALGORITHMS = frozenset({"AES_256_GCM", "XCHACHA20_POLY1305"})
REGION_ENDPOINT_PREFIX = {
    "US_EAST": "s3.us-east-",
    "US_WEST": "s3.us-west-",
    "EU_CENTRAL": "s3.eu-central-",
    "CA_EAST": "s3.ca-east-",
}
MANIFEST_FIELDS = frozenset({"path", "sha256", "bytes", "schema_version", "integrity_ok"})
TRANSFER_PLAN_FIELDS = frozenset({
    "format",
    "owner_scope",
    "approval_target",
    "proposal_sha256",
    "destination_kind",
    "provider",
    "destination_ref",
    "data_region",
    "provider_endpoint",
    "provider_writer_identity_ref",
    "client_encryption_key_ref",
    "provider_interface",
    "object_ref",
    "backup_sha256",
    "backup_bytes",
    "schema_version",
    "retention_mode",
    "retention_days",
    "window_start",
    "window_end",
    "max_cost_cad",
    "provider_encryption_required",
    "client_encryption_required",
    "object_lock_required",
    "credentials_included",
    "network_enabled",
    "execution_authorized",
    "plan_sha256",
})
SYNTHETIC_RECEIPT_FIELDS = frozenset({
    "format",
    "plan_sha256",
    "adapter",
    "validated",
    "artifact_encrypted",
    "uploaded",
    "network_performed",
    "execution_authorized",
    "provider_receipt_included",
    "status",
    "receipt_sha256",
})
UPLOAD_RECEIPT_FIELDS = frozenset({
    "format",
    "evidence_mode",
    "provider",
    "provider_region",
    "provider_endpoint",
    "provider_writer_identity_ref",
    "plan_sha256",
    "destination_ref",
    "object_ref",
    "backup_sha256",
    "backup_bytes",
    "ciphertext_sha256",
    "ciphertext_bytes",
    "client_encryption_algorithm",
    "client_encryption_key_ref",
    "provider_request_ref",
    "provider_version_ref",
    "encryption_mode",
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
    "source_path_included",
    "receipt_sha256",
})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OPAQUE_OBJECT_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
_BACKBLAZE_ENDPOINT = re.compile(
    r"s3\.(?:us-east|us-west|eu-central|ca-east)-[a-z0-9-]+\.backblazeb2\.com"
)


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_envelope(value: Mapping[str, Any], digest_field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    return hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()


def _validate_object_ref(value: Any) -> str:
    if not isinstance(value, str) or not _OPAQUE_OBJECT_REF.fullmatch(value):
        raise BackupAdapterError("Backup object reference must be one bounded opaque identifier")
    if value.startswith("/") or ".." in value or "\\" in value or secret_findings(value):
        raise BackupAdapterError("Backup object reference is unsafe")
    return value


def verify_backblaze_endpoint(value: Any, data_region: str) -> str:
    """Return a canonical non-secret B2 endpoint only when its region is exact."""
    endpoint = _safe_provider_ref("provider_endpoint", value)
    if (data_region not in REGION_ENDPOINT_PREFIX or
            not _BACKBLAZE_ENDPOINT.fullmatch(endpoint) or
            not endpoint.startswith(REGION_ENDPOINT_PREFIX[data_region])):
        raise BackupAdapterError("Backblaze endpoint does not match the approved data region")
    return endpoint


def verify_local_iac_backup_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Recheck a local SQLite backup and return path-free IAC evidence."""
    if not isinstance(manifest, Mapping) or set(manifest) != MANIFEST_FIELDS:
        raise BackupAdapterError("Backup manifest fields are incomplete or unsupported")
    if secret_findings(dict(manifest)):
        raise BackupAdapterError("Secret-like material is prohibited in backup evidence")
    if manifest["integrity_ok"] is not True:
        raise BackupAdapterError("Backup manifest must record successful integrity checks")
    if manifest["schema_version"] != LATEST_SCHEMA_VERSION:
        raise BackupAdapterError("Backup schema version is unsupported")
    expected_bytes = manifest["bytes"]
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes <= 0:
        raise BackupAdapterError("Backup size must be a positive integer")
    expected_sha = manifest["sha256"]
    if not isinstance(expected_sha, str) or not _SHA256.fullmatch(expected_sha):
        raise BackupAdapterError("Backup SHA-256 is malformed")
    raw_path = manifest["path"]
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096:
        raise BackupAdapterError("Backup path is invalid")
    path = Path(raw_path)
    if path.is_symlink() or not path.is_file():
        raise BackupAdapterError("Backup must be a regular, non-symlink file")
    if path.stat().st_size != expected_bytes or _hash_file(path) != expected_sha:
        raise BackupAdapterError("Backup file does not match its manifest")
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA query_only = ON")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
            version = connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
            profile = connection.execute(
                "SELECT value FROM runtime_state WHERE key='scope_profile'"
            ).fetchone()[0]
    except (sqlite3.Error, TypeError) as exc:
        raise BackupAdapterError("Backup database verification failed") from exc
    if integrity != "ok" or foreign_keys or version != LATEST_SCHEMA_VERSION:
        raise BackupAdapterError("Backup database integrity or schema verification failed")
    if profile != "IAC":
        raise BackupAdapterError("Independent backup transfer is restricted to an IAC database")
    return {
        "owner_scope": "IAC",
        "backup_sha256": expected_sha,
        "backup_bytes": expected_bytes,
        "schema_version": version,
    }


def build_backup_transfer_plan(
    approval_package: Mapping[str, Any],
    backup_manifest: Mapping[str, Any],
    *,
    object_ref: str,
    provider_endpoint: str,
    writer_identity_ref: str,
    client_encryption_key_ref: str,
) -> dict[str, Any]:
    """Build a path-free plan that cannot encrypt, upload, or use credentials."""
    package = verify_independent_backup_approval_package(approval_package)
    proposal = package["proposal"]
    if proposal["destination_kind"] != "ENCRYPTED_OBJECT_STORAGE":
        raise BackupAdapterError("This adapter contract requires encrypted object storage")
    evidence = verify_local_iac_backup_manifest(backup_manifest)
    plan: dict[str, Any] = {
        "format": TRANSFER_PLAN_FORMAT,
        "owner_scope": "IAC",
        "approval_target": package["approval_target"],
        "proposal_sha256": package["proposal_sha256"],
        "destination_kind": proposal["destination_kind"],
        "provider": proposal["destination_provider"],
        "destination_ref": proposal["destination_ref"],
        "data_region": proposal["data_region"],
        "provider_endpoint": verify_backblaze_endpoint(
            provider_endpoint, proposal["data_region"]
        ),
        "provider_writer_identity_ref": _safe_provider_ref(
            "provider_writer_identity_ref", writer_identity_ref
        ),
        "client_encryption_key_ref": _safe_provider_ref(
            "client_encryption_key_ref", client_encryption_key_ref
        ),
        "provider_interface": PROVIDER_INTERFACE,
        "object_ref": _validate_object_ref(object_ref),
        "backup_sha256": evidence["backup_sha256"],
        "backup_bytes": evidence["backup_bytes"],
        "schema_version": evidence["schema_version"],
        "retention_mode": "COMPLIANCE",
        "retention_days": proposal["retention_days"],
        "window_start": proposal["window_start"],
        "window_end": proposal["window_end"],
        "max_cost_cad": proposal["max_cost_cad"],
        "provider_encryption_required": "AES256",
        "client_encryption_required": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION",
        "object_lock_required": True,
        "credentials_included": False,
        "network_enabled": False,
        "execution_authorized": False,
    }
    plan["plan_sha256"] = _digest_envelope(plan, "plan_sha256")
    return plan


def verify_stored_backup_transfer_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Revalidate a durable path-free plan before any execution port is called."""
    if not isinstance(plan, Mapping) or set(plan) != TRANSFER_PLAN_FIELDS:
        raise BackupAdapterError("Stored backup transfer plan is invalid")
    value = dict(plan)
    required = {
        "format": TRANSFER_PLAN_FORMAT,
        "owner_scope": "IAC",
        "destination_kind": "ENCRYPTED_OBJECT_STORAGE",
        "provider": "BACKBLAZE_B2",
        "provider_interface": PROVIDER_INTERFACE,
        "retention_mode": "COMPLIANCE",
        "provider_encryption_required": "AES256",
        "client_encryption_required": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION",
        "object_lock_required": True,
        "credentials_included": False,
        "network_enabled": False,
        "execution_authorized": False,
    }
    if (secret_findings(value) or
            any(value.get(field) != expected for field, expected in required.items())):
        raise BackupAdapterError("Stored backup transfer plan violates the safety contract")
    if value.get("data_region") not in DATA_REGIONS:
        raise BackupAdapterError("Stored backup transfer data region is unsupported")
    _safe_provider_ref("destination_ref", value.get("destination_ref"))
    verify_backblaze_endpoint(value.get("provider_endpoint"), value["data_region"])
    _safe_provider_ref(
        "provider_writer_identity_ref", value.get("provider_writer_identity_ref")
    )
    _safe_provider_ref(
        "client_encryption_key_ref", value.get("client_encryption_key_ref")
    )
    _validate_object_ref(value.get("object_ref"))
    for field in ("approval_target", "proposal_sha256", "backup_sha256", "plan_sha256"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise BackupAdapterError("Stored backup transfer identity is incomplete")
    if (not _SHA256.fullmatch(value["proposal_sha256"]) or
            not _SHA256.fullmatch(value["backup_sha256"]) or
            not _SHA256.fullmatch(value["plan_sha256"])):
        raise BackupAdapterError("Stored backup transfer hash is malformed")
    if (isinstance(value.get("backup_bytes"), bool) or
            not isinstance(value.get("backup_bytes"), int) or value["backup_bytes"] <= 0):
        raise BackupAdapterError("Stored backup transfer size is invalid")
    if value.get("schema_version") != LATEST_SCHEMA_VERSION:
        raise BackupAdapterError("Stored backup transfer schema version is unsupported")
    if (isinstance(value.get("retention_days"), bool) or
            not isinstance(value.get("retention_days"), int) or
            not 7 <= value["retention_days"] <= 3650):
        raise BackupAdapterError("Stored backup transfer retention is invalid")
    start = _aware_instant("window_start", value.get("window_start"))
    end = _aware_instant("window_end", value.get("window_end"))
    if end <= start or (end - start).total_seconds() > 4 * 60 * 60:
        raise BackupAdapterError("Stored backup transfer execution window is invalid")
    cost = value.get("max_cost_cad")
    if (isinstance(cost, bool) or not isinstance(cost, (int, float)) or
            not math.isfinite(float(cost)) or not 0 <= float(cost) <= 15):
        raise BackupAdapterError("Stored backup transfer cost ceiling is invalid")
    value["max_cost_cad"] = float(cost)
    if value["plan_sha256"] != _digest_envelope(value, "plan_sha256"):
        raise BackupAdapterError("Stored backup transfer plan is invalid or modified")
    return json.loads(_canonical(value))


def verify_backup_transfer_plan(
    plan: Mapping[str, Any], approval_package: Mapping[str, Any],
) -> dict[str, Any]:
    value = verify_stored_backup_transfer_plan(plan)
    package = verify_independent_backup_approval_package(approval_package)
    proposal = package["proposal"]
    required = {
        "format": TRANSFER_PLAN_FORMAT,
        "owner_scope": "IAC",
        "approval_target": package["approval_target"],
        "proposal_sha256": package["proposal_sha256"],
        "destination_kind": "ENCRYPTED_OBJECT_STORAGE",
        "provider": proposal["destination_provider"],
        "destination_ref": proposal["destination_ref"],
        "data_region": proposal["data_region"],
        "provider_interface": PROVIDER_INTERFACE,
        "retention_mode": "COMPLIANCE",
        "retention_days": proposal["retention_days"],
        "window_start": proposal["window_start"],
        "window_end": proposal["window_end"],
        "max_cost_cad": proposal["max_cost_cad"],
        "provider_encryption_required": "AES256",
        "client_encryption_required": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION",
        "object_lock_required": True,
        "credentials_included": False,
        "network_enabled": False,
        "execution_authorized": False,
    }
    if any(value.get(field) != expected for field, expected in required.items()):
        raise BackupAdapterError("Backup transfer plan violates its approval or safety contract")
    _validate_object_ref(value["object_ref"])
    if not isinstance(value["backup_sha256"], str) or not _SHA256.fullmatch(value["backup_sha256"]):
        raise BackupAdapterError("Backup transfer SHA-256 is malformed")
    if (isinstance(value["backup_bytes"], bool) or
            not isinstance(value["backup_bytes"], int) or value["backup_bytes"] <= 0):
        raise BackupAdapterError("Backup transfer size is invalid")
    if value["schema_version"] != LATEST_SCHEMA_VERSION:
        raise BackupAdapterError("Backup transfer schema version is unsupported")
    if value["plan_sha256"] != _digest_envelope(value, "plan_sha256"):
        raise BackupAdapterError("Backup transfer plan is invalid or has been modified")
    return json.loads(_canonical(value))


def synthetic_backup_adapter_receipt(
    plan: Mapping[str, Any], approval_package: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a transfer plan while proving no encryption, upload, or network use."""
    validated = verify_backup_transfer_plan(plan, approval_package)
    receipt: dict[str, Any] = {
        "format": SYNTHETIC_RECEIPT_FORMAT,
        "plan_sha256": validated["plan_sha256"],
        "adapter": "SYNTHETIC_NO_NETWORK",
        "validated": True,
        "artifact_encrypted": False,
        "uploaded": False,
        "network_performed": False,
        "execution_authorized": False,
        "provider_receipt_included": False,
        "status": "READY_FOR_ENCRYPTION_AND_EXACT_APPROVAL",
    }
    receipt["receipt_sha256"] = _digest_envelope(receipt, "receipt_sha256")
    return receipt


def verify_synthetic_backup_adapter_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping) or set(receipt) != SYNTHETIC_RECEIPT_FIELDS:
        raise BackupAdapterError("Synthetic backup receipt fields are incomplete or unsupported")
    value = dict(receipt)
    required = {
        "format": SYNTHETIC_RECEIPT_FORMAT,
        "adapter": "SYNTHETIC_NO_NETWORK",
        "validated": True,
        "artifact_encrypted": False,
        "uploaded": False,
        "network_performed": False,
        "execution_authorized": False,
        "provider_receipt_included": False,
        "status": "READY_FOR_ENCRYPTION_AND_EXACT_APPROVAL",
    }
    if secret_findings(value) or any(value.get(field) != expected for field, expected in required.items()):
        raise BackupAdapterError("Synthetic backup receipt violates its no-network contract")
    if not isinstance(value["plan_sha256"], str) or not _SHA256.fullmatch(value["plan_sha256"]):
        raise BackupAdapterError("Synthetic backup receipt plan hash is malformed")
    if value["receipt_sha256"] != _digest_envelope(value, "receipt_sha256"):
        raise BackupAdapterError("Synthetic backup receipt is invalid or has been modified")
    return json.loads(_canonical(value))


def _aware_instant(name: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise BackupAdapterError(f"{name} must be a bounded ISO-8601 timestamp")
    try:
        instant=datetime.fromisoformat(value)
    except ValueError as exc:
        raise BackupAdapterError(f"{name} must be ISO-8601") from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupAdapterError(f"{name} must include a timezone")
    return instant


def _safe_provider_ref(name: str, value: Any) -> str:
    if (not isinstance(value, str) or not value or value.strip() != value or
            len(value) > 200 or any(ord(character) < 32 for character in value)):
        raise BackupAdapterError(f"{name} must be a bounded non-secret reference")
    if secret_findings(value):
        raise BackupAdapterError(f"{name} must not contain secret-like material")
    return value


def verify_backup_upload_receipt(
    receipt: Mapping[str, Any], plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify real provider evidence; this function performs no network action."""
    plan_value=verify_stored_backup_transfer_plan(plan)
    if not isinstance(receipt, Mapping) or set(receipt) != UPLOAD_RECEIPT_FIELDS:
        raise BackupAdapterError("Backup upload receipt fields are incomplete or unsupported")
    value=dict(receipt)
    if secret_findings(value):
        raise BackupAdapterError("Secret-like material is prohibited in backup upload receipts")
    required = {
        "format": UPLOAD_RECEIPT_FORMAT,
        "evidence_mode": "PRODUCTION",
        "provider": "BACKBLAZE_B2",
        "provider_region": plan_value["data_region"],
        "provider_endpoint": plan_value["provider_endpoint"],
        "provider_writer_identity_ref": plan_value["provider_writer_identity_ref"],
        "plan_sha256": plan_value["plan_sha256"],
        "destination_ref": plan_value["destination_ref"],
        "object_ref": plan_value["object_ref"],
        "backup_sha256": plan_value["backup_sha256"],
        "backup_bytes": plan_value["backup_bytes"],
        "encryption_mode": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION_PLUS_PROVIDER_AES256",
        "encryption_verified": True,
        "object_lock_mode": "COMPLIANCE",
        "object_lock_verified": True,
        "retention_days": plan_value["retention_days"],
        "network_performed": True,
        "uploaded": True,
        "overwrite_performed": False,
        "restore_authorized": False,
        "credentials_persisted": False,
        "source_path_included": False,
    }
    if any(value.get(field) != expected for field, expected in required.items()):
        raise BackupAdapterError("Backup upload receipt violates the exact transfer plan")
    _safe_provider_ref("provider_request_ref", value["provider_request_ref"])
    _safe_provider_ref("provider_version_ref", value["provider_version_ref"])
    verify_backblaze_endpoint(value["provider_endpoint"], value["provider_region"])
    _safe_provider_ref(
        "provider_writer_identity_ref", value["provider_writer_identity_ref"]
    )
    if value["client_encryption_key_ref"] != plan_value["client_encryption_key_ref"]:
        raise BackupAdapterError("Backup encryption key reference violates the exact transfer plan")
    if (not isinstance(value["ciphertext_sha256"], str) or
            not _SHA256.fullmatch(value["ciphertext_sha256"])):
        raise BackupAdapterError("Encrypted backup SHA-256 is malformed")
    if (isinstance(value["ciphertext_bytes"], bool) or
            not isinstance(value["ciphertext_bytes"], int) or value["ciphertext_bytes"] <= 0):
        raise BackupAdapterError("Encrypted backup size is invalid")
    if value["client_encryption_algorithm"] not in CLIENT_ENCRYPTION_ALGORITHMS:
        raise BackupAdapterError("Client encryption algorithm is unsupported")
    uploaded_at=_aware_instant("uploaded_at", value["uploaded_at"])
    retain_until=_aware_instant("retain_until", value["retain_until"])
    if not (_aware_instant("window_start", plan_value["window_start"]) <= uploaded_at <=
            _aware_instant("window_end", plan_value["window_end"])):
        raise BackupAdapterError("Provider upload occurred outside the approved window")
    minimum_seconds=int(plan_value["retention_days"]) * 24 * 60 * 60
    if (retain_until-uploaded_at).total_seconds() < minimum_seconds:
        raise BackupAdapterError("Provider retention evidence is shorter than the approved period")
    if value["receipt_sha256"] != _digest_envelope(value, "receipt_sha256"):
        raise BackupAdapterError("Backup upload receipt is invalid or has been modified")
    return json.loads(_canonical(value))
