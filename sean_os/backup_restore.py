"""Fail-closed contracts for a separately approved isolated backup restore.

This module is deliberately non-executing.  It defines the distinct read-only
credential shape and binds verified upload evidence to one isolated restore plan,
but it cannot create a key, resolve a secret, download, decrypt, or publish a file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from datetime import datetime
from typing import Any, Mapping

from .backup_adapter import (
    verify_backblaze_endpoint,
    verify_backup_upload_receipt,
    verify_stored_backup_transfer_plan,
)
from .security import secret_findings


class BackupRestoreError(ValueError):
    pass


RESTORE_KEY_PROPOSAL_FORMAT = "sean-os-backblaze-restore-key-proposal/v1"
RESTORE_KEY_PACKAGE_FORMAT = "sean-os-backblaze-restore-key-approval/v1"
RESTORE_KEY_ACTION_TYPE = "CREATE_BACKBLAZE_BACKUP_RESTORE_KEY"
RESTORE_PLAN_FORMAT = "sean-os-independent-backup-restore-plan/v1"
RESTORE_PREFLIGHT_FORMAT = "sean-os-synthetic-backup-restore-preflight/v1"
RESTORE_RECEIPT_FORMAT = "sean-os-isolated-backup-restore-receipt/v1"
RESTORE_ACTION_TYPE = "RUN_ISOLATED_BACKUP_RESTORE"

RESTORE_CAPABILITIES = frozenset({
    "listAllBucketNames",
    "listBuckets",
    "readBucketEncryption",
    "readBucketRetentions",
    "readFiles",
    "readFileRetentions",
})
PROHIBITED_RESTORE_CAPABILITIES = frozenset({
    "listKeys", "writeKeys", "deleteKeys",
    "readBuckets", "writeBuckets", "deleteBuckets",
    "writeBucketEncryption", "writeBucketRetentions",
    "listFiles", "writeFiles", "deleteFiles", "shareFiles",
    "writeFileRetentions", "bypassGovernance",
    "readFileLegalHolds", "writeFileLegalHolds",
    "readBucketReplications", "writeBucketReplications",
    "readBucketNotifications", "writeBucketNotifications",
    "readBucketLogging", "writeBucketLogging",
    "readBucketLifecycleRules", "writeBucketLifecycleRules",
})
RESTORE_KEY_PROPOSAL_FIELDS = frozenset({
    "format", "owner_scope", "provider", "data_region", "provider_endpoint",
    "bucket_ref", "key_name_ref", "file_name_prefix", "valid_duration_seconds",
    "capabilities", "credential_destination_ref", "access_owner", "operator",
    "production_data_authorized", "account_admin_authorized", "write_authorized",
    "approval_required", "creation_authorized",
})
RESTORE_KEY_PACKAGE_FIELDS = frozenset({
    "format", "proposal", "proposal_sha256", "approval_action_type",
    "approval_target", "approval_required", "creation_authorized",
})
RESTORE_PLAN_FIELDS = frozenset({
    "format", "owner_scope", "provider", "data_region", "provider_endpoint",
    "destination_ref", "object_ref", "provider_version_ref",
    "provider_writer_identity_ref", "provider_restore_identity_ref",
    "client_encryption_key_ref",
    "upload_plan_sha256", "upload_receipt_sha256", "ciphertext_sha256",
    "ciphertext_bytes", "expected_plaintext_sha256", "expected_plaintext_bytes",
    "expected_schema_version", "restore_target_ref", "window_start", "window_end",
    "retain_until", "max_cost_cad", "isolated_restore", "overwrite_permitted",
    "credentials_included", "network_enabled", "download_authorized",
    "decrypt_authorized", "restore_authorized", "approval_required",
    "approval_action_type", "approval_target", "restore_key_proposal_sha256",
    "plan_sha256",
})
RESTORE_PREFLIGHT_FIELDS = frozenset({
    "format", "restore_plan_sha256", "upload_receipt_sha256", "validated",
    "credentials_resolved", "network_performed", "downloaded", "decrypted",
    "restored", "execution_authorized", "status", "receipt_sha256",
})
RESTORE_RECEIPT_FIELDS = frozenset({
    "format", "evidence_mode", "restore_plan_sha256", "upload_receipt_sha256",
    "provider", "provider_region", "provider_endpoint",
    "provider_restore_identity_ref", "object_ref", "provider_version_ref",
    "ciphertext_sha256", "ciphertext_bytes", "client_encryption_key_ref",
    "plaintext_sha256", "plaintext_bytes", "schema_version", "restore_target_ref",
    "object_lock_mode", "object_lock_verified", "retain_until",
    "client_encryption_authenticated", "database_integrity_ok",
    "foreign_key_violations", "scope_profile", "network_performed", "downloaded",
    "decrypted", "restored", "isolated_restore", "overwrite_performed",
    "credentials_persisted", "source_path_included", "restored_at", "receipt_sha256",
})

_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{4,62}")
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Mapping[str, Any], field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != field}
    return hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()


def _safe_ref(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not _REFERENCE.fullmatch(value)
        or value.startswith("/")
        or ".." in value
        or "\\" in value
        or secret_findings(value)
    ):
        raise BackupRestoreError(f"{name} must be one bounded non-secret reference")
    return value


def _sha256(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise BackupRestoreError(f"{name} must be one SHA-256 digest")
    return value


def _aware(name: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise BackupRestoreError(f"{name} must be one bounded ISO-8601 timestamp")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BackupRestoreError(f"{name} must be ISO-8601") from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupRestoreError(f"{name} must include a timezone")
    return instant


def validate_backup_restore_key_proposal(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an exact, short-lived read-only key without creating it."""
    if not isinstance(proposal, Mapping) or set(proposal) != RESTORE_KEY_PROPOSAL_FIELDS:
        raise BackupRestoreError("Backup restore key proposal fields are incomplete")
    value = dict(proposal)
    if secret_findings(value):
        raise BackupRestoreError("Secret-like material is prohibited in restore key proposals")
    required = {
        "format": RESTORE_KEY_PROPOSAL_FORMAT,
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": "CA_EAST",
        "file_name_prefix": "backups/",
        "access_owner": "IAC",
        "operator": "sean",
        "production_data_authorized": False,
        "account_admin_authorized": False,
        "write_authorized": False,
        "approval_required": True,
        "creation_authorized": False,
    }
    if any(value.get(field) != expected for field, expected in required.items()):
        raise BackupRestoreError("Backup restore key proposal violates the isolated boundary")
    try:
        value["provider_endpoint"] = verify_backblaze_endpoint(
            value["provider_endpoint"], value["data_region"]
        )
    except ValueError as exc:
        raise BackupRestoreError(str(exc)) from exc
    if not isinstance(value["bucket_ref"], str) or not _BUCKET.fullmatch(value["bucket_ref"]):
        raise BackupRestoreError("Backup restore key must be restricted to one valid bucket")
    value["key_name_ref"] = _safe_ref("key_name_ref", value["key_name_ref"])
    value["credential_destination_ref"] = _safe_ref(
        "credential_destination_ref", value["credential_destination_ref"]
    )
    duration = value["valid_duration_seconds"]
    if isinstance(duration, bool) or not isinstance(duration, int) or not 300 <= duration <= 14400:
        raise BackupRestoreError("Restore key duration must be between 5 minutes and 4 hours")
    capabilities = value["capabilities"]
    if (
        not isinstance(capabilities, list)
        or capabilities != sorted(RESTORE_CAPABILITIES)
        or len(capabilities) != len(set(capabilities))
    ):
        raise BackupRestoreError("Backup restore capabilities must match the exact allowlist")
    if set(capabilities) & PROHIBITED_RESTORE_CAPABILITIES:
        raise BackupRestoreError("Backup restore proposal includes prohibited authority")
    return json.loads(_canonical(value))


def build_backup_restore_key_approval_package(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    value = validate_backup_restore_key_proposal(proposal)
    digest = hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()
    package = {
        "format": RESTORE_KEY_PACKAGE_FORMAT,
        "proposal": value,
        "proposal_sha256": digest,
        "approval_action_type": RESTORE_KEY_ACTION_TYPE,
        "approval_target": f"BACKBLAZE_B2_RESTORE_KEY:{value['key_name_ref']}:{digest[:16]}",
        "approval_required": True,
        "creation_authorized": False,
    }
    return json.loads(_canonical(package))


def verify_backup_restore_key_approval_package(
    package: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(package, Mapping) or set(package) != RESTORE_KEY_PACKAGE_FIELDS:
        raise BackupRestoreError("Backup restore key package fields are incomplete")
    value = dict(package)
    proposal = validate_backup_restore_key_proposal(value.get("proposal"))
    expected = build_backup_restore_key_approval_package(proposal)
    if not hmac.compare_digest(_canonical(value), _canonical(expected)):
        raise BackupRestoreError("Backup restore key package is invalid or modified")
    return expected


def build_isolated_backup_restore_plan(
    upload_plan: Mapping[str, Any],
    upload_receipt: Mapping[str, Any],
    restore_key_package: Mapping[str, Any],
    *,
    restore_target_ref: str,
    window_start: str,
    window_end: str,
    max_cost_cad: float,
) -> dict[str, Any]:
    """Bind one verified object version to a separate, still-disabled restore."""
    transfer = verify_stored_backup_transfer_plan(upload_plan)
    receipt = verify_backup_upload_receipt(upload_receipt, transfer)
    key_package = verify_backup_restore_key_approval_package(restore_key_package)
    key = key_package["proposal"]
    expected_destination = f"backblaze-b2-bucket:{key['bucket_ref']}"
    if transfer["destination_ref"] != expected_destination:
        raise BackupRestoreError("Restore key bucket does not match the uploaded destination")
    if (
        key["provider_endpoint"] != transfer["provider_endpoint"]
        or key["data_region"] != transfer["data_region"]
    ):
        raise BackupRestoreError("Restore key endpoint does not match the uploaded object")
    if key["credential_destination_ref"] == transfer["provider_writer_identity_ref"]:
        raise BackupRestoreError("Restore identity must be distinct from the writer identity")
    target = _safe_ref("restore_target_ref", restore_target_ref)
    if target in {transfer["destination_ref"], transfer["object_ref"]}:
        raise BackupRestoreError("Restore target must be isolated from the backup destination")
    start = _aware("window_start", window_start)
    end = _aware("window_end", window_end)
    if end <= start or (end - start).total_seconds() > key["valid_duration_seconds"]:
        raise BackupRestoreError("Restore window must be positive and within the key duration")
    uploaded_at = _aware("uploaded_at", receipt["uploaded_at"])
    retained_until = _aware("retain_until", receipt["retain_until"])
    if start < uploaded_at or end > retained_until:
        raise BackupRestoreError("Restore window must follow upload and remain within retention")
    if (
        isinstance(max_cost_cad, bool)
        or not isinstance(max_cost_cad, (int, float))
        or not math.isfinite(float(max_cost_cad))
        or not 0 <= float(max_cost_cad) <= 15
    ):
        raise BackupRestoreError("Restore cost ceiling must be between CAD 0 and CAD 15")
    plan: dict[str, Any] = {
        "format": RESTORE_PLAN_FORMAT,
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": transfer["data_region"],
        "provider_endpoint": transfer["provider_endpoint"],
        "destination_ref": transfer["destination_ref"],
        "object_ref": transfer["object_ref"],
        "provider_version_ref": receipt["provider_version_ref"],
        "provider_writer_identity_ref": transfer["provider_writer_identity_ref"],
        "provider_restore_identity_ref": key["credential_destination_ref"],
        "client_encryption_key_ref": receipt["client_encryption_key_ref"],
        "upload_plan_sha256": transfer["plan_sha256"],
        "upload_receipt_sha256": receipt["receipt_sha256"],
        "ciphertext_sha256": receipt["ciphertext_sha256"],
        "ciphertext_bytes": receipt["ciphertext_bytes"],
        "expected_plaintext_sha256": receipt["backup_sha256"],
        "expected_plaintext_bytes": receipt["backup_bytes"],
        "expected_schema_version": transfer["schema_version"],
        "restore_target_ref": target,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "retain_until": receipt["retain_until"],
        "max_cost_cad": float(max_cost_cad),
        "isolated_restore": True,
        "overwrite_permitted": False,
        "credentials_included": False,
        "network_enabled": False,
        "download_authorized": False,
        "decrypt_authorized": False,
        "restore_authorized": False,
        "approval_required": True,
        "approval_action_type": RESTORE_ACTION_TYPE,
        "approval_target": "PENDING",
        "restore_key_proposal_sha256": key_package["proposal_sha256"],
    }
    identity = {key: item for key, item in plan.items() if key != "approval_target"}
    identity_sha256 = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()
    plan["approval_target"] = f"ISOLATED_BACKUP_RESTORE:{identity_sha256[:24]}"
    plan["plan_sha256"] = _digest(plan, "plan_sha256")
    return json.loads(_canonical(plan))


def verify_isolated_backup_restore_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, Mapping) or set(plan) != RESTORE_PLAN_FIELDS:
        raise BackupRestoreError("Isolated backup restore plan fields are incomplete")
    value = dict(plan)
    required = {
        "format": RESTORE_PLAN_FORMAT,
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": "CA_EAST",
        "isolated_restore": True,
        "overwrite_permitted": False,
        "credentials_included": False,
        "network_enabled": False,
        "download_authorized": False,
        "decrypt_authorized": False,
        "restore_authorized": False,
        "approval_required": True,
        "approval_action_type": RESTORE_ACTION_TYPE,
    }
    if secret_findings(value) or any(value.get(field) != expected for field, expected in required.items()):
        raise BackupRestoreError("Isolated backup restore plan violates the safety boundary")
    try:
        verify_backblaze_endpoint(value["provider_endpoint"], value["data_region"])
    except ValueError as exc:
        raise BackupRestoreError(str(exc)) from exc
    for field in (
        "destination_ref", "object_ref", "provider_version_ref",
        "provider_writer_identity_ref", "provider_restore_identity_ref",
        "client_encryption_key_ref",
        "restore_target_ref", "approval_target",
    ):
        _safe_ref(field, value.get(field))
    for field in (
        "upload_plan_sha256", "upload_receipt_sha256", "ciphertext_sha256",
        "expected_plaintext_sha256", "restore_key_proposal_sha256", "plan_sha256",
    ):
        _sha256(field, value.get(field))
    for field in ("ciphertext_bytes", "expected_plaintext_bytes", "expected_schema_version"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise BackupRestoreError(f"{field} must be a positive integer")
    start = _aware("window_start", value.get("window_start"))
    end = _aware("window_end", value.get("window_end"))
    if end <= start or (end - start).total_seconds() > 14400:
        raise BackupRestoreError("Restore window must be positive and no longer than four hours")
    if end > _aware("retain_until", value.get("retain_until")):
        raise BackupRestoreError("Restore window exceeds the verified retention period")
    cost = value.get("max_cost_cad")
    if (
        isinstance(cost, bool)
        or not isinstance(cost, (int, float))
        or not math.isfinite(float(cost))
        or not 0 <= float(cost) <= 15
    ):
        raise BackupRestoreError("Restore cost ceiling must be between CAD 0 and CAD 15")
    value["max_cost_cad"] = float(cost)
    if value["provider_restore_identity_ref"] == value["provider_writer_identity_ref"]:
        raise BackupRestoreError("Restore identity must be distinct from the writer identity")
    identity = {
        key: item for key, item in value.items()
        if key not in {"approval_target", "plan_sha256"}
    }
    expected_target = (
        "ISOLATED_BACKUP_RESTORE:"
        + hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()[:24]
    )
    if value["approval_target"] != expected_target:
        raise BackupRestoreError("Isolated backup restore approval target is invalid")
    if value["plan_sha256"] != _digest(value, "plan_sha256"):
        raise BackupRestoreError("Isolated backup restore plan is invalid or modified")
    return json.loads(_canonical(value))


def verify_isolated_backup_restore_plan_against_evidence(
    plan: Mapping[str, Any],
    upload_plan: Mapping[str, Any],
    upload_receipt: Mapping[str, Any],
    restore_key_package: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild the plan from authoritative evidence and compare it byte-for-byte."""
    value = verify_isolated_backup_restore_plan(plan)
    expected = build_isolated_backup_restore_plan(
        upload_plan,
        upload_receipt,
        restore_key_package,
        restore_target_ref=value["restore_target_ref"],
        window_start=value["window_start"],
        window_end=value["window_end"],
        max_cost_cad=value["max_cost_cad"],
    )
    if not hmac.compare_digest(_canonical(value), _canonical(expected)):
        raise BackupRestoreError("Isolated backup restore plan does not match its evidence")
    return expected


def synthetic_backup_restore_preflight(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = verify_isolated_backup_restore_plan(plan)
    receipt: dict[str, Any] = {
        "format": RESTORE_PREFLIGHT_FORMAT,
        "restore_plan_sha256": value["plan_sha256"],
        "upload_receipt_sha256": value["upload_receipt_sha256"],
        "validated": True,
        "credentials_resolved": False,
        "network_performed": False,
        "downloaded": False,
        "decrypted": False,
        "restored": False,
        "execution_authorized": False,
        "status": "READY_FOR_DISTINCT_RESTORE_APPROVAL",
    }
    receipt["receipt_sha256"] = _digest(receipt, "receipt_sha256")
    return json.loads(_canonical(receipt))


def verify_synthetic_backup_restore_preflight(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(receipt, Mapping) or set(receipt) != RESTORE_PREFLIGHT_FIELDS:
        raise BackupRestoreError("Synthetic restore preflight fields are incomplete")
    value = dict(receipt)
    required = {
        "format": RESTORE_PREFLIGHT_FORMAT,
        "validated": True,
        "credentials_resolved": False,
        "network_performed": False,
        "downloaded": False,
        "decrypted": False,
        "restored": False,
        "execution_authorized": False,
        "status": "READY_FOR_DISTINCT_RESTORE_APPROVAL",
    }
    if secret_findings(value) or any(value.get(field) != expected for field, expected in required.items()):
        raise BackupRestoreError("Synthetic restore preflight violates its no-action contract")
    _sha256("restore_plan_sha256", value.get("restore_plan_sha256"))
    _sha256("upload_receipt_sha256", value.get("upload_receipt_sha256"))
    _sha256("receipt_sha256", value.get("receipt_sha256"))
    if value["receipt_sha256"] != _digest(value, "receipt_sha256"):
        raise BackupRestoreError("Synthetic restore preflight is invalid or modified")
    return json.loads(_canonical(value))


def build_isolated_backup_restore_receipt(
    plan: Mapping[str, Any], evidence: Mapping[str, Any], *, restored_at: str,
) -> dict[str, Any]:
    """Build path-free completion evidence from already verified execution ports."""
    value = verify_isolated_backup_restore_plan(plan)
    if not isinstance(evidence, Mapping):
        raise BackupRestoreError("Isolated restore completion evidence is required")
    expected = {
        "provider": value["provider"],
        "provider_region": value["data_region"],
        "provider_endpoint": value["provider_endpoint"],
        "provider_restore_identity_ref": value["provider_restore_identity_ref"],
        "object_ref": value["object_ref"],
        "provider_version_ref": value["provider_version_ref"],
        "ciphertext_sha256": value["ciphertext_sha256"],
        "ciphertext_bytes": value["ciphertext_bytes"],
        "client_encryption_key_ref": value["client_encryption_key_ref"],
        "plaintext_sha256": value["expected_plaintext_sha256"],
        "plaintext_bytes": value["expected_plaintext_bytes"],
        "schema_version": value["expected_schema_version"],
        "restore_target_ref": value["restore_target_ref"],
        "object_lock_mode": "COMPLIANCE",
        "object_lock_verified": True,
        "retain_until": value["retain_until"],
        "client_encryption_authenticated": True,
        "database_integrity_ok": True,
        "foreign_key_violations": 0,
        "scope_profile": "IAC",
        "network_performed": True,
        "downloaded": True,
        "decrypted": True,
        "restored": True,
        "isolated_restore": True,
        "overwrite_performed": False,
        "credentials_persisted": False,
        "source_path_included": False,
    }
    if secret_findings(dict(evidence)) or any(
        evidence.get(field) != wanted for field, wanted in expected.items()
    ) or set(evidence) != set(expected):
        raise BackupRestoreError("Isolated restore completion evidence does not match the plan")
    instant = _aware("restored_at", restored_at)
    if not _aware("window_start", value["window_start"]) <= instant <= _aware(
        "window_end", value["window_end"]
    ):
        raise BackupRestoreError("Isolated restore completed outside the approved window")
    receipt: dict[str, Any] = {
        "format": RESTORE_RECEIPT_FORMAT,
        "evidence_mode": "PRODUCTION",
        "restore_plan_sha256": value["plan_sha256"],
        "upload_receipt_sha256": value["upload_receipt_sha256"],
        **expected,
        "restored_at": instant.isoformat(),
    }
    receipt["receipt_sha256"] = _digest(receipt, "receipt_sha256")
    return verify_isolated_backup_restore_receipt(receipt, value)


def verify_isolated_backup_restore_receipt(
    receipt: Mapping[str, Any], plan: Mapping[str, Any],
) -> dict[str, Any]:
    value = verify_isolated_backup_restore_plan(plan)
    if not isinstance(receipt, Mapping) or set(receipt) != RESTORE_RECEIPT_FIELDS:
        raise BackupRestoreError("Isolated restore receipt fields are incomplete")
    item = dict(receipt)
    required = {
        "format": RESTORE_RECEIPT_FORMAT,
        "evidence_mode": "PRODUCTION",
        "restore_plan_sha256": value["plan_sha256"],
        "upload_receipt_sha256": value["upload_receipt_sha256"],
        "provider": value["provider"],
        "provider_region": value["data_region"],
        "provider_endpoint": value["provider_endpoint"],
        "provider_restore_identity_ref": value["provider_restore_identity_ref"],
        "object_ref": value["object_ref"],
        "provider_version_ref": value["provider_version_ref"],
        "ciphertext_sha256": value["ciphertext_sha256"],
        "ciphertext_bytes": value["ciphertext_bytes"],
        "client_encryption_key_ref": value["client_encryption_key_ref"],
        "plaintext_sha256": value["expected_plaintext_sha256"],
        "plaintext_bytes": value["expected_plaintext_bytes"],
        "schema_version": value["expected_schema_version"],
        "restore_target_ref": value["restore_target_ref"],
        "object_lock_mode": "COMPLIANCE",
        "object_lock_verified": True,
        "retain_until": value["retain_until"],
        "client_encryption_authenticated": True,
        "database_integrity_ok": True,
        "foreign_key_violations": 0,
        "scope_profile": "IAC",
        "network_performed": True,
        "downloaded": True,
        "decrypted": True,
        "restored": True,
        "isolated_restore": True,
        "overwrite_performed": False,
        "credentials_persisted": False,
        "source_path_included": False,
    }
    if secret_findings(item) or any(item.get(field) != wanted for field, wanted in required.items()):
        raise BackupRestoreError("Isolated restore receipt violates the exact plan")
    restored_at = _aware("restored_at", item.get("restored_at"))
    if not _aware("window_start", value["window_start"]) <= restored_at <= _aware(
        "window_end", value["window_end"]
    ):
        raise BackupRestoreError("Isolated restore receipt is outside the approved window")
    _sha256("receipt_sha256", item.get("receipt_sha256"))
    if item["receipt_sha256"] != _digest(item, "receipt_sha256"):
        raise BackupRestoreError("Isolated restore receipt is invalid or modified")
    return json.loads(_canonical(item))
