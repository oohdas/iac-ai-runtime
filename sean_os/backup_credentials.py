"""Deterministic, non-creating contract for a least-privilege B2 pilot key."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from .backup_adapter import verify_backblaze_endpoint
from .security import secret_findings


class BackupCredentialError(ValueError):
    pass


KEY_PROPOSAL_FORMAT = "sean-os-backblaze-writer-key-proposal/v1"
KEY_PACKAGE_FORMAT = "sean-os-backblaze-writer-key-approval/v1"
KEY_ACTION_TYPE = "CREATE_BACKBLAZE_BACKUP_WRITER_KEY"
WRITER_CAPABILITIES = frozenset({
    "listBuckets",
    "listAllBucketNames",
    "readBucketEncryption",
    "readBucketRetentions",
    "writeFiles",
    "readFileRetentions",
})
PROHIBITED_CAPABILITIES = frozenset({
    "listKeys", "writeKeys", "deleteKeys",
    "readBuckets", "writeBuckets", "deleteBuckets",
    "writeBucketEncryption", "writeBucketRetentions",
    "listFiles", "readFiles", "deleteFiles", "shareFiles",
    "writeFileRetentions", "bypassGovernance",
    "readFileLegalHolds", "writeFileLegalHolds",
    "readBucketReplications", "writeBucketReplications",
    "readBucketNotifications", "writeBucketNotifications",
    "readBucketLogging", "writeBucketLogging",
    "readBucketLifecycleRules", "writeBucketLifecycleRules",
})
KEY_PROPOSAL_FIELDS = frozenset({
    "format",
    "owner_scope",
    "provider",
    "data_region",
    "provider_endpoint",
    "bucket_ref",
    "key_name_ref",
    "file_name_prefix",
    "valid_duration_seconds",
    "capabilities",
    "credential_destination_ref",
    "access_owner",
    "operator",
    "production_data_authorized",
    "account_admin_authorized",
    "approval_required",
    "creation_authorized",
})
KEY_PACKAGE_FIELDS = frozenset({
    "format",
    "proposal",
    "proposal_sha256",
    "approval_action_type",
    "approval_target",
    "approval_required",
    "creation_authorized",
})
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{4,62}")
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _safe_ref(name: str, value: Any) -> str:
    if (not isinstance(value, str) or not _REFERENCE.fullmatch(value) or
            value.startswith("/") or ".." in value or "\\" in value or
            secret_findings(value)):
        raise BackupCredentialError(f"{name} must be one bounded non-secret reference")
    return value


def validate_backup_writer_key_proposal(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a one-drill key shape while always leaving key creation disabled."""
    if not isinstance(proposal, Mapping) or set(proposal) != KEY_PROPOSAL_FIELDS:
        raise BackupCredentialError("Backup writer key proposal fields are incomplete")
    value = dict(proposal)
    if secret_findings(value):
        raise BackupCredentialError("Secret-like material is prohibited in key proposals")
    required = {
        "format": KEY_PROPOSAL_FORMAT,
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": "CA_EAST",
        "file_name_prefix": "backups/",
        "access_owner": "IAC",
        "operator": "sean",
        "production_data_authorized": False,
        "account_admin_authorized": False,
        "approval_required": True,
        "creation_authorized": False,
    }
    if any(value.get(field) != expected for field, expected in required.items()):
        raise BackupCredentialError("Backup writer key proposal violates the pilot boundary")
    try:
        value["provider_endpoint"] = verify_backblaze_endpoint(
            value["provider_endpoint"], value["data_region"]
        )
    except ValueError as exc:
        raise BackupCredentialError(str(exc)) from exc
    if not isinstance(value["bucket_ref"], str) or not _BUCKET.fullmatch(value["bucket_ref"]):
        raise BackupCredentialError("Backup key must be restricted to one valid bucket")
    value["key_name_ref"] = _safe_ref("key_name_ref", value["key_name_ref"])
    value["credential_destination_ref"] = _safe_ref(
        "credential_destination_ref", value["credential_destination_ref"]
    )
    duration = value["valid_duration_seconds"]
    if isinstance(duration, bool) or not isinstance(duration, int) or not 300 <= duration <= 14400:
        raise BackupCredentialError("Pilot key duration must be between 5 minutes and 4 hours")
    capabilities = value["capabilities"]
    if (not isinstance(capabilities, list) or capabilities != sorted(WRITER_CAPABILITIES) or
            len(capabilities) != len(set(capabilities))):
        raise BackupCredentialError("Backup writer capabilities must match the exact allowlist")
    if set(capabilities) & PROHIBITED_CAPABILITIES:
        raise BackupCredentialError("Backup writer proposal includes prohibited authority")
    return json.loads(_canonical(value))


def build_backup_writer_key_approval_package(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    value = validate_backup_writer_key_proposal(proposal)
    digest = hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()
    package = {
        "format": KEY_PACKAGE_FORMAT,
        "proposal": value,
        "proposal_sha256": digest,
        "approval_action_type": KEY_ACTION_TYPE,
        "approval_target": f"BACKBLAZE_B2_KEY:{value['key_name_ref']}:{digest[:16]}",
        "approval_required": True,
        "creation_authorized": False,
    }
    return json.loads(_canonical(package))


def verify_backup_writer_key_approval_package(
    package: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(package, Mapping) or set(package) != KEY_PACKAGE_FIELDS:
        raise BackupCredentialError("Backup writer key package fields are incomplete")
    value = dict(package)
    proposal = validate_backup_writer_key_proposal(value["proposal"])
    expected = build_backup_writer_key_approval_package(proposal)
    if not hmac.compare_digest(_canonical(value), _canonical(expected)):
        raise BackupCredentialError("Backup writer key package is invalid or modified")
    return expected
