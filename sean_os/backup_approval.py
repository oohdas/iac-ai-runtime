"""Deterministic, non-executing approval contract for an independent backup drill."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import datetime
from typing import Any, Mapping

from .security import secret_findings


class BackupApprovalError(ValueError):
    pass


PROPOSAL_FORMAT = "sean-os-independent-backup-drill-proposal/v2"
PACKAGE_FORMAT = "sean-os-independent-backup-drill-approval/v2"
ACTION_TYPE = "RUN_INDEPENDENT_BACKUP_RESTORE_DRILL"
DESTINATION_KINDS = frozenset({"ENCRYPTED_OBJECT_STORAGE", "MANAGED_BACKUP_SERVICE"})
DESTINATION_PROVIDERS = frozenset({"BACKBLAZE_B2"})
DATA_REGIONS = frozenset({"US_EAST", "US_WEST", "EU_CENTRAL", "CA_EAST"})
PROPOSAL_FIELDS = frozenset({
    "format",
    "owner_scope",
    "project_id",
    "environment_id",
    "service_id",
    "primary_volume_id",
    "destination_kind",
    "destination_provider",
    "destination_ref",
    "data_region",
    "independent_from_primary",
    "encryption_at_rest",
    "encryption_key_owner",
    "access_owner",
    "retention_days",
    "object_lock_enabled",
    "restore_target_ref",
    "isolated_restore",
    "overwrite_production",
    "operator",
    "rollback_owner",
    "window_start",
    "window_end",
    "max_cost_cad",
    "kill_switch_change_requested",
    "live_connectors_enabled",
    "real_data_authorized",
})
PACKAGE_FIELDS = frozenset({
    "format",
    "proposal",
    "proposal_sha256",
    "approval_action_type",
    "approval_target",
    "approval_required",
    "execution_authorized",
})


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _safe_reference(name: str, value: Any) -> str:
    if not isinstance(value, str) or value.strip() != value or not value or len(value) > 200:
        raise BackupApprovalError(f"{name} must be a bounded non-empty reference")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BackupApprovalError(f"{name} must be a single printable line")
    return value


def _aware_instant(name: str, value: Any) -> datetime:
    text = _safe_reference(name, value)
    try:
        instant = datetime.fromisoformat(text)
    except ValueError as exc:
        raise BackupApprovalError(f"{name} must be ISO-8601") from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupApprovalError(f"{name} must include a timezone")
    return instant


def validate_independent_backup_proposal(proposal: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one exact IAC-only proposal without authorizing or executing it."""
    if not isinstance(proposal, Mapping):
        raise BackupApprovalError("Backup drill proposal must be an object")
    if set(proposal) != PROPOSAL_FIELDS:
        raise BackupApprovalError("Backup drill proposal fields are incomplete or unsupported")
    value = dict(proposal)
    findings = secret_findings(value)
    if findings:
        raise BackupApprovalError("Secret-like material is prohibited in backup approval evidence")
    if value["format"] != PROPOSAL_FORMAT:
        raise BackupApprovalError("Backup drill proposal format is unsupported")
    if value["owner_scope"] != "IAC":
        raise BackupApprovalError("Backup drill proposal must be IAC-owned")

    reference_fields = (
        "project_id", "environment_id", "service_id", "primary_volume_id",
        "destination_ref", "restore_target_ref", "operator", "rollback_owner",
    )
    for field in reference_fields:
        value[field] = _safe_reference(field, value[field])
    if value["destination_kind"] not in DESTINATION_KINDS:
        raise BackupApprovalError("Backup destination kind is unsupported")
    if value["destination_provider"] not in DESTINATION_PROVIDERS:
        raise BackupApprovalError("Backup destination provider is unsupported")
    if value["data_region"] not in DATA_REGIONS:
        raise BackupApprovalError("Backup data region is unsupported")
    if value["operator"] != "sean" or value["rollback_owner"] != "sean":
        raise BackupApprovalError("Sean must operate and own rollback for the v0.1 drill")
    if value["encryption_key_owner"] != "IAC" or value["access_owner"] != "IAC":
        raise BackupApprovalError("Backup encryption and access must remain IAC-owned")

    required_true = (
        "independent_from_primary", "encryption_at_rest", "object_lock_enabled",
        "isolated_restore", "kill_switch_change_requested",
    )
    required_false = ("overwrite_production", "live_connectors_enabled", "real_data_authorized")
    if any(value[field] is not True for field in required_true):
        raise BackupApprovalError("Backup drill safety controls must be explicitly enabled")
    if any(value[field] is not False for field in required_false):
        raise BackupApprovalError("Backup drill must exclude overwrite, connectors, and real data")

    retention = value["retention_days"]
    if isinstance(retention, bool) or not isinstance(retention, int) or not 7 <= retention <= 3650:
        raise BackupApprovalError("Backup retention must be between 7 and 3650 days")
    cost = value["max_cost_cad"]
    if (isinstance(cost, bool) or not isinstance(cost, (int, float)) or
            not math.isfinite(float(cost)) or not 0 <= float(cost) <= 15):
        raise BackupApprovalError("Backup drill maximum cost must be finite and at most CAD 15")
    value["max_cost_cad"] = float(cost)

    start = _aware_instant("window_start", value["window_start"])
    end = _aware_instant("window_end", value["window_end"])
    duration = (end - start).total_seconds()
    if duration <= 0 or duration > 4 * 60 * 60:
        raise BackupApprovalError("Backup drill window must be positive and no longer than four hours")
    primary_refs = {
        value["project_id"], value["environment_id"], value["service_id"],
        value["primary_volume_id"],
    }
    if value["destination_ref"] in primary_refs:
        raise BackupApprovalError("Backup destination must be independent from primary infrastructure")
    if value["restore_target_ref"] in primary_refs or value["restore_target_ref"] == value["destination_ref"]:
        raise BackupApprovalError("Restore target must be a distinct isolated destination")
    return json.loads(_canonical(value))


def build_independent_backup_approval_package(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    validated = validate_independent_backup_proposal(proposal)
    digest = hashlib.sha256(_canonical(validated).encode("utf-8")).hexdigest()
    return {
        "format": PACKAGE_FORMAT,
        "proposal": validated,
        "proposal_sha256": digest,
        "approval_action_type": ACTION_TYPE,
        "approval_target": f"backup-drill:{digest}",
        "approval_required": True,
        "execution_authorized": False,
    }


def verify_independent_backup_approval_package(
    package: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(package, Mapping) or set(package) != PACKAGE_FIELDS:
        raise BackupApprovalError("Backup approval package fields are incomplete or unsupported")
    rebuilt = build_independent_backup_approval_package(package["proposal"])
    if package["format"] != PACKAGE_FORMAT:
        raise BackupApprovalError("Backup approval package format is unsupported")
    for field in PACKAGE_FIELDS - {"proposal"}:
        if isinstance(package[field], str) and isinstance(rebuilt[field], str):
            matches = hmac.compare_digest(package[field], rebuilt[field])
        else:
            matches = package[field] == rebuilt[field]
        if not matches:
            raise BackupApprovalError("Backup approval package is invalid or has been modified")
    return rebuilt
