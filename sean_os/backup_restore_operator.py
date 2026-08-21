"""Hash-bound, state-only operator workflow for one isolated backup restore.

This module reviews and mutates durable approval state only. It has no provider,
download, decryption, filesystem, or secret-resolution capability.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .backup_restore import (
    verify_isolated_backup_restore_plan,
    verify_synthetic_backup_restore_preflight,
)
from .backup_restore_execution import (
    FORBIDDEN_DIRECT_RESTORE_SECRET_KEYS,
    RESTORE_EXECUTION_ENV_KEYS,
)
from .backup_restore_secrets import MANAGED_RESTORE_SECRET_VARIABLES
from .backup_secrets import MANAGED_SECRET_VARIABLES
from .security import secret_findings
from .store import Actor, SeanOSStore, ValidationError


REVIEW_FORMAT = "sean-os-backup-restore-operator-review/v1"
OPERATION_FORMAT = "sean-os-backup-restore-operator-operation/v1"
RESTORE_ACTIVATION_ENV_KEYS = (
    RESTORE_EXECUTION_ENV_KEYS
    | FORBIDDEN_DIRECT_RESTORE_SECRET_KEYS
    | MANAGED_RESTORE_SECRET_VARIABLES
    | MANAGED_SECRET_VARIABLES
)


class BackupRestoreOperatorError(ValueError):
    pass


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _require_hash(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BackupRestoreOperatorError(f"{name} must be one lowercase SHA-256 digest")
    return value


def review_backup_restore(
    store: SeanOSStore, actor: Actor, plan_sha256: str,
) -> dict[str, Any]:
    """Return a deterministic, path-free review of current durable restore state."""
    plan_sha256 = _require_hash("plan_sha256", plan_sha256)
    restore = store.get_backup_restore(actor, plan_sha256)
    if restore["owner_scope"] != "IAC":
        raise BackupRestoreOperatorError("Backup restore workflow is restricted to IAC")
    plan = verify_isolated_backup_restore_plan(restore["plan_payload"])
    preflight_valid = False
    if restore["preflight_receipt_payload"] is not None:
        preflight = verify_synthetic_backup_restore_preflight(
            restore["preflight_receipt_payload"]
        )
        preflight_valid = (
            preflight["restore_plan_sha256"] == plan_sha256
            and preflight["upload_receipt_sha256"] == plan["upload_receipt_sha256"]
        )
        if not preflight_valid:
            raise BackupRestoreOperatorError(
                "Restore preflight does not match the exact upload evidence"
            )
    expected_conditions = store._backup_restore_approval_conditions(restore)
    rows = store.connection.execute(
        """SELECT record_id, status, max_impact, expires_at, conditions
           FROM approvals WHERE action_type='RUN_ISOLATED_BACKUP_RESTORE'
           AND target=? AND scope='IAC' ORDER BY record_id""",
        (restore["approval_target"],),
    ).fetchall()
    approvals = []
    for row in rows:
        conditions = json.loads(row["conditions"])
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError) as exc:
            raise BackupRestoreOperatorError("Stored restore approval expiry is invalid") from exc
        if expires.tzinfo is None or expires.utcoffset() is None:
            raise BackupRestoreOperatorError(
                "Stored restore approval expiry must include a timezone"
            )
        approvals.append({
            "approval_id": row["record_id"],
            "status": row["status"],
            "max_impact": row["max_impact"],
            "expires_at": expires.isoformat(),
            "conditions_sha256": _digest(conditions),
            "conditions_match": conditions == expected_conditions,
        })
    review: dict[str, Any] = {
        "format": REVIEW_FORMAT,
        "owner_scope": "IAC",
        "restore_plan_sha256": plan_sha256,
        "upload_plan_sha256": plan["upload_plan_sha256"],
        "upload_receipt_sha256": plan["upload_receipt_sha256"],
        "restore_key_proposal_sha256": plan["restore_key_proposal_sha256"],
        "approval_target": plan["approval_target"],
        "restore_status": restore["status"],
        "preflight_validated": preflight_valid,
        "provider": plan["provider"],
        "data_region": plan["data_region"],
        "provider_endpoint": plan["provider_endpoint"],
        "destination_ref": plan["destination_ref"],
        "object_ref": plan["object_ref"],
        "provider_version_ref": plan["provider_version_ref"],
        "provider_restore_identity_ref": plan["provider_restore_identity_ref"],
        "client_encryption_key_ref": plan["client_encryption_key_ref"],
        "ciphertext_sha256": plan["ciphertext_sha256"],
        "expected_plaintext_sha256": plan["expected_plaintext_sha256"],
        "restore_target_ref": plan["restore_target_ref"],
        "window_start": plan["window_start"],
        "window_end": plan["window_end"],
        "max_cost_cad": plan["max_cost_cad"],
        "attempt_count": restore["attempt_count"],
        "max_attempts": restore["max_attempts"],
        "approval_id": restore["approval_id"],
        "approvals": approvals,
        "network_performed_by_operation": False,
        "download_performed_by_operation": False,
        "decryption_performed_by_operation": False,
        "restore_performed_by_operation": False,
    }
    if secret_findings(review):
        raise BackupRestoreOperatorError("Restore operator review contains secret-like material")
    review["review_sha256"] = _digest(review)
    return json.loads(_canonical(review))


def _require_current_review(
    store: SeanOSStore, actor: Actor, plan_sha256: str, expected_review_sha256: str,
) -> dict[str, Any]:
    expected = _require_hash("expected_review_sha256", expected_review_sha256)
    review = review_backup_restore(store, actor, plan_sha256)
    if review["review_sha256"] != expected:
        raise BackupRestoreOperatorError("Operator review is stale; review the restore again")
    return review


def _operation(
    name: str, review: dict[str, Any], *, approval_id: str,
) -> dict[str, Any]:
    approval = next(
        (item for item in review["approvals"] if item["approval_id"] == approval_id),
        None,
    )
    if approval is None:
        raise BackupRestoreOperatorError("Operation result is missing its approval state")
    result = {
        "format": OPERATION_FORMAT,
        "operation": name,
        "restore_plan_sha256": review["restore_plan_sha256"],
        "approval_id": approval_id,
        "approval_status": approval["status"],
        "restore_status": review["restore_status"],
        "review_sha256": review["review_sha256"],
        "next_action": "RUN_REVIEW",
        "network_performed": False,
        "downloaded": False,
        "decrypted": False,
        "restored": False,
        "restore_claimed": False,
    }
    if secret_findings(result):
        raise BackupRestoreOperatorError("Restore operator result contains secret-like material")
    return result


def request_exact_restore_approval(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *,
    expected_review_sha256: str, expires_at: str,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    if review["restore_status"] != "PREFLIGHT_VALIDATED" or not review["preflight_validated"]:
        raise BackupRestoreOperatorError(
            "Only a validated no-action restore preflight may request approval"
        )
    instant = current_time or datetime.now(timezone.utc)
    active = [
        item for item in review["approvals"]
        if item["status"] in {"PENDING", "APPROVED"}
        and datetime.fromisoformat(item["expires_at"]) > instant
    ]
    if active:
        raise BackupRestoreOperatorError("An active isolated restore approval already exists")
    try:
        expiry = datetime.fromisoformat(expires_at)
        start = datetime.fromisoformat(review["window_start"])
        end = datetime.fromisoformat(review["window_end"])
    except (TypeError, ValueError) as exc:
        raise BackupRestoreOperatorError(
            "Restore approval expiry must be timezone-aware ISO-8601"
        ) from exc
    if any(
        value.tzinfo is None or value.utcoffset() is None
        for value in (instant, expiry, start, end)
    ):
        raise BackupRestoreOperatorError("Restore approval times must include timezones")
    if not instant < expiry <= end or expiry <= start:
        raise BackupRestoreOperatorError(
            "Restore approval must remain valid inside the exact execution window"
        )
    if expiry - instant > timedelta(hours=4):
        raise BackupRestoreOperatorError(
            "Isolated restore approval lifetime must not exceed four hours"
        )
    impact = (
        "One isolated IAC restore into a new target; no overwrite; "
        f"CAD {float(review['max_cost_cad']):.2f} maximum"
    )
    approval_id = store.request_backup_restore_approval(
        actor, plan_sha256, max_impact=impact, expires_at=expiry.isoformat()
    )
    return _operation(
        "REQUEST_APPROVAL", review_backup_restore(store, actor, plan_sha256),
        approval_id=approval_id,
    )


def decide_exact_restore_approval(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *, approval_id: str,
    approve: bool, reason: str, expected_review_sha256: str,
) -> dict[str, Any]:
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    match = next(
        (item for item in review["approvals"] if item["approval_id"] == approval_id),
        None,
    )
    if match is None or match["status"] != "PENDING" or not match["conditions_match"]:
        raise BackupRestoreOperatorError(
            "Restore approval is not the exact pending request under review"
        )
    if not actor.is_sean:
        raise BackupRestoreOperatorError("Only Sean may decide an isolated restore approval")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 240:
        raise BackupRestoreOperatorError("Restore approval decision requires a bounded reason")
    if secret_findings(reason):
        raise BackupRestoreOperatorError(
            "Secret-like material is prohibited in restore approval evidence"
        )
    status = store.decide_approval(
        actor, approval_id, approve=approve, reason=reason
    )
    if status != ("APPROVED" if approve else "DENIED"):
        raise ValidationError("Restore approval decision did not reach the requested state")
    return _operation(
        "APPROVE" if approve else "DENY",
        review_backup_restore(store, actor, plan_sha256), approval_id=approval_id,
    )


def authorize_exact_restore_state(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *, approval_id: str,
    expected_review_sha256: str, confirm_plan_sha256: str,
    environment: Mapping[str, str] | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    plan_sha256 = _require_hash("plan_sha256", plan_sha256)
    if _require_hash("confirm_plan_sha256", confirm_plan_sha256) != plan_sha256:
        raise BackupRestoreOperatorError("Exact restore plan confirmation does not match")
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    match = next(
        (item for item in review["approvals"] if item["approval_id"] == approval_id),
        None,
    )
    if (
        review["restore_status"] != "PREFLIGHT_VALIDATED"
        or match is None
        or match["status"] != "APPROVED"
        or not match["conditions_match"]
    ):
        raise BackupRestoreOperatorError(
            "Restore approval is not the exact approved request under review"
        )
    active_environment = os.environ if environment is None else environment
    if any(active_environment.get(key) for key in RESTORE_ACTIVATION_ENV_KEYS):
        raise BackupRestoreOperatorError(
            "State authorization requires all restore execution and secret values absent"
        )
    instant = current_time or datetime.now(timezone.utc)
    start = datetime.fromisoformat(review["window_start"])
    end = datetime.fromisoformat(review["window_end"])
    if instant.tzinfo is None or instant.utcoffset() is None or not start <= instant < end:
        raise BackupRestoreOperatorError(
            "Restore state authorization is outside the exact execution window"
        )
    store.authorize_backup_restore(
        actor, plan_sha256, approval_id=approval_id, at=instant.isoformat()
    )
    updated = review_backup_restore(store, actor, plan_sha256)
    if updated["restore_status"] != "AUTHORIZED":
        raise ValidationError("Isolated restore did not reach authorized state")
    return _operation("AUTHORIZE_STATE_ONLY", updated, approval_id=approval_id)
