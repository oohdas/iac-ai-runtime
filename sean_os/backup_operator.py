"""Hash-bound, state-only operator workflow for one synthetic backup transfer.

This module has no provider, network, encryption, or secret-resolution imports.  It
only reviews and changes durable approval state.  A caller must present the digest of
the immediately preceding review before any mutation, preventing stale operator
screens or copied identifiers from authorizing a changed transfer.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .backup_adapter import (
    verify_stored_backup_transfer_plan,
    verify_synthetic_backup_adapter_receipt,
)
from .backup_activation import get_supervised_synthetic_backup_activation_evidence
from .backup_execution import EXECUTION_ENV_KEYS, FORBIDDEN_DIRECT_SECRET_ENV_KEYS
from .backup_secrets import MANAGED_SECRET_VARIABLES
from .commands import CommandGateway
from .security import secret_findings
from .store import Actor, SeanOSStore, ValidationError


REVIEW_FORMAT = "sean-os-backup-operator-review/v1"
OPERATION_FORMAT = "sean-os-backup-operator-operation/v1"
BACKUP_WORKER_ENV_KEYS = frozenset({
    "SEAN_OS_BACKUP_BUCKET",
    "SEAN_OS_BACKUP_MANIFEST_PATH",
    "SEAN_OS_BACKUP_OUTPUT_DIRECTORY",
})
BACKUP_ACTIVATION_ENV_KEYS = (
    EXECUTION_ENV_KEYS
    | FORBIDDEN_DIRECT_SECRET_ENV_KEYS
    | MANAGED_SECRET_VARIABLES
    | BACKUP_WORKER_ENV_KEYS
)
_HASH_LENGTH = 64


class BackupOperatorError(ValueError):
    pass


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _require_hash(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HASH_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BackupOperatorError(f"{name} must be one lowercase SHA-256 digest")
    return value


def _expected_conditions(store: SeanOSStore, transfer: dict[str, Any]) -> dict[str, Any]:
    return store._backup_transfer_approval_conditions(transfer)


def review_backup_transfer(
    store: SeanOSStore, actor: Actor, plan_sha256: str,
) -> dict[str, Any]:
    """Return a path-free, secret-free, deterministic review of current durable state."""
    plan_sha256 = _require_hash("plan_sha256", plan_sha256)
    transfer = store.get_backup_transfer(actor, plan_sha256)
    if transfer["owner_scope"] != "IAC":
        raise BackupOperatorError("Backup operator workflow is restricted to IAC")
    plan = verify_stored_backup_transfer_plan(transfer["plan_payload"])
    activation = get_supervised_synthetic_backup_activation_evidence(
        store, actor, plan_sha256
    )
    if (
        activation["backup_sha256"] != plan["backup_sha256"]
        or activation["backup_bytes"] != plan["backup_bytes"]
    ):
        raise BackupOperatorError("Synthetic activation does not match the transfer source")
    preflight = transfer["preflight_receipt_payload"]
    preflight_valid = False
    if preflight is not None:
        validated = verify_synthetic_backup_adapter_receipt(preflight)
        preflight_valid = validated["plan_sha256"] == plan_sha256
        if not preflight_valid:
            raise BackupOperatorError("Synthetic preflight does not match the transfer plan")

    expected_conditions = _expected_conditions(store, transfer)
    approval_rows = store.connection.execute(
        """SELECT record_id, status, max_impact, expires_at, conditions
           FROM approvals
           WHERE action_type='RUN_INDEPENDENT_BACKUP_RESTORE_DRILL'
             AND target=? AND scope='IAC'
           ORDER BY record_id""",
        (transfer["approval_target"],),
    ).fetchall()
    approvals = []
    for row in approval_rows:
        conditions = json.loads(row["conditions"])
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError) as exc:
            raise BackupOperatorError("Stored approval expiry is invalid") from exc
        if expires.tzinfo is None or expires.utcoffset() is None:
            raise BackupOperatorError("Stored approval expiry must include a timezone")
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
        "data_mode": "SYNTHETIC_IAC_DATABASE_ONLY",
        "activation_sha256": activation["activation_sha256"],
        "candidate_commit": activation["candidate_commit"],
        "plan_sha256": plan_sha256,
        "proposal_sha256": plan["proposal_sha256"],
        "approval_target": plan["approval_target"],
        "transfer_status": transfer["status"],
        "preflight_validated": preflight_valid,
        "provider": plan["provider"],
        "destination_ref": plan["destination_ref"],
        "data_region": plan["data_region"],
        "provider_endpoint": plan["provider_endpoint"],
        "provider_writer_identity_ref": plan["provider_writer_identity_ref"],
        "client_encryption_key_ref": plan["client_encryption_key_ref"],
        "object_ref": plan["object_ref"],
        "backup_sha256": plan["backup_sha256"],
        "backup_bytes": plan["backup_bytes"],
        "retention_mode": plan["retention_mode"],
        "retention_days": plan["retention_days"],
        "window_start": plan["window_start"],
        "window_end": plan["window_end"],
        "max_cost_cad": plan["max_cost_cad"],
        "attempt_count": transfer["attempt_count"],
        "max_attempts": transfer["max_attempts"],
        "approval_id": transfer["approval_id"],
        "approvals": approvals,
        "network_performed_by_operation": False,
        "upload_performed_by_operation": False,
    }
    if secret_findings(review):
        raise BackupOperatorError("Backup operator review contains secret-like material")
    review["review_sha256"] = _digest(review)
    return json.loads(_canonical(review))


def _require_current_review(
    store: SeanOSStore, actor: Actor, plan_sha256: str, expected_review_sha256: str,
) -> dict[str, Any]:
    expected_review_sha256 = _require_hash(
        "expected_review_sha256", expected_review_sha256
    )
    review = review_backup_transfer(store, actor, plan_sha256)
    if review["review_sha256"] != expected_review_sha256:
        raise BackupOperatorError("Operator review is stale; review the transfer again")
    return review


def _operation(
    name: str, review: dict[str, Any], *, approval_id: str,
) -> dict[str, Any]:
    approval = next(
        (item for item in review["approvals"] if item["approval_id"] == approval_id),
        None,
    )
    if approval is None:
        raise BackupOperatorError("Operation result is missing its approval state")
    result = {
        "format": OPERATION_FORMAT,
        "operation": name,
        "plan_sha256": review["plan_sha256"],
        "approval_id": approval_id,
        "approval_status": approval["status"],
        "transfer_status": review["transfer_status"],
        "review_sha256": review["review_sha256"],
        "next_action": "RUN_REVIEW",
        "network_performed": False,
        "upload_performed": False,
        "transfer_claimed": False,
    }
    if secret_findings(result):
        raise BackupOperatorError("Backup operator result contains secret-like material")
    return result


def request_exact_backup_approval(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *,
    expected_review_sha256: str, expires_at: str,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    """Request one bounded approval from the exact reviewed preflight state."""
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    if review["transfer_status"] != "PREFLIGHT_VALIDATED" or not review["preflight_validated"]:
        raise BackupOperatorError("Only a validated synthetic preflight may request approval")
    instant = current_time or datetime.now(timezone.utc)
    active_approvals = [
        item for item in review["approvals"]
        if item["status"] in {"PENDING", "APPROVED"}
        and datetime.fromisoformat(item["expires_at"]) > instant
    ]
    if active_approvals:
        raise BackupOperatorError("An active backup approval already exists")
    try:
        expiry = datetime.fromisoformat(expires_at)
        window_start = datetime.fromisoformat(review["window_start"])
        window_end = datetime.fromisoformat(review["window_end"])
    except (TypeError, ValueError) as exc:
        raise BackupOperatorError("Approval expiry must be timezone-aware ISO-8601") from exc
    if any(value.tzinfo is None or value.utcoffset() is None for value in (
        expiry, window_start, window_end, instant
    )):
        raise BackupOperatorError("Approval and execution times must include timezones")
    if not (instant < expiry <= window_end):
        raise BackupOperatorError("Approval must expire in the future and by the window end")
    if expiry - instant > timedelta(hours=4):
        raise BackupOperatorError("Backup approval lifetime must not exceed four hours")
    if expiry <= window_start:
        raise BackupOperatorError("Backup approval must remain valid after the window starts")
    max_impact = (
        "One synthetic IAC backup upload; no restore; "
        f"CAD {float(review['max_cost_cad']):.2f} maximum"
    )
    approval_id = CommandGateway(store, actor).request_backup_approval(
        plan_sha256, max_impact=max_impact, expires_at=expiry.isoformat()
    )
    updated = review_backup_transfer(store, actor, plan_sha256)
    return _operation("REQUEST_APPROVAL", updated, approval_id=approval_id)


def decide_exact_backup_approval(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *, approval_id: str,
    approve: bool, reason: str, expected_review_sha256: str,
) -> dict[str, Any]:
    """Decide one exact pending request while leaving transfer execution unauthorized."""
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    matches = [item for item in review["approvals"] if item["approval_id"] == approval_id]
    if (
        len(matches) != 1
        or matches[0]["status"] != "PENDING"
        or matches[0]["conditions_match"] is not True
    ):
        raise BackupOperatorError("Approval is not the exact pending request under review")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 240:
        raise BackupOperatorError("Approval decision requires a bounded reason")
    if secret_findings(reason):
        raise BackupOperatorError("Secret-like material is prohibited in approval evidence")
    status = CommandGateway(store, actor).decide_backup_approval(
        plan_sha256, approval_id=approval_id, approve=approve, reason=reason
    )
    if status != ("APPROVED" if approve else "DENIED"):
        raise BackupOperatorError("Approval decision did not reach the requested state")
    updated = review_backup_transfer(store, actor, plan_sha256)
    return _operation("APPROVE" if approve else "DENY", updated, approval_id=approval_id)


def authorize_exact_backup_state(
    store: SeanOSStore, actor: Actor, plan_sha256: str, *, approval_id: str,
    expected_review_sha256: str, confirm_plan_sha256: str,
    environment: Mapping[str, str] | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    """Consume approval only while every execution/secret environment key is absent."""
    plan_sha256 = _require_hash("plan_sha256", plan_sha256)
    if _require_hash("confirm_plan_sha256", confirm_plan_sha256) != plan_sha256:
        raise BackupOperatorError("Exact plan confirmation does not match")
    review = _require_current_review(
        store, actor, plan_sha256, expected_review_sha256
    )
    matches = [item for item in review["approvals"] if item["approval_id"] == approval_id]
    if (
        review["transfer_status"] != "PREFLIGHT_VALIDATED"
        or len(matches) != 1
        or matches[0]["status"] != "APPROVED"
        or matches[0]["conditions_match"] is not True
    ):
        raise BackupOperatorError("Approval is not the exact approved request under review")
    active_environment = os.environ if environment is None else environment
    if any(active_environment.get(key) for key in BACKUP_ACTIVATION_ENV_KEYS):
        raise BackupOperatorError(
            "State authorization requires all backup execution and secret values absent"
        )
    instant = current_time or datetime.now(timezone.utc)
    start = datetime.fromisoformat(review["window_start"])
    end = datetime.fromisoformat(review["window_end"])
    if instant.tzinfo is None or instant.utcoffset() is None or not start <= instant < end:
        raise BackupOperatorError("State authorization is outside the exact execution window")
    CommandGateway(store, actor).authorize_backup(
        plan_sha256, approval_id=approval_id
    )
    updated = review_backup_transfer(store, actor, plan_sha256)
    if updated["transfer_status"] != "AUTHORIZED":
        raise ValidationError("Backup transfer did not reach authorized state")
    return _operation("AUTHORIZE_STATE_ONLY", updated, approval_id=approval_id)
