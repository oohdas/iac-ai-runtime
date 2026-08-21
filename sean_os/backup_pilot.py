"""Exact, non-executing review package for the first supervised live-path pilot."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from .backup_approval import build_independent_backup_approval_package
from .backup_credentials import build_backup_writer_key_approval_package
from .backup_secrets import MANAGED_SECRET_VARIABLES
from .security import secret_findings


class BackupPilotError(ValueError):
    pass


PILOT_FORMAT = "sean-os-supervised-synthetic-backup-pilot/v1"
RAILWAY_PROJECT_ID = "aa5875de-3c73-44df-a7d8-00b5911d64d2"
RAILWAY_ENVIRONMENT_ID = "8bb602a7-8e67-4a34-8f57-def32780aeb9"
RAILWAY_SERVICE_ID = "f836e6ff-56ba-4b69-8dab-6c2e91478853"
RAILWAY_VOLUME_REF = "railway-volume:iac-ai-runtime-volume"
BACKBLAZE_BUCKET = "iac-sean-os-ca-east-20260820-v01-9k4m"
BACKBLAZE_ENDPOINT = "s3.ca-east-006.backblazeb2.com"
DESTINATION_REF = f"backblaze-b2-bucket:{BACKBLAZE_BUCKET}"
WRITER_IDENTITY_REF = "railway-managed-value:sean-os-b2-writer-v1"
ENCRYPTION_KEY_REF = "railway-managed-value:sean-os-aes256-v1"
RESTORE_TARGET_REF = "local-quarantine:synthetic-iac-restore-v1"
_COMMIT = re.compile(r"[0-9a-f]{40}")


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _aware(value: str, name: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise BackupPilotError(f"{name} must be one ISO-8601 timestamp") from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupPilotError(f"{name} must include a timezone")
    return instant


def build_supervised_backup_pilot_package(
    *, candidate_commit: str, window_start: str, window_end: str,
) -> dict[str, Any]:
    """Bind the actual pilot resources while authorizing no external action."""
    if not isinstance(candidate_commit, str) or not _COMMIT.fullmatch(candidate_commit):
        raise BackupPilotError("Candidate commit must be one full Git commit SHA")
    start = _aware(window_start, "window_start")
    end = _aware(window_end, "window_end")
    duration = int((end - start).total_seconds())
    if not 1 <= duration <= 4 * 60 * 60:
        raise BackupPilotError("Pilot window must be positive and at most four hours")
    utc_stamp = start.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    object_ref = f"backups/pilot-{candidate_commit[:12]}-{utc_stamp}.db.enc"
    drill = build_independent_backup_approval_package({
        "format": "sean-os-independent-backup-drill-proposal/v2",
        "owner_scope": "IAC",
        "project_id": RAILWAY_PROJECT_ID,
        "environment_id": RAILWAY_ENVIRONMENT_ID,
        "service_id": RAILWAY_SERVICE_ID,
        "primary_volume_id": RAILWAY_VOLUME_REF,
        "destination_kind": "ENCRYPTED_OBJECT_STORAGE",
        "destination_provider": "BACKBLAZE_B2",
        "destination_ref": DESTINATION_REF,
        "data_region": "CA_EAST",
        "independent_from_primary": True,
        "encryption_at_rest": True,
        "encryption_key_owner": "IAC",
        "access_owner": "IAC",
        "retention_days": 30,
        "object_lock_enabled": True,
        "restore_target_ref": RESTORE_TARGET_REF,
        "isolated_restore": True,
        "overwrite_production": False,
        "operator": "sean",
        "rollback_owner": "sean",
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "max_cost_cad": 15,
        "kill_switch_change_requested": True,
        "live_connectors_enabled": False,
        "real_data_authorized": False,
    })
    writer = build_backup_writer_key_approval_package({
        "format": "sean-os-backblaze-writer-key-proposal/v1",
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": "CA_EAST",
        "provider_endpoint": BACKBLAZE_ENDPOINT,
        "bucket_ref": BACKBLAZE_BUCKET,
        "file_name_prefix": "backups/",
        "key_name_ref": "sean-os-backup-writer-pilot-v1",
        "credential_destination_ref": WRITER_IDENTITY_REF,
        "operator": "sean",
        "access_owner": "IAC",
        "valid_duration_seconds": duration,
        "capabilities": [
            "listAllBucketNames",
            "listBuckets",
            "readBucketEncryption",
            "readBucketRetentions",
            "readFileRetentions",
            "writeFiles",
        ],
        "approval_required": True,
        "creation_authorized": False,
        "production_data_authorized": False,
        "account_admin_authorized": False,
    })
    package: dict[str, Any] = {
        "format": PILOT_FORMAT,
        "owner_scope": "IAC",
        "data_mode": "SYNTHETIC_IAC_DATABASE_ONLY",
        "candidate_commit": candidate_commit,
        # Staging is permitted only after this exact candidate is deployed and healthy.
        # An older source release must never be presented as a rollback baseline for a
        # newer schema; recovery uses the guarded pre-migration database backup instead.
        "deployed_baseline_commit": candidate_commit,
        "bucket_name": BACKBLAZE_BUCKET,
        "provider_endpoint": BACKBLAZE_ENDPOINT,
        "object_ref": object_ref,
        "writer_identity_ref": WRITER_IDENTITY_REF,
        "encryption_key_ref": ENCRYPTION_KEY_REF,
        "managed_variable_names": sorted(MANAGED_SECRET_VARIABLES),
        "drill_approval_package": drill,
        "writer_key_approval_package": writer,
        "non_secret_runtime": {
            "SEAN_OS_BACKUP_EXECUTION": "APPROVED",
            "SEAN_OS_BACKUP_PROVIDER": "BACKBLAZE_B2",
            "SEAN_OS_BACKUP_DATA_REGION": "CA_EAST",
            "SEAN_OS_BACKUP_ENDPOINT": BACKBLAZE_ENDPOINT,
            "SEAN_OS_BACKUP_DESTINATION_REF": DESTINATION_REF,
            "SEAN_OS_BACKUP_WRITER_IDENTITY_REF": WRITER_IDENTITY_REF,
            "SEAN_OS_BACKUP_ENCRYPTION_KEY_REF": ENCRYPTION_KEY_REF,
            "SEAN_OS_BACKUP_MAX_COST_CAD": "15",
        },
        "required_manual_gates": [
            "APPROVE_CANDIDATE_PUSH_AND_RAILWAY_DEPLOYMENT",
            "CREATE_EXACT_BACKBLAZE_WRITER_KEY",
            "PLACE_THREE_RAILWAY_MANAGED_VALUES",
            "AUTHORIZE_ONE_SYNTHETIC_UPLOAD",
            "AUTHORIZE_ISOLATED_SYNTHETIC_RESTORE",
            "REMOVE_OR_ROTATE_PILOT_VALUES",
        ],
        "key_creation_authorized": False,
        "secret_placement_authorized": False,
        "push_authorized": False,
        "deployment_authorized": False,
        "upload_authorized": False,
        "restore_authorized": False,
        "real_data_authorized": False,
        "network_enabled": False,
        "execution_authorized": False,
    }
    if secret_findings(package):
        raise BackupPilotError("Pilot package contains prohibited secret-like material")
    package["package_sha256"] = hashlib.sha256(
        _canonical(package).encode("utf-8")
    ).hexdigest()
    return json.loads(_canonical(package))


def verify_supervised_backup_pilot_package(
    package: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(package, Mapping):
        raise BackupPilotError("Pilot package must be an object")
    value = dict(package)
    digest = value.pop("package_sha256", None)
    try:
        rebuilt = build_supervised_backup_pilot_package(
            candidate_commit=value["candidate_commit"],
            window_start=value["drill_approval_package"]["proposal"]["window_start"],
            window_end=value["drill_approval_package"]["proposal"]["window_end"],
        )
    except (KeyError, TypeError) as exc:
        raise BackupPilotError("Pilot package is incomplete") from exc
    if not isinstance(digest, str) or not hmac.compare_digest(
        _canonical(package), _canonical(rebuilt)
    ):
        raise BackupPilotError("Pilot package is invalid or modified")
    return rebuilt
