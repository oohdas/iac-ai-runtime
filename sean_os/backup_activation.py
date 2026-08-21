"""Prepare one synthetic-only, no-network backup activation package."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .backup_adapter import (
    build_backup_transfer_plan,
    synthetic_backup_adapter_receipt,
    verify_backup_transfer_plan,
    verify_local_iac_backup_manifest,
    verify_synthetic_backup_adapter_receipt,
)
from .backup_execution import EXECUTION_ENV_KEYS, load_backup_runtime_config
from .backup_pilot import (
    BACKBLAZE_BUCKET,
    BACKBLAZE_ENDPOINT,
    ENCRYPTION_KEY_REF,
    WRITER_IDENTITY_REF,
    build_supervised_backup_pilot_package,
    verify_supervised_backup_pilot_package,
)
from .backup_secrets import MANAGED_SECRET_VARIABLES
from .security import secret_findings
from .store import Actor, SeanOSStore


ACTIVATION_FORMAT="sean-os-supervised-synthetic-backup-activation/v1"
ACTIVATION_FIELDS=frozenset({
    "format", "owner_scope", "data_mode", "candidate_commit", "pilot_package",
    "backup_manifest", "transfer_plan", "synthetic_preflight_receipt",
    "transfer_status", "non_secret_runtime", "managed_variable_names",
    "required_next_gates", "network_performed", "key_created", "secret_placed",
    "upload_authorized", "restore_authorized", "real_data_authorized",
    "activation_sha256",
})


class BackupActivationError(ValueError):
    pass


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _private_directory(path: Path, data_root: Path) -> Path:
    raw=Path(path)
    if raw.is_symlink():
        raise BackupActivationError("Backup staging workspace must not be a symlink")
    resolved=raw.resolve()
    root=data_root.resolve()
    if root not in resolved.parents:
        raise BackupActivationError("Backup staging workspace must be inside the data volume")
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not resolved.is_dir() or resolved.stat().st_mode & 0o077:
        raise BackupActivationError("Backup staging workspace must have private permissions")
    return resolved


def write_private_json(path: Path, value: Mapping[str, Any]) -> Path:
    """Write canonical JSON once with mode 0600 and no overwrite."""
    target=Path(path)
    descriptor=os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_canonical(value) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def prepare_supervised_synthetic_backup_activation(
    store: SeanOSStore, *, workspace: Path, candidate_commit: str,
    window_start: str, window_end: str,
) -> dict[str, Any]:
    """Create an isolated synthetic source and stage its exact no-network transfer."""
    if store.scope_profile != "IAC":
        raise BackupActivationError("Backup activation requires an IAC database profile")
    data_root=Path(store.database).resolve().parent
    workspace=_private_directory(workspace, data_root)
    pilot=build_supervised_backup_pilot_package(
        candidate_commit=candidate_commit,
        window_start=window_start,
        window_end=window_end,
    )
    start=datetime.fromisoformat(window_start)
    stamp=start.strftime("%Y%m%dT%H%M%S")
    prefix=f"synthetic-{candidate_commit[:12]}-{stamp}"
    source_path=workspace / f"{prefix}.db"
    manifest_path=workspace / f"{prefix}.manifest.json"
    activation_path=workspace / f"{prefix}.activation.json"
    output_directory=workspace / "encrypted"
    if any(path.exists() or path.is_symlink() for path in (
        source_path, manifest_path, activation_path
    )):
        raise BackupActivationError("Synthetic activation artifacts must not already exist")

    synthetic=SeanOSStore(":memory:", scope_profile="IAC")
    try:
        synthetic.create_record(
            Actor.sean(), "KNOWLEDGE", "IAC",
            {"name":"Synthetic backup drill sentinel", "data_mode":"SYNTHETIC_ONLY"},
        )
        manifest=synthetic.backup_manifest(Actor.sean(), source_path)
    finally:
        synthetic.close()
    write_private_json(manifest_path, manifest)
    plan=build_backup_transfer_plan(
        pilot["drill_approval_package"], manifest,
        object_ref=pilot["object_ref"], provider_endpoint=BACKBLAZE_ENDPOINT,
        writer_identity_ref=WRITER_IDENTITY_REF,
        client_encryption_key_ref=ENCRYPTION_KEY_REF,
    )
    preflight=synthetic_backup_adapter_receipt(
        plan, pilot["drill_approval_package"]
    )
    store.stage_backup_transfer(
        Actor.sean(), plan, pilot["drill_approval_package"]
    )
    staged=store.record_backup_transfer_preflight(
        Actor.sean(), plan["plan_sha256"], preflight
    )
    runtime={
        **pilot["non_secret_runtime"],
        "SEAN_OS_BACKUP_MAX_BYTES":str(plan["backup_bytes"]),
        "SEAN_OS_BACKUP_BUCKET":BACKBLAZE_BUCKET,
        "SEAN_OS_BACKUP_MANIFEST_PATH":str(manifest_path),
        "SEAN_OS_BACKUP_OUTPUT_DIRECTORY":str(output_directory),
    }
    load_backup_runtime_config(runtime)
    activation: dict[str, Any]={
        "format":ACTIVATION_FORMAT,
        "owner_scope":"IAC",
        "data_mode":"SYNTHETIC_IAC_DATABASE_ONLY",
        "candidate_commit":candidate_commit,
        "pilot_package":pilot,
        "backup_manifest":manifest,
        "transfer_plan":plan,
        "synthetic_preflight_receipt":preflight,
        "transfer_status":staged["status"],
        "non_secret_runtime":runtime,
        "managed_variable_names":sorted(MANAGED_SECRET_VARIABLES),
        "required_next_gates":[
            "APPROVE_CANDIDATE_PUSH_AND_RAILWAY_DEPLOYMENT",
            "CREATE_EXACT_BACKBLAZE_WRITER_KEY",
            "PLACE_THREE_RAILWAY_MANAGED_VALUES",
            "APPROVE_EXACT_SYNTHETIC_TRANSFER",
        ],
        "network_performed":False,
        "key_created":False,
        "secret_placed":False,
        "upload_authorized":False,
        "restore_authorized":False,
        "real_data_authorized":False,
    }
    if secret_findings(activation):
        raise BackupActivationError("Synthetic activation package contains secret-like material")
    activation["activation_sha256"]=hashlib.sha256(
        _canonical(activation).encode("utf-8")
    ).hexdigest()
    write_private_json(activation_path, activation)
    return verify_supervised_synthetic_backup_activation(activation)


def verify_supervised_synthetic_backup_activation(
    package: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(package, Mapping) or set(package) != ACTIVATION_FIELDS:
        raise BackupActivationError("Synthetic activation fields are unsupported")
    value=dict(package)
    digest=value.pop("activation_sha256", None)
    if not isinstance(digest, str) or digest != hashlib.sha256(
        _canonical(value).encode("utf-8")
    ).hexdigest():
        raise BackupActivationError("Synthetic activation package is invalid or modified")
    if secret_findings(value):
        raise BackupActivationError("Synthetic activation package contains secret-like material")
    required={
        "format":ACTIVATION_FORMAT,
        "owner_scope":"IAC",
        "data_mode":"SYNTHETIC_IAC_DATABASE_ONLY",
        "transfer_status":"PREFLIGHT_VALIDATED",
        "network_performed":False,
        "key_created":False,
        "secret_placed":False,
        "upload_authorized":False,
        "restore_authorized":False,
        "real_data_authorized":False,
    }
    if any(value.get(field) != expected for field, expected in required.items()):
        raise BackupActivationError("Synthetic activation violates the safety contract")
    pilot=verify_supervised_backup_pilot_package(value["pilot_package"])
    if pilot["candidate_commit"] != value["candidate_commit"]:
        raise BackupActivationError("Synthetic activation candidate does not match its pilot")
    manifest=value["backup_manifest"]
    evidence=verify_local_iac_backup_manifest(manifest)
    plan=verify_backup_transfer_plan(
        value["transfer_plan"], pilot["drill_approval_package"]
    )
    preflight=verify_synthetic_backup_adapter_receipt(
        value["synthetic_preflight_receipt"]
    )
    if (
        plan["plan_sha256"] != preflight["plan_sha256"]
        or plan["backup_sha256"] != evidence["backup_sha256"]
        or plan["backup_bytes"] != evidence["backup_bytes"]
    ):
        raise BackupActivationError("Synthetic activation evidence does not match")
    runtime=load_backup_runtime_config(value["non_secret_runtime"])
    runtime_values=value["non_secret_runtime"]
    worker_keys={
        "SEAN_OS_BACKUP_BUCKET", "SEAN_OS_BACKUP_MANIFEST_PATH",
        "SEAN_OS_BACKUP_OUTPUT_DIRECTORY",
    }
    manifest_path=Path(str(runtime_values.get("SEAN_OS_BACKUP_MANIFEST_PATH", "")))
    expected_manifest_path=Path(str(manifest["path"])).with_suffix(".manifest.json")
    output_path=Path(str(runtime_values.get("SEAN_OS_BACKUP_OUTPUT_DIRECTORY", "")))
    source_path=Path(str(manifest.get("path", "")))
    try:
        stored_manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BackupActivationError("Synthetic activation manifest sidecar is invalid") from exc
    if (
        set(runtime_values) != (set(EXECUTION_ENV_KEYS) | worker_keys)
        or runtime.destination_ref != plan["destination_ref"]
        or runtime.endpoint != plan["provider_endpoint"]
        or runtime.writer_identity_ref != plan["provider_writer_identity_ref"]
        or runtime.encryption_key_ref != plan["client_encryption_key_ref"]
        or runtime.max_bytes != plan["backup_bytes"]
        or runtime_values.get("SEAN_OS_BACKUP_BUCKET") != BACKBLAZE_BUCKET
        or manifest_path != expected_manifest_path
        or output_path != expected_manifest_path.parent / "encrypted"
        or manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.stat().st_mode & 0o077
        or source_path.is_symlink()
        or not source_path.is_file()
        or source_path.stat().st_mode & 0o077
        or stored_manifest != manifest
        or value.get("managed_variable_names") != sorted(MANAGED_SECRET_VARIABLES)
        or value.get("required_next_gates") != [
            "APPROVE_CANDIDATE_PUSH_AND_RAILWAY_DEPLOYMENT",
            "CREATE_EXACT_BACKBLAZE_WRITER_KEY",
            "PLACE_THREE_RAILWAY_MANAGED_VALUES",
            "APPROVE_EXACT_SYNTHETIC_TRANSFER",
        ]
    ):
        raise BackupActivationError("Synthetic activation runtime does not match its plan")
    verified=dict(value)
    verified["activation_sha256"]=digest
    return json.loads(_canonical(verified))
