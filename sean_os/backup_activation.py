"""Prepare one synthetic-only, no-network backup activation package."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
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
from .store import Actor, SeanOSStore, now


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


_SYNTHETIC_EMPTY_TABLES = (
    "relationships", "project_state", "approvals", "work_queue", "budgets",
    "cost_reservations", "usage_events", "worker_heartbeats", "report_runs",
    "schedule_dispatches", "action_executions", "imported_artifacts",
    "coding_deliveries", "coding_delivery_requests", "command_requests",
    "alert_observations", "alert_incidents", "alert_delivery_outbox",
    "backup_transfer_outbox", "backup_activation_evidence",
)


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


def _verify_synthetic_source_database(path: Path) -> None:
    """Prove the staged source contains only the expected synthetic sentinel."""
    try:
        with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as connection:
            connection.row_factory=sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            records=connection.execute(
                """SELECT id, entity_type, owner_scope, source, created_by, payload
                   FROM records"""
            ).fetchall()
            if len(records) != 1:
                raise BackupActivationError(
                    "Synthetic backup source must contain exactly one sentinel record"
                )
            record=records[0]
            if (
                record["entity_type"] != "KNOWLEDGE"
                or record["owner_scope"] != "IAC"
                or record["source"] != "user"
                or record["created_by"] != "sean"
                or json.loads(record["payload"]) != {
                    "name":"Synthetic backup drill sentinel",
                    "data_mode":"SYNTHETIC_ONLY",
                }
            ):
                raise BackupActivationError("Synthetic backup sentinel is invalid")
            if any(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != 0
                for table in _SYNTHETIC_EMPTY_TABLES
            ):
                raise BackupActivationError(
                    "Synthetic backup source contains non-sentinel operational state"
                )
            audits=connection.execute(
                """SELECT actor_id, action, result, affected_record_id FROM audit_log"""
            ).fetchall()
            if (
                len(audits) != 1
                or audits[0]["actor_id"] != "sean"
                or audits[0]["action"] != "CREATE_RECORD"
                or audits[0]["result"] != "ALLOWED"
                or audits[0]["affected_record_id"] != record["id"]
            ):
                raise BackupActivationError("Synthetic backup audit sentinel is invalid")
    except BackupActivationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BackupActivationError("Synthetic backup source verification failed") from exc


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
    verified=verify_supervised_synthetic_backup_activation(activation)
    record_supervised_synthetic_backup_activation(store, Actor.sean(), verified)
    return verified


def record_supervised_synthetic_backup_activation(
    store: SeanOSStore, actor: Actor, package: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind one verified synthetic activation attestation to its durable transfer."""
    verified=verify_supervised_synthetic_backup_activation(package)
    plan=verified["transfer_plan"]
    transfer=store.get_backup_transfer(actor, plan["plan_sha256"])
    store._authorize(actor, "IAC", (), "write")
    if (
        transfer["status"] != "PREFLIGHT_VALIDATED"
        or transfer["proposal_sha256"] != plan["proposal_sha256"]
        or transfer["preflight_receipt_payload"] != verified["synthetic_preflight_receipt"]
    ):
        raise BackupActivationError(
            "Synthetic activation does not match the durable preflight state"
        )
    evidence={
        "plan_sha256":plan["plan_sha256"],
        "activation_sha256":verified["activation_sha256"],
        "activation_format":verified["format"],
        "candidate_commit":verified["candidate_commit"],
        "data_mode":verified["data_mode"],
        "backup_sha256":plan["backup_sha256"],
        "backup_bytes":plan["backup_bytes"],
        "activation_payload":_canonical(verified),
        "network_performed":int(verified["network_performed"]),
        "key_created":int(verified["key_created"]),
        "secret_placed":int(verified["secret_placed"]),
        "upload_authorized":int(verified["upload_authorized"]),
        "restore_authorized":int(verified["restore_authorized"]),
        "real_data_authorized":int(verified["real_data_authorized"]),
    }
    existing=store.connection.execute(
        "SELECT * FROM backup_activation_evidence WHERE plan_sha256=?",
        (plan["plan_sha256"],),
    ).fetchone()
    if existing is not None:
        current=dict(existing)
        current.pop("recorded_at", None)
        if current != evidence:
            raise BackupActivationError(
                "Backup plan is already bound to different activation evidence"
            )
        return get_supervised_synthetic_backup_activation_evidence(
            store, actor, plan["plan_sha256"]
        )
    store.connection.execute(
        """INSERT INTO backup_activation_evidence
           (plan_sha256, activation_sha256, activation_format, candidate_commit,
            data_mode, backup_sha256, backup_bytes, activation_payload,
            network_performed, key_created, secret_placed, upload_authorized,
            restore_authorized, real_data_authorized, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            evidence["plan_sha256"], evidence["activation_sha256"],
            evidence["activation_format"], evidence["candidate_commit"],
            evidence["data_mode"], evidence["backup_sha256"],
            evidence["backup_bytes"], evidence["activation_payload"],
            evidence["network_performed"], evidence["key_created"],
            evidence["secret_placed"], evidence["upload_authorized"],
            evidence["restore_authorized"], evidence["real_data_authorized"], now(),
        ),
    )
    store.connection.commit()
    store._audit(
        actor, "RECORD_SYNTHETIC_BACKUP_ACTIVATION", "ALLOWED",
        "Verified synthetic-only activation bound to exact backup plan",
        details={
            "scope":"IAC",
            "plan_sha256":plan["plan_sha256"],
            "activation_sha256":verified["activation_sha256"],
            "data_mode":verified["data_mode"],
            "network_performed":False,
            "upload_authorized":False,
            "real_data_authorized":False,
        },
    )
    return get_supervised_synthetic_backup_activation_evidence(
        store, actor, plan["plan_sha256"]
    )


def get_supervised_synthetic_backup_activation_evidence(
    store: SeanOSStore, actor: Actor, plan_sha256: str,
) -> dict[str, Any]:
    """Return validated internal activation evidence or fail closed when absent."""
    store._authorize(actor, "IAC", (), "read")
    row=store.connection.execute(
        "SELECT * FROM backup_activation_evidence WHERE plan_sha256=?", (plan_sha256,)
    ).fetchone()
    if row is None:
        raise BackupActivationError(
            "Backup transfer lacks verified synthetic activation evidence"
        )
    evidence=dict(row)
    required={
        "activation_format":ACTIVATION_FORMAT,
        "data_mode":"SYNTHETIC_IAC_DATABASE_ONLY",
        "network_performed":0,
        "key_created":0,
        "secret_placed":0,
        "upload_authorized":0,
        "restore_authorized":0,
        "real_data_authorized":0,
    }
    hashes=(
        evidence.get("plan_sha256"), evidence.get("activation_sha256"),
        evidence.get("backup_sha256"),
    )
    candidate=evidence.get("candidate_commit")
    try:
        activation=verify_supervised_synthetic_backup_activation(
            json.loads(evidence.get("activation_payload", ""))
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BackupActivationError("Stored synthetic activation payload is invalid") from exc
    if (
        any(evidence.get(field) != expected for field, expected in required.items())
        or any(
            not isinstance(value, str) or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in hashes
        )
        or not isinstance(candidate, str) or len(candidate) != 40
        or any(character not in "0123456789abcdef" for character in candidate)
        or isinstance(evidence.get("backup_bytes"), bool)
        or not isinstance(evidence.get("backup_bytes"), int)
        or evidence["backup_bytes"] <= 0
        or activation["activation_sha256"] != evidence["activation_sha256"]
        or activation["candidate_commit"] != evidence["candidate_commit"]
        or activation["data_mode"] != evidence["data_mode"]
        or activation["transfer_plan"]["plan_sha256"] != evidence["plan_sha256"]
        or activation["transfer_plan"]["backup_sha256"] != evidence["backup_sha256"]
        or activation["transfer_plan"]["backup_bytes"] != evidence["backup_bytes"]
        or secret_findings(evidence)
    ):
        raise BackupActivationError("Stored synthetic activation evidence is invalid")
    return evidence


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
    _verify_synthetic_source_database(Path(str(manifest["path"])))
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
