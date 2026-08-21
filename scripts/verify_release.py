#!/usr/bin/env python3
"""Fail-closed release verification for the independently owned IAC runtime."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGE_SCHEMA_SHA256 = "70f271353b4e6696ada8816f6bad821cfabaec4e87aa96edaae97a14ac7f41d8"


def run(
    label: str, command: list[str], *, environment: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(command, cwd=ROOT, check=False, env=environment)
    if completed.returncode:
        raise SystemExit(f"{label} failed with exit code {completed.returncode}")
    return {"check": label, "passed": True}


def main() -> int:
    checks: list[dict[str, object]] = []
    schema = ROOT / "bridge-contract.schema.json"
    digest = hashlib.sha256(schema.read_bytes()).hexdigest()
    if digest != BRIDGE_SCHEMA_SHA256:
        raise SystemExit("bridge contract changed without an explicit version/hash update")
    checks.append({"check": "bridge_contract_sha256", "passed": True, "sha256": digest})
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    required_container_invariants = (
        "SEAN_OS_DATABASE=/data/sean-os.db",
        "mkdir -p /data",
        "chown sean-os:sean-os /data",
        'CMD ["python", "scripts/container_entrypoint.py"]',
    )
    if any(invariant not in dockerfile for invariant in required_container_invariants):
        raise SystemExit("container must run non-root with a writable /data mount point")
    if 'VOLUME ["/data"]' in dockerfile:
        raise SystemExit("Railway volumes must be attached by the platform, not declared in Dockerfile")
    entrypoint = (ROOT / "scripts" / "container_entrypoint.py").read_text(encoding="utf-8")
    required_privilege_drop = (
        "sys.path.insert(0, str(APP_ROOT))",
        "os.chown(database.parent, WORKER_UID, WORKER_GID)",
        "os.setgroups([])",
        "os.setgid(WORKER_GID)",
        "os.setuid(WORKER_UID)",
        '"scripts/worker.py"',
    )
    if any(invariant not in entrypoint for invariant in required_privilege_drop):
        raise SystemExit("container entrypoint must prepare /data and drop privileges before worker startup")
    checks.append({"check": "container_safety_invariants", "passed": True})
    migration_guard = (ROOT / "sean_os" / "migration_guard.py").read_text(encoding="utf-8")
    required_migration_invariants = (
        "ensure_pre_migration_backup",
        "restore_pre_migration_backup",
        "worker start denied",
        "SAME_RAILWAY_VOLUME",
    )
    if any(invariant not in migration_guard for invariant in required_migration_invariants):
        raise SystemExit("schema migration must retain its fail-closed backup and restore guard")
    recovery_hold = (ROOT / "scripts" / "recovery_hold.py").read_text(encoding="utf-8")
    if "MIGRATION_RECOVERY_HOLD" not in recovery_hold or any(
        forbidden in recovery_hold for forbidden in ("sqlite3", "SeanOSStore", "worker.py")
    ):
        raise SystemExit("migration recovery hold must not open the database or start the worker")
    checks.append({"check": "migration_backup_and_recovery_hold", "passed": True})
    store_source = (ROOT / "sean_os" / "store.py").read_text(encoding="utf-8")
    security_source = (ROOT / "sean_os" / "security.py").read_text(encoding="utf-8")
    worker_source = (ROOT / "scripts" / "worker.py").read_text(encoding="utf-8")
    interface_source = (ROOT / "scripts" / "interface.py").read_text(encoding="utf-8")
    required_secret_boundaries = (
        "Secret-like material is prohibited in durable work payloads",
        "Secret-like material is prohibited in durable action results",
        "Secret-like material is prohibited in completed work",
        "Sensitive audit detail redacted",
    )
    if any(invariant not in store_source for invariant in required_secret_boundaries):
        raise SystemExit("durable queue, result, and audit boundaries must reject secrets")
    if "safe_exception_summary" not in security_source or "safe_exception_summary" not in worker_source:
        raise SystemExit("worker failures must not persist raw exception messages")
    if "safe_persisted_text" not in interface_source or "urlparse(self.path).path" not in interface_source:
        raise SystemExit("interface errors and authentication audit must not reflect secret input")
    checks.append({"check": "durable_secret_boundaries", "passed": True})
    backup_approval_source = (ROOT / "sean_os" / "backup_approval.py").read_text(
        encoding="utf-8"
    )
    required_backup_approval_invariants = (
        "RUN_INDEPENDENT_BACKUP_RESTORE_DRILL",
        '"approval_required": True',
        '"execution_authorized": False',
        '"owner_scope"] != "IAC"',
        '"destination_provider"] not in DESTINATION_PROVIDERS',
        '"data_region"] not in DATA_REGIONS',
        '"overwrite_production", "live_connectors_enabled", "real_data_authorized"',
    )
    if any(
        invariant not in backup_approval_source
        for invariant in required_backup_approval_invariants
    ):
        raise SystemExit("independent backup drill must remain exact, IAC-only, and non-executing")
    checks.append({"check": "independent_backup_approval_contract", "passed": True})
    backup_adapter_source = (ROOT / "sean_os" / "backup_adapter.py").read_text(
        encoding="utf-8"
    )
    required_backup_adapter_invariants = (
        "S3_COMPATIBLE_OBJECT_STORAGE_V1",
        '"retention_mode": "COMPLIANCE"',
        '"credentials_included": False',
        '"network_enabled": False',
        '"execution_authorized": False',
        '"adapter": "SYNTHETIC_NO_NETWORK"',
        '"uploaded": False',
        "sean-os-independent-backup-transfer-plan/v3",
        '"provider_endpoint": verify_backblaze_endpoint',
        '"provider_writer_identity_ref": _safe_provider_ref',
        '"window_start": proposal["window_start"]',
        '"max_cost_cad": proposal["max_cost_cad"]',
        "sean-os-independent-backup-upload-receipt/v3",
        '"evidence_mode": "PRODUCTION"',
        '"provider": "BACKBLAZE_B2"',
        '"provider_region": plan_value["data_region"]',
        '"object_lock_verified": True',
        '"credentials_persisted": False',
    )
    forbidden_backup_networking = (
        "import boto", "import requests", "import socket", "import urllib",
        "http.client", "subprocess", "urlopen(",
    )
    if any(
        invariant not in backup_adapter_source
        for invariant in required_backup_adapter_invariants
    ) or any(forbidden in backup_adapter_source for forbidden in forbidden_backup_networking):
        raise SystemExit("backup adapter contract must remain path-free, default-off, and no-network")
    checks.append({"check": "independent_backup_adapter_no_network", "passed": True})
    backup_execution_source = (ROOT / "sean_os" / "backup_execution.py").read_text(
        encoding="utf-8"
    )
    required_backup_execution_invariants = (
        '"SEAN_OS_BACKUP_EXECUTION"',
        '"SEAN_OS_BACKUP_MAX_COST_CAD"',
        "Raw backup secrets are prohibited in runtime configuration",
        "Backup execution is outside the exact approved window",
        'guard("BEFORE_ENCRYPTION")',
        'guard("BEFORE_UPLOAD")',
        'guard("AFTER_UPLOAD")',
        "class BackupExecutionReconciliationRequired",
        "Verified provider write requires manual reconciliation",
        "verify_backblaze_endpoint",
        '"overwrite_performed": False',
        '"credentials_persisted": False',
    )
    if any(
        invariant not in backup_execution_source
        for invariant in required_backup_execution_invariants
    ) or any(forbidden in backup_execution_source for forbidden in forbidden_backup_networking):
        raise SystemExit(
            "backup execution boundary must remain default-off, bounded, and port-injected"
        )
    checks.append({"check": "default_off_backup_execution_boundary", "passed": True})
    backup_credential_source = (ROOT / "sean_os" / "backup_credentials.py").read_text(
        encoding="utf-8"
    )
    required_backup_credential_invariants = (
        "sean-os-backblaze-writer-key-proposal/v1",
        '"creation_authorized": False',
        '"account_admin_authorized": False',
        '"production_data_authorized": False',
        '"file_name_prefix": "backups/"',
        '"writeFiles"',
        '"readFileRetentions"',
        '"writeKeys", "deleteKeys"',
        '"readFiles", "deleteFiles"',
        '"writeBucketRetentions"',
        '"bypassGovernance"',
        "14400",
    )
    if any(
        invariant not in backup_credential_source
        for invariant in required_backup_credential_invariants
    ) or any(forbidden in backup_credential_source for forbidden in forbidden_backup_networking):
        raise SystemExit(
            "backup credential contract must remain bucket-scoped, short-lived, and non-creating"
        )
    checks.append({"check": "least_privilege_backup_writer_key_contract", "passed": True})
    backup_encryption_source = (ROOT / "sean_os" / "backup_encryption.py").read_text(
        encoding="utf-8"
    )
    required_backup_encryption_invariants = (
        "sean-os-client-encrypted-backup-envelope/v1",
        'ALGORITHM = "AES_256_GCM"',
        "algorithms.AES256(key_material)",
        "modes.GCM(nonce)",
        "encryptor.authenticate_additional_data(prefix)",
        "decryptor.authenticate_additional_data(prefix)",
        "os.urandom(NONCE_BYTES)",
        "os.O_EXCL",
        "os.fchmod(descriptor, 0o600)",
        "_wipe_key(resolved)",
        "except InvalidTag",
        "os.link(partial, destination)",
        '"credentials_persisted": False',
        '"source_path_included": False',
    )
    forbidden_encryption_sources = (
        "os.environ", "getenv(", "import boto", "import requests", "import socket",
        "import urllib", "http.client", "subprocess", "urlopen(",
    )
    if any(
        invariant not in backup_encryption_source
        for invariant in required_backup_encryption_invariants
    ) or any(
        forbidden in backup_encryption_source for forbidden in forbidden_encryption_sources
    ):
        raise SystemExit(
            "backup encryption must remain streaming, authenticated, private, and resolver-injected"
        )
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if 'cryptography==50.0.0' not in project or "pip install --no-cache-dir ." not in dockerfile:
        raise SystemExit("reviewed backup cryptography dependency must be exact and containerized")
    checks.append({"check": "streaming_authenticated_backup_encryption", "passed": True})
    backup_provider_source = (ROOT / "sean_os" / "backup_provider.py").read_text(
        encoding="utf-8"
    )
    required_backup_provider_invariants = (
        "class S3CompatibleBackupClient(Protocol)",
        "class BackupReconciliationRequired",
        "retry_permitted = False",
        'IfNoneMatch="*"',
        'ServerSideEncryption="AES256"',
        'ContentType="application/octet-stream"',
        "get_bucket_encryption",
        "get_object_lock_configuration",
        "get_object_retention",
        'default.get("Mode") != "COMPLIANCE"',
        'retention_value.get("Mode") != "COMPLIANCE"',
        '"overwrite_performed": False',
        '"credentials_persisted": False',
        "automatic retry is prohibited",
        "verify_backblaze_bucket_name",
        "does not match the approved destination reference",
    )
    forbidden_provider_construction = (
        "import boto", "import requests", "import socket", "import urllib",
        "http.client", "subprocess", "urlopen(", "os.environ", "getenv(",
    )
    if any(
        invariant not in backup_provider_source
        for invariant in required_backup_provider_invariants
    ) or any(
        forbidden in backup_provider_source for forbidden in forbidden_provider_construction
    ):
        raise SystemExit(
            "backup provider port must remain injected, conditional, verified, and non-retrying"
        )
    checks.append({"check": "disconnected_backblaze_upload_port", "passed": True})
    backup_secret_source = (ROOT / "sean_os" / "backup_secrets.py").read_text(
        encoding="utf-8"
    )
    required_backup_secret_invariants = (
        'B2_KEY_ID_VARIABLE = "SEAN_OS_MANAGED_B2_KEY_ID"',
        'B2_APPLICATION_KEY_VARIABLE = "SEAN_OS_MANAGED_B2_APPLICATION_KEY"',
        'ENCRYPTION_KEY_VARIABLE = "SEAN_OS_MANAGED_BACKUP_AES256_KEY_B64"',
        "base64.b64decode(encoded, validate=True)",
        "for index in range(len(material))",
        'endpoint_url=f"https://{config.endpoint}"',
        'region_name=endpoint_match.group("region")',
        'retries={"mode": "standard", "total_max_attempts": 1}',
        '"addressing_style": "path", "payload_signing_enabled": True',
        "ignore_configured_endpoint_urls=True",
        "aws_access_key_id=key_id",
        "aws_secret_access_key=application_key",
    )
    if any(
        invariant not in backup_secret_source
        for invariant in required_backup_secret_invariants
    ):
        raise SystemExit(
            "backup secret/client factory must remain exact, no-retry, and non-persisting"
        )
    if 'boto3==1.43.76' not in project:
        raise SystemExit("reviewed Backblaze SDK dependency must remain exact")
    checks.append({"check": "managed_backup_secret_and_client_boundary", "passed": True})
    backup_pilot_source = (ROOT / "sean_os" / "backup_pilot.py").read_text(
        encoding="utf-8"
    )
    required_backup_pilot_invariants = (
        "sean-os-supervised-synthetic-backup-pilot/v1",
        '"data_mode": "SYNTHETIC_IAC_DATABASE_ONLY"',
        '"aa5875de-3c73-44df-a7d8-00b5911d64d2"',
        '"8bb602a7-8e67-4a34-8f57-def32780aeb9"',
        '"f836e6ff-56ba-4b69-8dab-6c2e91478853"',
        '"iac-sean-os-ca-east-20260820-v01-9k4m"',
        '"s3.ca-east-006.backblazeb2.com"',
        '"real_data_authorized": False',
        '"key_creation_authorized": False',
        '"secret_placement_authorized": False',
        '"push_authorized": False',
        '"deployment_authorized": False',
        '"upload_authorized": False',
        '"restore_authorized": False',
        '"network_enabled": False',
        '"execution_authorized": False',
    )
    if any(
        invariant not in backup_pilot_source
        for invariant in required_backup_pilot_invariants
    ):
        raise SystemExit(
            "supervised pilot package must bind exact resources and authorize nothing"
        )
    checks.append({"check": "non_executing_supervised_backup_pilot_package", "passed": True})
    backup_activation_source = (ROOT / "sean_os" / "backup_activation.py").read_text(
        encoding="utf-8"
    )
    backup_activation_cli = (
        ROOT / "scripts" / "prepare_supervised_backup_activation.py"
    ).read_text(encoding="utf-8")
    required_backup_activation_invariants = (
        "sean-os-supervised-synthetic-backup-activation/v1",
        '"data_mode":"SYNTHETIC_IAC_DATABASE_ONLY"',
        "Synthetic backup drill sentinel",
        "Synthetic backup source must contain exactly one sentinel record",
        "Synthetic backup source contains non-sentinel operational state",
        "_SYNTHETIC_EMPTY_TABLES",
        "build_supervised_backup_pilot_package",
        "build_backup_transfer_plan",
        "synthetic_backup_adapter_receipt",
        "stage_backup_transfer",
        "record_backup_transfer_preflight",
        "record_supervised_synthetic_backup_activation",
        "get_supervised_synthetic_backup_activation_evidence",
        '"activation_payload":_canonical(verified)',
        "write_private_json",
        "os.O_EXCL",
        "SEAN_OS_BACKUP_MANIFEST_PATH",
        "SEAN_OS_BACKUP_OUTPUT_DIRECTORY",
        '"network_performed":False',
        '"key_created":False',
        '"secret_placed":False',
        '"upload_authorized":False',
        '"restore_authorized":False',
        '"real_data_authorized":False',
    )
    if any(
        item not in backup_activation_source for item in required_backup_activation_invariants
    ) or any(
        forbidden in backup_activation_source for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "synthetic backup activation must remain private, no-network, and unauthorized"
        )
    if '"backup_manifest"' in backup_activation_cli or '"non_secret_runtime"' in backup_activation_cli:
        raise SystemExit("backup activation CLI must print only its bounded summary")
    checks.append({"check": "synthetic_backup_activation_staging", "passed": True})
    backup_operator_source = (ROOT / "sean_os" / "backup_operator.py").read_text(
        encoding="utf-8"
    )
    backup_operator_cli = (ROOT / "scripts" / "backup_operator.py").read_text(
        encoding="utf-8"
    )
    required_backup_operator_invariants = (
        "sean-os-backup-operator-review/v1",
        "review_sha256",
        "Operator review is stale; review the transfer again",
        "Only a validated synthetic preflight may request approval",
        "get_supervised_synthetic_backup_activation_evidence",
        "BACKUP_ACTIVATION_ENV_KEYS",
        "State authorization requires all backup execution and secret values absent",
        "State authorization is outside the exact execution window",
        '"network_performed": False',
        '"upload_performed": False',
        '"transfer_claimed": False',
        "CommandGateway(store, actor).authorize_backup",
    )
    required_backup_operator_cli_invariants = (
        'Actor("iac-backup-interface", frozenset({"IAC"}))',
        "Actor.sean()",
        '"backup_operator_request_rejected"',
        '"--expected-review-sha256"',
        '"--confirm-plan-sha256"',
    )
    if any(
        item not in backup_operator_source for item in required_backup_operator_invariants
    ) or any(
        item not in backup_operator_cli for item in required_backup_operator_cli_invariants
    ) or any(
        forbidden in backup_operator_source + backup_operator_cli
        for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "backup operator must remain hash-bound, state-only, and no-network"
        )
    checks.append({"check": "hash_bound_state_only_backup_operator", "passed": True})
    schema_source = (ROOT / "sean_os" / "schema.sql").read_text(encoding="utf-8")
    required_backup_outbox_invariants = (
        "CREATE TABLE IF NOT EXISTS backup_transfer_outbox",
        "'RECONCILIATION_REQUIRED'",
        "approval_id TEXT REFERENCES approvals(record_id)",
        "idx_backup_transfer_outbox_claim",
        "lease_expires_at TEXT",
        "preflight_receipt_payload TEXT",
        "CREATE TABLE IF NOT EXISTS backup_activation_evidence",
        "data_mode TEXT NOT NULL CHECK (data_mode = 'SYNTHETIC_IAC_DATABASE_ONLY')",
        "real_data_authorized INTEGER NOT NULL CHECK (real_data_authorized = 0)",
        "activation_payload TEXT NOT NULL",
    )
    required_backup_authorization_invariants = (
        "record_backup_transfer_preflight",
        "request_backup_transfer_approval",
        "authorize_backup_transfer",
        "Approval conditions do not match the exact action plan",
        'action_type="RUN_INDEPENDENT_BACKUP_RESTORE_DRILL"',
        'conditions=conditions',
        '"data_region":plan["data_region"]',
        '"network_performed":False',
        '"upload_performed":False',
        "claim_authorized_backup_transfer",
        "assert_backup_transfer_execution_allowed",
        '"provider_endpoint":plan["provider_endpoint"]',
        '"max_cost_cad":plan["max_cost_cad"]',
        "fail_claimed_backup_transfer",
        "hold_claimed_backup_transfer_for_reconciliation",
        '"automatic_retry_permitted":False',
        "Backup transfer lease must be between 1 and 900 seconds",
        'backup_counts.get("FAILED", 0) == 0',
        "complete_claimed_backup_transfer",
        "verify_backup_upload_receipt",
        "Encrypted retention-locked provider receipt verified",
    )
    if any(item not in schema_source for item in required_backup_outbox_invariants) or any(
        item not in store_source for item in required_backup_authorization_invariants
    ):
        raise SystemExit("backup transfer authorization must remain durable and exact-plan bound")
    checks.append({"check": "durable_backup_transfer_authorization", "passed": True})
    required_backup_worker_invariants = (
        "process_backup_transfer_once",
        "validate_claimed_backup_transfer",
        "verify_backblaze_bucket_name",
        "_load_private_backup_manifest",
        "_private_output_directory",
        "hold_claimed_backup_transfer_for_reconciliation",
        '"Provider write result is ambiguous; automatic retry prohibited"',
        "client_factory(environment, config)",
    )
    if any(item not in worker_source for item in required_backup_worker_invariants):
        raise SystemExit("backup worker must remain exact, default-off, and reconciliation-safe")
    if worker_source.index("validate_claimed_backup_transfer(") > worker_source.index(
        "client_factory(environment, config)"
    ):
        raise SystemExit("backup worker must validate the exact plan before resolving its client")
    required_entrypoint_backup_invariants = (
        "load_backup_runtime_config(environment)",
        '"SEAN_OS_BACKUP_BUCKET"',
        '"SEAN_OS_BACKUP_MANIFEST_PATH"',
        '"SEAN_OS_BACKUP_OUTPUT_DIRECTORY"',
        "_backup_volume_path",
        "inside the database volume",
        '"--backup-execution"',
        "Disabled backup execution cannot retain worker configuration",
    )
    if any(item not in entrypoint for item in required_entrypoint_backup_invariants):
        raise SystemExit("container backup activation must require one complete default-off contract")
    if "Backup destination must not already exist" not in store_source or "os.O_EXCL" not in store_source:
        raise SystemExit("local backup sources must be private and non-overwriting")
    checks.append({"check": "default_off_reconciliation_safe_backup_worker", "passed": True})
    restore_contract_source = (ROOT / "sean_os" / "backup_restore.py").read_text(
        encoding="utf-8"
    )
    required_restore_contract_invariants = (
        "sean-os-backblaze-restore-key-proposal/v1",
        "sean-os-independent-backup-restore-plan/v1",
        "sean-os-isolated-backup-restore-receipt/v1",
        '"readFiles"',
        '"writeFiles", "deleteFiles"',
        '"write_authorized": False',
        '"creation_authorized": False',
        '"network_enabled": False',
        '"download_authorized": False',
        '"decrypt_authorized": False',
        '"restore_authorized": False',
        '"overwrite_permitted": False',
        "Restore identity must be distinct from the writer identity",
        "verify_backup_upload_receipt",
        "object_lock_verified",
        "database_integrity_ok",
        '"scope_profile": "IAC"',
    )
    if any(
        item not in restore_contract_source for item in required_restore_contract_invariants
    ) or any(
        forbidden in restore_contract_source for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "isolated restore contract must remain read-only, exact-evidence-bound, and non-executing"
        )
    checks.append({"check": "least_privilege_isolated_restore_contract", "passed": True})
    restore_execution_source = (
        ROOT / "sean_os" / "backup_restore_execution.py"
    ).read_text(encoding="utf-8")
    required_restore_execution_invariants = (
        '"SEAN_OS_BACKUP_RESTORE_EXECUTION"',
        "Raw restore secrets are prohibited in runtime configuration",
        "Disabled backup restore cannot retain partial configuration",
        "Backup restore requires an active approved lease",
        'guard("BEFORE_DOWNLOAD")',
        'guard("AFTER_DOWNLOAD")',
        'guard("AFTER_DECRYPTION")',
        "class BackupRestoreExecutionReconciliationRequired",
        "Published isolated restore requires manual reconciliation",
        "PRAGMA integrity_check",
        "PRAGMA foreign_key_check",
        'scope_profile != "IAC"',
        "Restore destination must be new and non-overwriting",
    )
    if any(
        item not in restore_execution_source
        for item in required_restore_execution_invariants
    ) or any(
        forbidden in restore_execution_source for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "restore execution boundary must remain default-off, injected, isolated, and fail-closed"
        )
    checks.append({"check": "default_off_isolated_restore_execution", "passed": True})
    restore_provider_source = (
        ROOT / "sean_os" / "backup_restore_provider.py"
    ).read_text(encoding="utf-8")
    required_restore_provider_invariants = (
        "class S3CompatibleRestoreClient(Protocol)",
        "def get_object_retention",
        "def get_object",
        "VersionId=value[\"provider_version_ref\"]",
        'retention_value.get("Mode") != "COMPLIANCE"',
        'response.get("ServerSideEncryption") != "AES256"',
        'os.O_EXCL',
        'os.fchmod(descriptor, 0o600)',
        "Backblaze encrypted object hash does not match upload evidence",
        '"overwrite_performed":False',
        '"credentials_persisted":False',
    )
    forbidden_restore_provider = forbidden_provider_construction + (
        "put_object", "delete_object", "list_objects", "list_object_versions",
    )
    if any(
        item not in restore_provider_source for item in required_restore_provider_invariants
    ) or any(
        forbidden in restore_provider_source for forbidden in forbidden_restore_provider
    ):
        raise SystemExit(
            "restore provider port must remain exact-version, read-only, private, and injected"
        )
    checks.append({"check": "read_only_exact_version_restore_port", "passed": True})
    restore_secret_source = (
        ROOT / "sean_os" / "backup_restore_secrets.py"
    ).read_text(encoding="utf-8")
    required_restore_secret_invariants = (
        'RESTORE_KEY_ID_VARIABLE = "SEAN_OS_MANAGED_B2_RESTORE_KEY_ID"',
        'RESTORE_APPLICATION_KEY_VARIABLE = "SEAN_OS_MANAGED_B2_RESTORE_APPLICATION_KEY"',
        'retries={"mode":"standard", "total_max_attempts":1}',
        's3={"addressing_style":"path", "payload_signing_enabled":True}',
        "ignore_configured_endpoint_urls=True",
        "aws_access_key_id=key_id",
        "aws_secret_access_key=application_key",
    )
    if any(
        item not in restore_secret_source for item in required_restore_secret_invariants
    ):
        raise SystemExit(
            "restore secret factory must remain distinct, Canada-bound, signed, and non-retrying"
        )
    restore_worker_source = (ROOT / "scripts" / "restore_worker.py").read_text(
        encoding="utf-8"
    )
    required_restore_worker_invariants = (
        "process_backup_restore_once",
        "claim_authorized_backup_restore",
        "client_factory(environment, config)",
        "assert_backup_restore_execution_allowed",
        "hold_claimed_backup_restore_for_reconciliation",
        "Published isolated restore requires manual reconciliation",
        "Restore destination must be new inside the isolated directory",
    )
    if any(
        item not in restore_worker_source for item in required_restore_worker_invariants
    ):
        raise SystemExit("one-shot restore worker must remain isolated and reconciliation-safe")
    if restore_worker_source.index("claim_authorized_backup_restore(") > restore_worker_source.index(
        "client_factory(environment, config)"
    ):
        raise SystemExit("restore worker must claim exact authorization before resolving secrets")
    if "restore_worker.py" in entrypoint or "backup_restore" in worker_source:
        raise SystemExit("isolated restore worker must never run through the continuous container worker")
    checks.append({"check": "separate_one_shot_restore_worker", "passed": True})
    required_restore_outbox_invariants = (
        "CREATE TABLE IF NOT EXISTS backup_restore_outbox",
        "'STAGED','PREFLIGHT_VALIDATED','AUTHORIZED','RESTORED','FAILED'",
        "'RECONCILIATION_REQUIRED'",
        "restore_key_proposal_sha256 TEXT NOT NULL",
        "approval_id TEXT REFERENCES approvals(record_id)",
        "idx_backup_restore_outbox_claim",
    )
    required_restore_authorization_invariants = (
        "stage_backup_restore",
        "record_backup_restore_preflight",
        "request_backup_restore_approval",
        "authorize_backup_restore",
        'action_type="RUN_ISOLATED_BACKUP_RESTORE"',
        "claim_authorized_backup_restore",
        "assert_backup_restore_execution_allowed",
        "fail_claimed_backup_restore",
        "hold_claimed_backup_restore_for_reconciliation",
        '"automatic_retry_permitted":False',
        "Backup restore lease must be between 1 and 900 seconds",
        "complete_claimed_backup_restore",
        "verify_isolated_backup_restore_receipt",
        'restore_counts.get("FAILED", 0) == 0',
    )
    if any(
        item not in schema_source for item in required_restore_outbox_invariants
    ) or any(
        item not in store_source for item in required_restore_authorization_invariants
    ):
        raise SystemExit(
            "isolated restore authorization must remain durable, exact, leased, and health-visible"
        )
    checks.append({"check": "durable_isolated_restore_authorization", "passed": True})
    restore_operator_source = (
        ROOT / "sean_os" / "backup_restore_operator.py"
    ).read_text(encoding="utf-8")
    restore_operator_cli = (ROOT / "scripts" / "restore_operator.py").read_text(
        encoding="utf-8"
    )
    required_restore_operator_invariants = (
        "sean-os-backup-restore-operator-review/v1",
        "Operator review is stale; review the restore again",
        "Only a validated no-action restore preflight may request approval",
        "State authorization requires all restore execution and secret values absent",
        "Restore state authorization is outside the exact execution window",
        '"network_performed": False',
        '"downloaded": False',
        '"decrypted": False',
        '"restored": False',
        '"restore_claimed": False',
        "store.authorize_backup_restore",
    )
    required_restore_operator_cli_invariants = (
        'Actor("iac-restore-interface", frozenset({"IAC"}))',
        "Actor.sean()",
        '"restore_operator_request_rejected"',
        '"--expected-review-sha256"',
        '"--confirm-plan-sha256"',
    )
    if any(
        item not in restore_operator_source for item in required_restore_operator_invariants
    ) or any(
        item not in restore_operator_cli for item in required_restore_operator_cli_invariants
    ) or any(
        forbidden in restore_operator_source + restore_operator_cli
        for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "restore operator must remain hash-bound, state-only, bounded, and no-network"
        )
    checks.append({"check": "hash_bound_state_only_restore_operator", "passed": True})
    chief_source = (ROOT / "sean_os" / "chief_of_staff.py").read_text(
        encoding="utf-8"
    )
    scheduler_source = (ROOT / "sean_os" / "scheduler.py").read_text(
        encoding="utf-8"
    )
    reporting_source = (ROOT / "sean_os" / "reporting.py").read_text(
        encoding="utf-8"
    )
    required_continuous_portfolio_invariants = (
        "def maintain_portfolio(",
        "AND ps.state IN ('ACTIVE','INCUBATOR')",
        "Portfolio maintenance exceeds the bounded project limit",
        '"missing_metrics_project_ids":missing',
        '"autonomously_paused":review["autonomously_paused"]',
        '"external_effect":False',
        '"approval_consumed":False',
        '"CHIEF_MAINTAIN_PORTFOLIO"',
    )
    required_scheduler_invariants = (
        '"daily-portfolio-maintenance"',
        '"CHIEF_MAINTAIN_PORTFOLIO", {"period_key":day}, 40',
        '"GENERATE_OPERATIONAL_REPORT", {"cadence":"DAILY", "period_key":day}, 50',
        '"weekly-operational-report"',
        '"priority":priority',
    )
    required_report_invariants = (
        "AND status IN ('PENDING','APPROVED')",
        "AND expires_at>?",
        '"portfolio_score":score',
        '"approval_outcomes":approval_outcomes',
        '"overnight_work":completed_work',
        '"project_changes":project_changes',
        '"deadlines_at_risk":deadlines',
        '"invalid_deadline_task_ids":sorted(set(invalid_deadline_task_ids))',
        '"Completed durable work since prior report"',
        '"Promises or deadlines at risk"',
        '"delivery": "LOCAL_ONLY"',
    )
    continuous_sources = chief_source + scheduler_source + reporting_source
    if any(
        item not in chief_source for item in required_continuous_portfolio_invariants
    ) or any(
        item not in scheduler_source for item in required_scheduler_invariants
    ) or any(
        item not in reporting_source for item in required_report_invariants
    ) or any(
        forbidden in continuous_sources for forbidden in forbidden_backup_networking
    ):
        raise SystemExit(
            "continuous portfolio maintenance and reporting must remain bounded, internal, and no-network"
        )
    if scheduler_source.index('"CHIEF_MAINTAIN_PORTFOLIO"') > scheduler_source.index(
        '"GENERATE_OPERATIONAL_REPORT"'
    ) or "scheduler.tick()" not in worker_source:
        raise SystemExit("portfolio maintenance must run before reports in the always-on worker")
    checks.append({"check": "continuous_internal_portfolio_maintenance", "passed": True})
    command_source = (ROOT / "sean_os" / "commands.py").read_text(encoding="utf-8")
    required_backup_interface_invariants = (
        "backup-transfers",
        "request_backup_approval",
        "decide_backup_approval",
        "authorize_backup",
        "operator_authorization_required",
    )
    if any(
        item not in command_source + interface_source
        for item in required_backup_interface_invariants
    ):
        raise SystemExit("backup review and authorization must use the separated interface identities")
    checks.append({"check": "backup_operator_interface_boundary", "passed": True})
    workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    if "contents: read" not in workflow or "docker build" not in workflow:
        raise SystemExit("continuous verification must be read-only and build the container")
    if "docker push" in workflow or "railway up" in workflow:
        raise SystemExit("verification workflow must not publish or deploy")
    checks.append({"check": "workflow_permissions_and_no_deploy", "passed": True})
    with tempfile.TemporaryDirectory(prefix="sean-os-release-") as cache_dir:
        environment=dict(os.environ)
        environment["PYTHONPYCACHEPREFIX"]=str(Path(cache_dir) / "pycache")
        checks.append(run(
            "compile", [sys.executable, "-m", "compileall", "-q", "sean_os", "tests"],
            environment=environment,
        ))
        checks.append(run(
            "tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            environment=environment,
        ))
        checks.append(run(
            "recovery_drill", [sys.executable, "scripts/recovery_drill.py"],
            environment=environment,
        ))
    print(json.dumps({"passed": True, "checks": checks}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
