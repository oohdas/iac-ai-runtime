"""Local continuous-worker prototype. Use --once in tests/demos; production needs a supervised cloud process."""
from pathlib import Path
import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import (
    Actor, AES256GCMFileEncryptor, BackblazeS3UploadPort,
    BackupExecutionReconciliationRequired, BackupReconciliationRequired,
    EscalationRoute, LocalScheduler, PolicyDenied,
    RuntimeMonitor, SeanOSStore, build_backblaze_s3_client,
    chief_of_staff_registry, execute_claimed_backup_transfer,
    load_backup_runtime_config, synthetic_delivery_receipt,
    validate_claimed_backup_transfer,
    verify_backblaze_bucket_name,
)
from sean_os.backup_secrets import ManagedEnvironmentEncryptionKeyResolver
from sean_os.security import safe_exception_summary


STOP = False


def stop(*_args):
    global STOP
    STOP = True


def process_synthetic_delivery_once(
    store: SeanOSStore, actor: Actor, worker_id: str
):
    delivery=store.claim_authorized_alert_delivery(actor, worker_id, lease_seconds=30)
    if delivery is None:
        return None
    try:
        receipt=synthetic_delivery_receipt(
            delivery, delivered_at=datetime.now(timezone.utc).isoformat()
        )
        return store.complete_claimed_synthetic_alert_delivery(
            actor, delivery["delivery_id"], worker_id, receipt
        )
    except Exception as exc:
        safe_error=f"{type(exc).__name__}: synthetic no-network adapter failed"
        store.fail_claimed_alert_delivery(
            actor, delivery["delivery_id"], worker_id, safe_error
        )
        return {"delivery_id":delivery["delivery_id"], "status":"RETRY_SCHEDULED"}


def _load_private_backup_manifest(manifest_path: Path, data_root: Path):
    manifest_path=Path(manifest_path)
    if manifest_path.is_symlink():
        raise ValueError("Backup manifest must be a regular file inside the data directory")
    manifest_path=manifest_path.resolve()
    data_root=data_root.resolve()
    if data_root not in manifest_path.parents or manifest_path.is_symlink():
        raise ValueError("Backup manifest must be a regular file inside the data directory")
    if not manifest_path.is_file() or manifest_path.stat().st_mode & 0o077:
        raise ValueError("Backup manifest must exist with private permissions")
    try:
        manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Backup manifest is unreadable or malformed") from exc
    if not isinstance(manifest, dict):
        raise ValueError("Backup manifest is unreadable or malformed")
    source_path=Path(str(manifest.get("path", "")))
    if source_path.is_symlink():
        raise ValueError("Backup source must be a regular file inside the data directory")
    source_path=source_path.resolve()
    if data_root not in source_path.parents:
        raise ValueError("Backup source must be a regular file inside the data directory")
    if not source_path.is_file() or source_path.stat().st_mode & 0o077:
        raise ValueError("Backup source must exist with private permissions")
    return manifest


def _private_output_directory(path: Path, data_root: Path) -> Path:
    path=Path(path)
    if path.is_symlink():
        raise ValueError("Backup output must be a directory inside the data directory")
    path=path.resolve()
    data_root=data_root.resolve()
    if data_root not in path.parents:
        raise ValueError("Backup output must be a directory inside the data directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.stat().st_mode & 0o077:
        raise ValueError("Backup output directory must have private permissions")
    return path


def process_backup_transfer_once(
    store: SeanOSStore, actor: Actor, worker_id: str, *, environment,
    bucket_name: str, manifest_path: Path, output_directory: Path,
    data_root: Path | None = None, client_factory=build_backblaze_s3_client,
    resolver_factory=ManagedEnvironmentEncryptionKeyResolver,
    encryptor_factory=AES256GCMFileEncryptor,
    uploader_factory=BackblazeS3UploadPort,
):
    """Run at most one exact authorized transfer; ambiguous writes never retry."""
    config=load_backup_runtime_config(environment)
    if not config.enabled:
        raise ValueError("Backup worker execution is disabled")
    bucket_name=verify_backblaze_bucket_name(bucket_name)
    if config.destination_ref != f"backblaze-b2-bucket:{bucket_name}":
        raise ValueError("Backup bucket does not match the approved destination reference")
    root=(data_root or manifest_path.parent).resolve()
    manifest=_load_private_backup_manifest(manifest_path, root)
    claimed=store.claim_authorized_backup_transfer(actor, worker_id, lease_seconds=300)
    if claimed is None:
        return None
    plan_sha256=claimed["plan_sha256"]
    upload_receipt_ready=False
    try:
        validate_claimed_backup_transfer(
            claimed, manifest, worker_id=worker_id, config=config
        )
        output=_private_output_directory(output_directory, root)
        resolver=resolver_factory(environment, key_ref=str(config.encryption_key_ref))
        encryptor=encryptor_factory(output, resolver)
        client=client_factory(environment, config)
        uploader=uploader_factory(
            client, bucket_name=bucket_name,
            destination_ref=str(config.destination_ref), endpoint=str(config.endpoint),
            writer_identity_ref=str(config.writer_identity_ref),
        )
        receipt=execute_claimed_backup_transfer(
            claimed, manifest, worker_id=worker_id, config=config,
            encryptor=encryptor, uploader=uploader,
            guard=lambda _stage: store.assert_backup_transfer_execution_allowed(
                actor, plan_sha256, worker_id
            ),
        )
        upload_receipt_ready=True
        return store.complete_claimed_backup_transfer(
            actor, plan_sha256, worker_id, receipt
        )
    except (BackupReconciliationRequired, BackupExecutionReconciliationRequired):
        status=store.hold_claimed_backup_transfer_for_reconciliation(
            actor, plan_sha256, worker_id,
            "Provider write result is ambiguous; automatic retry prohibited",
        )
        return {"plan_sha256":plan_sha256, "status":status}
    except Exception as exc:
        if upload_receipt_ready:
            status=store.hold_claimed_backup_transfer_for_reconciliation(
                actor, plan_sha256, worker_id,
                "Verified provider write requires manual reconciliation; automatic retry prohibited",
            )
            return {"plan_sha256":plan_sha256, "status":status}
        safe_error=safe_exception_summary(exc, context="backup transfer failed")
        status=store.fail_claimed_backup_transfer(
            actor, plan_sha256, worker_id, safe_error
        )
        return {"plan_sha256":plan_sha256, "status":status}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--worker-id", default="local-worker-1")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--monitor-route-id")
    parser.add_argument("--monitor-destination-kind", choices=("EMAIL", "WEBHOOK"))
    parser.add_argument("--monitor-destination-ref")
    parser.add_argument("--monitor-interval-seconds", type=float, default=30.0)
    parser.add_argument("--synthetic-delivery", action="store_true")
    parser.add_argument("--backup-execution", action="store_true")
    parser.add_argument("--backup-bucket")
    parser.add_argument("--backup-manifest", type=Path)
    parser.add_argument("--backup-output-directory", type=Path)
    parser.add_argument("--once", action="store_true")
    args=parser.parse_args()
    route_fields=(args.monitor_route_id, args.monitor_destination_kind,
                  args.monitor_destination_ref)
    if any(route_fields) and not all(route_fields):
        parser.error("integrated monitoring requires the complete route contract")
    backup_fields=(args.backup_bucket, args.backup_manifest, args.backup_output_directory)
    if args.backup_execution != all(backup_fields):
        parser.error("backup execution requires the complete explicit worker contract")
    monitor=None
    if all(route_fields):
        monitor=RuntimeMonitor(
            EscalationRoute(
                args.monitor_route_id, "IAC", args.monitor_destination_kind,
                args.monitor_destination_ref,
            ),
            interval_seconds=args.monitor_interval_seconds,
        )
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    store=SeanOSStore(args.database, scope_profile="IAC")
    actor=Actor(args.worker_id, frozenset({"IAC"}))
    registry=chief_of_staff_registry(store, actor)
    scheduler=LocalScheduler(store, actor)
    store.heartbeat(args.worker_id, "IAC", "STARTING")
    try:
        while not STOP:
            store.heartbeat(args.worker_id, "IAC", "IDLE")
            if monitor is not None:
                snapshot=monitor.tick(store, monotonic_now=time.monotonic())
                if snapshot is not None:
                    print(json.dumps(snapshot, sort_keys=True), flush=True)
            scheduler.tick()
            if args.synthetic_delivery:
                process_synthetic_delivery_once(store, actor, args.worker_id)
            if args.backup_execution:
                process_backup_transfer_once(
                    store, actor, args.worker_id, environment=os.environ,
                    bucket_name=args.backup_bucket,
                    manifest_path=args.backup_manifest,
                    output_directory=args.backup_output_directory,
                    data_root=Path(args.database).resolve().parent,
                )
            work=store.claim_work(actor, args.worker_id, lease_seconds=30)
            if work is None:
                if args.once: break
                time.sleep(args.poll_seconds); continue
            try:
                store.heartbeat(args.worker_id, "IAC", "WORKING", current_work_id=work["id"])
                result=registry.execute(store, actor, work)
                store.complete_work(actor, work["id"], args.worker_id, result)
            except PolicyDenied as exc:
                store.block_work(
                    actor, work["id"], args.worker_id, exc.reason,
                    approval_required=exc.approval_required,
                )
            except Exception as exc:
                safe_error=safe_exception_summary(exc, context="worker handler failed")
                store.heartbeat(
                    args.worker_id, "IAC", "ERROR", current_work_id=work["id"],
                    details={"error":safe_error},
                )
                store.fail_work(actor, work["id"], args.worker_id, safe_error)
            if args.once: break
    finally:
        store.heartbeat(args.worker_id, "IAC", "STOPPED")
        store.close()


if __name__ == "__main__":
    main()
