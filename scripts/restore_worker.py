#!/usr/bin/env python3
"""Run at most one separately authorized isolated restore; never runs by default."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import (  # noqa: E402
    AES256GCMFileDecryptor,
    Actor,
    BackblazeS3DownloadPort,
    BackupRestoreExecutionReconciliationRequired,
    SeanOSStore,
    build_backblaze_s3_restore_client,
    execute_claimed_backup_restore,
    load_backup_restore_runtime_config,
)
from sean_os.backup_provider import verify_backblaze_bucket_name  # noqa: E402
from sean_os.backup_secrets import ManagedEnvironmentEncryptionKeyResolver  # noqa: E402
from sean_os.security import safe_exception_summary  # noqa: E402


def _private_directory(path: Path, data_root: Path, description: str) -> Path:
    raw=Path(path)
    if raw.is_symlink():
        raise ValueError(f"{description} must be a directory inside the data volume")
    value=raw.resolve(); root=Path(data_root).resolve()
    if root not in value.parents:
        raise ValueError(f"{description} must be a directory inside the data volume")
    value.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        value.is_symlink() or not value.is_dir()
        or stat.S_IMODE(value.stat().st_mode) != 0o700
    ):
        raise ValueError(f"{description} must have private permissions")
    return value


def _new_restore_destination(path: Path, restore_root: Path) -> Path:
    raw=Path(path)
    if raw.is_symlink():
        raise ValueError("Restore destination must be new inside the isolated directory")
    value=raw.resolve(); root=Path(restore_root).resolve()
    if root not in value.parents or value.exists():
        raise ValueError("Restore destination must be new inside the isolated directory")
    return value


def process_backup_restore_once(
    store: SeanOSStore, actor: Actor, worker_id: str, *, environment,
    bucket_name: str, download_directory: Path, restore_directory: Path,
    restore_destination: Path, data_root: Path,
    client_factory=build_backblaze_s3_restore_client,
    resolver_factory=ManagedEnvironmentEncryptionKeyResolver,
    downloader_factory=BackblazeS3DownloadPort,
    decryptor_factory=AES256GCMFileDecryptor,
):
    config=load_backup_restore_runtime_config(environment)
    if not config.enabled:
        raise ValueError("Backup restore execution is disabled")
    bucket=verify_backblaze_bucket_name(bucket_name)
    if config.destination_ref != f"backblaze-b2-bucket:{bucket}":
        raise ValueError("Restore bucket does not match the approved destination")
    root=Path(data_root).resolve()
    downloads=_private_directory(download_directory, root, "Restore download directory")
    restores=_private_directory(restore_directory, root, "Isolated restore directory")
    destination=_new_restore_destination(restore_destination, restores)
    claimed=store.claim_authorized_backup_restore(actor, worker_id, lease_seconds=900)
    if claimed is None:
        return None
    plan_sha256=claimed["restore_plan_sha256"]
    restore_published=False
    try:
        client=client_factory(environment, config)
        downloader=downloader_factory(
            client, bucket_name=bucket, destination_ref=str(config.destination_ref),
            endpoint=str(config.endpoint),
            restore_identity_ref=str(config.restore_identity_ref),
            output_directory=downloads,
        )
        resolver=resolver_factory(
            environment, key_ref=str(config.encryption_key_ref)
        )
        receipt=execute_claimed_backup_restore(
            claimed, worker_id=worker_id, config=config, downloader=downloader,
            decryptor=decryptor_factory(resolver), restore_destination=destination,
            guard=lambda _stage: store.assert_backup_restore_execution_allowed(
                actor, plan_sha256, worker_id
            ),
        )
        restore_published=True
        try:
            return store.complete_claimed_backup_restore(
                actor, plan_sha256, worker_id, receipt
            )
        except Exception as exc:
            raise BackupRestoreExecutionReconciliationRequired(
                "Published isolated restore requires manual reconciliation"
            ) from exc
    except BackupRestoreExecutionReconciliationRequired:
        status=store.hold_claimed_backup_restore_for_reconciliation(
            actor, plan_sha256, worker_id,
            "Published isolated restore requires manual reconciliation",
        )
        return {"restore_plan_sha256":plan_sha256, "status":status}
    except Exception as exc:
        if restore_published or destination.exists():
            status=store.hold_claimed_backup_restore_for_reconciliation(
                actor, plan_sha256, worker_id,
                "Published isolated restore requires manual reconciliation",
            )
        else:
            status=store.fail_claimed_backup_restore(
                actor, plan_sha256, worker_id,
                safe_exception_summary(exc, context="backup restore failed"),
            )
        return {"restore_plan_sha256":plan_sha256, "status":status}


def main() -> int:
    parser=argparse.ArgumentParser(
        description="Process at most one exact authorized isolated backup restore."
    )
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--worker-id", default="isolated-restore-worker-1")
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--download-directory", required=True, type=Path)
    parser.add_argument("--restore-directory", required=True, type=Path)
    parser.add_argument("--restore-destination", required=True, type=Path)
    arguments=parser.parse_args()
    store=SeanOSStore(arguments.database, scope_profile="IAC")
    try:
        result=process_backup_restore_once(
            store, Actor(arguments.worker_id, frozenset({"IAC"})),
            arguments.worker_id, environment=os.environ,
            bucket_name=arguments.bucket,
            download_directory=arguments.download_directory,
            restore_directory=arguments.restore_directory,
            restore_destination=arguments.restore_destination,
            data_root=arguments.database.resolve().parent,
        )
        bounded={
            "processed":result is not None,
            "restore_plan_sha256":result.get("restore_plan_sha256") if result else None,
            "status":result.get("status") if result else "NO_AUTHORIZED_RESTORE",
        }
        print(json.dumps(bounded, sort_keys=True))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
