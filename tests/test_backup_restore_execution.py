import hashlib
import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from sean_os import (
    AES256GCMFileDecryptor,
    AES256GCMFileEncryptor,
    Actor,
    BackupRestoreExecutionError,
    BackupRestoreExecutionReconciliationRequired,
    DownloadedBackupArtifact,
    SeanOSStore,
    build_backup_restore_key_approval_package,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    build_isolated_backup_restore_plan,
    execute_claimed_backup_restore,
    load_backup_restore_runtime_config,
    synthetic_backup_restore_preflight,
)


BUCKET = "synthetic-ca-east-backup-bucket"


class SyntheticKeyResolver:
    @contextmanager
    def open_key(self, _key_ref):
        material = bytearray(b"k" * 32)
        yield material


class SyntheticExactDownloader:
    def __init__(self, artifact, *, mutate=None):
        self.artifact = artifact
        self.mutate = mutate
        self.calls = 0

    def download_exact(self, *, plan, config):
        self.calls += 1
        evidence = {
            "format": "sean-os-downloaded-encrypted-backup/v1",
            "restore_plan_sha256": plan["plan_sha256"],
            "provider": plan["provider"],
            "provider_region": plan["data_region"],
            "provider_endpoint": plan["provider_endpoint"],
            "provider_restore_identity_ref": plan["provider_restore_identity_ref"],
            "destination_ref": plan["destination_ref"],
            "object_ref": plan["object_ref"],
            "provider_version_ref": plan["provider_version_ref"],
            "ciphertext_sha256": plan["ciphertext_sha256"],
            "ciphertext_bytes": plan["ciphertext_bytes"],
            "provider_encryption": "AES256",
            "object_lock_mode": "COMPLIANCE",
            "object_lock_verified": True,
            "retain_until": plan["retain_until"],
            "network_performed": True,
            "downloaded": True,
            "overwrite_performed": False,
            "credentials_persisted": False,
            "source_path_included": False,
        }
        if self.mutate:
            self.mutate(evidence)
        return DownloadedBackupArtifact(self.artifact.path, evidence)


def drill_proposal():
    return {
        "format": "sean-os-independent-backup-drill-proposal/v2",
        "owner_scope": "IAC",
        "project_id": "synthetic-project",
        "environment_id": "synthetic-environment",
        "service_id": "synthetic-service",
        "primary_volume_id": "synthetic-primary-volume",
        "destination_kind": "ENCRYPTED_OBJECT_STORAGE",
        "destination_provider": "BACKBLAZE_B2",
        "destination_ref": f"backblaze-b2-bucket:{BUCKET}",
        "data_region": "CA_EAST",
        "independent_from_primary": True,
        "encryption_at_rest": True,
        "encryption_key_owner": "IAC",
        "access_owner": "IAC",
        "retention_days": 30,
        "object_lock_enabled": True,
        "restore_target_ref": "synthetic-isolated-restore:001",
        "isolated_restore": True,
        "overwrite_production": False,
        "operator": "sean",
        "rollback_owner": "sean",
        "window_start": "2030-01-02T09:00:00-05:00",
        "window_end": "2030-01-02T11:00:00-05:00",
        "max_cost_cad": 10,
        "kill_switch_change_requested": True,
        "live_connectors_enabled": False,
        "real_data_authorized": False,
    }


def restore_key_proposal():
    return {
        "format": "sean-os-backblaze-restore-key-proposal/v1",
        "owner_scope": "IAC",
        "provider": "BACKBLAZE_B2",
        "data_region": "CA_EAST",
        "provider_endpoint": "s3.ca-east-006.backblazeb2.com",
        "bucket_ref": BUCKET,
        "key_name_ref": "sean-os-backup-restore-pilot-v1",
        "file_name_prefix": "backups/",
        "valid_duration_seconds": 14400,
        "capabilities": [
            "listAllBucketNames", "listBuckets", "readBucketEncryption",
            "readBucketRetentions", "readFileRetentions", "readFiles",
        ],
        "credential_destination_ref": "managed-secret-store:synthetic-restore-v1",
        "access_owner": "IAC",
        "operator": "sean",
        "production_data_authorized": False,
        "account_admin_authorized": False,
        "write_authorized": False,
        "approval_required": True,
        "creation_authorized": False,
    }


class BackupRestoreExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SeanOSStore(self.root / "iac.db", scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name": "Sentinel"})
        manifest = self.store.backup_manifest(Actor.sean(), self.root / "backup.db")
        approval = build_independent_backup_approval_package(drill_proposal())
        self.upload_plan = build_backup_transfer_plan(
            approval, manifest, object_ref="backups/synthetic-execution.db.enc",
            provider_endpoint="s3.ca-east-006.backblazeb2.com",
            writer_identity_ref="managed-secret-store:synthetic-writer-v1",
            client_encryption_key_ref="managed-secret-store:synthetic-aes256-v1",
        )
        encrypted_dir = self.root / "encrypted"
        encrypted_dir.mkdir(mode=0o700)
        (self.root / "isolated").mkdir(mode=0o700)
        self.encrypted = AES256GCMFileEncryptor(
            encrypted_dir, SyntheticKeyResolver()
        ).encrypt(
            Path(manifest["path"]), plan=self.upload_plan,
            key_ref=self.upload_plan["client_encryption_key_ref"],
        )
        upload_receipt = {
            "format": "sean-os-independent-backup-upload-receipt/v3",
            "evidence_mode": "PRODUCTION",
            "provider": "BACKBLAZE_B2",
            "provider_region": self.upload_plan["data_region"],
            "provider_endpoint": self.upload_plan["provider_endpoint"],
            "provider_writer_identity_ref": self.upload_plan["provider_writer_identity_ref"],
            "plan_sha256": self.upload_plan["plan_sha256"],
            "destination_ref": self.upload_plan["destination_ref"],
            "object_ref": self.upload_plan["object_ref"],
            "backup_sha256": self.upload_plan["backup_sha256"],
            "backup_bytes": self.upload_plan["backup_bytes"],
            "ciphertext_sha256": self.encrypted.evidence["ciphertext_sha256"],
            "ciphertext_bytes": self.encrypted.evidence["ciphertext_bytes"],
            "client_encryption_algorithm": "AES_256_GCM",
            "client_encryption_key_ref": self.upload_plan["client_encryption_key_ref"],
            "provider_request_ref": "request-001",
            "provider_version_ref": "version-001",
            "encryption_mode": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION_PLUS_PROVIDER_AES256",
            "encryption_verified": True,
            "object_lock_mode": "COMPLIANCE",
            "object_lock_verified": True,
            "retention_days": 30,
            "uploaded_at": "2030-01-02T10:00:00-05:00",
            "retain_until": "2030-02-01T10:00:00-05:00",
            "network_performed": True,
            "uploaded": True,
            "overwrite_performed": False,
            "restore_authorized": False,
            "credentials_persisted": False,
            "source_path_included": False,
        }
        upload_receipt["receipt_sha256"] = hashlib.sha256(
            json.dumps(
                upload_receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        ).hexdigest()
        self.upload_receipt = upload_receipt
        self.key_package = build_backup_restore_key_approval_package(
            restore_key_proposal()
        )
        self.plan = build_isolated_backup_restore_plan(
            self.upload_plan, upload_receipt, self.key_package,
            restore_target_ref="isolated-restore:synthetic-iac-execution-v1",
            window_start="2030-01-03T09:00:00-05:00",
            window_end="2030-01-03T11:00:00-05:00",
            max_cost_cad=1,
        )
        self.environment = {
            "SEAN_OS_BACKUP_RESTORE_EXECUTION": "APPROVED",
            "SEAN_OS_BACKUP_RESTORE_PROVIDER": "BACKBLAZE_B2",
            "SEAN_OS_BACKUP_RESTORE_DATA_REGION": "CA_EAST",
            "SEAN_OS_BACKUP_RESTORE_ENDPOINT": "s3.ca-east-006.backblazeb2.com",
            "SEAN_OS_BACKUP_RESTORE_DESTINATION_REF": f"backblaze-b2-bucket:{BUCKET}",
            "SEAN_OS_BACKUP_RESTORE_IDENTITY_REF": (
                "managed-secret-store:synthetic-restore-v1"
            ),
            "SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY_REF": (
                "managed-secret-store:synthetic-aes256-v1"
            ),
            "SEAN_OS_BACKUP_RESTORE_MAX_BYTES": str(
                self.encrypted.evidence["ciphertext_bytes"]
            ),
            "SEAN_OS_BACKUP_RESTORE_MAX_COST_CAD": "1",
        }

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def claim(self):
        self.store.stage_backup_restore(
            Actor.sean(), self.plan, self.upload_plan, self.upload_receipt,
            self.key_package,
        )
        self.store.record_backup_restore_preflight(
            Actor.sean(), self.plan["plan_sha256"],
            synthetic_backup_restore_preflight(self.plan),
        )
        approval_id = self.store.request_backup_restore_approval(
            Actor("iac-interface", frozenset({"IAC"})), self.plan["plan_sha256"],
            max_impact="One isolated synthetic restore",
            expires_at="2030-01-03T10:30:00-05:00",
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic execution test"
        )
        self.store.authorize_backup_restore(
            Actor.sean(), self.plan["plan_sha256"], approval_id=approval_id,
            at="2030-01-03T09:30:00-05:00",
        )
        return self.store.claim_authorized_backup_restore(
            Actor("restore-worker", frozenset({"IAC"})), "restore-worker-1",
            lease_seconds=600, at="2030-01-03T09:31:00-05:00",
        )

    def test_runtime_config_is_default_off_complete_and_secret_reference_only(self):
        self.assertFalse(load_backup_restore_runtime_config({}).enabled)
        config = load_backup_restore_runtime_config(self.environment)
        self.assertTrue(config.enabled)
        self.assertEqual(config.restore_identity_ref, self.plan["provider_restore_identity_ref"])
        partial = dict(self.environment)
        partial.pop("SEAN_OS_BACKUP_RESTORE_ENDPOINT")
        with self.assertRaisesRegex(BackupRestoreExecutionError, "complete"):
            load_backup_restore_runtime_config(partial)
        with self.assertRaisesRegex(BackupRestoreExecutionError, "Raw restore secrets"):
            load_backup_restore_runtime_config({
                "SEAN_OS_BACKUP_RESTORE_ACCESS_KEY_ID": "not-allowed"
            })

    def test_injected_restore_is_authenticated_integrity_checked_and_durable(self):
        claimed = self.claim()
        guards = []
        receipt = execute_claimed_backup_restore(
            claimed, worker_id="restore-worker-1",
            config=load_backup_restore_runtime_config(self.environment),
            downloader=SyntheticExactDownloader(self.encrypted),
            decryptor=AES256GCMFileDecryptor(SyntheticKeyResolver()),
            restore_destination=self.root / "isolated" / "restored.db",
            guard=guards.append,
            at=datetime.fromisoformat("2030-01-03T09:32:00-05:00"),
        )
        self.assertEqual(
            guards, ["BEFORE_DOWNLOAD", "AFTER_DOWNLOAD", "AFTER_DECRYPTION"]
        )
        self.assertTrue(receipt["database_integrity_ok"])
        self.assertEqual(receipt["scope_profile"], "IAC")
        self.assertFalse(receipt["overwrite_performed"])
        completed = self.store.complete_claimed_backup_restore(
            Actor("restore-worker", frozenset({"IAC"})), self.plan["plan_sha256"],
            "restore-worker-1", receipt, at="2030-01-03T09:33:00-05:00",
        )
        self.assertEqual(completed["status"], "RESTORED")
        self.assertEqual(completed["receipt_payload"], receipt)

    def test_changed_download_or_config_fails_before_plaintext_publication(self):
        claimed = self.claim()
        config = load_backup_restore_runtime_config(self.environment)
        with self.assertRaisesRegex(BackupRestoreExecutionError, "evidence"):
            execute_claimed_backup_restore(
                claimed, worker_id="restore-worker-1", config=config,
                downloader=SyntheticExactDownloader(
                    self.encrypted, mutate=lambda item: item.update({"object_ref":"changed"})
                ),
                decryptor=AES256GCMFileDecryptor(SyntheticKeyResolver()),
                restore_destination=self.root / "wrong-download.db",
                guard=lambda _stage: None,
                at=datetime.fromisoformat("2030-01-03T09:32:00-05:00"),
            )
        self.assertFalse((self.root / "wrong-download.db").exists())
        changed = dict(self.environment)
        changed["SEAN_OS_BACKUP_RESTORE_IDENTITY_REF"] = "managed-secret-store:other"
        with self.assertRaisesRegex(BackupRestoreExecutionError, "does not match"):
            execute_claimed_backup_restore(
                claimed, worker_id="restore-worker-1",
                config=load_backup_restore_runtime_config(changed),
                downloader=SyntheticExactDownloader(self.encrypted),
                decryptor=AES256GCMFileDecryptor(SyntheticKeyResolver()),
                restore_destination=self.root / "wrong-config.db",
                guard=lambda _stage: None,
                at=datetime.fromisoformat("2030-01-03T09:32:00-05:00"),
            )

    def test_post_decryption_failure_requires_manual_reconciliation(self):
        claimed = self.claim()
        destination = self.root / "isolated" / "manual-review.db"

        def guard(stage):
            if stage == "AFTER_DECRYPTION":
                raise RuntimeError("synthetic completion uncertainty")

        with self.assertRaises(BackupRestoreExecutionReconciliationRequired):
            execute_claimed_backup_restore(
                claimed, worker_id="restore-worker-1",
                config=load_backup_restore_runtime_config(self.environment),
                downloader=SyntheticExactDownloader(self.encrypted),
                decryptor=AES256GCMFileDecryptor(SyntheticKeyResolver()),
                restore_destination=destination, guard=guard,
                at=datetime.fromisoformat("2030-01-03T09:32:00-05:00"),
            )
        self.assertTrue(destination.exists())
        status = self.store.hold_claimed_backup_restore_for_reconciliation(
            Actor("restore-worker", frozenset({"IAC"})), self.plan["plan_sha256"],
            "restore-worker-1", "Published isolated restore requires manual reconciliation",
        )
        self.assertEqual(status, "RECONCILIATION_REQUIRED")
        self.assertEqual(
            self.store.get_backup_restore(Actor.sean(), self.plan["plan_sha256"])["status"],
            "RECONCILIATION_REQUIRED",
        )


if __name__ == "__main__":
    unittest.main()
