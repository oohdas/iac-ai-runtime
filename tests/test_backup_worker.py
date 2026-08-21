import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.worker import process_backup_transfer_once
from sean_os import (
    Actor,
    BackupReconciliationRequired,
    SeanOSStore,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    synthetic_backup_adapter_receipt,
)


BUCKET="synthetic-ca-east-backup"
ENDPOINT="s3.ca-east-006.backblazeb2.com"
DESTINATION=f"backblaze-b2-bucket:{BUCKET}"
WRITER_REF="iac-vault-writer:backup-only-v1"
KEY_REF="iac-keyring:backup-key-v1"


class SyntheticResolver:
    def __init__(self, _environment, *, key_ref):
        self.key_ref=key_ref

    @contextmanager
    def open_key(self, key_ref):
        if key_ref != self.key_ref:
            raise ValueError("Synthetic key reference mismatch")
        material=bytearray(b"k" * 32)
        try:
            yield material
        finally:
            for index in range(len(material)):
                material[index]=0


class SyntheticUploader:
    def __init__(
        self, client, *, bucket_name, destination_ref, endpoint, writer_identity_ref,
    ):
        self.client=client
        self.bucket_name=bucket_name
        self.destination_ref=destination_ref
        self.endpoint=endpoint
        self.writer_identity_ref=writer_identity_ref

    def upload_new(self, artifact, *, plan, config):
        if self.client.get("ambiguous"):
            raise BackupReconciliationRequired("Synthetic ambiguous write")
        uploaded_at=datetime.now(timezone.utc)
        evidence={
            "provider":"BACKBLAZE_B2",
            "provider_region":"CA_EAST",
            "provider_endpoint":self.endpoint,
            "provider_writer_identity_ref":self.writer_identity_ref,
            "plan_sha256":plan["plan_sha256"],
            "destination_ref":self.destination_ref,
            "object_ref":plan["object_ref"],
            "content_sha256":artifact.evidence["ciphertext_sha256"],
            "content_bytes":artifact.evidence["ciphertext_bytes"],
            "provider_request_ref":"synthetic-request-001",
            "provider_version_ref":"synthetic-version-001",
            "provider_encryption":"AES256",
            "encryption_verified":True,
            "object_lock_mode":"COMPLIANCE",
            "object_lock_verified":True,
            "retention_days":plan["retention_days"],
            "uploaded_at":uploaded_at.isoformat(),
            "retain_until":(
                uploaded_at + timedelta(days=plan["retention_days"], seconds=1)
            ).isoformat(),
            "network_performed":True,
            "uploaded":True,
            "overwrite_performed":False,
            "restore_authorized":False,
            "credentials_persisted":False,
        }
        if self.client.get("after_upload"):
            self.client["after_upload"]()
        return evidence


class BackupWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        self.database=self.root / "iac.db"
        self.store=SeanOSStore(self.database, scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name":"Synthetic"})
        self.manifest=self.store.backup_manifest(
            Actor.sean(), self.root / "approved-source.db"
        )
        self.manifest_path=self.root / "approved-source.manifest.json"
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True), encoding="utf-8"
        )
        self.manifest_path.chmod(0o600)
        instant=datetime.now(timezone.utc)
        package=build_independent_backup_approval_package({
            "format":"sean-os-independent-backup-drill-proposal/v2",
            "owner_scope":"IAC",
            "project_id":"synthetic-project",
            "environment_id":"synthetic-environment",
            "service_id":"synthetic-service",
            "primary_volume_id":"synthetic-primary-volume",
            "destination_kind":"ENCRYPTED_OBJECT_STORAGE",
            "destination_provider":"BACKBLAZE_B2",
            "destination_ref":DESTINATION,
            "data_region":"CA_EAST",
            "independent_from_primary":True,
            "encryption_at_rest":True,
            "encryption_key_owner":"IAC",
            "access_owner":"IAC",
            "retention_days":30,
            "object_lock_enabled":True,
            "restore_target_ref":"synthetic-isolated-restore:001",
            "isolated_restore":True,
            "overwrite_production":False,
            "operator":"sean",
            "rollback_owner":"sean",
            "window_start":(instant - timedelta(minutes=5)).isoformat(),
            "window_end":(instant + timedelta(hours=1)).isoformat(),
            "max_cost_cad":10,
            "kill_switch_change_requested":True,
            "live_connectors_enabled":False,
            "real_data_authorized":False,
        })
        self.plan=build_backup_transfer_plan(
            package, self.manifest, object_ref="backups/synthetic-worker.db.enc",
            provider_endpoint=ENDPOINT, writer_identity_ref=WRITER_REF,
            client_encryption_key_ref=KEY_REF,
        )
        self.store.stage_backup_transfer(Actor.sean(), self.plan, package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), self.plan["plan_sha256"],
            synthetic_backup_adapter_receipt(self.plan, package),
        )
        approval_id=self.store.request_backup_transfer_approval(
            Actor.sean(), self.plan["plan_sha256"], max_impact="Synthetic",
            expires_at=(instant + timedelta(hours=1)).isoformat(),
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic worker test"
        )
        self.store.authorize_backup_transfer(
            Actor.sean(), self.plan["plan_sha256"], approval_id=approval_id
        )
        self.environment={
            "SEAN_OS_BACKUP_EXECUTION":"APPROVED",
            "SEAN_OS_BACKUP_PROVIDER":"BACKBLAZE_B2",
            "SEAN_OS_BACKUP_DATA_REGION":"CA_EAST",
            "SEAN_OS_BACKUP_ENDPOINT":ENDPOINT,
            "SEAN_OS_BACKUP_DESTINATION_REF":DESTINATION,
            "SEAN_OS_BACKUP_WRITER_IDENTITY_REF":WRITER_REF,
            "SEAN_OS_BACKUP_ENCRYPTION_KEY_REF":KEY_REF,
            "SEAN_OS_BACKUP_MAX_BYTES":str(self.plan["backup_bytes"]),
            "SEAN_OS_BACKUP_MAX_COST_CAD":"10",
        }
        self.worker_id="backup-worker-1"
        self.worker=Actor(self.worker_id, frozenset({"IAC"}))
        self.output=self.root / "encrypted"

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def run_worker(self, *, client=None, environment=None, bucket=BUCKET):
        calls=[]

        def client_factory(_environment, _config):
            calls.append("client")
            return client or {"ambiguous":False}

        result=process_backup_transfer_once(
            self.store, self.worker, self.worker_id,
            environment=environment or self.environment,
            bucket_name=bucket, manifest_path=self.manifest_path,
            output_directory=self.output, data_root=self.root,
            client_factory=client_factory, resolver_factory=SyntheticResolver,
            uploader_factory=SyntheticUploader,
        )
        return result, calls

    def test_exact_authorized_transfer_completes_once(self):
        result, calls=self.run_worker()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(calls, ["client"])
        self.assertEqual(len(list(self.output.glob("*.enc"))), 1)
        self.assertTrue(result["receipt_payload"]["network_performed"])
        self.assertIsNone(self.store.claim_authorized_backup_transfer(
            self.worker, "backup-worker-2"
        ))

    def test_no_authorized_transfer_resolves_no_client_and_creates_no_artifact_directory(self):
        self.store.connection.execute(
            """UPDATE backup_transfer_outbox SET status='PREFLIGHT_VALIDATED',
               approval_id=NULL WHERE plan_sha256=?""",
            (self.plan["plan_sha256"],),
        )
        self.store.connection.commit()
        result, calls=self.run_worker()
        self.assertIsNone(result)
        self.assertEqual(calls, [])
        self.assertFalse(self.output.exists())

    def test_runtime_plan_mismatch_fails_before_managed_client_resolution(self):
        changed=dict(self.environment)
        changed["SEAN_OS_BACKUP_MAX_COST_CAD"]="9"
        result, calls=self.run_worker(environment=changed)
        self.assertEqual(result["status"], "AUTHORIZED")
        self.assertEqual(calls, [])
        transfer=self.store.get_backup_transfer(
            self.worker, self.plan["plan_sha256"]
        )
        self.assertEqual(transfer["attempt_count"], 1)
        self.assertIsNone(transfer["lease_owner"])

    def test_ambiguous_write_requires_reconciliation_and_cannot_retry(self):
        result, calls=self.run_worker(client={"ambiguous":True})
        self.assertEqual(calls, ["client"])
        self.assertEqual(result["status"], "RECONCILIATION_REQUIRED")
        transfer=self.store.get_backup_transfer(
            self.worker, self.plan["plan_sha256"]
        )
        self.assertEqual(transfer["status"], "RECONCILIATION_REQUIRED")
        self.assertIsNone(self.store.claim_authorized_backup_transfer(
            self.worker, "backup-worker-2"
        ))

    def test_guard_failure_after_verified_upload_also_requires_reconciliation(self):
        result, calls=self.run_worker(client={
            "after_upload":lambda: self.store.set_kill_switch(Actor.sean(), True)
        })
        self.assertEqual(calls, ["client"])
        self.assertEqual(result["status"], "RECONCILIATION_REQUIRED")
        self.assertEqual(
            self.store.get_backup_transfer(
                self.worker, self.plan["plan_sha256"]
            )["status"],
            "RECONCILIATION_REQUIRED",
        )

    def test_bucket_mismatch_fails_before_claim_or_client_resolution(self):
        with self.assertRaisesRegex(ValueError, "approved destination"):
            self.run_worker(bucket="different-ca-east-backup")
        transfer=self.store.get_backup_transfer(
            self.worker, self.plan["plan_sha256"]
        )
        self.assertEqual(transfer["attempt_count"], 0)

    def test_manifest_and_source_must_be_private_and_inside_data_root(self):
        self.manifest_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private permissions"):
            self.run_worker()
        self.assertEqual(
            self.store.get_backup_transfer(
                self.worker, self.plan["plan_sha256"]
            )["attempt_count"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
