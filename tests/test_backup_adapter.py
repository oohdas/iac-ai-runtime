import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sean_os import (
    Actor,
    BackupAdapterError,
    SeanOSStore,
    build_backup_transfer_plan as _build_backup_transfer_plan,
    build_independent_backup_approval_package,
    synthetic_backup_adapter_receipt,
    verify_backup_transfer_plan,
    verify_backup_upload_receipt,
    verify_local_iac_backup_manifest,
    verify_synthetic_backup_adapter_receipt,
)
from sean_os.monitoring import classify_alerts


ROOT = Path(__file__).resolve().parents[1]


def build_backup_transfer_plan(package, manifest, *, object_ref):
    return _build_backup_transfer_plan(
        package,
        manifest,
        object_ref=object_ref,
        provider_endpoint="s3.ca-east-006.backblazeb2.com",
        writer_identity_ref="iac-vault-writer:backup-only-v1",
        client_encryption_key_ref="iac-keyring:backup-key-v1",
    )


def production_receipt(plan, **overrides):
    value={
        "format":"sean-os-independent-backup-upload-receipt/v3",
        "evidence_mode":"PRODUCTION",
        "provider":"BACKBLAZE_B2",
        "provider_region":plan["data_region"],
        "provider_endpoint":plan["provider_endpoint"],
        "provider_writer_identity_ref":plan["provider_writer_identity_ref"],
        "plan_sha256":plan["plan_sha256"],
        "destination_ref":plan["destination_ref"],
        "object_ref":plan["object_ref"],
        "backup_sha256":plan["backup_sha256"],
        "backup_bytes":plan["backup_bytes"],
        "ciphertext_sha256":"1" * 64,
        "ciphertext_bytes":plan["backup_bytes"] + 128,
        "client_encryption_algorithm":"AES_256_GCM",
        "client_encryption_key_ref":plan["client_encryption_key_ref"],
        "provider_request_ref":"request-001",
        "provider_version_ref":"version-001",
        "encryption_mode":"IAC_MANAGED_AUTHENTICATED_ENCRYPTION_PLUS_PROVIDER_AES256",
        "encryption_verified":True,
        "object_lock_mode":"COMPLIANCE",
        "object_lock_verified":True,
        "retention_days":plan["retention_days"],
        "uploaded_at":"2030-01-02T10:00:00-05:00",
        "retain_until":"2030-02-01T10:00:00-05:00",
        "network_performed":True,
        "uploaded":True,
        "overwrite_performed":False,
        "restore_authorized":False,
        "credentials_persisted":False,
        "source_path_included":False,
    }
    value.update(overrides)
    value["receipt_sha256"]=hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return value


def synthetic_proposal():
    return {
        "format":"sean-os-independent-backup-drill-proposal/v2",
        "owner_scope":"IAC",
        "project_id":"synthetic-project",
        "environment_id":"synthetic-environment",
        "service_id":"synthetic-service",
        "primary_volume_id":"synthetic-primary-volume",
        "destination_kind":"ENCRYPTED_OBJECT_STORAGE",
        "destination_provider":"BACKBLAZE_B2",
        "destination_ref":"synthetic-backup-vault:object-001",
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
        "window_start":"2030-01-02T09:00:00-05:00",
        "window_end":"2030-01-02T11:00:00-05:00",
        "max_cost_cad":10,
        "kill_switch_change_requested":True,
        "live_connectors_enabled":False,
        "real_data_authorized":False,
    }


class BackupAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = SeanOSStore(root / "iac.db", scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name":"Synthetic"})
        self.manifest = self.store.backup_manifest(Actor.sean(), root / "backup.db")
        self.package = build_independent_backup_approval_package(synthetic_proposal())

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_transfer_plan_is_hash_bound_path_free_and_non_executing(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/synthetic-001.db.enc"
        )
        verified = verify_backup_transfer_plan(plan, self.package)
        self.assertEqual(verified, plan)
        self.assertFalse(plan["network_enabled"])
        self.assertFalse(plan["execution_authorized"])
        self.assertFalse(plan["credentials_included"])
        self.assertNotIn(self.manifest["path"], json.dumps(plan))
        self.assertEqual(plan["backup_sha256"], self.manifest["sha256"])
        self.assertEqual(plan["retention_mode"], "COMPLIANCE")
        self.assertEqual(plan["provider"], "BACKBLAZE_B2")
        self.assertEqual(plan["data_region"], "CA_EAST")
        self.assertEqual(plan["provider_endpoint"], "s3.ca-east-006.backblazeb2.com")
        self.assertEqual(
            plan["provider_writer_identity_ref"], "iac-vault-writer:backup-only-v1"
        )
        self.assertEqual(plan["client_encryption_key_ref"], "iac-keyring:backup-key-v1")
        self.assertEqual(plan["window_start"], self.package["proposal"]["window_start"])
        self.assertEqual(plan["window_end"], self.package["proposal"]["window_end"])
        self.assertEqual(plan["max_cost_cad"], 10.0)

    def test_synthetic_adapter_proves_no_encryption_upload_or_network(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/synthetic-002.db.enc"
        )
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        self.assertEqual(verify_synthetic_backup_adapter_receipt(receipt), receipt)
        self.assertFalse(receipt["artifact_encrypted"])
        self.assertFalse(receipt["uploaded"])
        self.assertFalse(receipt["network_performed"])
        self.assertFalse(receipt["execution_authorized"])
        self.assertNotIn(self.manifest["path"], json.dumps(receipt))

    def test_modified_plan_or_receipt_fails_closed(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/synthetic-003.db.enc"
        )
        changed = copy.deepcopy(plan)
        changed["network_enabled"] = True
        with self.assertRaises(BackupAdapterError):
            verify_backup_transfer_plan(changed, self.package)
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        changed_receipt = copy.deepcopy(receipt)
        changed_receipt["uploaded"] = True
        with self.assertRaises(BackupAdapterError):
            verify_synthetic_backup_adapter_receipt(changed_receipt)

    def test_non_iac_database_is_rejected(self):
        root = Path(self.temp.name)
        development = SeanOSStore(root / "development.db")
        try:
            manifest = development.backup_manifest(Actor.sean(), root / "development-backup.db")
        finally:
            development.close()
        with self.assertRaisesRegex(BackupAdapterError, "IAC database"):
            verify_local_iac_backup_manifest(manifest)

    def test_modified_backup_or_manifest_is_rejected(self):
        backup = Path(self.manifest["path"])
        backup.write_bytes(backup.read_bytes() + b"changed")
        with self.assertRaisesRegex(BackupAdapterError, "does not match"):
            verify_local_iac_backup_manifest(self.manifest)

    def test_unsafe_or_secret_like_object_reference_is_rejected(self):
        for object_ref in ("../backup.db", "/backup.db", "sk-" + "x" * 24):
            with self.subTest(object_ref=object_ref):
                with self.assertRaises(BackupAdapterError):
                    build_backup_transfer_plan(
                        self.package, self.manifest, object_ref=object_ref
                    )

    def test_modified_approval_package_cannot_bind_a_plan(self):
        changed = copy.deepcopy(self.package)
        changed["proposal_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            build_backup_transfer_plan(
                changed, self.manifest, object_ref="backups/synthetic-004.db.enc"
            )

    def test_symlink_backup_is_rejected(self):
        link = Path(self.temp.name) / "backup-link.db"
        link.symlink_to(Path(self.manifest["path"]))
        linked_manifest = dict(self.manifest)
        linked_manifest["path"] = str(link)
        with self.assertRaisesRegex(BackupAdapterError, "non-symlink"):
            verify_local_iac_backup_manifest(linked_manifest)

    def test_cli_prints_only_a_no_network_plan_and_synthetic_receipt(self):
        root = Path(self.temp.name)
        package_path = root / "package.json"
        manifest_path = root / "manifest.json"
        package_path.write_text(json.dumps(self.package), encoding="utf-8")
        manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "scripts/prepare_backup_transfer.py",
                str(package_path),
                str(manifest_path),
                "--object-ref",
                "backups/synthetic-cli.db.enc",
                "--provider-endpoint",
                "s3.ca-east-006.backblazeb2.com",
                "--writer-identity-ref",
                "iac-vault-writer:backup-only-v1",
                "--client-encryption-key-ref",
                "iac-keyring:backup-key-v1",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertFalse(output["plan"]["network_enabled"])
        self.assertFalse(output["plan"]["execution_authorized"])
        self.assertFalse(output["synthetic_receipt"]["uploaded"])
        self.assertFalse(output["synthetic_receipt"]["network_performed"])
        self.assertNotIn(self.manifest["path"], result.stdout)

    def test_durable_preflight_requires_exact_single_use_sean_approval(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/durable-001.db.enc"
        )
        staged = self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        self.assertEqual(staged["status"], "STAGED")
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        preflight = self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], receipt
        )
        self.assertEqual(preflight["status"], "PREFLIGHT_VALIDATED")
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        requester = Actor("backup-worker", frozenset({"IAC"}))
        approval_id = self.store.request_backup_transfer_approval(
            requester,
            plan["plan_sha256"],
            max_impact="One encrypted, locked synthetic IAC backup drill; CAD 10 maximum",
            expires_at=expiry,
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic exact-plan test"
        )
        authorized = self.store.authorize_backup_transfer(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id
        )
        self.assertEqual(authorized["status"], "AUTHORIZED")
        self.assertEqual(authorized["approval_id"], approval_id)
        self.assertFalse(authorized["plan_payload"]["network_enabled"])
        self.assertFalse(authorized["plan_payload"]["execution_authorized"])
        approval_status = self.store.connection.execute(
            "SELECT status FROM approvals WHERE record_id=?", (approval_id,)
        ).fetchone()[0]
        self.assertEqual(approval_status, "CONSUMED")
        repeated = self.store.authorize_backup_transfer(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id
        )
        self.assertEqual(repeated, authorized)

    def test_backup_approval_conditions_are_byte_exact_and_atomic(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/durable-002.db.enc"
        )
        self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], receipt
        )
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        wrong = self.store.create_approval(
            Actor.sean(),
            action_type="RUN_INDEPENDENT_BACKUP_RESTORE_DRILL",
            target=plan["approval_target"],
            scope="IAC",
            max_impact="Synthetic mismatch",
            approver="sean",
            expires_at=expiry,
            conditions={"plan_sha256":"0" * 64},
        )
        with self.assertRaisesRegex(PermissionError, "conditions"):
            self.store.authorize_backup_transfer(
                Actor.sean(), plan["plan_sha256"], approval_id=wrong
            )
        row = self.store.get_backup_transfer(Actor.sean(), plan["plan_sha256"])
        self.assertEqual(row["status"], "PREFLIGHT_VALIDATED")
        self.assertIsNone(row["approval_id"])
        self.assertEqual(
            self.store.connection.execute(
                "SELECT status FROM approvals WHERE record_id=?", (wrong,)
            ).fetchone()[0],
            "APPROVED",
        )

    def test_backup_transfer_requires_preflight_iac_profile_and_sean_authorization(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/durable-003.db.enc"
        )
        staged = self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        with self.assertRaisesRegex(ValueError, "preflight"):
            self.store.request_backup_transfer_approval(
                Actor.sean(), staged["plan_sha256"], max_impact="Synthetic", expires_at=expiry
            )
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], receipt
        )
        approval_id = self.store.request_backup_transfer_approval(
            Actor.sean(), plan["plan_sha256"], max_impact="Synthetic", expires_at=expiry
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic exact-plan test"
        )
        with self.assertRaisesRegex(PermissionError, "Only Sean"):
            self.store.authorize_backup_transfer(
                Actor("backup-worker", frozenset({"IAC"})),
                plan["plan_sha256"],
                approval_id=approval_id,
            )
        development = SeanOSStore(Path(self.temp.name) / "development-outbox.db")
        try:
            with self.assertRaisesRegex(PermissionError, "IAC database profile"):
                development.stage_backup_transfer(Actor.sean(), plan, self.package)
        finally:
            development.close()

    def test_authorized_transfer_leases_recover_and_fail_after_bounded_retries(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/lease-recovery.db.enc"
        )
        self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], receipt
        )
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        approval_id = self.store.request_backup_transfer_approval(
            Actor.sean(), plan["plan_sha256"], max_impact="Synthetic", expires_at=expiry
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic lease test"
        )
        self.store.authorize_backup_transfer(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id
        )
        worker=Actor("backup-worker", frozenset({"IAC"}))
        first=self.store.claim_authorized_backup_transfer(
            worker, "backup-worker-1", lease_seconds=30
        )
        self.assertEqual(first["attempt_count"], 1)
        self.assertIsNone(self.store.claim_authorized_backup_transfer(worker, "backup-worker-2"))
        self.store.connection.execute(
            """UPDATE backup_transfer_outbox SET attempt_count=2,
               lease_expires_at='2000-01-01T00:00:00+00:00' WHERE plan_sha256=?""",
            (plan["plan_sha256"],),
        )
        self.store.connection.commit()
        recovered=self.store.claim_authorized_backup_transfer(
            worker, "backup-worker-2", lease_seconds=30
        )
        self.assertEqual(recovered["attempt_count"], 3)
        self.assertEqual(recovered["lease_owner"], "backup-worker-2")
        status=self.store.fail_claimed_backup_transfer(
            worker, plan["plan_sha256"], "backup-worker-2",
            "Synthetic provider failure", retry_seconds=0,
        )
        self.assertEqual(status, "FAILED")
        health=self.store.runtime_health(scope="IAC")
        self.assertFalse(health["healthy"])
        self.assertEqual(health["backup_transfer_outbox"]["FAILED"], 1)
        self.assertIn(
            "BACKUP_TRANSFER_FAILED",
            {alert["code"] for alert in classify_alerts(health)},
        )

    def test_kill_switch_and_secret_failures_block_backup_transfer_worker(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/kill-switch.db.enc"
        )
        self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        receipt = synthetic_backup_adapter_receipt(plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], receipt
        )
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        approval_id = self.store.request_backup_transfer_approval(
            Actor.sean(), plan["plan_sha256"], max_impact="Synthetic", expires_at=expiry
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic kill-switch test"
        )
        self.store.authorize_backup_transfer(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id
        )
        worker=Actor("backup-worker", frozenset({"IAC"}))
        self.store.set_kill_switch(Actor.sean(), True)
        self.assertIsNone(self.store.claim_authorized_backup_transfer(worker, "backup-worker-1"))
        self.store.set_kill_switch(Actor.sean(), False)
        self.store.claim_authorized_backup_transfer(worker, "backup-worker-1")
        with self.assertRaisesRegex(ValueError, "Secret-like"):
            self.store.fail_claimed_backup_transfer(
                worker, plan["plan_sha256"], "backup-worker-1",
                "sk-" + "z" * 24,
            )

    def test_verified_provider_receipt_completes_claim_and_preserves_preflight(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/complete.db.enc"
        )
        self.store.stage_backup_transfer(Actor.sean(), plan, self.package)
        preflight = synthetic_backup_adapter_receipt(plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"], preflight
        )
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        approval_id = self.store.request_backup_transfer_approval(
            Actor.sean(), plan["plan_sha256"], max_impact="Synthetic", expires_at=expiry
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic completion test"
        )
        self.store.authorize_backup_transfer(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id
        )
        worker=Actor("backup-worker", frozenset({"IAC"}))
        self.store.claim_authorized_backup_transfer(worker, "backup-worker-1")
        receipt=production_receipt(plan)
        completed=self.store.complete_claimed_backup_transfer(
            worker, plan["plan_sha256"], "backup-worker-1", receipt
        )
        self.assertEqual(completed["status"], "COMPLETED")
        self.assertEqual(completed["preflight_receipt_payload"], preflight)
        self.assertEqual(completed["receipt_payload"], receipt)
        self.assertIsNone(completed["lease_owner"])
        self.assertEqual(
            self.store.complete_claimed_backup_transfer(
                worker, plan["plan_sha256"], "backup-worker-1", receipt
            ),
            completed,
        )

    def test_provider_receipt_fails_closed_on_mismatch_or_weak_evidence(self):
        plan = build_backup_transfer_plan(
            self.package, self.manifest, object_ref="backups/receipt-reject.db.enc"
        )
        for field, replacement in (
            ("network_performed", False),
            ("encryption_verified", False),
            ("object_lock_verified", False),
            ("overwrite_performed", True),
            ("restore_authorized", True),
            ("retain_until", "2030-01-03T10:00:00-05:00"),
            ("provider_request_ref", "sk-" + "r" * 24),
            ("provider_region", "US_EAST"),
            ("provider_endpoint", "s3.us-east-005.backblazeb2.com"),
            ("provider_endpoint", "s3.ca-east-999.backblazeb2.com"),
            ("provider_writer_identity_ref", "sk-" + "w" * 24),
            ("provider_writer_identity_ref", "iac-vault-writer:wrong"),
            ("client_encryption_key_ref", "iac-keyring:wrong"),
            ("ciphertext_sha256", "not-a-hash"),
            ("ciphertext_bytes", 0),
            ("client_encryption_algorithm", "AES_CBC"),
            ("uploaded_at", "2029-01-02T10:00:00-05:00"),
            ("plan_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                with self.assertRaises(BackupAdapterError):
                    verify_backup_upload_receipt(
                        production_receipt(plan, **{field:replacement}), plan
                    )
        tampered=production_receipt(plan)
        tampered["provider_version_ref"]="changed"
        with self.assertRaisesRegex(BackupAdapterError, "modified"):
            verify_backup_upload_receipt(tampered, plan)


if __name__ == "__main__":
    unittest.main()
