import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sean_os import (
    Actor,
    BackupRestoreError,
    SeanOSStore,
    build_backup_restore_key_approval_package,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    build_isolated_backup_restore_plan,
    synthetic_backup_restore_preflight,
    validate_backup_restore_key_proposal,
    verify_backup_restore_key_approval_package,
    verify_isolated_backup_restore_plan,
    verify_synthetic_backup_restore_preflight,
)
from sean_os.monitoring import classify_alerts


ROOT = Path(__file__).resolve().parents[1]
BUCKET = "synthetic-ca-east-backup-bucket"


def restore_key_proposal():
    return json.loads(
        (ROOT / "backup-restore-key-proposal.example.json").read_text(encoding="utf-8")
    )


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


def upload_receipt(plan, **overrides):
    value = {
        "format": "sean-os-independent-backup-upload-receipt/v3",
        "evidence_mode": "PRODUCTION",
        "provider": "BACKBLAZE_B2",
        "provider_region": plan["data_region"],
        "provider_endpoint": plan["provider_endpoint"],
        "provider_writer_identity_ref": plan["provider_writer_identity_ref"],
        "plan_sha256": plan["plan_sha256"],
        "destination_ref": plan["destination_ref"],
        "object_ref": plan["object_ref"],
        "backup_sha256": plan["backup_sha256"],
        "backup_bytes": plan["backup_bytes"],
        "ciphertext_sha256": "1" * 64,
        "ciphertext_bytes": plan["backup_bytes"] + 512,
        "client_encryption_algorithm": "AES_256_GCM",
        "client_encryption_key_ref": plan["client_encryption_key_ref"],
        "provider_request_ref": "request-001",
        "provider_version_ref": "version-001",
        "encryption_mode": "IAC_MANAGED_AUTHENTICATED_ENCRYPTION_PLUS_PROVIDER_AES256",
        "encryption_verified": True,
        "object_lock_mode": "COMPLIANCE",
        "object_lock_verified": True,
        "retention_days": plan["retention_days"],
        "uploaded_at": "2030-01-02T10:00:00-05:00",
        "retain_until": "2030-02-01T10:00:00-05:00",
        "network_performed": True,
        "uploaded": True,
        "overwrite_performed": False,
        "restore_authorized": False,
        "credentials_persisted": False,
        "source_path_included": False,
    }
    value.update(overrides)
    value["receipt_sha256"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return value


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = SeanOSStore(root / "iac.db", scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name": "Synthetic"})
        manifest = self.store.backup_manifest(Actor.sean(), root / "backup.db")
        package = build_independent_backup_approval_package(drill_proposal())
        self.upload_plan = build_backup_transfer_plan(
            package,
            manifest,
            object_ref="backups/synthetic-restore-source.db.enc",
            provider_endpoint="s3.ca-east-006.backblazeb2.com",
            writer_identity_ref="managed-secret-store:synthetic-backup-writer-v1",
            client_encryption_key_ref="managed-secret-store:synthetic-aes256-v1",
        )
        self.upload_receipt = upload_receipt(self.upload_plan)
        self.key_package = build_backup_restore_key_approval_package(
            restore_key_proposal()
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def build_plan(self, **overrides):
        arguments = {
            "restore_target_ref": "isolated-restore:synthetic-iac-v1",
            "window_start": "2030-01-03T09:00:00-05:00",
            "window_end": "2030-01-03T11:00:00-05:00",
            "max_cost_cad": 1,
        }
        arguments.update(overrides)
        return build_isolated_backup_restore_plan(
            self.upload_plan, self.upload_receipt, self.key_package, **arguments
        )

    def test_restore_key_is_exact_read_only_distinct_and_non_creating(self):
        proposal = validate_backup_restore_key_proposal(restore_key_proposal())
        package = build_backup_restore_key_approval_package(proposal)
        self.assertEqual(verify_backup_restore_key_approval_package(package), package)
        self.assertIn("readFiles", proposal["capabilities"])
        for forbidden in (
            "listFiles", "writeFiles", "deleteFiles", "writeKeys", "deleteKeys",
            "writeBucketRetentions", "writeFileRetentions", "bypassGovernance",
        ):
            self.assertNotIn(forbidden, proposal["capabilities"])
        self.assertFalse(proposal["write_authorized"])
        self.assertFalse(package["creation_authorized"])

    def test_restore_key_rejects_writes_admin_secrets_and_long_duration(self):
        changes = []
        changed = restore_key_proposal()
        changed["capabilities"].append("writeFiles")
        changes.append(changed)
        changed = restore_key_proposal()
        changed["valid_duration_seconds"] = 14401
        changes.append(changed)
        changed = restore_key_proposal()
        changed["credential_destination_ref"] = "sk-" + "x" * 24
        changes.append(changed)
        changed = restore_key_proposal()
        changed["account_admin_authorized"] = True
        changes.append(changed)
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(BackupRestoreError):
                    validate_backup_restore_key_proposal(changed)

    def test_restore_plan_binds_exact_version_hashes_identity_and_is_no_action(self):
        plan = self.build_plan()
        self.assertEqual(verify_isolated_backup_restore_plan(plan), plan)
        self.assertEqual(plan["provider_version_ref"], "version-001")
        self.assertEqual(plan["ciphertext_sha256"], "1" * 64)
        self.assertNotEqual(
            plan["provider_restore_identity_ref"], plan["provider_writer_identity_ref"]
        )
        self.assertTrue(plan["isolated_restore"])
        for field in (
            "overwrite_permitted", "credentials_included", "network_enabled",
            "download_authorized", "decrypt_authorized", "restore_authorized",
        ):
            self.assertFalse(plan[field])
        preflight = synthetic_backup_restore_preflight(plan)
        self.assertEqual(verify_synthetic_backup_restore_preflight(preflight), preflight)
        self.assertFalse(preflight["network_performed"])
        self.assertFalse(preflight["downloaded"])
        self.assertFalse(preflight["restored"])

    def test_wrong_bucket_endpoint_identity_window_or_target_fails_closed(self):
        changed_key = restore_key_proposal()
        changed_key["bucket_ref"] = "different-ca-east-backup-bucket"
        wrong_bucket = build_backup_restore_key_approval_package(changed_key)
        with self.assertRaisesRegex(BackupRestoreError, "bucket"):
            build_isolated_backup_restore_plan(
                self.upload_plan, self.upload_receipt, wrong_bucket,
                restore_target_ref="isolated-restore:synthetic-iac-v1",
                window_start="2030-01-03T09:00:00-05:00",
                window_end="2030-01-03T11:00:00-05:00",
                max_cost_cad=1,
            )
        for overrides in (
            {"restore_target_ref": self.upload_plan["object_ref"]},
            {"window_start": "2030-01-01T09:00:00-05:00"},
            {"window_end": "2030-02-02T11:00:00-05:00"},
            {"max_cost_cad": 16},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(BackupRestoreError):
                    self.build_plan(**overrides)
        same_identity = copy.deepcopy(self.key_package)
        same_identity["proposal"]["credential_destination_ref"] = self.upload_plan[
            "provider_writer_identity_ref"
        ]
        same_identity = build_backup_restore_key_approval_package(same_identity["proposal"])
        with self.assertRaisesRegex(BackupRestoreError, "distinct"):
            build_isolated_backup_restore_plan(
                self.upload_plan, self.upload_receipt, same_identity,
                restore_target_ref="isolated-restore:synthetic-iac-v1",
                window_start="2030-01-03T09:00:00-05:00",
                window_end="2030-01-03T11:00:00-05:00",
                max_cost_cad=1,
            )

    def test_tampering_and_unverified_upload_evidence_are_rejected(self):
        plan = self.build_plan()
        changed = copy.deepcopy(plan)
        changed["download_authorized"] = True
        with self.assertRaises(BackupRestoreError):
            verify_isolated_backup_restore_plan(changed)
        changed = copy.deepcopy(plan)
        changed["approval_target"] = "ISOLATED_BACKUP_RESTORE:changed"
        changed["plan_sha256"] = hashlib.sha256(b"changed").hexdigest()
        with self.assertRaises(BackupRestoreError):
            verify_isolated_backup_restore_plan(changed)
        changed_receipt = copy.deepcopy(self.upload_receipt)
        changed_receipt["object_lock_verified"] = False
        with self.assertRaises(ValueError):
            build_isolated_backup_restore_plan(
                self.upload_plan, changed_receipt, self.key_package,
                restore_target_ref="isolated-restore:synthetic-iac-v1",
                window_start="2030-01-03T09:00:00-05:00",
                window_end="2030-01-03T11:00:00-05:00",
                max_cost_cad=1,
            )

    def test_cli_outputs_only_non_executing_restore_evidence(self):
        root = Path(self.temp.name)
        plan_path = root / "upload-plan.json"
        receipt_path = root / "upload-receipt.json"
        key_path = root / "restore-key.json"
        plan_path.write_text(json.dumps(self.upload_plan), encoding="utf-8")
        receipt_path.write_text(json.dumps(self.upload_receipt), encoding="utf-8")
        key_path.write_text(json.dumps(restore_key_proposal()), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable, "scripts/prepare_backup_restore.py",
                str(plan_path), str(receipt_path), str(key_path),
                "--restore-target-ref", "isolated-restore:synthetic-iac-v1",
                "--window-start", "2030-01-03T09:00:00-05:00",
                "--window-end", "2030-01-03T11:00:00-05:00",
                "--max-cost-cad", "1",
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertFalse(output["restore_key_package"]["creation_authorized"])
        self.assertFalse(output["restore_plan"]["network_enabled"])
        self.assertFalse(output["synthetic_preflight"]["execution_authorized"])
        self.assertNotIn("secret_access_key", result.stdout.lower())

    def test_durable_restore_requires_preflight_exact_approval_and_active_lease(self):
        plan = self.build_plan()
        staged = self.store.stage_backup_restore(
            Actor.sean(), plan, self.upload_plan, self.upload_receipt, self.key_package
        )
        self.assertEqual(staged["status"], "STAGED")
        preflight = synthetic_backup_restore_preflight(plan)
        ready = self.store.record_backup_restore_preflight(
            Actor("restore-operator", frozenset({"IAC"})), plan["plan_sha256"], preflight
        )
        self.assertEqual(ready["status"], "PREFLIGHT_VALIDATED")
        requester = Actor("iac-interface", frozenset({"IAC"}))
        approval_id = self.store.request_backup_restore_approval(
            requester, plan["plan_sha256"],
            max_impact="One isolated synthetic restore; no overwrite; CAD 1 maximum",
            expires_at="2030-01-03T10:30:00-05:00",
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True,
            reason="Exact isolated synthetic restore reviewed",
        )
        with self.assertRaisesRegex(PermissionError, "Only Sean"):
            self.store.authorize_backup_restore(
                requester, plan["plan_sha256"], approval_id=approval_id,
                at="2030-01-03T09:30:00-05:00",
            )
        authorized = self.store.authorize_backup_restore(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id,
            at="2030-01-03T09:30:00-05:00",
        )
        self.assertEqual(authorized["status"], "AUTHORIZED")
        self.assertFalse(authorized["plan_payload"]["network_enabled"])
        worker = Actor("restore-worker", frozenset({"IAC"}))
        claimed = self.store.claim_authorized_backup_restore(
            worker, "restore-worker-1", lease_seconds=300,
            at="2030-01-03T09:31:00-05:00",
        )
        self.assertEqual(claimed["lease_owner"], "restore-worker-1")
        self.assertEqual(claimed["attempt_count"], 1)
        guarded = self.store.assert_backup_restore_execution_allowed(
            worker, plan["plan_sha256"], "restore-worker-1",
            at="2030-01-03T09:32:00-05:00",
        )
        self.assertEqual(guarded["restore_plan_sha256"], plan["plan_sha256"])

    def test_restore_approval_conditions_are_exact_and_unconsumed_on_mismatch(self):
        plan = self.build_plan()
        self.store.stage_backup_restore(
            Actor.sean(), plan, self.upload_plan, self.upload_receipt, self.key_package
        )
        self.store.record_backup_restore_preflight(
            Actor.sean(), plan["plan_sha256"], synthetic_backup_restore_preflight(plan)
        )
        wrong = self.store.create_approval(
            Actor.sean(), action_type="RUN_ISOLATED_BACKUP_RESTORE",
            target=plan["approval_target"], scope="IAC", max_impact="Synthetic mismatch",
            approver="sean", expires_at="2030-01-03T10:30:00-05:00",
            conditions={"restore_plan_sha256": "0" * 64},
        )
        with self.assertRaisesRegex(PermissionError, "conditions"):
            self.store.authorize_backup_restore(
                Actor.sean(), plan["plan_sha256"], approval_id=wrong,
                at="2030-01-03T09:30:00-05:00",
            )
        self.assertEqual(
            self.store.connection.execute(
                "SELECT status FROM approvals WHERE record_id=?", (wrong,)
            ).fetchone()[0],
            "APPROVED",
        )
        self.assertEqual(
            self.store.get_backup_restore(Actor.sean(), plan["plan_sha256"])["status"],
            "PREFLIGHT_VALIDATED",
        )

    def test_restore_lease_is_kill_switch_window_and_retry_bounded(self):
        plan = self.build_plan()
        self.store.stage_backup_restore(
            Actor.sean(), plan, self.upload_plan, self.upload_receipt, self.key_package
        )
        self.store.record_backup_restore_preflight(
            Actor.sean(), plan["plan_sha256"], synthetic_backup_restore_preflight(plan)
        )
        approval_id = self.store.request_backup_restore_approval(
            Actor("iac-interface", frozenset({"IAC"})), plan["plan_sha256"],
            max_impact="Synthetic isolated restore",
            expires_at="2030-01-03T10:30:00-05:00",
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic retry test"
        )
        self.store.authorize_backup_restore(
            Actor.sean(), plan["plan_sha256"], approval_id=approval_id,
            at="2030-01-03T09:30:00-05:00",
        )
        worker = Actor("restore-worker", frozenset({"IAC"}))
        self.store.set_kill_switch(Actor.sean(), True)
        self.assertIsNone(self.store.claim_authorized_backup_restore(
            worker, "restore-worker-1", at="2030-01-03T09:31:00-05:00"
        ))
        self.store.set_kill_switch(Actor.sean(), False)
        first = self.store.claim_authorized_backup_restore(
            worker, "restore-worker-1", at="2030-01-03T09:31:00-05:00"
        )
        self.assertEqual(first["attempt_count"], 1)
        self.store.connection.execute(
            """UPDATE backup_restore_outbox SET attempt_count=2,
               lease_expires_at='2030-01-03T09:31:30-05:00'
               WHERE restore_plan_sha256=?""",
            (plan["plan_sha256"],),
        )
        self.store.connection.commit()
        final = self.store.claim_authorized_backup_restore(
            worker, "restore-worker-2", at="2030-01-03T09:32:00-05:00"
        )
        self.assertEqual(final["attempt_count"], 3)
        self.assertEqual(
            self.store.fail_claimed_backup_restore(
                worker, plan["plan_sha256"], "restore-worker-2",
                "Synthetic restore failure", retry_seconds=0,
            ),
            "FAILED",
        )
        health = self.store.runtime_health(scope="IAC")
        self.assertFalse(health["healthy"])
        self.assertEqual(health["backup_restore_outbox"]["FAILED"], 1)
        self.assertIn(
            "BACKUP_RESTORE_FAILED", {item["code"] for item in classify_alerts(health)}
        )

    def test_restore_outbox_requires_iac_profile_and_rejects_changed_preflight(self):
        plan = self.build_plan()
        development = SeanOSStore(Path(self.temp.name) / "development.db")
        try:
            with self.assertRaisesRegex(PermissionError, "IAC database profile"):
                development.stage_backup_restore(
                    Actor.sean(), plan, self.upload_plan, self.upload_receipt,
                    self.key_package,
                )
        finally:
            development.close()
        self.store.stage_backup_restore(
            Actor.sean(), plan, self.upload_plan, self.upload_receipt, self.key_package
        )
        changed = synthetic_backup_restore_preflight(plan)
        changed["upload_receipt_sha256"] = "0" * 64
        changed["receipt_sha256"] = hashlib.sha256(
            json.dumps(
                {key: value for key, value in changed.items() if key != "receipt_sha256"},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode()
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "upload evidence"):
            self.store.record_backup_restore_preflight(
                Actor.sean(), plan["plan_sha256"], changed
            )


if __name__ == "__main__":
    unittest.main()
