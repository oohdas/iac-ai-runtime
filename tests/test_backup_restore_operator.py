import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from sean_os import (
    Actor,
    BackupRestoreOperatorError,
    SeanOSStore,
    authorize_exact_restore_state,
    build_backup_restore_key_approval_package,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    build_isolated_backup_restore_plan,
    decide_exact_restore_approval,
    request_exact_restore_approval,
    review_backup_restore,
    synthetic_backup_restore_preflight,
)
from tests.test_backup_restore import drill_proposal, restore_key_proposal, upload_receipt


ROOT = Path(__file__).resolve().parents[1]


class BackupRestoreOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "iac.db"
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name": "Synthetic"})
        manifest = self.store.backup_manifest(Actor.sean(), self.root / "backup.db")
        self.upload_plan = build_backup_transfer_plan(
            build_independent_backup_approval_package(drill_proposal()),
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
        self.plan = build_isolated_backup_restore_plan(
            self.upload_plan,
            self.upload_receipt,
            self.key_package,
            restore_target_ref="isolated-restore:synthetic-iac-v1",
            window_start="2030-01-03T09:00:00-05:00",
            window_end="2030-01-03T11:00:00-05:00",
            max_cost_cad=1,
        )
        self.plan_sha256 = self.plan["plan_sha256"]
        self.interface = Actor("iac-restore-interface", frozenset({"IAC"}))
        self.store.stage_backup_restore(
            self.interface,
            self.plan,
            self.upload_plan,
            self.upload_receipt,
            self.key_package,
        )
        self.store.record_backup_restore_preflight(
            self.interface,
            self.plan_sha256,
            synthetic_backup_restore_preflight(self.plan),
        )
        self.instant = datetime.fromisoformat("2030-01-03T09:30:00-05:00")
        self.expiry = self.instant + timedelta(hours=1)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def review(self, actor=None):
        return review_backup_restore(
            self.store, actor or self.interface, self.plan_sha256
        )

    def request(self, review):
        return request_exact_restore_approval(
            self.store,
            self.interface,
            self.plan_sha256,
            expected_review_sha256=review["review_sha256"],
            expires_at=self.expiry.isoformat(),
            current_time=self.instant,
        )

    def test_review_is_stable_path_free_and_read_only(self):
        before = len(self.store.audit_events())
        first = self.review()
        self.assertEqual(first, self.review())
        self.assertEqual(len(self.store.audit_events()), before)
        self.assertTrue(first["preflight_validated"])
        self.assertEqual(first["restore_status"], "PREFLIGHT_VALIDATED")
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("plan_payload", serialized)
        self.assertFalse(first["network_performed_by_operation"])
        self.assertFalse(first["restore_performed_by_operation"])

    def test_request_decision_and_state_authorization_are_separate(self):
        requested = self.request(self.review())
        approval_id = requested["approval_id"]
        self.assertEqual(requested["approval_status"], "PENDING")
        self.assertEqual(requested["restore_status"], "PREFLIGHT_VALIDATED")
        self.assertFalse(requested["restore_claimed"])
        pending = self.review(Actor.sean())
        approved = decide_exact_restore_approval(
            self.store,
            Actor.sean(),
            self.plan_sha256,
            approval_id=approval_id,
            approve=True,
            reason="Exact isolated synthetic restore reviewed",
            expected_review_sha256=pending["review_sha256"],
        )
        self.assertEqual(approved["approval_status"], "APPROVED")
        authorized = authorize_exact_restore_state(
            self.store,
            Actor.sean(),
            self.plan_sha256,
            approval_id=approval_id,
            expected_review_sha256=self.review(Actor.sean())["review_sha256"],
            confirm_plan_sha256=self.plan_sha256,
            environment={},
            current_time=self.instant,
        )
        self.assertEqual(authorized["approval_status"], "CONSUMED")
        self.assertEqual(authorized["restore_status"], "AUTHORIZED")
        for field in ("network_performed", "downloaded", "decrypted", "restored"):
            self.assertFalse(authorized[field])
        row = self.store.get_backup_restore(Actor.sean(), self.plan_sha256)
        self.assertIsNone(row["lease_owner"])

    def test_stale_review_configured_runtime_and_wrong_confirmation_fail_closed(self):
        stale = self.review()
        approval_id = self.request(stale)["approval_id"]
        with self.assertRaisesRegex(BackupRestoreOperatorError, "stale"):
            decide_exact_restore_approval(
                self.store,
                Actor.sean(),
                self.plan_sha256,
                approval_id=approval_id,
                approve=True,
                reason="Reviewed",
                expected_review_sha256=stale["review_sha256"],
            )
        pending = self.review(Actor.sean())
        decide_exact_restore_approval(
            self.store,
            Actor.sean(),
            self.plan_sha256,
            approval_id=approval_id,
            approve=True,
            reason="Reviewed",
            expected_review_sha256=pending["review_sha256"],
        )
        approved = self.review(Actor.sean())
        with self.assertRaisesRegex(BackupRestoreOperatorError, "confirmation"):
            authorize_exact_restore_state(
                self.store,
                Actor.sean(),
                self.plan_sha256,
                approval_id=approval_id,
                expected_review_sha256=approved["review_sha256"],
                confirm_plan_sha256="0" * 64,
                environment={},
                current_time=self.instant,
            )
        with self.assertRaisesRegex(BackupRestoreOperatorError, "values absent"):
            authorize_exact_restore_state(
                self.store,
                Actor.sean(),
                self.plan_sha256,
                approval_id=approval_id,
                expected_review_sha256=approved["review_sha256"],
                confirm_plan_sha256=self.plan_sha256,
                environment={"SEAN_OS_MANAGED_B2_RESTORE_KEY_ID": "configured"},
                current_time=self.instant,
            )
        self.assertEqual(
            self.store.get_backup_restore(Actor.sean(), self.plan_sha256)["status"],
            "PREFLIGHT_VALIDATED",
        )

    def test_cli_review_is_bounded_and_rejects_stale_request(self):
        self.store.close()
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/restore_operator.py",
                "review",
                str(self.database),
                self.plan_sha256,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(completed.stdout)["restore_plan_sha256"], self.plan_sha256
        )
        self.assertNotIn(str(self.root), completed.stdout)
        self.store.close()
        rejected = subprocess.run(
            [
                sys.executable,
                "scripts/restore_operator.py",
                "request",
                str(self.database),
                self.plan_sha256,
                "--expected-review-sha256",
                "0" * 64,
                "--expires-at",
                self.expiry.isoformat(),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(
            json.loads(rejected.stdout),
            {"ok": False, "error": "restore_operator_request_rejected"},
        )
        self.assertNotIn(self.plan_sha256, rejected.stdout)

    def test_cli_stage_reverifies_evidence_and_records_only_no_action_state(self):
        upload_plan = self.root / "upload-plan.json"
        upload_receipt_path = self.root / "upload-receipt.json"
        key_proposal = self.root / "restore-key-proposal.json"
        upload_plan.write_text(json.dumps(self.upload_plan), encoding="utf-8")
        upload_receipt_path.write_text(
            json.dumps(self.upload_receipt), encoding="utf-8"
        )
        key_proposal.write_text(json.dumps(restore_key_proposal()), encoding="utf-8")
        staged_database = self.root / "staged-iac.db"
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/restore_operator.py",
                "stage",
                str(staged_database),
                str(upload_plan),
                str(upload_receipt_path),
                str(key_proposal),
                "--restore-target-ref",
                self.plan["restore_target_ref"],
                "--window-start",
                self.plan["window_start"],
                "--window-end",
                self.plan["window_end"],
                "--max-cost-cad",
                str(self.plan["max_cost_cad"]),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["restore_plan_sha256"], self.plan_sha256)
        self.assertEqual(result["status"], "PREFLIGHT_VALIDATED")
        for field in (
            "network_performed", "downloaded", "decrypted", "restored",
            "execution_authorized",
        ):
            self.assertFalse(result[field])
        self.assertNotIn(str(self.root), completed.stdout)
        staged = SeanOSStore(staged_database, scope_profile="IAC")
        try:
            row = staged.get_backup_restore(Actor.sean(), self.plan_sha256)
            self.assertEqual(row["status"], "PREFLIGHT_VALIDATED")
            self.assertIsNone(row["approval_id"])
            self.assertIsNone(row["lease_owner"])
        finally:
            staged.close()


if __name__ == "__main__":
    unittest.main()
