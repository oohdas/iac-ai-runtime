import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sean_os import (
    Actor,
    BackupActivationError,
    AuthorizationError,
    BackupOperatorError,
    SeanOSStore,
    authorize_exact_backup_state,
    decide_exact_backup_approval,
    prepare_supervised_synthetic_backup_activation,
    request_exact_backup_approval,
    review_backup_transfer,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "3" * 40


class BackupOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "iac.db"
        self.workspace = self.root / "backup-staging"
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.instant = datetime.now(timezone.utc).replace(microsecond=0)
        self.start = self.instant - timedelta(minutes=1)
        self.end = self.instant + timedelta(hours=1)
        self.expiry = self.instant + timedelta(minutes=45)
        package = prepare_supervised_synthetic_backup_activation(
            self.store,
            workspace=self.workspace,
            candidate_commit=COMMIT,
            window_start=self.start.isoformat(),
            window_end=self.end.isoformat(),
        )
        self.plan_sha256 = package["transfer_plan"]["plan_sha256"]
        self.interface_actor = Actor("iac-backup-interface", frozenset({"IAC"}))

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def review(self, actor=None):
        return review_backup_transfer(
            self.store, actor or self.interface_actor, self.plan_sha256
        )

    def request(self, review):
        return request_exact_backup_approval(
            self.store,
            self.interface_actor,
            self.plan_sha256,
            expected_review_sha256=review["review_sha256"],
            expires_at=self.expiry.isoformat(),
            current_time=self.instant,
        )

    def approve(self, approval_id, review):
        return decide_exact_backup_approval(
            self.store,
            Actor.sean(),
            self.plan_sha256,
            approval_id=approval_id,
            approve=True,
            reason="Exact synthetic plan reviewed",
            expected_review_sha256=review["review_sha256"],
        )

    def test_review_is_stable_path_free_secret_free_and_read_only(self):
        before = len(self.store.audit_events())
        first = self.review()
        second = self.review()
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.audit_events()), before)
        self.assertEqual(first["transfer_status"], "PREFLIGHT_VALIDATED")
        self.assertTrue(first["preflight_validated"])
        self.assertEqual(first["data_mode"], "SYNTHETIC_IAC_DATABASE_ONLY")
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("plan_payload", first)
        self.assertNotIn("preflight_receipt_payload", first)
        self.store.close()
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(self.review(), first)

    def test_operator_rejects_transfer_without_durable_synthetic_attestation(self):
        self.store.connection.execute(
            "DELETE FROM backup_activation_evidence WHERE plan_sha256=?",
            (self.plan_sha256,),
        )
        self.store.connection.commit()
        with self.assertRaisesRegex(BackupActivationError, "lacks verified synthetic"):
            self.review()
        self.store.close()
        completed=subprocess.run(
            [
                sys.executable, "scripts/backup_operator.py", "review",
                str(self.database), self.plan_sha256,
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.store=SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            json.loads(completed.stdout),
            {"ok":False, "error":"backup_operator_request_rejected"},
        )
        self.assertNotIn(str(self.root), completed.stdout + completed.stderr)

    def test_request_decision_and_authorization_are_separate_and_restart_safe(self):
        initial = self.review()
        requested = self.request(initial)
        approval_id = requested["approval_id"]
        self.assertEqual(requested["operation"], "REQUEST_APPROVAL")
        self.assertEqual(requested["approval_status"], "PENDING")
        self.assertEqual(requested["transfer_status"], "PREFLIGHT_VALIDATED")
        self.assertFalse(requested["network_performed"])

        pending = self.review()
        self.assertEqual(pending["approvals"][0]["status"], "PENDING")
        self.assertTrue(pending["approvals"][0]["conditions_match"])
        with self.assertRaises(AuthorizationError):
            decide_exact_backup_approval(
                self.store,
                self.interface_actor,
                self.plan_sha256,
                approval_id=approval_id,
                approve=True,
                reason="Not Sean",
                expected_review_sha256=pending["review_sha256"],
            )

        self.store.close()
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        pending = self.review()
        approved = self.approve(approval_id, pending)
        self.assertEqual(approved["operation"], "APPROVE")
        self.assertEqual(approved["approval_status"], "APPROVED")
        self.assertEqual(approved["transfer_status"], "PREFLIGHT_VALIDATED")

        decided = self.review(Actor.sean())
        authorized = authorize_exact_backup_state(
            self.store,
            Actor.sean(),
            self.plan_sha256,
            approval_id=approval_id,
            expected_review_sha256=decided["review_sha256"],
            confirm_plan_sha256=self.plan_sha256,
            environment={},
            current_time=self.instant,
        )
        self.assertEqual(authorized["operation"], "AUTHORIZE_STATE_ONLY")
        self.assertEqual(authorized["approval_status"], "CONSUMED")
        self.assertEqual(authorized["transfer_status"], "AUTHORIZED")
        self.assertFalse(authorized["network_performed"])
        self.assertFalse(authorized["upload_performed"])
        self.assertFalse(authorized["transfer_claimed"])
        consumed = self.store.connection.execute(
            "SELECT status FROM approvals WHERE record_id=?", (approval_id,)
        ).fetchone()["status"]
        self.assertEqual(consumed, "CONSUMED")

    def test_stale_review_wrong_confirmation_and_configured_runtime_fail_closed(self):
        stale = self.review()
        requested = self.request(stale)
        approval_id = requested["approval_id"]
        with self.assertRaisesRegex(BackupOperatorError, "stale"):
            self.approve(approval_id, stale)
        pending = self.review()
        self.approve(approval_id, pending)
        approved = self.review(Actor.sean())
        with self.assertRaisesRegex(BackupOperatorError, "confirmation"):
            authorize_exact_backup_state(
                self.store, Actor.sean(), self.plan_sha256,
                approval_id=approval_id,
                expected_review_sha256=approved["review_sha256"],
                confirm_plan_sha256="4" * 64,
                environment={}, current_time=self.instant,
            )
        with self.assertRaisesRegex(BackupOperatorError, "values absent"):
            authorize_exact_backup_state(
                self.store, Actor.sean(), self.plan_sha256,
                approval_id=approval_id,
                expected_review_sha256=approved["review_sha256"],
                confirm_plan_sha256=self.plan_sha256,
                environment={"SEAN_OS_BACKUP_EXECUTION": "APPROVED"},
                current_time=self.instant,
            )
        transfer = self.store.get_backup_transfer(Actor.sean(), self.plan_sha256)
        self.assertEqual(transfer["status"], "PREFLIGHT_VALIDATED")
        approval = self.store.connection.execute(
            "SELECT status FROM approvals WHERE record_id=?", (approval_id,)
        ).fetchone()
        self.assertEqual(approval["status"], "APPROVED")

    def test_out_of_window_expiry_denial_and_changed_conditions_cannot_authorize(self):
        initial = self.review()
        with self.assertRaisesRegex(BackupOperatorError, "window end"):
            request_exact_backup_approval(
                self.store, self.interface_actor, self.plan_sha256,
                expected_review_sha256=initial["review_sha256"],
                expires_at=(self.instant + timedelta(hours=5)).isoformat(),
                current_time=self.instant,
            )
        requested = self.request(initial)
        approval_id = requested["approval_id"]
        pending = self.review()
        denied = decide_exact_backup_approval(
            self.store, Actor.sean(), self.plan_sha256,
            approval_id=approval_id, approve=False,
            reason="Synthetic transfer not approved",
            expected_review_sha256=pending["review_sha256"],
        )
        self.assertEqual(denied["operation"], "DENY")
        with self.assertRaises(BackupOperatorError):
            authorize_exact_backup_state(
                self.store, Actor.sean(), self.plan_sha256,
                approval_id=approval_id,
                expected_review_sha256=self.review()["review_sha256"],
                confirm_plan_sha256=self.plan_sha256,
                environment={}, current_time=self.instant,
            )

        fresh = self.review()
        requested = self.request(fresh)
        second_id = requested["approval_id"]
        conditions = self.store.connection.execute(
            "SELECT conditions FROM approvals WHERE record_id=?", (second_id,)
        ).fetchone()["conditions"]
        changed = json.loads(conditions)
        changed["retention_days"] = 31
        self.store.connection.execute(
            "UPDATE approvals SET conditions=? WHERE record_id=?",
            (json.dumps(changed, sort_keys=True), second_id),
        )
        self.store.connection.commit()
        changed_review = self.review(Actor.sean())
        changed_approval = next(
            item for item in changed_review["approvals"]
            if item["approval_id"] == second_id
        )
        self.assertFalse(changed_approval["conditions_match"])
        with self.assertRaisesRegex(BackupOperatorError, "exact pending"):
            self.approve(second_id, changed_review)

    def test_expired_pending_request_is_retired_before_fresh_request(self):
        first = self.request(self.review())
        old_id = first["approval_id"]
        expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.store.connection.execute(
            "UPDATE approvals SET expires_at=? WHERE record_id=?", (expired, old_id)
        )
        self.store.connection.commit()
        stale_pending = self.review()
        second = self.request(stale_pending)
        self.assertNotEqual(second["approval_id"], old_id)
        old_status = self.store.connection.execute(
            "SELECT status FROM approvals WHERE record_id=?", (old_id,)
        ).fetchone()["status"]
        self.assertEqual(old_status, "EXPIRED")
        current = self.review()
        pending = [item for item in current["approvals"] if item["status"] == "PENDING"]
        self.assertEqual([item["approval_id"] for item in pending], [second["approval_id"]])

    def test_cli_review_is_bounded_and_rejects_stale_mutation_without_detail_leak(self):
        self.store.close()
        completed = subprocess.run(
            [
                sys.executable, "scripts/backup_operator.py", "review",
                str(self.database), self.plan_sha256,
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        review = json.loads(completed.stdout)
        self.assertEqual(review["plan_sha256"], self.plan_sha256)
        self.assertNotIn(str(self.root), completed.stdout)

        self.store.close()
        rejected = subprocess.run(
            [
                sys.executable, "scripts/backup_operator.py", "request",
                str(self.database), self.plan_sha256,
                "--expected-review-sha256", "0" * 64,
                "--expires-at", self.expiry.isoformat(),
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.store = SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(
            json.loads(rejected.stdout),
            {"ok": False, "error": "backup_operator_request_rejected"},
        )
        self.assertNotIn(self.plan_sha256, rejected.stdout)


if __name__ == "__main__":
    unittest.main()
