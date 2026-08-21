import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sean_os import (
    BackupApprovalError,
    build_independent_backup_approval_package,
    validate_independent_backup_proposal,
    verify_independent_backup_approval_package,
)


ROOT = Path(__file__).resolve().parents[1]


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


class BackupApprovalTests(unittest.TestCase):
    def test_package_is_deterministic_exact_and_non_executing(self):
        proposal=synthetic_proposal()
        first=build_independent_backup_approval_package(proposal)
        second=build_independent_backup_approval_package(copy.deepcopy(proposal))
        self.assertEqual(first, second)
        canonical=json.dumps(
            first["proposal"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        self.assertEqual(
            first["proposal_sha256"], hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
        self.assertEqual(
            first["approval_target"], f"backup-drill:{first['proposal_sha256']}"
        )
        self.assertTrue(first["approval_required"])
        self.assertFalse(first["execution_authorized"])
        self.assertEqual(verify_independent_backup_approval_package(first), first)

    def test_unknown_or_missing_fields_fail_closed(self):
        extra=synthetic_proposal(); extra["provider_token"]="not-allowed"
        missing=synthetic_proposal(); missing.pop("retention_days")
        for proposal in (extra, missing):
            with self.subTest(fields=set(proposal)):
                with self.assertRaisesRegex(BackupApprovalError, "fields"):
                    build_independent_backup_approval_package(proposal)

    def test_scope_identity_and_ownership_are_fixed_for_v01(self):
        mutations={
            "owner_scope":"PERSONAL",
            "operator":"automation-agent",
            "rollback_owner":"automation-agent",
            "encryption_key_owner":"PERSONAL",
            "access_owner":"PERSONAL",
        }
        for field, replacement in mutations.items():
            proposal=synthetic_proposal(); proposal[field]=replacement
            with self.subTest(field=field):
                with self.assertRaises(BackupApprovalError):
                    validate_independent_backup_proposal(proposal)

    def test_provider_and_data_region_are_exact_and_supported(self):
        for field, replacement in (
            ("destination_provider", "GENERIC_S3"),
            ("data_region", "AUTO"),
            ("data_region", "ca-east"),
        ):
            proposal=synthetic_proposal(); proposal[field]=replacement
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaises(BackupApprovalError):
                    validate_independent_backup_proposal(proposal)

    def test_required_safety_flags_cannot_be_weakened(self):
        mutations={
            "independent_from_primary":False,
            "encryption_at_rest":False,
            "object_lock_enabled":False,
            "isolated_restore":False,
            "kill_switch_change_requested":False,
            "overwrite_production":True,
            "live_connectors_enabled":True,
            "real_data_authorized":True,
        }
        for field, replacement in mutations.items():
            proposal=synthetic_proposal(); proposal[field]=replacement
            with self.subTest(field=field):
                with self.assertRaises(BackupApprovalError):
                    validate_independent_backup_proposal(proposal)

    def test_retention_cost_and_window_are_bounded(self):
        mutations=(
            ("retention_days", 6),
            ("retention_days", 3651),
            ("max_cost_cad", -1),
            ("max_cost_cad", 15.01),
            ("max_cost_cad", float("nan")),
            ("window_end", "2030-01-02T08:00:00-05:00"),
            ("window_end", "2030-01-02T14:00:01-05:00"),
            ("window_start", "2030-01-02T09:00:00"),
        )
        for field, replacement in mutations:
            proposal=synthetic_proposal(); proposal[field]=replacement
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaises(BackupApprovalError):
                    validate_independent_backup_proposal(proposal)

    def test_primary_destination_restore_and_secret_evidence_are_rejected(self):
        for field, replacement in (
            ("destination_ref", "synthetic-primary-volume"),
            ("restore_target_ref", "synthetic-service"),
            ("restore_target_ref", "synthetic-backup-vault:object-001"),
            ("destination_ref", "sk-" + "b" * 24),
        ):
            proposal=synthetic_proposal(); proposal[field]=replacement
            with self.subTest(field=field):
                with self.assertRaises(BackupApprovalError):
                    validate_independent_backup_proposal(proposal)

    def test_modified_package_fails_verification(self):
        package=build_independent_backup_approval_package(synthetic_proposal())
        mutations=(
            ("proposal_sha256", "0" * 64),
            ("approval_target", "backup-drill:" + "0" * 64),
            ("approval_required", False),
            ("execution_authorized", True),
        )
        for field, replacement in mutations:
            modified=copy.deepcopy(package); modified[field]=replacement
            with self.subTest(field=field):
                with self.assertRaisesRegex(BackupApprovalError, "modified"):
                    verify_independent_backup_approval_package(modified)

    def test_cli_prints_package_but_never_authorizes_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            proposal=Path(directory) / "proposal.json"
            proposal.write_text(json.dumps(synthetic_proposal()), encoding="utf-8")
            result=subprocess.run(
                [sys.executable, "scripts/prepare_backup_approval.py", str(proposal)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        package=json.loads(result.stdout)
        self.assertFalse(package["execution_authorized"])
        self.assertTrue(package["approval_required"])
        verify_independent_backup_approval_package(package)


if __name__ == "__main__":
    unittest.main()
