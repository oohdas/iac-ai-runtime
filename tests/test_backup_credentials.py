import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from sean_os import (
    BackupCredentialError,
    build_backup_writer_key_approval_package,
    validate_backup_writer_key_proposal,
    verify_backup_writer_key_approval_package,
)


ROOT = Path(__file__).resolve().parents[1]


def synthetic_proposal():
    return json.loads(
        (ROOT / "backup-writer-key-proposal.example.json").read_text(encoding="utf-8")
    )


class BackupCredentialTests(unittest.TestCase):
    def test_exact_writer_key_contract_is_deterministic_and_non_creating(self):
        proposal = synthetic_proposal()
        package = build_backup_writer_key_approval_package(proposal)
        self.assertEqual(package, build_backup_writer_key_approval_package(proposal))
        self.assertEqual(verify_backup_writer_key_approval_package(package), package)
        self.assertTrue(package["approval_required"])
        self.assertFalse(package["creation_authorized"])
        self.assertFalse(package["proposal"]["production_data_authorized"])
        self.assertFalse(package["proposal"]["account_admin_authorized"])

    def test_capability_allowlist_is_bucket_prefix_and_upload_only(self):
        value = validate_backup_writer_key_proposal(synthetic_proposal())
        self.assertEqual(value["file_name_prefix"], "backups/")
        self.assertEqual(value["data_region"], "CA_EAST")
        self.assertIn("writeFiles", value["capabilities"])
        for prohibited in (
            "readFiles", "deleteFiles", "writeKeys", "deleteKeys",
            "writeBuckets", "deleteBuckets", "writeBucketRetentions",
            "writeFileRetentions", "bypassGovernance",
        ):
            self.assertNotIn(prohibited, value["capabilities"])

    def test_extra_missing_or_modified_capabilities_fail_closed(self):
        for mutate in (
            lambda value: value["capabilities"].append("deleteFiles"),
            lambda value: value["capabilities"].remove("readFileRetentions"),
            lambda value: value["capabilities"].reverse(),
        ):
            changed = synthetic_proposal()
            mutate(changed)
            with self.assertRaisesRegex(BackupCredentialError, "exact allowlist"):
                validate_backup_writer_key_proposal(changed)

    def test_wrong_region_bucket_prefix_or_duration_fails_closed(self):
        for field, replacement in (
            ("provider_endpoint", "s3.us-east-005.backblazeb2.com"),
            ("bucket_ref", "Not A Bucket"),
            ("file_name_prefix", ""),
            ("valid_duration_seconds", 14401),
            ("valid_duration_seconds", True),
        ):
            changed = synthetic_proposal()
            changed[field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(BackupCredentialError):
                    validate_backup_writer_key_proposal(changed)

    def test_secret_material_and_package_tampering_are_rejected(self):
        changed = synthetic_proposal()
        changed["credential_destination_ref"] = "sk-" + "x" * 24
        with self.assertRaisesRegex(BackupCredentialError, "Secret-like"):
            validate_backup_writer_key_proposal(changed)
        package = build_backup_writer_key_approval_package(synthetic_proposal())
        tampered = copy.deepcopy(package)
        tampered["proposal_sha256"] = "0" * 64
        with self.assertRaisesRegex(BackupCredentialError, "modified"):
            verify_backup_writer_key_approval_package(tampered)

    def test_cli_prints_a_non_creating_package_without_secrets(self):
        result = subprocess.run(
            [
                sys.executable,
                "scripts/prepare_backup_writer_key.py",
                "backup-writer-key-proposal.example.json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        package = json.loads(result.stdout)
        self.assertFalse(package["creation_authorized"])
        self.assertNotIn("secret_access_key", result.stdout.lower())
        self.assertNotIn("application_key_id", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
