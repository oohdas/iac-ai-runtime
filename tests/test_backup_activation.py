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
    BackupActivationError,
    SeanOSStore,
    get_supervised_synthetic_backup_activation_evidence,
    prepare_supervised_synthetic_backup_activation,
    verify_supervised_synthetic_backup_activation,
)
from sean_os.backup_activation import _verify_synthetic_source_database


ROOT=Path(__file__).resolve().parents[1]
COMMIT="2" * 40
START="2030-01-02T09:00:00-05:00"
END="2030-01-02T11:00:00-05:00"


def rehash(package):
    value=copy.deepcopy(package)
    value.pop("activation_sha256", None)
    value["activation_sha256"]=hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()
    return value


class BackupActivationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        self.database=self.root / "iac.db"
        self.workspace=self.root / "backup-staging"
        self.store=SeanOSStore(self.database, scope_profile="IAC")

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def prepare(self):
        return prepare_supervised_synthetic_backup_activation(
            self.store, workspace=self.workspace, candidate_commit=COMMIT,
            window_start=START, window_end=END,
        )

    def test_prepares_private_synthetic_source_and_stages_no_network_transfer(self):
        package=self.prepare()
        self.assertEqual(
            verify_supervised_synthetic_backup_activation(package), package
        )
        self.assertEqual(package["data_mode"], "SYNTHETIC_IAC_DATABASE_ONLY")
        self.assertEqual(package["transfer_status"], "PREFLIGHT_VALIDATED")
        self.assertFalse(package["network_performed"])
        self.assertFalse(package["key_created"])
        self.assertFalse(package["secret_placed"])
        self.assertFalse(package["upload_authorized"])
        source=Path(package["backup_manifest"]["path"])
        manifest=Path(package["non_secret_runtime"]["SEAN_OS_BACKUP_MANIFEST_PATH"])
        activation=next(self.workspace.glob("*.activation.json"))
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(activation.stat().st_mode & 0o777, 0o600)
        self.assertFalse(Path(
            package["non_secret_runtime"]["SEAN_OS_BACKUP_OUTPUT_DIRECTORY"]
        ).exists())
        synthetic=SeanOSStore(source, scope_profile="IAC")
        try:
            records=synthetic.list_records(Actor.sean(), entity_type="KNOWLEDGE")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["payload"]["data_mode"], "SYNTHETIC_ONLY")
        finally:
            synthetic.close()
        transfer=self.store.get_backup_transfer(
            Actor.sean(), package["transfer_plan"]["plan_sha256"]
        )
        self.assertEqual(transfer["status"], "PREFLIGHT_VALIDATED")
        self.assertIsNone(transfer["approval_id"])
        self.assertEqual(transfer["attempt_count"], 0)
        activation=self.store.connection.execute(
            "SELECT * FROM backup_activation_evidence WHERE plan_sha256=?",
            (package["transfer_plan"]["plan_sha256"],),
        ).fetchone()
        self.assertEqual(activation["activation_sha256"], package["activation_sha256"])
        self.assertEqual(activation["data_mode"], "SYNTHETIC_IAC_DATABASE_ONLY")
        self.assertEqual(activation["real_data_authorized"], 0)
        self.assertEqual(
            json.loads(activation["activation_payload"])["activation_sha256"],
            package["activation_sha256"],
        )

    def test_tampering_remains_invalid_even_if_digest_is_recomputed(self):
        package=self.prepare()
        for mutate in (
            lambda value: value.__setitem__("upload_authorized", True),
            lambda value: value["required_next_gates"].pop(),
            lambda value: value["non_secret_runtime"].__setitem__(
                "SEAN_OS_BACKUP_BUCKET", "different-ca-east-bucket"
            ),
        ):
            changed=copy.deepcopy(package)
            mutate(changed)
            changed=rehash(changed)
            with self.assertRaises(BackupActivationError):
                verify_supervised_synthetic_backup_activation(changed)

    def test_durable_activation_payload_is_reverified_before_operator_use(self):
        package=self.prepare()
        plan_sha=package["transfer_plan"]["plan_sha256"]
        row=self.store.connection.execute(
            "SELECT activation_payload FROM backup_activation_evidence WHERE plan_sha256=?",
            (plan_sha,),
        ).fetchone()
        changed=json.loads(row["activation_payload"])
        changed["data_mode"]="UNTRUSTED"
        self.store.connection.execute(
            "UPDATE backup_activation_evidence SET activation_payload=? WHERE plan_sha256=?",
            (json.dumps(changed, sort_keys=True), plan_sha),
        )
        self.store.connection.commit()
        with self.assertRaisesRegex(BackupActivationError, "payload is invalid"):
            get_supervised_synthetic_backup_activation_evidence(
                self.store, Actor.sean(), plan_sha
            )

    def test_workspace_is_volume_confined_private_and_non_overwriting(self):
        outside=Path(self.temporary.name).parent / "outside-backup-staging"
        with self.assertRaisesRegex(BackupActivationError, "inside the data volume"):
            prepare_supervised_synthetic_backup_activation(
                self.store, workspace=outside, candidate_commit=COMMIT,
                window_start=START, window_end=END,
            )
        self.prepare()
        with self.assertRaisesRegex(BackupActivationError, "must not already exist"):
            self.prepare()

    def test_non_sentinel_iac_database_cannot_be_attested_as_synthetic(self):
        source=self.root / "not-synthetic.db"
        other=SeanOSStore(source, scope_profile="IAC")
        try:
            other.create_record(
                Actor.sean(), "KNOWLEDGE", "IAC", {"name":"Ordinary IAC record"}
            )
        finally:
            other.close()
        with self.assertRaisesRegex(BackupActivationError, "sentinel is invalid"):
            _verify_synthetic_source_database(source)

        second=SeanOSStore(source, scope_profile="IAC")
        try:
            second.create_record(
                Actor.sean(), "KNOWLEDGE", "IAC",
                {"name":"Synthetic backup drill sentinel", "data_mode":"SYNTHETIC_ONLY"},
            )
        finally:
            second.close()
        with self.assertRaisesRegex(BackupActivationError, "exactly one"):
            _verify_synthetic_source_database(source)

    def test_cli_outputs_only_bounded_no_network_summary(self):
        self.store.close()
        completed=subprocess.run(
            [
                sys.executable, "scripts/prepare_supervised_backup_activation.py",
                str(self.database), str(self.workspace), COMMIT, START,
                "--duration-minutes", "120",
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.store=SeanOSStore(self.database, scope_profile="IAC")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary=json.loads(completed.stdout)
        self.assertEqual(summary["data_mode"], "SYNTHETIC_IAC_DATABASE_ONLY")
        self.assertEqual(summary["transfer_status"], "PREFLIGHT_VALIDATED")
        self.assertFalse(summary["network_performed"])
        self.assertFalse(summary["key_created"])
        self.assertFalse(summary["secret_placed"])
        self.assertFalse(summary["upload_authorized"])
        self.assertNotIn("backup_manifest", summary)
        self.assertNotIn("non_secret_runtime", summary)


if __name__ == "__main__":
    unittest.main()
