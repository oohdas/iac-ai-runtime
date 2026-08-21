import copy
import hashlib
import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sean_os import (
    Actor,
    AES256GCMFileEncryptor,
    AuthorizationError,
    BackupExecutionError,
    EncryptedBackupArtifact,
    SeanOSStore,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    execute_claimed_backup_transfer,
    load_backup_runtime_config,
    synthetic_backup_adapter_receipt,
)


class SyntheticKeyResolver:
    def __init__(self):
        self.buffers = []

    @contextmanager
    def open_key(self, key_ref):
        material = bytearray(b"e" * 32)
        self.buffers.append(material)
        yield material


def proposal_for(instant: datetime) -> dict[str, object]:
    return {
        "format":"sean-os-independent-backup-drill-proposal/v2",
        "owner_scope":"IAC",
        "project_id":"synthetic-project",
        "environment_id":"synthetic-environment",
        "service_id":"synthetic-service",
        "primary_volume_id":"synthetic-primary-volume",
        "destination_kind":"ENCRYPTED_OBJECT_STORAGE",
        "destination_provider":"BACKBLAZE_B2",
        "destination_ref":"synthetic-ca-east-vault:object-001",
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
    }


class FakeEncryptor:
    def __init__(self, root: Path, *, after_write=None, evidence_overrides=None):
        self.root = root
        self.after_write = after_write
        self.evidence_overrides = evidence_overrides or {}
        self.calls = 0

    def encrypt(self, source, *, plan, key_ref):
        self.calls += 1
        content = b"authenticated-synthetic-ciphertext:" + hashlib.sha256(
            source.read_bytes()
        ).digest()
        path = self.root / "synthetic-backup.db.enc"
        path.write_bytes(content)
        if self.after_write is not None:
            self.after_write()
        evidence = {
            "format":"sean-os-client-encrypted-backup-artifact/v1",
            "plan_sha256":plan["plan_sha256"],
            "plaintext_sha256":plan["backup_sha256"],
            "plaintext_bytes":plan["backup_bytes"],
            "ciphertext_sha256":hashlib.sha256(content).hexdigest(),
            "ciphertext_bytes":len(content),
            "algorithm":"AES_256_GCM",
            "key_owner":"IAC",
            "key_ref":key_ref,
            "authenticated":True,
            "aad_plan_sha256":plan["plan_sha256"],
            "credentials_persisted":False,
            "source_path_included":False,
        }
        evidence.update(self.evidence_overrides)
        return EncryptedBackupArtifact(path=path, evidence=evidence)


class FakeUploader:
    def __init__(self, instant: datetime, *, overrides=None):
        self.instant = instant
        self.overrides = overrides or {}
        self.calls = 0
        self.artifact = None

    def upload_new(self, artifact, *, plan, config):
        self.calls += 1
        self.artifact = artifact
        evidence = {
            "provider":"BACKBLAZE_B2",
            "provider_region":plan["data_region"],
            "provider_endpoint":config.endpoint,
            "provider_writer_identity_ref":config.writer_identity_ref,
            "plan_sha256":plan["plan_sha256"],
            "destination_ref":plan["destination_ref"],
            "object_ref":plan["object_ref"],
            "content_sha256":artifact.evidence["ciphertext_sha256"],
            "content_bytes":artifact.evidence["ciphertext_bytes"],
            "provider_request_ref":"request-001",
            "provider_version_ref":"version-001",
            "provider_encryption":"AES256",
            "encryption_verified":True,
            "object_lock_mode":"COMPLIANCE",
            "object_lock_verified":True,
            "retention_days":plan["retention_days"],
            "uploaded_at":self.instant.isoformat(),
            "retain_until":(
                self.instant + timedelta(days=plan["retention_days"])
            ).isoformat(),
            "network_performed":True,
            "uploaded":True,
            "overwrite_performed":False,
            "restore_authorized":False,
            "credentials_persisted":False,
        }
        evidence.update(self.overrides)
        return evidence


class BackupExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.instant = datetime.now(timezone.utc)
        self.store = SeanOSStore(self.root / "iac.db", scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name":"Synthetic"})
        self.manifest = self.store.backup_manifest(
            Actor.sean(), self.root / "backup.db"
        )
        self.package = build_independent_backup_approval_package(
            proposal_for(self.instant)
        )
        self.plan = build_backup_transfer_plan(
            self.package,
            self.manifest,
            object_ref="backups/synthetic-execution.db.enc",
            provider_endpoint="s3.ca-east-006.backblazeb2.com",
            writer_identity_ref="iac-vault-writer:backup-only-v1",
            client_encryption_key_ref="iac-keyring:backup-key-v1",
        )
        self.store.stage_backup_transfer(Actor.sean(), self.plan, self.package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), self.plan["plan_sha256"],
            synthetic_backup_adapter_receipt(self.plan, self.package),
        )
        expiry = (self.instant + timedelta(hours=1)).isoformat()
        approval_id = self.store.request_backup_transfer_approval(
            Actor.sean(), self.plan["plan_sha256"],
            max_impact="One synthetic encrypted CA East upload; CAD 10 maximum",
            expires_at=expiry,
        )
        self.store.decide_approval(
            Actor.sean(), approval_id, approve=True, reason="Synthetic execution test"
        )
        self.store.authorize_backup_transfer(
            Actor.sean(), self.plan["plan_sha256"], approval_id=approval_id
        )
        self.worker_id = "backup-worker-1"
        self.worker = Actor(self.worker_id, frozenset({"IAC"}))
        self.claimed = self.store.claim_authorized_backup_transfer(
            self.worker, self.worker_id, lease_seconds=300
        )
        self.environment = {
            "SEAN_OS_BACKUP_EXECUTION":"APPROVED",
            "SEAN_OS_BACKUP_PROVIDER":"BACKBLAZE_B2",
            "SEAN_OS_BACKUP_DATA_REGION":"CA_EAST",
            "SEAN_OS_BACKUP_ENDPOINT":"s3.ca-east-006.backblazeb2.com",
            "SEAN_OS_BACKUP_DESTINATION_REF":self.plan["destination_ref"],
            "SEAN_OS_BACKUP_WRITER_IDENTITY_REF":"iac-vault-writer:backup-only-v1",
            "SEAN_OS_BACKUP_ENCRYPTION_KEY_REF":"iac-keyring:backup-key-v1",
            "SEAN_OS_BACKUP_MAX_BYTES":str(self.plan["backup_bytes"]),
            "SEAN_OS_BACKUP_MAX_COST_CAD":"10",
        }

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def guard(self, stages):
        def check(stage):
            stages.append(stage)
            self.store.assert_backup_transfer_execution_allowed(
                self.worker, self.plan["plan_sha256"], self.worker_id
            )
        return check

    def test_runtime_config_is_default_off_complete_and_region_exact(self):
        self.assertFalse(load_backup_runtime_config({}).enabled)
        partial = {"SEAN_OS_BACKUP_PROVIDER":"BACKBLAZE_B2"}
        with self.assertRaisesRegex(BackupExecutionError, "partial"):
            load_backup_runtime_config(partial)
        for key, value in (
            ("SEAN_OS_BACKUP_ENDPOINT", "s3.us-east-005.backblazeb2.com"),
            ("SEAN_OS_BACKUP_MAX_COST_CAD", "nan"),
        ):
            changed = dict(self.environment)
            changed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(BackupExecutionError):
                    load_backup_runtime_config(changed)
        direct_secret = dict(self.environment)
        direct_secret["SEAN_OS_BACKUP_SECRET_ACCESS_KEY"] = "not-persisted"
        with self.assertRaisesRegex(BackupExecutionError, "Raw backup secrets"):
            load_backup_runtime_config(direct_secret)

    def test_mocked_execution_produces_a_verified_path_free_receipt(self):
        stages = []
        encryptor = FakeEncryptor(self.root)
        uploader = FakeUploader(self.instant)
        receipt = execute_claimed_backup_transfer(
            self.claimed,
            self.manifest,
            worker_id=self.worker_id,
            config=load_backup_runtime_config(self.environment),
            encryptor=encryptor,
            uploader=uploader,
            guard=self.guard(stages),
            at=self.instant,
        )
        completed = self.store.complete_claimed_backup_transfer(
            self.worker, self.plan["plan_sha256"], self.worker_id, receipt
        )
        self.assertEqual(completed["status"], "COMPLETED")
        self.assertEqual(stages, ["BEFORE_ENCRYPTION", "BEFORE_UPLOAD", "AFTER_UPLOAD"])
        self.assertEqual(encryptor.calls, 1)
        self.assertEqual(uploader.calls, 1)
        self.assertEqual(receipt["provider_region"], "CA_EAST")
        self.assertEqual(receipt["provider_endpoint"], self.environment["SEAN_OS_BACKUP_ENDPOINT"])
        self.assertEqual(
            receipt["provider_writer_identity_ref"],
            self.environment["SEAN_OS_BACKUP_WRITER_IDENTITY_REF"],
        )
        serialized = json.dumps(receipt)
        self.assertNotIn(self.manifest["path"], serialized)
        self.assertNotIn("synthetic-backup.db.enc", serialized)

    def test_reviewed_streaming_encryptor_satisfies_execution_port_contract(self):
        stages = []
        output = self.root / "encrypted"
        output.mkdir(mode=0o700)
        resolver = SyntheticKeyResolver()
        uploader = FakeUploader(self.instant)
        receipt = execute_claimed_backup_transfer(
            self.claimed,
            self.manifest,
            worker_id=self.worker_id,
            config=load_backup_runtime_config(self.environment),
            encryptor=AES256GCMFileEncryptor(output, resolver),
            uploader=uploader,
            guard=self.guard(stages),
            at=self.instant,
        )
        self.assertEqual(stages, ["BEFORE_ENCRYPTION", "BEFORE_UPLOAD", "AFTER_UPLOAD"])
        self.assertEqual(receipt["client_encryption_algorithm"], "AES_256_GCM")
        self.assertEqual(
            receipt["ciphertext_sha256"],
            uploader.artifact.evidence["ciphertext_sha256"],
        )
        self.assertEqual(len(list(output.iterdir())), 1)
        self.assertTrue(all(value == 0 for value in resolver.buffers[0]))

    def test_window_cost_and_configuration_mismatches_block_before_ports(self):
        for change, instant in (
            ({"SEAN_OS_BACKUP_MAX_COST_CAD":"9"}, self.instant),
            ({"SEAN_OS_BACKUP_DATA_REGION":"US_EAST",
              "SEAN_OS_BACKUP_ENDPOINT":"s3.us-east-005.backblazeb2.com"}, self.instant),
            ({}, self.instant + timedelta(hours=2)),
        ):
            environment = dict(self.environment)
            environment.update(change)
            encryptor = FakeEncryptor(self.root)
            uploader = FakeUploader(self.instant)
            with self.subTest(change=change, instant=instant):
                with self.assertRaises(BackupExecutionError):
                    execute_claimed_backup_transfer(
                        self.claimed, self.manifest, worker_id=self.worker_id,
                        config=load_backup_runtime_config(environment),
                        encryptor=encryptor, uploader=uploader,
                        guard=self.guard([]), at=instant,
                    )
                self.assertEqual(encryptor.calls, 0)
                self.assertEqual(uploader.calls, 0)

    def test_kill_switch_change_after_encryption_blocks_upload(self):
        stages = []
        encryptor = FakeEncryptor(
            self.root,
            after_write=lambda: self.store.set_kill_switch(Actor.sean(), True),
        )
        uploader = FakeUploader(self.instant)
        with self.assertRaisesRegex(AuthorizationError, "Kill switch"):
            execute_claimed_backup_transfer(
                self.claimed, self.manifest, worker_id=self.worker_id,
                config=load_backup_runtime_config(self.environment),
                encryptor=encryptor, uploader=uploader,
                guard=self.guard(stages), at=self.instant,
            )
        self.assertEqual(stages, ["BEFORE_ENCRYPTION", "BEFORE_UPLOAD"])
        self.assertEqual(encryptor.calls, 1)
        self.assertEqual(uploader.calls, 0)

    def test_expired_lease_change_after_encryption_blocks_upload(self):
        stages = []

        def expire_lease():
            self.store.connection.execute(
                "UPDATE backup_transfer_outbox SET lease_expires_at=? WHERE plan_sha256=?",
                ("2000-01-01T00:00:00+00:00", self.plan["plan_sha256"]),
            )
            self.store.connection.commit()

        encryptor = FakeEncryptor(self.root, after_write=expire_lease)
        uploader = FakeUploader(self.instant)
        with self.assertRaisesRegex(AuthorizationError, "lease expired"):
            execute_claimed_backup_transfer(
                self.claimed, self.manifest, worker_id=self.worker_id,
                config=load_backup_runtime_config(self.environment),
                encryptor=encryptor, uploader=uploader,
                guard=self.guard(stages), at=self.instant,
            )
        self.assertEqual(stages, ["BEFORE_ENCRYPTION", "BEFORE_UPLOAD"])
        self.assertEqual(uploader.calls, 0)

    def test_encryption_and_provider_evidence_fail_closed(self):
        bad_encryptor = FakeEncryptor(
            self.root, evidence_overrides={"authenticated":False}
        )
        uploader = FakeUploader(self.instant)
        with self.assertRaisesRegex(BackupExecutionError, "encryption evidence"):
            execute_claimed_backup_transfer(
                self.claimed, self.manifest, worker_id=self.worker_id,
                config=load_backup_runtime_config(self.environment),
                encryptor=bad_encryptor, uploader=uploader,
                guard=self.guard([]), at=self.instant,
            )
        self.assertEqual(uploader.calls, 0)

        good_encryptor = FakeEncryptor(self.root)
        wrong_provider = FakeUploader(
            self.instant, overrides={"provider_region":"US_EAST"}
        )
        with self.assertRaisesRegex(BackupExecutionError, "Provider upload evidence"):
            execute_claimed_backup_transfer(
                self.claimed, self.manifest, worker_id=self.worker_id,
                config=load_backup_runtime_config(self.environment),
                encryptor=good_encryptor, uploader=wrong_provider,
                guard=self.guard([]), at=self.instant,
            )
        self.assertEqual(wrong_provider.calls, 1)

    def test_missing_approval_or_active_lease_blocks_execution(self):
        for field, replacement in (
            ("approval_id", None),
            ("lease_owner", "another-worker"),
            ("lease_expires_at", None),
        ):
            changed = copy.deepcopy(self.claimed)
            changed[field] = replacement
            with self.subTest(field=field):
                with self.assertRaisesRegex(BackupExecutionError, "active approved worker lease"):
                    execute_claimed_backup_transfer(
                        changed, self.manifest, worker_id=self.worker_id,
                        config=load_backup_runtime_config(self.environment),
                        encryptor=FakeEncryptor(self.root),
                        uploader=FakeUploader(self.instant),
                        guard=self.guard([]), at=self.instant,
                    )

    def test_completion_rechecks_live_lease_after_upload(self):
        receipt = execute_claimed_backup_transfer(
            self.claimed, self.manifest, worker_id=self.worker_id,
            config=load_backup_runtime_config(self.environment),
            encryptor=FakeEncryptor(self.root), uploader=FakeUploader(self.instant),
            guard=self.guard([]), at=self.instant,
        )
        self.store.connection.execute(
            "UPDATE backup_transfer_outbox SET lease_expires_at=? WHERE plan_sha256=?",
            ("2000-01-01T00:00:00+00:00", self.plan["plan_sha256"]),
        )
        self.store.connection.commit()
        with self.assertRaisesRegex(AuthorizationError, "active backup transfer lease"):
            self.store.complete_claimed_backup_transfer(
                self.worker, self.plan["plan_sha256"], self.worker_id, receipt
            )
        self.assertEqual(
            self.store.get_backup_transfer(
                self.worker, self.plan["plan_sha256"]
            )["status"],
            "AUTHORIZED",
        )


if __name__ == "__main__":
    unittest.main()
