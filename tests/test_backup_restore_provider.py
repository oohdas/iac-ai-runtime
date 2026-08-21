import hashlib
import io
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from sean_os import (
    Actor,
    BackblazeS3DownloadPort,
    BackupRestoreProviderError,
    BackupRestoreSecretError,
    SeanOSStore,
    build_backblaze_s3_restore_client,
    build_backup_restore_key_approval_package,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    build_isolated_backup_restore_plan,
    load_backup_restore_runtime_config,
)
from sean_os.backup_restore_secrets import (
    RESTORE_APPLICATION_KEY_VARIABLE,
    RESTORE_KEY_ID_VARIABLE,
)
from tests.test_backup_restore import (
    BUCKET,
    drill_proposal,
    restore_key_proposal,
    upload_receipt,
)


class ClosingBody(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.was_closed = False

    def close(self):
        self.was_closed = True
        super().close()


class SyntheticRestoreClient:
    def __init__(self, content, plan):
        self.content = content
        self.plan = plan
        self.calls = []
        self.retention_mode = "COMPLIANCE"
        self.retain_until = datetime.fromisoformat(plan["retain_until"])
        self.version = plan["provider_version_ref"]
        self.sse = "AES256"
        self.metadata = {
            "sean-os-plan-sha256": plan["upload_plan_sha256"],
            "sean-os-content-sha256": plan["ciphertext_sha256"],
        }
        self.body = None

    def get_object_retention(self, **kwargs):
        self.calls.append(("get_object_retention", kwargs))
        return {
            "Retention": {
                "Mode": self.retention_mode,
                "RetainUntilDate": self.retain_until,
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        self.body = ClosingBody(self.content)
        return {
            "Body": self.body,
            "ContentLength": len(self.content),
            "VersionId": self.version,
            "ServerSideEncryption": self.sse,
            "Metadata": self.metadata,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class FakeConfig:
    def __init__(self, **kwargs):
        self.arguments = kwargs


class FakeBoto3:
    def __init__(self):
        self.calls = []
        self.result = object()

    def client(self, service, **kwargs):
        self.calls.append((service, kwargs))
        return self.result


class BackupRestoreProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "downloads"
        self.output.mkdir(mode=0o700)
        self.store = SeanOSStore(self.root / "iac.db", scope_profile="IAC")
        self.store.create_record(Actor.sean(), "GOAL", "IAC", {"name":"Synthetic"})
        manifest = self.store.backup_manifest(Actor.sean(), self.root / "backup.db")
        package = build_independent_backup_approval_package(drill_proposal())
        upload_plan = build_backup_transfer_plan(
            package, manifest, object_ref="backups/synthetic-provider.db.enc",
            provider_endpoint="s3.ca-east-006.backblazeb2.com",
            writer_identity_ref="managed-secret-store:synthetic-writer-v1",
            client_encryption_key_ref="managed-secret-store:synthetic-aes256-v1",
        )
        self.content = b"synthetic-encrypted-backup" * 200
        receipt = upload_receipt(
            upload_plan,
            ciphertext_sha256=hashlib.sha256(self.content).hexdigest(),
            ciphertext_bytes=len(self.content),
        )
        self.plan = build_isolated_backup_restore_plan(
            upload_plan, receipt,
            build_backup_restore_key_approval_package(restore_key_proposal()),
            restore_target_ref="isolated-restore:provider-test-v1",
            window_start="2030-01-03T09:00:00-05:00",
            window_end="2030-01-03T11:00:00-05:00", max_cost_cad=1,
        )
        self.environment = {
            "SEAN_OS_BACKUP_RESTORE_EXECUTION":"APPROVED",
            "SEAN_OS_BACKUP_RESTORE_PROVIDER":"BACKBLAZE_B2",
            "SEAN_OS_BACKUP_RESTORE_DATA_REGION":"CA_EAST",
            "SEAN_OS_BACKUP_RESTORE_ENDPOINT":self.plan["provider_endpoint"],
            "SEAN_OS_BACKUP_RESTORE_DESTINATION_REF":self.plan["destination_ref"],
            "SEAN_OS_BACKUP_RESTORE_IDENTITY_REF":self.plan[
                "provider_restore_identity_ref"
            ],
            "SEAN_OS_BACKUP_RESTORE_ENCRYPTION_KEY_REF":self.plan[
                "client_encryption_key_ref"
            ],
            "SEAN_OS_BACKUP_RESTORE_MAX_BYTES":str(len(self.content)),
            "SEAN_OS_BACKUP_RESTORE_MAX_COST_CAD":"1",
        }
        self.config = load_backup_restore_runtime_config(self.environment)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def port(self, client):
        return BackblazeS3DownloadPort(
            client, bucket_name=BUCKET, destination_ref=self.plan["destination_ref"],
            endpoint=self.plan["provider_endpoint"],
            restore_identity_ref=self.plan["provider_restore_identity_ref"],
            output_directory=self.output,
        )

    def test_exact_version_download_is_private_hash_checked_and_read_only(self):
        client = SyntheticRestoreClient(self.content, self.plan)
        artifact = self.port(client).download_exact(plan=self.plan, config=self.config)
        self.assertEqual(artifact.path.read_bytes(), self.content)
        self.assertEqual(artifact.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(client.body.was_closed)
        self.assertEqual(
            [name for name, _ in client.calls],
            ["get_object_retention", "get_object"],
        )
        for _, arguments in client.calls:
            self.assertEqual(arguments["Bucket"], BUCKET)
            self.assertEqual(arguments["Key"], self.plan["object_ref"])
            self.assertEqual(arguments["VersionId"], self.plan["provider_version_ref"])
        self.assertTrue(artifact.evidence["object_lock_verified"])
        self.assertFalse(artifact.evidence["overwrite_performed"])

    def test_changed_retention_version_sse_metadata_or_body_fails_closed(self):
        mutations = (
            lambda client: setattr(client, "retention_mode", "GOVERNANCE"),
            lambda client: setattr(client, "version", "other-version"),
            lambda client: setattr(client, "sse", ""),
            lambda client: setattr(client, "metadata", {}),
            lambda client: setattr(client, "content", client.content + b"changed"),
        )
        for mutate in mutations:
            client = SyntheticRestoreClient(self.content, self.plan)
            mutate(client)
            with self.subTest(mutate=mutate):
                with self.assertRaises(BackupRestoreProviderError):
                    self.port(client).download_exact(plan=self.plan, config=self.config)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_wrong_binding_or_nonprivate_output_blocks_before_network(self):
        client = SyntheticRestoreClient(self.content, self.plan)
        wrong_environment = dict(self.environment)
        wrong_environment["SEAN_OS_BACKUP_RESTORE_IDENTITY_REF"] = (
            "managed-secret-store:other-restore"
        )
        with self.assertRaisesRegex(BackupRestoreProviderError, "does not match"):
            self.port(client).download_exact(
                plan=self.plan,
                config=load_backup_restore_runtime_config(wrong_environment),
            )
        self.assertEqual(client.calls, [])
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(BackupRestoreProviderError, "private"):
            BackblazeS3DownloadPort(
                client, bucket_name=BUCKET,
                destination_ref=self.plan["destination_ref"],
                endpoint=self.plan["provider_endpoint"],
                restore_identity_ref=self.plan["provider_restore_identity_ref"],
                output_directory=unsafe,
            )

    def test_restore_client_factory_uses_distinct_fixed_secrets_and_one_attempt(self):
        boto = FakeBoto3()
        environment = {
            RESTORE_KEY_ID_VARIABLE:"synthetic-restore-key-id",
            RESTORE_APPLICATION_KEY_VARIABLE:"synthetic-restore-application-key",
        }
        result = build_backblaze_s3_restore_client(
            environment, self.config, boto3_module=boto, config_type=FakeConfig
        )
        self.assertIs(result, boto.result)
        service, arguments = boto.calls[0]
        self.assertEqual(service, "s3")
        self.assertEqual(arguments["aws_access_key_id"], environment[RESTORE_KEY_ID_VARIABLE])
        self.assertEqual(
            arguments["aws_secret_access_key"], environment[RESTORE_APPLICATION_KEY_VARIABLE]
        )
        self.assertEqual(arguments["config"].arguments["retries"]["total_max_attempts"], 1)
        self.assertTrue(arguments["config"].arguments["s3"]["payload_signing_enabled"])

    def test_restore_client_factory_fails_on_writer_names_or_partial_values(self):
        boto = FakeBoto3()
        for environment in (
            {RESTORE_KEY_ID_VARIABLE:"synthetic-restore-key-id"},
            {
                "SEAN_OS_MANAGED_B2_KEY_ID":"writer-key-id",
                "SEAN_OS_MANAGED_B2_APPLICATION_KEY":"writer-application-key",
            },
        ):
            with self.assertRaises(BackupRestoreSecretError):
                build_backblaze_s3_restore_client(
                    environment, self.config, boto3_module=boto, config_type=FakeConfig
                )
        self.assertEqual(boto.calls, [])


if __name__ == "__main__":
    unittest.main()
