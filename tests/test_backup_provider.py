import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

from sean_os import (
    BackblazeS3UploadPort,
    BackupProviderError,
    BackupReconciliationRequired,
    BackupRuntimeConfig,
    EncryptedBackupArtifact,
)


class SyntheticS3Client:
    def __init__(self, instant: datetime):
        self.instant = instant
        self.calls = []
        self.uploaded = b""
        self.encryption = "AES256"
        self.lock_mode = "COMPLIANCE"
        self.lock_days = 30
        self.object_mode = "COMPLIANCE"
        self.retain_until = instant + timedelta(days=30, seconds=1)
        self.upload_sse = "AES256"
        self.raise_message = None

    def _maybe_raise(self):
        if self.raise_message:
            raise RuntimeError(self.raise_message)

    def get_bucket_encryption(self, **kwargs):
        self.calls.append(("get_bucket_encryption", kwargs))
        self._maybe_raise()
        return {
            "ServerSideEncryptionConfiguration": {"Rules": [{
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": self.encryption}
            }]},
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def get_object_lock_configuration(self, **kwargs):
        self.calls.append(("get_object_lock_configuration", kwargs))
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {
                    "Mode": self.lock_mode,
                    "Days": self.lock_days,
                }},
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def put_object(self, **kwargs):
        captured = dict(kwargs)
        captured["Body"] = "<stream>"
        self.calls.append(("put_object", captured))
        self.uploaded = kwargs["Body"].read()
        return {
            "ServerSideEncryption": self.upload_sse,
            "VersionId": "4_zsynthetic_version_001",
            "ResponseMetadata": {
                "HTTPStatusCode": 200,
                "RequestId": "synthetic-request-001",
                "HTTPHeaders": {"date": format_datetime(self.instant, usegmt=True)},
            },
        }

    def get_object_retention(self, **kwargs):
        self.calls.append(("get_object_retention", kwargs))
        return {
            "Retention": {
                "Mode": self.object_mode,
                "RetainUntilDate": self.retain_until,
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class BackupProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.instant = datetime(2026, 8, 20, 21, 30, tzinfo=timezone.utc)
        self.content = b"authenticated-encrypted-artifact" * 100
        self.path = self.root / "artifact.enc"
        self.path.write_bytes(self.content)
        self.plan_sha = hashlib.sha256(b"plan").hexdigest()
        self.content_sha = hashlib.sha256(self.content).hexdigest()
        self.artifact = EncryptedBackupArtifact(
            path=self.path,
            evidence={
                "plan_sha256": self.plan_sha,
                "ciphertext_sha256": self.content_sha,
                "ciphertext_bytes": len(self.content),
                "authenticated": True,
                "credentials_persisted": False,
                "source_path_included": False,
            },
        )
        self.endpoint = "s3.ca-east-006.backblazeb2.com"
        self.destination_ref = "backblaze-b2-bucket:synthetic-ca-east-bucket"
        self.writer_ref = "iac-secret-store:backup-writer-v1"
        self.plan = {
            "provider": "BACKBLAZE_B2",
            "data_region": "CA_EAST",
            "provider_endpoint": self.endpoint,
            "destination_ref": self.destination_ref,
            "provider_writer_identity_ref": self.writer_ref,
            "object_ref": "backups/synthetic-plan-001.enc",
            "plan_sha256": self.plan_sha,
            "retention_days": 30,
        }
        self.config = BackupRuntimeConfig(
            enabled=True,
            provider="BACKBLAZE_B2",
            data_region="CA_EAST",
            endpoint=self.endpoint,
            destination_ref=self.destination_ref,
            writer_identity_ref=self.writer_ref,
            encryption_key_ref="iac-keyring:backup-key-v1",
            max_bytes=len(self.content),
            max_cost_cad=10,
        )
        self.client = SyntheticS3Client(self.instant)
        self.port = BackblazeS3UploadPort(
            self.client,
            bucket_name="synthetic-ca-east-bucket",
            destination_ref=self.destination_ref,
            endpoint=self.endpoint,
            writer_identity_ref=self.writer_ref,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_conditional_upload_and_retention_evidence(self):
        evidence = self.port.upload_new(
            self.artifact, plan=self.plan, config=self.config
        )
        self.assertEqual(
            [name for name, _ in self.client.calls],
            [
                "get_bucket_encryption",
                "get_object_lock_configuration",
                "put_object",
                "get_object_retention",
            ],
        )
        upload = self.client.calls[2][1]
        self.assertEqual(upload["IfNoneMatch"], "*")
        self.assertEqual(upload["ServerSideEncryption"], "AES256")
        self.assertEqual(upload["ContentLength"], len(self.content))
        self.assertEqual(upload["Metadata"]["sean-os-plan-sha256"], self.plan_sha)
        self.assertNotIn("ObjectLockMode", upload)
        self.assertNotIn("ObjectLockRetainUntilDate", upload)
        self.assertNotIn("ACL", upload)
        self.assertEqual(self.client.uploaded, self.content)
        self.assertEqual(evidence["provider_version_ref"], "4_zsynthetic_version_001")
        self.assertTrue(evidence["object_lock_verified"])
        self.assertFalse(evidence["overwrite_performed"])
        self.assertNotIn(str(self.path), json.dumps(evidence))

    def test_wrong_runtime_binding_or_prefix_blocks_before_network(self):
        changed = dict(self.plan)
        changed["object_ref"] = "outside/synthetic.enc"
        with self.assertRaises(BackupProviderError):
            self.port.upload_new(self.artifact, plan=changed, config=self.config)
        self.assertEqual(self.client.calls, [])
        wrong_config = BackupRuntimeConfig(**{
            **self.config.__dict__, "endpoint": "s3.ca-east-999.backblazeb2.com"
        })
        with self.assertRaises(BackupProviderError):
            self.port.upload_new(self.artifact, plan=self.plan, config=wrong_config)
        self.assertEqual(self.client.calls, [])

    def test_modified_artifact_blocks_before_network(self):
        self.path.write_bytes(self.content + b"changed")
        with self.assertRaisesRegex(BackupProviderError, "does not match"):
            self.port.upload_new(self.artifact, plan=self.plan, config=self.config)
        self.assertEqual(self.client.calls, [])

    def test_wrong_bucket_controls_block_before_upload(self):
        for field, value in (
            ("encryption", "aws:kms"),
            ("lock_mode", "GOVERNANCE"),
            ("lock_days", 29),
        ):
            with self.subTest(field=field):
                client = SyntheticS3Client(self.instant)
                setattr(client, field, value)
                port = BackblazeS3UploadPort(
                    client,
                    bucket_name="synthetic-ca-east-bucket",
                    destination_ref=self.destination_ref,
                    endpoint=self.endpoint,
                    writer_identity_ref=self.writer_ref,
                )
                with self.assertRaises(BackupProviderError):
                    port.upload_new(self.artifact, plan=self.plan, config=self.config)
                self.assertNotIn("put_object", [name for name, _ in client.calls])

    def test_weak_upload_or_retention_evidence_fails_closed(self):
        for field, value in (
            ("upload_sse", ""),
            ("object_mode", "GOVERNANCE"),
            ("retain_until", self.instant + timedelta(days=29)),
        ):
            with self.subTest(field=field):
                client = SyntheticS3Client(self.instant)
                setattr(client, field, value)
                port = BackblazeS3UploadPort(
                    client,
                    bucket_name="synthetic-ca-east-bucket",
                    destination_ref=self.destination_ref,
                    endpoint=self.endpoint,
                    writer_identity_ref=self.writer_ref,
                )
                with self.assertRaises(BackupProviderError):
                    port.upload_new(self.artifact, plan=self.plan, config=self.config)

    def test_provider_exception_is_generic_and_requires_manual_reconciliation(self):
        self.client.raise_message = "secret provider detail must not escape"
        with self.assertRaisesRegex(BackupProviderError, "preflight failed") as raised:
            self.port.upload_new(self.artifact, plan=self.plan, config=self.config)
        self.assertNotIn("secret provider detail", str(raised.exception))

    def test_any_failure_after_write_attempt_prohibits_automatic_retry(self):
        self.client.upload_sse = ""
        with self.assertRaisesRegex(
            BackupReconciliationRequired, "automatic retry is prohibited"
        ) as raised:
            self.port.upload_new(self.artifact, plan=self.plan, config=self.config)
        self.assertNotIn("SSE-B2", str(raised.exception))
        self.assertIn("put_object", [name for name, _ in self.client.calls])


if __name__ == "__main__":
    unittest.main()
