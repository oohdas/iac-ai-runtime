import base64
import unittest

from sean_os import (
    BackupRuntimeConfig,
    BackupSecretError,
    ManagedEnvironmentEncryptionKeyResolver,
    build_backblaze_s3_client,
)
from sean_os.backup_secrets import (
    B2_APPLICATION_KEY_VARIABLE,
    B2_KEY_ID_VARIABLE,
    ENCRYPTION_KEY_VARIABLE,
)


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


class BackupSecretTests(unittest.TestCase):
    def setUp(self):
        self.key_ref = "iac-keyring:backup-key-v1"
        self.secret_bytes = bytes(range(32))
        self.environment = {
            ENCRYPTION_KEY_VARIABLE: base64.b64encode(self.secret_bytes).decode("ascii"),
            B2_KEY_ID_VARIABLE: "synthetic-key-id-001",
            B2_APPLICATION_KEY_VARIABLE: "synthetic-application-key-001",
        }
        self.config = BackupRuntimeConfig(
            enabled=True,
            provider="BACKBLAZE_B2",
            data_region="CA_EAST",
            endpoint="s3.ca-east-006.backblazeb2.com",
            destination_ref="backblaze-b2-bucket:synthetic-ca-east",
            writer_identity_ref="iac-secret-store:backup-writer-v1",
            encryption_key_ref=self.key_ref,
            max_bytes=1024,
            max_cost_cad=10,
        )

    def test_encryption_key_is_exact_scoped_and_wiped_after_use(self):
        resolver = ManagedEnvironmentEncryptionKeyResolver(
            self.environment, key_ref=self.key_ref
        )
        captured = None
        with resolver.open_key(self.key_ref) as material:
            captured = material
            self.assertEqual(bytes(material), self.secret_bytes)
        self.assertEqual(bytes(captured), b"\x00" * 32)
        with self.assertRaisesRegex(BackupSecretError, "does not match"):
            with resolver.open_key("iac-keyring:another-key"):
                pass

    def test_missing_malformed_or_wrong_length_key_fails_without_value_disclosure(self):
        values = (None, "not-base64", base64.b64encode(b"short").decode("ascii"))
        for value in values:
            with self.subTest(value=value):
                environment = dict(self.environment)
                if value is None:
                    environment.pop(ENCRYPTION_KEY_VARIABLE)
                else:
                    environment[ENCRYPTION_KEY_VARIABLE] = value
                resolver = ManagedEnvironmentEncryptionKeyResolver(
                    environment, key_ref=self.key_ref
                )
                with self.assertRaises(BackupSecretError) as raised:
                    with resolver.open_key(self.key_ref):
                        pass
                if value:
                    self.assertNotIn(value, str(raised.exception))

    def test_client_factory_binds_exact_endpoint_region_secrets_and_no_retry(self):
        boto = FakeBoto3()
        result = build_backblaze_s3_client(
            self.environment,
            self.config,
            boto3_module=boto,
            config_type=FakeConfig,
        )
        self.assertIs(result, boto.result)
        service, arguments = boto.calls[0]
        self.assertEqual(service, "s3")
        self.assertEqual(
            arguments["endpoint_url"], "https://s3.ca-east-006.backblazeb2.com"
        )
        self.assertEqual(arguments["region_name"], "ca-east-006")
        self.assertEqual(
            arguments["aws_access_key_id"], self.environment[B2_KEY_ID_VARIABLE]
        )
        self.assertEqual(
            arguments["aws_secret_access_key"],
            self.environment[B2_APPLICATION_KEY_VARIABLE],
        )
        options = arguments["config"].arguments
        self.assertEqual(options["retries"]["total_max_attempts"], 1)
        self.assertTrue(options["s3"]["payload_signing_enabled"])
        self.assertEqual(options["s3"]["addressing_style"], "path")
        self.assertTrue(options["ignore_configured_endpoint_urls"])

    def test_disabled_wrong_region_or_partial_secrets_fail_before_client(self):
        boto = FakeBoto3()
        for config, environment in (
            (BackupRuntimeConfig(enabled=False), self.environment),
            (BackupRuntimeConfig(**{
                **self.config.__dict__,
                "endpoint": "s3.us-east-005.backblazeb2.com",
            }), self.environment),
            (self.config, {B2_KEY_ID_VARIABLE: "synthetic-key-id-001"}),
        ):
            with self.subTest(config=config, environment=environment):
                with self.assertRaises(BackupSecretError):
                    build_backblaze_s3_client(
                        environment,
                        config,
                        boto3_module=boto,
                        config_type=FakeConfig,
                    )
        self.assertEqual(boto.calls, [])

    def test_unreviewed_key_variable_name_is_rejected(self):
        with self.assertRaisesRegex(BackupSecretError, "reviewed managed variable"):
            ManagedEnvironmentEncryptionKeyResolver(
                self.environment,
                key_ref=self.key_ref,
                variable_name="SOME_OTHER_VARIABLE",
            )


if __name__ == "__main__":
    unittest.main()
