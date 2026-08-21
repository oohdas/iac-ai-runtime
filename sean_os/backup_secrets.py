"""Managed-secret adapters for an explicitly enabled Backblaze backup runtime.

Railway injects managed variables into the process environment. This module reads only
three fixed names, never returns them as evidence, and never constructs a client unless
the non-secret backup runtime configuration is complete and enabled.
"""

from __future__ import annotations

import base64
import re
from contextlib import contextmanager
from typing import Any, Iterator, Mapping

from .backup_execution import BackupRuntimeConfig


class BackupSecretError(ValueError):
    pass


B2_KEY_ID_VARIABLE = "SEAN_OS_MANAGED_B2_KEY_ID"
B2_APPLICATION_KEY_VARIABLE = "SEAN_OS_MANAGED_B2_APPLICATION_KEY"
ENCRYPTION_KEY_VARIABLE = "SEAN_OS_MANAGED_BACKUP_AES256_KEY_B64"
MANAGED_SECRET_VARIABLES = frozenset({
    B2_KEY_ID_VARIABLE,
    B2_APPLICATION_KEY_VARIABLE,
    ENCRYPTION_KEY_VARIABLE,
})
_BACKBLAZE_ENDPOINT = re.compile(
    r"s3\.(?P<region>ca-east-[a-z0-9-]+)\.backblazeb2\.com"
)


def _managed_secret(environment: Mapping[str, str], variable: str) -> str:
    value = environment.get(variable)
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 256
        or value.strip() != value
        or any(character.isspace() or ord(character) < 33 for character in value)
    ):
        raise BackupSecretError("Required managed backup secret is missing or malformed")
    return value


class ManagedEnvironmentEncryptionKeyResolver:
    """Yield one mutable key buffer for one exact opaque reference."""

    def __init__(
        self,
        environment: Mapping[str, str],
        *,
        key_ref: str,
        variable_name: str = ENCRYPTION_KEY_VARIABLE,
    ):
        if variable_name != ENCRYPTION_KEY_VARIABLE:
            raise BackupSecretError("Encryption key must use the reviewed managed variable")
        if not isinstance(key_ref, str) or not key_ref or len(key_ref) > 200:
            raise BackupSecretError("Encryption key reference is malformed")
        self._environment = environment
        self._key_ref = key_ref
        self._variable_name = variable_name

    @contextmanager
    def open_key(self, key_ref: str) -> Iterator[bytearray]:
        if key_ref != self._key_ref:
            raise BackupSecretError("Encryption key reference does not match the runtime")
        encoded = _managed_secret(self._environment, self._variable_name)
        try:
            material = bytearray(base64.b64decode(encoded, validate=True))
        except (TypeError, ValueError) as exc:
            raise BackupSecretError("Managed backup encryption key is malformed") from exc
        if len(material) != 32:
            for index in range(len(material)):
                material[index] = 0
            raise BackupSecretError("Managed backup encryption key must contain 32 bytes")
        try:
            yield material
        finally:
            for index in range(len(material)):
                material[index] = 0


def build_backblaze_s3_client(
    environment: Mapping[str, str],
    config: BackupRuntimeConfig,
    *,
    boto3_module: Any | None = None,
    config_type: Any | None = None,
) -> Any:
    """Construct one exact, no-retry B2 client without persisting credentials."""
    if (
        not config.enabled
        or config.provider != "BACKBLAZE_B2"
        or config.data_region != "CA_EAST"
        or not isinstance(config.endpoint, str)
    ):
        raise BackupSecretError("Backblaze client requires an enabled Canada East runtime")
    endpoint_match = _BACKBLAZE_ENDPOINT.fullmatch(config.endpoint)
    if endpoint_match is None:
        raise BackupSecretError("Backblaze client endpoint is outside Canada East")
    key_id = _managed_secret(environment, B2_KEY_ID_VARIABLE)
    application_key = _managed_secret(environment, B2_APPLICATION_KEY_VARIABLE)
    if boto3_module is None or config_type is None:
        try:
            import boto3 as imported_boto3
            from botocore.config import Config as imported_config
        except ImportError as exc:
            raise BackupSecretError("Reviewed Backblaze SDK is unavailable") from exc
        boto3_module = imported_boto3
        config_type = imported_config
    client_config = config_type(
        signature_version="s3v4",
        connect_timeout=10,
        read_timeout=120,
        parameter_validation=True,
        retries={"mode": "standard", "total_max_attempts": 1},
        s3={"addressing_style": "path", "payload_signing_enabled": True},
        ignore_configured_endpoint_urls=True,
        user_agent_appid="sean-os-backup-v0.1",
    )
    try:
        return boto3_module.client(
            "s3",
            endpoint_url=f"https://{config.endpoint}",
            region_name=endpoint_match.group("region"),
            aws_access_key_id=key_id,
            aws_secret_access_key=application_key,
            config=client_config,
        )
    except Exception as exc:
        raise BackupSecretError("Backblaze client construction failed") from exc
