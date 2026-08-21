"""Distinct managed-secret factory for the read-only Backblaze restore identity."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .backup_restore_execution import BackupRestoreRuntimeConfig


class BackupRestoreSecretError(ValueError):
    pass


RESTORE_KEY_ID_VARIABLE = "SEAN_OS_MANAGED_B2_RESTORE_KEY_ID"
RESTORE_APPLICATION_KEY_VARIABLE = "SEAN_OS_MANAGED_B2_RESTORE_APPLICATION_KEY"
MANAGED_RESTORE_SECRET_VARIABLES = frozenset({
    RESTORE_KEY_ID_VARIABLE, RESTORE_APPLICATION_KEY_VARIABLE,
})
_ENDPOINT = re.compile(r"s3\.(?P<region>ca-east-[a-z0-9-]+)\.backblazeb2\.com")


def _secret(environment: Mapping[str, str], name: str) -> str:
    value=environment.get(name)
    if (
        not isinstance(value, str) or not 8 <= len(value) <= 256
        or value.strip() != value
        or any(character.isspace() or ord(character) < 33 for character in value)
    ):
        raise BackupRestoreSecretError(
            "Required managed restore secret is missing or malformed"
        )
    return value


def build_backblaze_s3_restore_client(
    environment: Mapping[str, str], config: BackupRestoreRuntimeConfig, *,
    boto3_module: Any | None = None, config_type: Any | None = None,
) -> Any:
    if (
        not config.enabled or config.provider != "BACKBLAZE_B2"
        or config.data_region != "CA_EAST" or not isinstance(config.endpoint, str)
    ):
        raise BackupRestoreSecretError(
            "Backblaze restore client requires an enabled Canada East runtime"
        )
    match=_ENDPOINT.fullmatch(config.endpoint)
    if match is None:
        raise BackupRestoreSecretError(
            "Backblaze restore client endpoint is outside Canada East"
        )
    key_id=_secret(environment, RESTORE_KEY_ID_VARIABLE)
    application_key=_secret(environment, RESTORE_APPLICATION_KEY_VARIABLE)
    if boto3_module is None or config_type is None:
        try:
            import boto3 as imported_boto3
            from botocore.config import Config as imported_config
        except ImportError as exc:
            raise BackupRestoreSecretError("Reviewed Backblaze SDK is unavailable") from exc
        boto3_module=imported_boto3; config_type=imported_config
    client_config=config_type(
        signature_version="s3v4", connect_timeout=10, read_timeout=120,
        parameter_validation=True,
        retries={"mode":"standard", "total_max_attempts":1},
        s3={"addressing_style":"path", "payload_signing_enabled":True},
        ignore_configured_endpoint_urls=True,
        user_agent_appid="sean-os-restore-v0.1",
    )
    try:
        return boto3_module.client(
            "s3", endpoint_url=f"https://{config.endpoint}",
            region_name=match.group("region"), aws_access_key_id=key_id,
            aws_secret_access_key=application_key, config=client_config,
        )
    except Exception as exc:
        raise BackupRestoreSecretError(
            "Backblaze restore client construction failed"
        ) from exc
