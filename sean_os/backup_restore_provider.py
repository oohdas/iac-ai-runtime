"""Injected read-only Backblaze port for one exact isolated restore object."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from .backup_restore import verify_isolated_backup_restore_plan
from .backup_restore_execution import (
    BackupRestoreRuntimeConfig,
    DOWNLOADED_ARTIFACT_FORMAT,
    DownloadedBackupArtifact,
)
from .backup_provider import verify_backblaze_bucket_name
from .security import secret_findings


class BackupRestoreProviderError(ValueError):
    pass


class S3CompatibleRestoreClient(Protocol):
    def get_object_retention(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


_OBJECT_KEY = re.compile(r"backups/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}")


def _safe_ref(name: str, value: Any) -> str:
    if (
        not isinstance(value, str) or not value or value.strip() != value
        or len(value) > 200 or any(ord(character) < 32 for character in value)
        or secret_findings(value)
    ):
        raise BackupRestoreProviderError(f"{name} must be one bounded non-secret reference")
    return value


def _response(value: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    metadata=value.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or metadata.get("HTTPStatusCode") != 200:
        raise BackupRestoreProviderError(
            f"Backblaze {operation} did not return a verified success"
        )
    return metadata


def _aware(value: Any) -> datetime:
    if isinstance(value, datetime):
        instant=value
    elif isinstance(value, str) and 1 <= len(value) <= 100:
        try:
            instant=parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                instant=datetime.fromisoformat(value)
            except ValueError as exc:
                raise BackupRestoreProviderError(
                    "Backblaze retention timestamp is malformed"
                ) from exc
    else:
        raise BackupRestoreProviderError("Backblaze retention timestamp is missing")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupRestoreProviderError(
            "Backblaze retention timestamp must include a timezone"
        )
    return instant


class BackblazeS3DownloadPort:
    """Read one exact version into a new private file; never list, write, or delete."""

    def __init__(
        self, client: S3CompatibleRestoreClient, *, bucket_name: str,
        destination_ref: str, endpoint: str, restore_identity_ref: str,
        output_directory: Path,
    ):
        bucket_name=verify_backblaze_bucket_name(bucket_name)
        destination_ref=_safe_ref("destination_ref", destination_ref)
        if destination_ref != f"backblaze-b2-bucket:{bucket_name}":
            raise BackupRestoreProviderError(
                "Backblaze bucket does not match the approved restore destination"
            )
        output=Path(output_directory)
        if (
            output.is_symlink() or not output.is_dir()
            or stat.S_IMODE(output.stat().st_mode) != 0o700
        ):
            raise BackupRestoreProviderError(
                "Restore download directory must exist with private permissions"
            )
        self.client=client
        self.bucket_name=bucket_name
        self.destination_ref=destination_ref
        self.endpoint=_safe_ref("endpoint", endpoint)
        self.restore_identity_ref=_safe_ref(
            "restore_identity_ref", restore_identity_ref
        )
        self.output_directory=output

    def _validate(
        self, plan: Mapping[str, Any], config: BackupRestoreRuntimeConfig,
    ) -> dict[str, Any]:
        value=verify_isolated_backup_restore_plan(plan)
        if (
            not config.enabled or config.provider != "BACKBLAZE_B2"
            or config.data_region != "CA_EAST" or config.endpoint != self.endpoint
            or config.destination_ref != self.destination_ref
            or config.restore_identity_ref != self.restore_identity_ref
            or value["provider_endpoint"] != self.endpoint
            or value["destination_ref"] != self.destination_ref
            or value["provider_restore_identity_ref"] != self.restore_identity_ref
        ):
            raise BackupRestoreProviderError(
                "Backblaze restore client does not match the approved runtime plan"
            )
        object_ref=value["object_ref"]
        if (
            not _OBJECT_KEY.fullmatch(object_ref) or ".." in object_ref
            or "//" in object_ref
        ):
            raise BackupRestoreProviderError(
                "Backblaze restore object is outside the exact backup prefix"
            )
        if value["ciphertext_bytes"] > int(config.max_bytes or 0):
            raise BackupRestoreProviderError("Restore object exceeds the byte ceiling")
        return value

    def download_exact(
        self, *, plan: Mapping[str, Any], config: BackupRestoreRuntimeConfig,
    ) -> DownloadedBackupArtifact:
        value=self._validate(plan, config)
        try:
            retention=self.client.get_object_retention(
                Bucket=self.bucket_name, Key=value["object_ref"],
                VersionId=value["provider_version_ref"],
            )
            _response(retention, "restore retention check")
            retention_value=retention.get("Retention")
            if (
                not isinstance(retention_value, Mapping)
                or retention_value.get("Mode") != "COMPLIANCE"
                or _aware(retention_value.get("RetainUntilDate")).isoformat()
                != datetime.fromisoformat(value["retain_until"]).isoformat()
            ):
                raise BackupRestoreProviderError(
                    "Backblaze object compliance retention does not match upload evidence"
                )
            response=self.client.get_object(
                Bucket=self.bucket_name, Key=value["object_ref"],
                VersionId=value["provider_version_ref"],
            )
            _response(response, "exact object download")
        except BackupRestoreProviderError:
            raise
        except Exception as exc:
            raise BackupRestoreProviderError(
                "Backblaze restore read failed without exposing provider detail"
            ) from exc
        if (
            response.get("VersionId") != value["provider_version_ref"]
            or response.get("ServerSideEncryption") != "AES256"
            or response.get("ContentLength") != value["ciphertext_bytes"]
        ):
            raise BackupRestoreProviderError(
                "Backblaze object version, encryption, or size does not match"
            )
        metadata=response.get("Metadata")
        if not isinstance(metadata, Mapping) or metadata != {
            "sean-os-plan-sha256":value["upload_plan_sha256"],
            "sean-os-content-sha256":value["ciphertext_sha256"],
        }:
            raise BackupRestoreProviderError("Backblaze object metadata does not match")
        body=response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise BackupRestoreProviderError("Backblaze object body is missing")
        target=self.output_directory / (
            f"restore-{value['plan_sha256'][:16]}-{secrets.token_hex(6)}.enc"
        )
        descriptor=None
        digest=hashlib.sha256(); total=0
        try:
            descriptor=os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor=None
                remaining=value["ciphertext_bytes"]
                while remaining:
                    chunk=body.read(min(1024 * 1024, remaining))
                    if not isinstance(chunk, bytes) or not chunk:
                        raise BackupRestoreProviderError(
                            "Backblaze encrypted object is truncated"
                        )
                    remaining -= len(chunk); total += len(chunk)
                    digest.update(chunk); output.write(chunk)
                if body.read(1) not in (b"", None):
                    raise BackupRestoreProviderError(
                        "Backblaze encrypted object exceeds the approved size"
                    )
                output.flush(); os.fsync(output.fileno())
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            target.unlink(missing_ok=True)
            raise
        finally:
            close=getattr(body, "close", None)
            if callable(close):
                close()
        if total != value["ciphertext_bytes"] or digest.hexdigest() != value["ciphertext_sha256"]:
            target.unlink(missing_ok=True)
            raise BackupRestoreProviderError(
                "Backblaze encrypted object hash does not match upload evidence"
            )
        evidence={
            "format":DOWNLOADED_ARTIFACT_FORMAT,
            "restore_plan_sha256":value["plan_sha256"],
            "provider":"BACKBLAZE_B2",
            "provider_region":"CA_EAST",
            "provider_endpoint":self.endpoint,
            "provider_restore_identity_ref":self.restore_identity_ref,
            "destination_ref":self.destination_ref,
            "object_ref":value["object_ref"],
            "provider_version_ref":value["provider_version_ref"],
            "ciphertext_sha256":value["ciphertext_sha256"],
            "ciphertext_bytes":value["ciphertext_bytes"],
            "provider_encryption":"AES256",
            "object_lock_mode":"COMPLIANCE",
            "object_lock_verified":True,
            "retain_until":value["retain_until"],
            "network_performed":True,
            "downloaded":True,
            "overwrite_performed":False,
            "credentials_persisted":False,
            "source_path_included":False,
        }
        return DownloadedBackupArtifact(path=target, evidence=evidence)
