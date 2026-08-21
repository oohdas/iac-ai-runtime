"""Injected S3-compatible upload port for the Backblaze B2 backup pilot.

This module does not construct a network client or resolve credentials. A reviewed
client must be injected later. The port performs one conditional upload, never retries
an ambiguous write, and turns only bounded provider facts into receipt evidence.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from .backup_execution import BackupRuntimeConfig, EncryptedBackupArtifact
from .security import secret_findings


class BackupProviderError(ValueError):
    pass


class BackupReconciliationRequired(BackupProviderError):
    """The provider may have accepted a write, so automatic retry is prohibited."""

    retry_permitted = False


class S3CompatibleBackupClient(Protocol):
    def get_bucket_encryption(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object_lock_configuration(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object_retention(self, **kwargs: Any) -> Mapping[str, Any]: ...


_BUCKET_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{4,61}[a-z0-9]")
_OBJECT_KEY = re.compile(r"backups/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def verify_backblaze_bucket_name(value: Any) -> str:
    if not isinstance(value, str) or not _BUCKET_NAME.fullmatch(value):
        raise BackupProviderError("Backblaze bucket name is malformed")
    if ".." in value or ".-" in value or "-." in value:
        raise BackupProviderError("Backblaze bucket name is unsafe")
    return value


def _safe_reference(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > 200
        or any(ord(character) < 32 for character in value)
        or secret_findings(value)
    ):
        raise BackupProviderError(f"{name} must be one bounded non-secret reference")
    return value


def _bounded_provider_reference(name: str, value: Any) -> str:
    value = _safe_reference(name, value)
    if len(value) > 160:
        raise BackupProviderError(f"{name} is too long")
    return value


def _response_metadata(value: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    metadata = value.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or metadata.get("HTTPStatusCode") != 200:
        raise BackupProviderError(f"Backblaze {operation} did not return a verified success")
    return metadata


def _provider_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        instant = value
    elif isinstance(value, str) and 1 <= len(value) <= 100:
        try:
            instant = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                instant = datetime.fromisoformat(value)
            except ValueError as exc:
                raise BackupProviderError("Backblaze response timestamp is malformed") from exc
    else:
        raise BackupProviderError("Backblaze response timestamp is missing")
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise BackupProviderError("Backblaze response timestamp must include a timezone")
    return instant


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BackblazeS3UploadPort:
    """Verify bucket controls, upload once, and verify immutable retention."""

    def __init__(
        self,
        client: S3CompatibleBackupClient,
        *,
        bucket_name: str,
        destination_ref: str,
        endpoint: str,
        writer_identity_ref: str,
    ):
        bucket_name=verify_backblaze_bucket_name(bucket_name)
        destination_ref=_safe_reference("destination_ref", destination_ref)
        if destination_ref != f"backblaze-b2-bucket:{bucket_name}":
            raise BackupProviderError(
                "Backblaze bucket does not match the approved destination reference"
            )
        self.client = client
        self.bucket_name = bucket_name
        self.destination_ref = destination_ref
        self.endpoint = _safe_reference("endpoint", endpoint)
        self.writer_identity_ref = _safe_reference(
            "writer_identity_ref", writer_identity_ref
        )

    def _verify_exact_contract(
        self,
        artifact: EncryptedBackupArtifact,
        plan: Mapping[str, Any],
        config: BackupRuntimeConfig,
    ) -> tuple[Path, str, str, int]:
        if (
            not config.enabled
            or config.provider != "BACKBLAZE_B2"
            or config.data_region != "CA_EAST"
            or config.endpoint != self.endpoint
            or config.destination_ref != self.destination_ref
            or config.writer_identity_ref != self.writer_identity_ref
            or plan.get("provider") != config.provider
            or plan.get("data_region") != config.data_region
            or plan.get("provider_endpoint") != config.endpoint
            or plan.get("destination_ref") != config.destination_ref
            or plan.get("provider_writer_identity_ref") != config.writer_identity_ref
        ):
            raise BackupProviderError(
                "Backblaze client binding does not match the approved runtime plan"
            )
        object_key = plan.get("object_ref")
        if (
            not isinstance(object_key, str)
            or not _OBJECT_KEY.fullmatch(object_key)
            or ".." in object_key
            or "//" in object_key
        ):
            raise BackupProviderError("Backblaze object key is outside the backup prefix")
        evidence = artifact.evidence
        content_sha256 = evidence.get("ciphertext_sha256")
        content_bytes = evidence.get("ciphertext_bytes")
        plan_sha256 = plan.get("plan_sha256")
        if (
            not isinstance(content_sha256, str)
            or not _SHA256.fullmatch(content_sha256)
            or isinstance(content_bytes, bool)
            or not isinstance(content_bytes, int)
            or content_bytes <= 0
            or not isinstance(plan_sha256, str)
            or not _SHA256.fullmatch(plan_sha256)
            or evidence.get("plan_sha256") != plan_sha256
            or evidence.get("authenticated") is not True
            or evidence.get("credentials_persisted") is not False
            or evidence.get("source_path_included") is not False
        ):
            raise BackupProviderError("Encrypted artifact evidence is incomplete or unsafe")
        path = artifact.path
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != content_bytes
            or _hash_file(path) != content_sha256
            or content_bytes > int(config.max_bytes or 0) + 64 * 1024
        ):
            raise BackupProviderError("Encrypted artifact does not match its evidence")
        return path, object_key, content_sha256, content_bytes

    def _verify_bucket_controls(self, retention_days: int) -> None:
        encryption = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        _response_metadata(encryption, "bucket encryption check")
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not any(
            isinstance(rule, Mapping)
            and rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            == "AES256"
            for rule in rules
        ):
            raise BackupProviderError("Backblaze bucket default SSE-B2 is not verified")
        lock = self.client.get_object_lock_configuration(Bucket=self.bucket_name)
        _response_metadata(lock, "bucket retention check")
        configuration = lock.get("ObjectLockConfiguration", {})
        default = configuration.get("Rule", {}).get("DefaultRetention", {})
        if (
            configuration.get("ObjectLockEnabled") != "Enabled"
            or default.get("Mode") != "COMPLIANCE"
            or default.get("Days") != retention_days
        ):
            raise BackupProviderError(
                "Backblaze bucket compliance retention does not match the plan"
            )

    def upload_new(
        self,
        artifact: EncryptedBackupArtifact,
        *,
        plan: Mapping[str, Any],
        config: BackupRuntimeConfig,
    ) -> Mapping[str, Any]:
        path, object_key, content_sha256, content_bytes = self._verify_exact_contract(
            artifact, plan, config
        )
        retention_days = plan.get("retention_days")
        if isinstance(retention_days, bool) or not isinstance(retention_days, int):
            raise BackupProviderError("Backblaze retention period is malformed")
        upload_attempted = False
        try:
            self._verify_bucket_controls(retention_days)
            with path.open("rb") as body:
                upload_attempted = True
                uploaded = self.client.put_object(
                    Body=body,
                    Bucket=self.bucket_name,
                    Key=object_key,
                    ContentLength=content_bytes,
                    ContentType="application/octet-stream",
                    IfNoneMatch="*",
                    Metadata={
                        "sean-os-plan-sha256": plan["plan_sha256"],
                        "sean-os-content-sha256": content_sha256,
                    },
                    ServerSideEncryption="AES256",
                )
            uploaded_metadata = _response_metadata(uploaded, "conditional upload")
            if uploaded.get("ServerSideEncryption") != "AES256":
                raise BackupProviderError("Backblaze object SSE-B2 is not verified")
            version_ref = _bounded_provider_reference(
                "provider_version_ref", uploaded.get("VersionId")
            )
            request_ref = _bounded_provider_reference(
                "provider_request_ref", uploaded_metadata.get("RequestId")
            )
            headers = uploaded_metadata.get("HTTPHeaders")
            if not isinstance(headers, Mapping):
                raise BackupProviderError("Backblaze response headers are missing")
            uploaded_at = _provider_time(headers.get("date"))
            retention = self.client.get_object_retention(
                Bucket=self.bucket_name,
                Key=object_key,
                VersionId=version_ref,
            )
            _response_metadata(retention, "object retention check")
            retention_value = retention.get("Retention")
            if (
                not isinstance(retention_value, Mapping)
                or retention_value.get("Mode") != "COMPLIANCE"
            ):
                raise BackupProviderError("Backblaze object compliance lock is not verified")
            retain_until = _provider_time(retention_value.get("RetainUntilDate"))
            if (retain_until - uploaded_at).total_seconds() < retention_days * 86400:
                raise BackupProviderError("Backblaze object retention is shorter than approved")
        except BackupProviderError as exc:
            if upload_attempted:
                raise BackupReconciliationRequired(
                    "Backblaze write result requires manual reconciliation; automatic retry is prohibited"
                ) from exc
            raise
        except Exception as exc:
            if upload_attempted:
                raise BackupReconciliationRequired(
                    "Backblaze write result requires manual reconciliation; automatic retry is prohibited"
                ) from exc
            raise BackupProviderError("Backblaze preflight failed before upload") from exc
        return {
            "provider": "BACKBLAZE_B2",
            "provider_region": "CA_EAST",
            "provider_endpoint": self.endpoint,
            "provider_writer_identity_ref": self.writer_identity_ref,
            "plan_sha256": plan["plan_sha256"],
            "destination_ref": self.destination_ref,
            "object_ref": object_key,
            "content_sha256": content_sha256,
            "content_bytes": content_bytes,
            "provider_request_ref": request_ref,
            "provider_version_ref": version_ref,
            "provider_encryption": "AES256",
            "encryption_verified": True,
            "object_lock_mode": "COMPLIANCE",
            "object_lock_verified": True,
            "retention_days": retention_days,
            "uploaded_at": uploaded_at.isoformat(),
            "retain_until": retain_until.isoformat(),
            "network_performed": True,
            "uploaded": True,
            "overwrite_performed": False,
            "restore_authorized": False,
            "credentials_persisted": False,
        }
