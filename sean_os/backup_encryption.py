"""Streaming authenticated client encryption for independent IAC backups.

The key resolver is intentionally injected. This module never reads secrets from the
environment, never persists key material, and cannot contact a secret provider. Its
binary envelope keeps only non-secret recovery metadata and authenticates that metadata
alongside the ciphertext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .backup_execution import ENCRYPTED_ARTIFACT_FORMAT, EncryptedBackupArtifact
from .security import secret_findings


class BackupEncryptionError(ValueError):
    pass


ENVELOPE_FORMAT = "sean-os-client-encrypted-backup-envelope/v1"
DECRYPTED_ARTIFACT_FORMAT = "sean-os-authenticated-backup-restore/v1"
ALGORITHM = "AES_256_GCM"
MAGIC = b"SEANOSB1"
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 4096
MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024 * 1024
HEADER_FIELDS = frozenset({
    "format",
    "algorithm",
    "plan_sha256",
    "plaintext_sha256",
    "plaintext_bytes",
    "key_owner",
    "key_ref",
    "nonce_b64",
    "tag_bytes",
})
_SHA256 = re.compile(r"[0-9a-f]{64}")


class EncryptionKeyResolver(Protocol):
    """Resolve one opaque IAC key reference for the duration of one operation."""

    def open_key(self, key_ref: str) -> AbstractContextManager[bytearray]: ...


@dataclass(frozen=True)
class DecryptedBackupArtifact:
    path: Path
    evidence: Mapping[str, Any]


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _safe_reference(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > 200
        or any(ord(character) < 32 for character in value)
        or secret_findings(value)
    ):
        raise BackupEncryptionError(f"{name} must be one bounded non-secret reference")
    return value


def _validate_sha256(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise BackupEncryptionError(f"{name} must be one SHA-256 digest")
    return value


def _validate_plaintext_bytes(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_PLAINTEXT_BYTES
    ):
        raise BackupEncryptionError("plaintext_bytes is outside the supported range")
    return value


def _wipe_key(key_material: bytearray) -> None:
    for index in range(len(key_material)):
        key_material[index] = 0


def _require_key_material(value: Any) -> bytearray:
    if not isinstance(value, bytearray) or len(value) != 32:
        raise BackupEncryptionError(
            "The key resolver must yield one mutable 32-byte AES-256 key"
        )
    return value


def _require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BackupEncryptionError(f"{description} must be a regular, non-symlink file")


def _require_private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise BackupEncryptionError(
            "Encryption output directory must be an existing non-symlink directory"
        )


def _exclusive_private_file(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "wb")


def _header_from_plan(
    plan: Mapping[str, Any], key_ref: str, nonce: bytes
) -> dict[str, Any]:
    return {
        "format": ENVELOPE_FORMAT,
        "algorithm": ALGORITHM,
        "plan_sha256": _validate_sha256("plan_sha256", plan.get("plan_sha256")),
        "plaintext_sha256": _validate_sha256(
            "backup_sha256", plan.get("backup_sha256")
        ),
        "plaintext_bytes": _validate_plaintext_bytes(plan.get("backup_bytes")),
        "key_owner": "IAC",
        "key_ref": _safe_reference("key_ref", key_ref),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "tag_bytes": TAG_BYTES,
    }


def _parse_header(raw: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupEncryptionError("Encrypted backup header is malformed") from exc
    if not isinstance(value, dict) or set(value) != HEADER_FIELDS:
        raise BackupEncryptionError("Encrypted backup header fields are unsupported")
    expected = {
        "format": ENVELOPE_FORMAT,
        "algorithm": ALGORITHM,
        "key_owner": "IAC",
        "tag_bytes": TAG_BYTES,
    }
    if any(value.get(field) != wanted for field, wanted in expected.items()):
        raise BackupEncryptionError("Encrypted backup header contract is unsupported")
    _validate_sha256("plan_sha256", value.get("plan_sha256"))
    _validate_sha256("plaintext_sha256", value.get("plaintext_sha256"))
    _validate_plaintext_bytes(value.get("plaintext_bytes"))
    _safe_reference("key_ref", value.get("key_ref"))
    try:
        nonce = base64.b64decode(value.get("nonce_b64"), validate=True)
    except (TypeError, ValueError) as exc:
        raise BackupEncryptionError("Encrypted backup nonce is malformed") from exc
    if len(nonce) != NONCE_BYTES:
        raise BackupEncryptionError("Encrypted backup nonce has the wrong length")
    if _canonical(value) != raw:
        raise BackupEncryptionError("Encrypted backup header is not canonical")
    return value, nonce


class AES256GCMFileEncryptor:
    """Create a new path-free, authenticated envelope with a random nonce."""

    def __init__(self, output_directory: Path, key_resolver: EncryptionKeyResolver):
        self.output_directory = Path(output_directory)
        self.key_resolver = key_resolver

    def encrypt(
        self, source: Path, *, plan: Mapping[str, Any], key_ref: str
    ) -> EncryptedBackupArtifact:
        source = Path(source)
        _require_regular_file(source, "Backup source")
        _require_private_directory(self.output_directory)
        nonce = os.urandom(NONCE_BYTES)
        header = _header_from_plan(plan, key_ref, nonce)
        header_bytes = _canonical(header)
        if len(header_bytes) > MAX_HEADER_BYTES:
            raise BackupEncryptionError("Encrypted backup header is too large")
        prefix = MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes
        target = self.output_directory / (
            f"backup-{header['plan_sha256'][:16]}-{secrets.token_hex(6)}.enc"
        )
        plaintext_digest = hashlib.sha256()
        ciphertext_digest = hashlib.sha256()
        plaintext_bytes = 0
        created = False
        try:
            with self.key_resolver.open_key(header["key_ref"]) as resolved:
                try:
                    key_material = _require_key_material(resolved)
                    encryptor = Cipher(
                        algorithms.AES256(key_material), modes.GCM(nonce)
                    ).encryptor()
                    encryptor.authenticate_additional_data(prefix)
                    with _exclusive_private_file(target) as output:
                        created = True
                        output.write(prefix)
                        ciphertext_digest.update(prefix)
                        with source.open("rb") as plaintext:
                            for chunk in iter(lambda: plaintext.read(CHUNK_BYTES), b""):
                                plaintext_digest.update(chunk)
                                plaintext_bytes += len(chunk)
                                encrypted = encryptor.update(chunk)
                                output.write(encrypted)
                                ciphertext_digest.update(encrypted)
                        final = encryptor.finalize()
                        output.write(final)
                        ciphertext_digest.update(final)
                        tag = encryptor.tag
                        if len(tag) != TAG_BYTES:
                            raise BackupEncryptionError(
                                "AES-GCM produced an unsupported authentication tag"
                            )
                        output.write(tag)
                        ciphertext_digest.update(tag)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    if isinstance(resolved, bytearray):
                        _wipe_key(resolved)
            if (
                plaintext_bytes != header["plaintext_bytes"]
                or plaintext_digest.hexdigest() != header["plaintext_sha256"]
            ):
                raise BackupEncryptionError(
                    "Backup source changed after approval or no longer matches its plan"
                )
            mode = stat.S_IMODE(target.stat().st_mode)
            if mode != 0o600:
                raise BackupEncryptionError("Encrypted backup file is not private")
        except Exception:
            if created:
                target.unlink(missing_ok=True)
            raise
        evidence = {
            "format": ENCRYPTED_ARTIFACT_FORMAT,
            "plan_sha256": header["plan_sha256"],
            "plaintext_sha256": header["plaintext_sha256"],
            "plaintext_bytes": header["plaintext_bytes"],
            "ciphertext_sha256": ciphertext_digest.hexdigest(),
            "ciphertext_bytes": target.stat().st_size,
            "algorithm": ALGORITHM,
            "key_owner": "IAC",
            "key_ref": header["key_ref"],
            "authenticated": True,
            "aad_plan_sha256": header["plan_sha256"],
            "credentials_persisted": False,
            "source_path_included": False,
        }
        return EncryptedBackupArtifact(path=target, evidence=evidence)


class AES256GCMFileDecryptor:
    """Authenticate into a private temporary file, then publish without overwrite."""

    def __init__(self, key_resolver: EncryptionKeyResolver):
        self.key_resolver = key_resolver

    def decrypt_to(
        self,
        encrypted: Path,
        destination: Path,
        *,
        key_ref: str,
        expected_plan_sha256: str,
    ) -> DecryptedBackupArtifact:
        encrypted = Path(encrypted)
        destination = Path(destination)
        _require_regular_file(encrypted, "Encrypted backup")
        _require_private_directory(destination.parent)
        if destination.exists() or destination.is_symlink():
            raise BackupEncryptionError("Restore destination must not already exist")
        expected_plan_sha256 = _validate_sha256(
            "expected_plan_sha256", expected_plan_sha256
        )
        key_ref = _safe_reference("key_ref", key_ref)
        partial = destination.parent / (
            f".{destination.name}.partial-{secrets.token_hex(6)}"
        )
        created = False
        published = False
        try:
            with encrypted.open("rb") as source:
                if source.read(len(MAGIC)) != MAGIC:
                    raise BackupEncryptionError("Encrypted backup magic is invalid")
                raw_length = source.read(4)
                if len(raw_length) != 4:
                    raise BackupEncryptionError("Encrypted backup header length is missing")
                header_length = int.from_bytes(raw_length, "big")
                if not 1 <= header_length <= MAX_HEADER_BYTES:
                    raise BackupEncryptionError("Encrypted backup header length is invalid")
                header_bytes = source.read(header_length)
                if len(header_bytes) != header_length:
                    raise BackupEncryptionError("Encrypted backup header is truncated")
                header, nonce = _parse_header(header_bytes)
                if (
                    header["plan_sha256"] != expected_plan_sha256
                    or header["key_ref"] != key_ref
                ):
                    raise BackupEncryptionError(
                        "Encrypted backup does not match the approved restore request"
                    )
                prefix = MAGIC + raw_length + header_bytes
                ciphertext_offset = len(prefix)
                expected_size = (
                    ciphertext_offset + header["plaintext_bytes"] + TAG_BYTES
                )
                if encrypted.stat().st_size != expected_size:
                    raise BackupEncryptionError("Encrypted backup size is inconsistent")
                source.seek(-TAG_BYTES, os.SEEK_END)
                tag = source.read(TAG_BYTES)
                source.seek(ciphertext_offset)
                plaintext_digest = hashlib.sha256()
                plaintext_bytes = 0
                with self.key_resolver.open_key(key_ref) as resolved:
                    try:
                        key_material = _require_key_material(resolved)
                        decryptor = Cipher(
                            algorithms.AES256(key_material), modes.GCM(nonce, tag)
                        ).decryptor()
                        decryptor.authenticate_additional_data(prefix)
                        with _exclusive_private_file(partial) as output:
                            created = True
                            remaining = header["plaintext_bytes"]
                            while remaining:
                                chunk = source.read(min(CHUNK_BYTES, remaining))
                                if not chunk:
                                    raise BackupEncryptionError(
                                        "Encrypted backup ciphertext is truncated"
                                    )
                                remaining -= len(chunk)
                                plaintext = decryptor.update(chunk)
                                output.write(plaintext)
                                plaintext_digest.update(plaintext)
                                plaintext_bytes += len(plaintext)
                            try:
                                final = decryptor.finalize()
                            except InvalidTag as exc:
                                raise BackupEncryptionError(
                                    "Encrypted backup authentication failed"
                                ) from exc
                            output.write(final)
                            plaintext_digest.update(final)
                            plaintext_bytes += len(final)
                            output.flush()
                            os.fsync(output.fileno())
                    finally:
                        if isinstance(resolved, bytearray):
                            _wipe_key(resolved)
            if (
                plaintext_bytes != header["plaintext_bytes"]
                or plaintext_digest.hexdigest() != header["plaintext_sha256"]
            ):
                raise BackupEncryptionError(
                    "Authenticated restore does not match the recorded plaintext"
                )
            os.link(partial, destination)
            published = True
            partial.unlink()
            created = False
        except Exception:
            if created:
                partial.unlink(missing_ok=True)
            if published:
                destination.unlink(missing_ok=True)
            raise
        evidence = {
            "format": DECRYPTED_ARTIFACT_FORMAT,
            "plan_sha256": header["plan_sha256"],
            "plaintext_sha256": header["plaintext_sha256"],
            "plaintext_bytes": header["plaintext_bytes"],
            "algorithm": ALGORITHM,
            "key_owner": "IAC",
            "key_ref": key_ref,
            "authenticated": True,
            "credentials_persisted": False,
            "source_path_included": False,
        }
        return DecryptedBackupArtifact(path=destination, evidence=evidence)
