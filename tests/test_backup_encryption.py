import hashlib
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from sean_os import (
    AES256GCMFileDecryptor,
    AES256GCMFileEncryptor,
    BackupEncryptionError,
)


class SyntheticKeyResolver:
    def __init__(self, key: bytes = b"k" * 32):
        self.key = key
        self.buffers = []
        self.references = []

    @contextmanager
    def open_key(self, key_ref):
        self.references.append(key_ref)
        material = bytearray(self.key)
        self.buffers.append(material)
        yield material


def plan_for(content: bytes):
    return {
        "plan_sha256": hashlib.sha256(b"synthetic-plan").hexdigest(),
        "backup_sha256": hashlib.sha256(content).hexdigest(),
        "backup_bytes": len(content),
    }


class BackupEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "encrypted"
        self.output.mkdir(mode=0o700)
        self.content = (b"synthetic-iac-backup\x00" * 100_000) + b"end"
        self.source = self.root / "source.db"
        self.source.write_bytes(self.content)
        self.plan = plan_for(self.content)
        self.key_ref = "iac-keyring:backup-key-v1"

    def tearDown(self):
        self.temp.cleanup()

    def encrypt(self):
        resolver = SyntheticKeyResolver()
        artifact = AES256GCMFileEncryptor(self.output, resolver).encrypt(
            self.source, plan=self.plan, key_ref=self.key_ref
        )
        return resolver, artifact

    def test_streaming_round_trip_is_authenticated_private_and_path_free(self):
        encrypt_resolver, artifact = self.encrypt()
        self.assertNotEqual(artifact.path.read_bytes(), self.content)
        self.assertEqual(stat.S_IMODE(artifact.path.stat().st_mode), 0o600)
        self.assertTrue(all(value == 0 for value in encrypt_resolver.buffers[0]))
        serialized = json.dumps(artifact.evidence)
        self.assertNotIn(str(self.source), serialized)
        self.assertNotIn(str(artifact.path), serialized)
        self.assertNotIn(self.content[:20].decode("ascii"), serialized)

        restore_resolver = SyntheticKeyResolver()
        restored = AES256GCMFileDecryptor(restore_resolver).decrypt_to(
            artifact.path,
            self.root / "restored.db",
            key_ref=self.key_ref,
            expected_plan_sha256=self.plan["plan_sha256"],
        )
        self.assertEqual(restored.path.read_bytes(), self.content)
        self.assertEqual(stat.S_IMODE(restored.path.stat().st_mode), 0o600)
        self.assertTrue(restored.evidence["authenticated"])
        self.assertTrue(all(value == 0 for value in restore_resolver.buffers[0]))

    def test_fresh_nonce_makes_repeated_encryption_distinct(self):
        _, first = self.encrypt()
        _, second = self.encrypt()
        self.assertNotEqual(
            first.evidence["ciphertext_sha256"],
            second.evidence["ciphertext_sha256"],
        )

    def test_source_mismatch_fails_closed_and_removes_partial_output(self):
        wrong = dict(self.plan)
        wrong["backup_sha256"] = hashlib.sha256(b"different").hexdigest()
        resolver = SyntheticKeyResolver()
        with self.assertRaisesRegex(BackupEncryptionError, "no longer matches"):
            AES256GCMFileEncryptor(self.output, resolver).encrypt(
                self.source, plan=wrong, key_ref=self.key_ref
            )
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertTrue(all(value == 0 for value in resolver.buffers[0]))

    def test_tampering_never_publishes_restore_plaintext(self):
        _, artifact = self.encrypt()
        with artifact.path.open("r+b") as handle:
            handle.seek(-17, os.SEEK_END)
            byte = handle.read(1)
            handle.seek(-1, os.SEEK_CUR)
            handle.write(bytes([byte[0] ^ 1]))
        destination = self.root / "tampered-restore.db"
        resolver = SyntheticKeyResolver()
        with self.assertRaisesRegex(BackupEncryptionError, "authentication failed"):
            AES256GCMFileDecryptor(resolver).decrypt_to(
                artifact.path,
                destination,
                key_ref=self.key_ref,
                expected_plan_sha256=self.plan["plan_sha256"],
            )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".*.partial-*")), [])
        self.assertTrue(all(value == 0 for value in resolver.buffers[0]))

    def test_restore_requires_exact_plan_key_and_new_destination(self):
        _, artifact = self.encrypt()
        for key_ref, plan_sha in (
            ("iac-keyring:other-key-v1", self.plan["plan_sha256"]),
            (self.key_ref, hashlib.sha256(b"other-plan").hexdigest()),
        ):
            with self.subTest(key_ref=key_ref, plan_sha=plan_sha):
                with self.assertRaisesRegex(BackupEncryptionError, "approved restore"):
                    AES256GCMFileDecryptor(SyntheticKeyResolver()).decrypt_to(
                        artifact.path,
                        self.root / "not-created.db",
                        key_ref=key_ref,
                        expected_plan_sha256=plan_sha,
                    )
        existing = self.root / "existing.db"
        existing.write_bytes(b"keep")
        with self.assertRaisesRegex(BackupEncryptionError, "must not already exist"):
            AES256GCMFileDecryptor(SyntheticKeyResolver()).decrypt_to(
                artifact.path,
                existing,
                key_ref=self.key_ref,
                expected_plan_sha256=self.plan["plan_sha256"],
            )
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_resolver_must_yield_mutable_exact_aes256_key(self):
        for key in (b"short", b"long" * 16):
            with self.subTest(length=len(key)):
                resolver = SyntheticKeyResolver(key)
                with self.assertRaisesRegex(BackupEncryptionError, "mutable 32-byte"):
                    AES256GCMFileEncryptor(
                        self.output, resolver
                    ).encrypt(self.source, plan=self.plan, key_ref=self.key_ref)
                self.assertTrue(all(value == 0 for value in resolver.buffers[0]))
        self.assertEqual(list(self.output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
