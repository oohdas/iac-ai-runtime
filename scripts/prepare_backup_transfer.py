#!/usr/bin/env python3
"""Prepare and validate a no-network backup transfer plan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import (  # noqa: E402
    build_backup_transfer_plan,
    synthetic_backup_adapter_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a local IAC backup and print a no-network transfer plan."
    )
    parser.add_argument("approval_package", type=Path)
    parser.add_argument("backup_manifest", type=Path)
    parser.add_argument("--object-ref", required=True)
    parser.add_argument("--provider-endpoint", required=True)
    parser.add_argument("--writer-identity-ref", required=True)
    parser.add_argument("--client-encryption-key-ref", required=True)
    arguments = parser.parse_args()
    package = json.loads(arguments.approval_package.read_text(encoding="utf-8"))
    manifest = json.loads(arguments.backup_manifest.read_text(encoding="utf-8"))
    plan = build_backup_transfer_plan(
        package,
        manifest,
        object_ref=arguments.object_ref,
        provider_endpoint=arguments.provider_endpoint,
        writer_identity_ref=arguments.writer_identity_ref,
        client_encryption_key_ref=arguments.client_encryption_key_ref,
    )
    receipt = synthetic_backup_adapter_receipt(plan, package)
    print(json.dumps({"plan": plan, "synthetic_receipt": receipt}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
