#!/usr/bin/env python3
"""Prepare a deterministic non-creating Backblaze writer-key approval package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import build_backup_writer_key_approval_package  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a least-privilege key proposal without creating a key."
    )
    parser.add_argument("proposal", type=Path)
    arguments = parser.parse_args()
    proposal = json.loads(arguments.proposal.read_text(encoding="utf-8"))
    print(json.dumps(
        build_backup_writer_key_approval_package(proposal), indent=2, sort_keys=True
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
