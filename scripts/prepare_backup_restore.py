#!/usr/bin/env python3
"""Prepare a deterministic, non-executing isolated-restore approval package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import (  # noqa: E402
    build_backup_restore_key_approval_package,
    build_isolated_backup_restore_plan,
    synthetic_backup_restore_preflight,
)


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bind verified upload evidence to an isolated restore without creating "
            "a key, resolving secrets, downloading, decrypting, or restoring."
        )
    )
    parser.add_argument("upload_plan", type=Path)
    parser.add_argument("upload_receipt", type=Path)
    parser.add_argument("restore_key_proposal", type=Path)
    parser.add_argument("--restore-target-ref", required=True)
    parser.add_argument("--window-start", required=True)
    parser.add_argument("--window-end", required=True)
    parser.add_argument("--max-cost-cad", type=float, required=True)
    arguments = parser.parse_args()
    key_package = build_backup_restore_key_approval_package(
        _read(arguments.restore_key_proposal)
    )
    plan = build_isolated_backup_restore_plan(
        _read(arguments.upload_plan),
        _read(arguments.upload_receipt),
        key_package,
        restore_target_ref=arguments.restore_target_ref,
        window_start=arguments.window_start,
        window_end=arguments.window_end,
        max_cost_cad=arguments.max_cost_cad,
    )
    print(json.dumps({
        "restore_key_package": key_package,
        "restore_plan": plan,
        "synthetic_preflight": synthetic_backup_restore_preflight(plan),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
