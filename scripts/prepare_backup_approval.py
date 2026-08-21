"""Validate and print an exact, non-executing independent-backup approval package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os.backup_approval import (
    BackupApprovalError,
    build_independent_backup_approval_package,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("proposal", type=Path)
    args = parser.parse_args()
    try:
        proposal = json.loads(args.proposal.read_text(encoding="utf-8"))
        package = build_independent_backup_approval_package(proposal)
    except (OSError, json.JSONDecodeError, BackupApprovalError) as exc:
        parser.error(str(exc))
    print(json.dumps(package, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
