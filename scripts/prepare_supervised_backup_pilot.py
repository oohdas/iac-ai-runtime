#!/usr/bin/env python3
"""Print an exact non-executing package for the supervised synthetic pilot."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import build_supervised_backup_pilot_package  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_commit")
    parser.add_argument("window_start", help="Timezone-aware ISO-8601 start")
    parser.add_argument("--duration-minutes", type=int, default=120)
    arguments = parser.parse_args()
    start = datetime.fromisoformat(arguments.window_start)
    end = start + timedelta(minutes=arguments.duration_minutes)
    package = build_supervised_backup_pilot_package(
        candidate_commit=arguments.candidate_commit,
        window_start=start.isoformat(),
        window_end=end.isoformat(),
    )
    print(json.dumps(package, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
