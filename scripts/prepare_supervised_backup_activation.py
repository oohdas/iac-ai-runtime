#!/usr/bin/env python3
"""Create and stage one synthetic-only backup activation without network use."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import SeanOSStore, prepare_supervised_synthetic_backup_activation


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("candidate_commit")
    parser.add_argument("window_start", help="Timezone-aware ISO-8601 start")
    parser.add_argument("--duration-minutes", type=int, default=120)
    arguments=parser.parse_args()
    start=datetime.fromisoformat(arguments.window_start)
    end=start + timedelta(minutes=arguments.duration_minutes)
    store=SeanOSStore(arguments.database, scope_profile="IAC")
    try:
        package=prepare_supervised_synthetic_backup_activation(
            store, workspace=arguments.workspace,
            candidate_commit=arguments.candidate_commit,
            window_start=start.isoformat(), window_end=end.isoformat(),
        )
    finally:
        store.close()
    print(json.dumps({
        "activation_sha256":package["activation_sha256"],
        "plan_sha256":package["transfer_plan"]["plan_sha256"],
        "transfer_status":package["transfer_status"],
        "data_mode":package["data_mode"],
        "network_performed":package["network_performed"],
        "key_created":package["key_created"],
        "secret_placed":package["secret_placed"],
        "upload_authorized":package["upload_authorized"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
