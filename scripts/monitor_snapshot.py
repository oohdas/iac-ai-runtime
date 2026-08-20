"""Emit a machine-readable health and escalation snapshot without delivery."""

from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import SeanOSStore, classify_alerts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--stale-after-seconds", type=int, default=90)
    parser.add_argument("--backup-ok", choices=("true", "false", "unknown"), default="unknown")
    args = parser.parse_args()
    backup_ok = None if args.backup_ok == "unknown" else args.backup_ok == "true"
    store = SeanOSStore(args.database)
    try:
        health = store.runtime_health(
            stale_after_seconds=args.stale_after_seconds, require_active_worker=True
        )
        alerts = classify_alerts(health, backup_ok=backup_ok)
        result = {
            "healthy": health["healthy"] and backup_ok is not False,
            "delivery_authorized": False,
            "alerts": alerts,
            "health": health,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["healthy"] else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
