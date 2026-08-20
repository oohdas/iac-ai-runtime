from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import SeanOSStore


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--stale-after-seconds", type=int, default=90)
    args=parser.parse_args()
    store=SeanOSStore(args.database)
    try:
        health=store.runtime_health(
            stale_after_seconds=args.stale_after_seconds, require_active_worker=True
        )
        print(json.dumps(health, indent=2, sort_keys=True))
        return 0 if health["healthy"] else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
