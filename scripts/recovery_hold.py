"""Keep a restored Railway volume mounted without opening the canonical database."""

from __future__ import annotations

import json
import signal
import threading


def main() -> None:
    stop=threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(json.dumps({
        "state":"MIGRATION_RECOVERY_HOLD",
        "database_opened":False,
        "worker_started":False,
        "external_effect":False,
    }, sort_keys=True), flush=True)
    while not stop.wait(30):
        print(json.dumps({"state":"MIGRATION_RECOVERY_HOLD"}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
