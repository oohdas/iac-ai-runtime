"""Prepare Railway's root-owned volume, drop privileges, and start the worker."""

from __future__ import annotations

import os
from pathlib import Path
import sys


WORKER_UID = 10001
WORKER_GID = 10001


def main() -> None:
    database = Path(os.environ.get("SEAN_OS_DATABASE", "/data/sean-os.db"))
    database.parent.mkdir(parents=True, exist_ok=True)
    os.chown(database.parent, WORKER_UID, WORKER_GID)
    os.setgroups([])
    os.setgid(WORKER_GID)
    os.setuid(WORKER_UID)
    os.execv(
        sys.executable,
        [sys.executable, "scripts/worker.py", "--database", str(database)],
    )


if __name__ == "__main__":
    main()
