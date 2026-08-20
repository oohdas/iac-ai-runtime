"""Prepare Railway's root-owned volume, drop privileges, and start the worker."""

from __future__ import annotations

import os
import math
from pathlib import Path
import sys
from typing import Mapping


WORKER_UID = 10001
WORKER_GID = 10001


def _safe_reference(name: str, value: str) -> str:
    if not value or len(value) > 200 or any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must be a non-empty single-line reference")
    return value


def worker_arguments(environment: Mapping[str, str]) -> list[str]:
    """Translate a complete non-secret environment contract into worker arguments."""
    database = environment.get("SEAN_OS_DATABASE", "/data/sean-os.db")
    arguments = ["scripts/worker.py", "--database", database]
    route_id = environment.get("SEAN_OS_MONITOR_ROUTE_ID")
    destination_kind = environment.get("SEAN_OS_MONITOR_DESTINATION_KIND")
    destination_ref = environment.get("SEAN_OS_MONITOR_DESTINATION_REF")
    interval = environment.get("SEAN_OS_MONITOR_INTERVAL_SECONDS")
    route_fields = (route_id, destination_kind, destination_ref)
    if any(route_fields) or interval is not None:
        if not all(route_fields):
            raise ValueError("Monitoring environment requires a complete route contract")
        if destination_kind not in {"EMAIL", "WEBHOOK"}:
            raise ValueError("Unsupported monitoring destination kind")
        try:
            interval_value = float(interval) if interval is not None else 30.0
        except ValueError as exc:
            raise ValueError("Monitoring interval must be numeric") from exc
        if not math.isfinite(interval_value) or interval_value < 1:
            raise ValueError("Monitoring interval must be finite and at least one second")
        arguments.extend(
            [
                "--monitor-route-id", _safe_reference("route ID", route_id),
                "--monitor-destination-kind", destination_kind,
                "--monitor-destination-ref", _safe_reference("destination ref", destination_ref),
                "--monitor-interval-seconds", str(interval_value),
            ]
        )
    delivery_mode=environment.get("SEAN_OS_ALERT_DELIVERY_MODE")
    if delivery_mode is not None:
        if delivery_mode != "SYNTHETIC_ONLY":
            raise ValueError("Alert delivery mode must be SYNTHETIC_ONLY when configured")
        arguments.append("--synthetic-delivery")
    return arguments


def main() -> None:
    database = Path(os.environ.get("SEAN_OS_DATABASE", "/data/sean-os.db"))
    arguments = worker_arguments(os.environ)
    database.parent.mkdir(parents=True, exist_ok=True)
    os.chown(database.parent, WORKER_UID, WORKER_GID)
    os.setgroups([])
    os.setgid(WORKER_GID)
    os.setuid(WORKER_UID)
    os.execv(
        sys.executable,
        [sys.executable, *arguments],
    )


if __name__ == "__main__":
    main()
