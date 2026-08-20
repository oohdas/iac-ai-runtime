"""Supervised local monitor that persists alert evidence but never delivers it."""

from __future__ import annotations

from pathlib import Path
import argparse
import json
import signal
import sys
from threading import Event
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import EscalationRoute, SeanOSStore
from scripts.monitor_snapshot import build_snapshot


SnapshotSink = Callable[[dict], None]
Waiter = Callable[[float], bool]


def run_monitor_loop(
    store: SeanOSStore, route: EscalationRoute, *, interval_seconds: float,
    wait: Waiter, sink: SnapshotSink, max_iterations: int | None = None,
    stale_after_seconds: int = 90,
) -> int:
    """Run bounded-cadence snapshots; return completed iteration count."""
    if interval_seconds < 1:
        raise ValueError("Monitoring interval must be at least one second")
    if max_iterations is not None and max_iterations < 1:
        raise ValueError("max_iterations must be positive")
    completed = 0
    while max_iterations is None or completed < max_iterations:
        snapshot = build_snapshot(
            store, stale_after_seconds=stale_after_seconds, route=route
        )
        sink(snapshot)
        completed += 1
        if max_iterations is not None and completed >= max_iterations:
            break
        if wait(interval_seconds):
            break
    return completed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--scope-profile", choices=("IAC", "PERSONAL"), required=True)
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--owner-scope", choices=("IAC", "PERSONAL"), required=True)
    parser.add_argument("--destination-kind", choices=("EMAIL", "WEBHOOK"), required=True)
    parser.add_argument("--destination-ref", required=True)
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--stale-after-seconds", type=int, default=90)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.scope_profile != args.owner_scope:
        parser.error("scope profile must match route owner scope")

    route = EscalationRoute(
        args.route_id, args.owner_scope, args.destination_kind, args.destination_ref
    )
    stopped = Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    store = SeanOSStore(args.database, scope_profile=args.scope_profile)
    try:
        run_monitor_loop(
            store,
            route,
            interval_seconds=args.interval_seconds,
            wait=stopped.wait,
            sink=lambda snapshot: print(json.dumps(snapshot, sort_keys=True), flush=True),
            max_iterations=1 if args.once else None,
            stale_after_seconds=args.stale_after_seconds,
        )
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
