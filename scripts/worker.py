"""Local continuous-worker prototype. Use --once in tests/demos; production needs a supervised cloud process."""
from pathlib import Path
import argparse
import json
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import (
    Actor, EscalationRoute, LocalScheduler, PolicyDenied, RuntimeMonitor,
    SeanOSStore, chief_of_staff_registry,
)


STOP = False


def stop(*_args):
    global STOP
    STOP = True


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--worker-id", default="local-worker-1")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--monitor-route-id")
    parser.add_argument("--monitor-destination-kind", choices=("EMAIL", "WEBHOOK"))
    parser.add_argument("--monitor-destination-ref")
    parser.add_argument("--monitor-interval-seconds", type=float, default=30.0)
    parser.add_argument("--once", action="store_true")
    args=parser.parse_args()
    route_fields=(args.monitor_route_id, args.monitor_destination_kind,
                  args.monitor_destination_ref)
    if any(route_fields) and not all(route_fields):
        parser.error("integrated monitoring requires the complete route contract")
    monitor=None
    if all(route_fields):
        monitor=RuntimeMonitor(
            EscalationRoute(
                args.monitor_route_id, "IAC", args.monitor_destination_kind,
                args.monitor_destination_ref,
            ),
            interval_seconds=args.monitor_interval_seconds,
        )
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    store=SeanOSStore(args.database, scope_profile="IAC")
    actor=Actor(args.worker_id, frozenset({"IAC"}))
    registry=chief_of_staff_registry(store, actor)
    scheduler=LocalScheduler(store, actor)
    store.heartbeat(args.worker_id, "IAC", "STARTING")
    try:
        while not STOP:
            store.heartbeat(args.worker_id, "IAC", "IDLE")
            if monitor is not None:
                snapshot=monitor.tick(store, monotonic_now=time.monotonic())
                if snapshot is not None:
                    print(json.dumps(snapshot, sort_keys=True), flush=True)
            scheduler.tick()
            work=store.claim_work(actor, args.worker_id, lease_seconds=30)
            if work is None:
                if args.once: break
                time.sleep(args.poll_seconds); continue
            try:
                store.heartbeat(args.worker_id, "IAC", "WORKING", current_work_id=work["id"])
                result=registry.execute(store, actor, work)
                store.complete_work(actor, work["id"], args.worker_id, result)
            except PolicyDenied as exc:
                store.block_work(
                    actor, work["id"], args.worker_id, exc.reason,
                    approval_required=exc.approval_required,
                )
            except Exception as exc:
                store.heartbeat(args.worker_id, "IAC", "ERROR", current_work_id=work["id"], details={"error": str(exc)})
                store.fail_work(actor, work["id"], args.worker_id, str(exc))
            if args.once: break
    finally:
        store.heartbeat(args.worker_id, "IAC", "STOPPED")
        store.close()


if __name__ == "__main__":
    main()
