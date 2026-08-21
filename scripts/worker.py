"""Local continuous-worker prototype. Use --once in tests/demos; production needs a supervised cloud process."""
from pathlib import Path
import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import (
    Actor, EscalationRoute, LocalScheduler, PolicyDenied, RuntimeMonitor,
    SeanOSStore, chief_of_staff_registry, synthetic_delivery_receipt,
)
from sean_os.security import safe_exception_summary


STOP = False


def stop(*_args):
    global STOP
    STOP = True


def process_synthetic_delivery_once(
    store: SeanOSStore, actor: Actor, worker_id: str
):
    delivery=store.claim_authorized_alert_delivery(actor, worker_id, lease_seconds=30)
    if delivery is None:
        return None
    try:
        receipt=synthetic_delivery_receipt(
            delivery, delivered_at=datetime.now(timezone.utc).isoformat()
        )
        return store.complete_claimed_synthetic_alert_delivery(
            actor, delivery["delivery_id"], worker_id, receipt
        )
    except Exception as exc:
        safe_error=f"{type(exc).__name__}: synthetic no-network adapter failed"
        store.fail_claimed_alert_delivery(
            actor, delivery["delivery_id"], worker_id, safe_error
        )
        return {"delivery_id":delivery["delivery_id"], "status":"RETRY_SCHEDULED"}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--worker-id", default="local-worker-1")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--monitor-route-id")
    parser.add_argument("--monitor-destination-kind", choices=("EMAIL", "WEBHOOK"))
    parser.add_argument("--monitor-destination-ref")
    parser.add_argument("--monitor-interval-seconds", type=float, default=30.0)
    parser.add_argument("--synthetic-delivery", action="store_true")
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
            if args.synthetic_delivery:
                process_synthetic_delivery_once(store, actor, args.worker_id)
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
                safe_error=safe_exception_summary(exc, context="worker handler failed")
                store.heartbeat(
                    args.worker_id, "IAC", "ERROR", current_work_id=work["id"],
                    details={"error":safe_error},
                )
                store.fail_work(actor, work["id"], args.worker_id, safe_error)
            if args.once: break
    finally:
        store.heartbeat(args.worker_id, "IAC", "STOPPED")
        store.close()


if __name__ == "__main__":
    main()
