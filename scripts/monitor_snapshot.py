"""Emit a machine-readable health and escalation snapshot without delivery."""

from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import (
    Actor, EscalationRoute, SeanOSStore, classify_alerts, plan_alert_deliveries,
)


def build_snapshot(
    store: SeanOSStore, *, stale_after_seconds: int = 90,
    backup_ok: bool | None = None, route: EscalationRoute | None = None,
) -> dict:
    health = store.runtime_health(
        stale_after_seconds=stale_after_seconds, require_active_worker=True
    )
    alerts = classify_alerts(health, backup_ok=backup_ok)
    observations = []
    if route is not None:
        plans = plan_alert_deliveries(alerts, route=route, owner_scope=route.owner_scope)
        actor = Actor("local-monitor", frozenset({route.owner_scope}))
        observations = [store.record_alert_observation(actor, plan) for plan in plans]
    return {
        "healthy": health["healthy"] and backup_ok is not False,
        "delivery_authorized": False,
        "alerts": alerts,
        "recorded_observations": [
            {"plan_id": item["plan_id"], "occurrence_count": item["occurrence_count"]}
            for item in observations
        ],
        "health": health,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--stale-after-seconds", type=int, default=90)
    parser.add_argument("--backup-ok", choices=("true", "false", "unknown"), default="unknown")
    parser.add_argument("--scope-profile", choices=("DEVELOPMENT", "IAC", "PERSONAL"), default="DEVELOPMENT")
    parser.add_argument("--record-route-id")
    parser.add_argument("--owner-scope", choices=("IAC", "PERSONAL"))
    parser.add_argument("--destination-kind", choices=("EMAIL", "WEBHOOK"))
    parser.add_argument("--destination-ref")
    args = parser.parse_args()
    backup_ok = None if args.backup_ok == "unknown" else args.backup_ok == "true"
    route_fields = (
        args.record_route_id, args.owner_scope, args.destination_kind, args.destination_ref,
    )
    if any(route_fields) and not all(route_fields):
        parser.error("recording requires route ID, owner scope, destination kind, and destination ref")
    route = None
    if all(route_fields):
        route = EscalationRoute(
            args.record_route_id, args.owner_scope, args.destination_kind, args.destination_ref
        )
    store = SeanOSStore(args.database, scope_profile=args.scope_profile)
    try:
        result = build_snapshot(
            store, stale_after_seconds=args.stale_after_seconds,
            backup_ok=backup_ok, route=route,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["healthy"] else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
