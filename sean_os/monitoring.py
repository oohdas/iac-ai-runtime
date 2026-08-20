"""Pure monitoring decisions; delivery remains outside v0.1 authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any


_SEVERITY_RANK = {"ATTENTION": 1, "HIGH": 2, "CRITICAL": 3}
_DESTINATION_KINDS = frozenset({"EMAIL", "WEBHOOK"})


@dataclass(frozen=True)
class EscalationRoute:
    """Non-secret routing metadata for a future approval-gated delivery adapter."""

    route_id: str
    owner_scope: str
    destination_kind: str
    destination_ref: str
    minimum_severity: str = "ATTENTION"

    def __post_init__(self) -> None:
        if not self.route_id.strip() or not self.destination_ref.strip():
            raise ValueError("route_id and destination_ref are required")
        if self.owner_scope not in {"PERSONAL", "IAC"}:
            raise ValueError("Escalation routes must be owned by PERSONAL or IAC")
        if self.destination_kind not in _DESTINATION_KINDS:
            raise ValueError("Unsupported escalation destination kind")
        if self.minimum_severity not in _SEVERITY_RANK:
            raise ValueError("Unsupported minimum severity")


@dataclass
class RuntimeMonitor:
    """Cadence gate for monitoring inside an existing supervised worker."""

    route: EscalationRoute
    interval_seconds: float = 30.0
    stale_after_seconds: int = 90
    next_due: float = 0.0

    def __post_init__(self) -> None:
        if self.interval_seconds < 1:
            raise ValueError("Monitoring interval must be at least one second")
        if self.stale_after_seconds < 1:
            raise ValueError("Stale threshold must be positive")

    def tick(self, store: Any, *, monotonic_now: float) -> dict[str, Any] | None:
        if monotonic_now < self.next_due:
            return None
        snapshot = capture_monitor_snapshot(
            store, stale_after_seconds=self.stale_after_seconds, route=self.route
        )
        self.next_due = monotonic_now + self.interval_seconds
        return snapshot


def classify_alerts(
    health: dict[str, Any], *, backup_ok: bool | None = None
) -> list[dict[str, str]]:
    """Convert a health snapshot into deterministic, non-delivering alerts."""
    alerts: list[dict[str, str]] = []

    def add(code: str, severity: str, summary: str) -> None:
        alerts.append({"code": code, "severity": severity, "summary": summary})

    if not health.get("integrity", {}).get("ok", False):
        add("DATABASE_INTEGRITY_FAILED", "CRITICAL", "Database integrity check failed")
    if health.get("kill_switch"):
        add("KILL_SWITCH_ACTIVE", "CRITICAL", "Runtime kill switch is active")
    if any(worker.get("stale") for worker in health.get("workers", [])):
        add("STALE_WORKER", "CRITICAL", "At least one runtime worker is stale")

    queue = health.get("queue", {})
    for status, severity, summary in (
        ("DEAD_LETTER", "CRITICAL", "Work reached the dead-letter queue"),
        ("POLICY_BLOCKED", "HIGH", "Work was blocked by runtime policy"),
        ("BUDGET_BLOCKED", "HIGH", "Work was blocked by its budget ceiling"),
        ("APPROVAL_BLOCKED", "ATTENTION", "Work requires an exact approval"),
    ):
        count = int(queue.get(status, 0))
        if count:
            add(status, severity, f"{count} work item(s): {summary}")

    if int(health.get("active_worker_count", 0)) == 0:
        add("NO_ACTIVE_WORKER", "CRITICAL", "No active runtime worker is reporting")
    if backup_ok is False:
        add("BACKUP_FAILED", "CRITICAL", "Latest verified backup failed")

    return alerts


def plan_alert_deliveries(
    alerts: list[dict[str, str]], *, route: EscalationRoute, owner_scope: str
) -> list[dict[str, Any]]:
    """Build reviewable delivery envelopes; never contacts the destination."""
    if owner_scope != route.owner_scope:
        raise ValueError("Alert scope does not match escalation route ownership")
    threshold = _SEVERITY_RANK[route.minimum_severity]
    plans: list[dict[str, Any]] = []
    for alert in alerts:
        severity = alert.get("severity", "")
        if severity not in _SEVERITY_RANK:
            raise ValueError("Alert has unsupported severity")
        if _SEVERITY_RANK[severity] < threshold:
            continue
        identity = {
            "owner_scope": owner_scope,
            "route_id": route.route_id,
            "alert": dict(alert),
        }
        plan_id = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        plans.append(
            {
                "schema_version": 1,
                "plan_id": plan_id,
                "status": "PLANNED",
                "delivery_authorized": False,
                "approval_required": True,
                "approval_action_type": "DELIVER_ALERT",
                "action_target": route.route_id,
                "owner_scope": owner_scope,
                "route": {
                    "route_id": route.route_id,
                    "destination_kind": route.destination_kind,
                    "destination_ref": route.destination_ref,
                },
                "alert": dict(alert),
            }
        )
    return plans


def deduplicate_alert_plans(
    plans: list[dict[str, Any]], *, previously_seen_plan_ids: set[str] | None = None
) -> list[dict[str, Any]]:
    """Suppress repeat evidence by deterministic plan ID without mutating input."""
    seen = set(previously_seen_plan_ids or ())
    unique: list[dict[str, Any]] = []
    for plan in plans:
        plan_id = plan.get("plan_id")
        if not isinstance(plan_id, str) or len(plan_id) != 64:
            raise ValueError("Alert plan requires a deterministic plan_id")
        if plan_id in seen:
            continue
        seen.add(plan_id)
        unique.append(dict(plan))
    return unique


def acknowledge_alert_plan(
    plan: dict[str, Any], *, acknowledged_by: str, acknowledged_at: str
) -> dict[str, Any]:
    """Create immutable acknowledgement evidence; this never authorizes delivery."""
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or len(plan_id) != 64:
        raise ValueError("Alert plan requires a deterministic plan_id")
    if not acknowledged_by.strip():
        raise ValueError("acknowledged_by is required")
    try:
        instant = datetime.fromisoformat(acknowledged_at)
    except ValueError as exc:
        raise ValueError("acknowledged_at must be ISO-8601") from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("acknowledged_at must include a timezone")
    evidence = {
        "schema_version": 1,
        "plan_id": plan_id,
        "owner_scope": plan.get("owner_scope"),
        "route_id": plan.get("action_target"),
        "acknowledged_by": acknowledged_by,
        "acknowledged_at": instant.isoformat(),
        "delivery_authorized": False,
    }
    evidence["receipt_sha256"] = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return evidence


def capture_monitor_snapshot(
    store: Any, *, stale_after_seconds: int = 90,
    backup_ok: bool | None = None, route: EscalationRoute | None = None,
) -> dict[str, Any]:
    """Capture health and optionally persist plans, with no delivery capability."""
    health = store.runtime_health(
        stale_after_seconds=stale_after_seconds, require_active_worker=True
    )
    alerts = classify_alerts(health, backup_ok=backup_ok)
    observations = []
    if route is not None:
        from .store import Actor

        plans = plan_alert_deliveries(alerts, route=route, owner_scope=route.owner_scope)
        actor = Actor("runtime-monitor", frozenset({route.owner_scope}))
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
