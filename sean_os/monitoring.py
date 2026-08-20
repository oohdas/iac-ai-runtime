"""Pure monitoring decisions; delivery remains outside v0.1 authority."""

from __future__ import annotations

from dataclasses import dataclass
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
        plans.append(
            {
                "schema_version": 1,
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
