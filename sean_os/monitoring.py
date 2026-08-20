"""Pure monitoring decisions; delivery remains outside v0.1 authority."""

from __future__ import annotations

from typing import Any


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
