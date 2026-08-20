import unittest
import tempfile
from pathlib import Path

from sean_os import (
    Actor, AuthorizationError, CommandGateway, EscalationRoute, ReportingService,
    RuntimeMonitor, SeanOSStore, ValidationError,
    acknowledge_alert_plan, classify_alerts,
    deduplicate_alert_plans, plan_alert_deliveries,
)
from scripts.monitor_snapshot import build_snapshot


class MonitoringTests(unittest.TestCase):
    def base_health(self):
        return {
            "healthy": True,
            "kill_switch": False,
            "integrity": {"ok": True},
            "queue": {},
            "workers": [{"worker_id": "worker-1", "stale": False}],
            "active_worker_count": 1,
        }

    def test_healthy_snapshot_has_no_alerts(self):
        self.assertEqual(classify_alerts(self.base_health(), backup_ok=True), [])

    def test_all_required_escalation_classes_are_deterministic(self):
        health = self.base_health()
        health.update(
            {
                "kill_switch": True,
                "integrity": {"ok": False},
                "queue": {
                    "DEAD_LETTER": 1,
                    "POLICY_BLOCKED": 2,
                    "BUDGET_BLOCKED": 3,
                    "APPROVAL_BLOCKED": 4,
                },
                "workers": [{"worker_id": "worker-1", "stale": True}],
                "active_worker_count": 0,
            }
        )
        alerts = classify_alerts(health, backup_ok=False)
        self.assertEqual(
            {alert["code"] for alert in alerts},
            {
                "DATABASE_INTEGRITY_FAILED",
                "KILL_SWITCH_ACTIVE",
                "STALE_WORKER",
                "DEAD_LETTER",
                "POLICY_BLOCKED",
                "BUDGET_BLOCKED",
                "APPROVAL_BLOCKED",
                "NO_ACTIVE_WORKER",
                "BACKUP_FAILED",
            },
        )
        self.assertTrue(all(set(alert) == {"code", "severity", "summary"} for alert in alerts))

    def test_delivery_plan_is_explicitly_unauthorized(self):
        route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
        plans = plan_alert_deliveries(
            [{"code": "STALE_WORKER", "severity": "CRITICAL", "summary": "stale"}],
            route=route,
            owner_scope="IAC",
        )
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["status"], "PLANNED")
        self.assertFalse(plans[0]["delivery_authorized"])
        self.assertTrue(plans[0]["approval_required"])
        self.assertEqual(plans[0]["approval_action_type"], "DELIVER_ALERT")

    def test_delivery_plan_filters_below_route_threshold(self):
        route = EscalationRoute(
            "critical-only", "IAC", "WEBHOOK", "iac-monitor-hook", "CRITICAL"
        )
        plans = plan_alert_deliveries(
            [{"code": "POLICY_BLOCKED", "severity": "HIGH", "summary": "blocked"}],
            route=route,
            owner_scope="IAC",
        )
        self.assertEqual(plans, [])

    def test_delivery_route_rejects_cross_scope_use(self):
        route = EscalationRoute("personal-operator", "PERSONAL", "EMAIL", "owner-alias")
        with self.assertRaisesRegex(ValueError, "ownership"):
            plan_alert_deliveries([], route=route, owner_scope="IAC")

    def test_delivery_route_rejects_shared_ownership(self):
        with self.assertRaisesRegex(ValueError, "PERSONAL or IAC"):
            EscalationRoute("shared", "SHARED", "EMAIL", "shared-alias")

    def test_plan_id_is_deterministic_and_deduplicated(self):
        route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
        alerts = [{"code": "DEAD_LETTER", "severity": "CRITICAL", "summary": "one"}]
        first = plan_alert_deliveries(alerts, route=route, owner_scope="IAC")[0]
        second = plan_alert_deliveries(alerts, route=route, owner_scope="IAC")[0]
        self.assertEqual(first["plan_id"], second["plan_id"])
        self.assertEqual(deduplicate_alert_plans([first, second]), [first])
        self.assertEqual(
            deduplicate_alert_plans([first], previously_seen_plan_ids={first["plan_id"]}),
            [],
        )

    def test_acknowledgement_is_deterministic_and_never_authorizes_delivery(self):
        route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
        plan = plan_alert_deliveries(
            [{"code": "STALE_WORKER", "severity": "CRITICAL", "summary": "stale"}],
            route=route,
            owner_scope="IAC",
        )[0]
        kwargs = {"acknowledged_by": "synthetic-operator", "acknowledged_at": "2030-01-01T12:00:00+00:00"}
        first = acknowledge_alert_plan(plan, **kwargs)
        second = acknowledge_alert_plan(plan, **kwargs)
        self.assertEqual(first, second)
        self.assertFalse(first["delivery_authorized"])
        self.assertEqual(len(first["receipt_sha256"]), 64)

    def test_acknowledgement_requires_timezone(self):
        route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
        plan = plan_alert_deliveries(
            [{"code": "BACKUP_FAILED", "severity": "CRITICAL", "summary": "failed"}],
            route=route,
            owner_scope="IAC",
        )[0]
        with self.assertRaisesRegex(ValueError, "timezone"):
            acknowledge_alert_plan(
                plan, acknowledged_by="synthetic-operator", acknowledged_at="2030-01-01T12:00:00"
            )

    def test_alert_observation_is_durable_deduplicated_and_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "alerts.db")
            try:
                iac = Actor("monitor", frozenset({"IAC"}))
                personal = Actor("personal-monitor", frozenset({"PERSONAL"}))
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                plan = plan_alert_deliveries(
                    [{"code": "DEAD_LETTER", "severity": "CRITICAL", "summary": "one"}],
                    route=route,
                    owner_scope="IAC",
                )[0]
                store.record_alert_observation(iac, plan)
                observed = store.record_alert_observation(iac, plan)
                self.assertEqual(observed["occurrence_count"], 2)
                with self.assertRaises(AuthorizationError):
                    store.get_alert_observation(personal, plan["plan_id"])
            finally:
                store.close()

    def test_alert_acknowledgement_is_single_and_sean_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "alerts.db")
            try:
                iac = Actor("monitor", frozenset({"IAC"}))
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                plan = plan_alert_deliveries(
                    [{"code": "STALE_WORKER", "severity": "CRITICAL", "summary": "stale"}],
                    route=route,
                    owner_scope="IAC",
                )[0]
                store.record_alert_observation(iac, plan)
                receipt = acknowledge_alert_plan(
                    plan, acknowledged_by="sean", acknowledged_at="2030-01-01T12:00:00+00:00"
                )
                with self.assertRaises(AuthorizationError):
                    store.acknowledge_alert_observation(iac, receipt)
                acknowledged = store.acknowledge_alert_observation(Actor.sean(), receipt)
                self.assertEqual(acknowledged["acknowledgement_payload"], receipt)
                changed = dict(receipt); changed["acknowledged_at"] = "2030-01-01T12:01:00+00:00"
                with self.assertRaisesRegex(ValidationError, "already acknowledged"):
                    store.acknowledge_alert_observation(Actor.sean(), changed)
            finally:
                store.close()

    def test_incident_resolves_and_reopens_when_alert_reappears(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "incidents.db")
            try:
                monitor = Actor("monitor", frozenset({"IAC"}))
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                plan = plan_alert_deliveries(
                    [{"code": "DEAD_LETTER", "severity": "CRITICAL", "summary": "one"}],
                    route=route,
                    owner_scope="IAC",
                )[0]
                observed = store.record_alert_observation(monitor, plan)
                incident_id = observed["incident"]["incident_id"]
                resolved = store.resolve_alert_incident(
                    Actor.sean(), incident_id, reason="Synthetic recovery verified"
                )
                self.assertEqual(resolved["status"], "RESOLVED")
                self.assertEqual(store.active_alert_incidents(monitor, "IAC"), [])
                reopened = store.record_alert_observation(monitor, plan)["incident"]
                self.assertEqual(reopened["status"], "ACTIVE")
                self.assertEqual(reopened["reopen_count"], 1)
                self.assertEqual(reopened["occurrence_count"], 2)
                self.assertIsNone(reopened["resolution_reason"])
            finally:
                store.close()

    def test_incident_resolution_is_sean_only_and_scope_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "incidents.db")
            try:
                monitor = Actor("monitor", frozenset({"IAC"}))
                personal = Actor("personal-reader", frozenset({"PERSONAL"}))
                plan = plan_alert_deliveries(
                    [{"code": "STALE_WORKER", "severity": "CRITICAL", "summary": "stale"}],
                    route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    owner_scope="IAC",
                )[0]
                incident_id = store.record_alert_observation(monitor, plan)["incident"]["incident_id"]
                with self.assertRaises(AuthorizationError):
                    store.get_alert_incident(personal, incident_id)
                with self.assertRaises(AuthorizationError):
                    store.resolve_alert_incident(
                        monitor, incident_id, reason="Synthetic recovery verified"
                    )
                store.resolve_alert_incident(
                    Actor.sean(), incident_id, reason="Synthetic recovery verified"
                )
                with self.assertRaisesRegex(ValidationError, "already resolved"):
                    store.resolve_alert_incident(
                        Actor.sean(), incident_id, reason="Duplicate resolution"
                    )
            finally:
                store.close()

    def test_incident_identity_ignores_changing_summary_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "incidents.db")
            try:
                monitor = Actor("monitor", frozenset({"IAC"}))
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                first = plan_alert_deliveries(
                    [{"code": "BUDGET_BLOCKED", "severity": "HIGH", "summary": "1 item"}],
                    route=route, owner_scope="IAC",
                )[0]
                second = plan_alert_deliveries(
                    [{"code": "BUDGET_BLOCKED", "severity": "HIGH", "summary": "2 items"}],
                    route=route, owner_scope="IAC",
                )[0]
                first_incident = store.record_alert_observation(monitor, first)["incident"]
                second_incident = store.record_alert_observation(monitor, second)["incident"]
                self.assertNotEqual(first["plan_id"], second["plan_id"])
                self.assertEqual(first_incident["incident_id"], second_incident["incident_id"])
                self.assertEqual(second_incident["current_summary"], "2 items")
            finally:
                store.close()

    def test_operational_report_includes_only_active_scoped_incidents(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "reports.db")
            try:
                monitor = Actor("monitor", frozenset({"IAC"}))
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                high = plan_alert_deliveries(
                    [{"code": "BUDGET_BLOCKED", "severity": "HIGH", "summary": "blocked"}],
                    route=route, owner_scope="IAC",
                )[0]
                critical = plan_alert_deliveries(
                    [{"code": "DEAD_LETTER", "severity": "CRITICAL", "summary": "failed"}],
                    route=route, owner_scope="IAC",
                )[0]
                high_incident = store.record_alert_observation(monitor, high)["incident"]
                store.record_alert_observation(monitor, critical)
                report = ReportingService(store, monitor).generate(
                    "DAILY", "IAC", period_key="2030-01-01"
                )
                self.assertEqual(report["headline"], "ATTENTION REQUIRED")
                self.assertEqual(
                    [item["severity"] for item in report["active_incidents"]],
                    ["CRITICAL", "HIGH"],
                )
                self.assertEqual(report["delivery"], "LOCAL_ONLY")
                store.resolve_alert_incident(
                    Actor.sean(), high_incident["incident_id"], reason="Synthetic recovery verified"
                )
                next_report = ReportingService(store, monitor).generate(
                    "DAILY", "IAC", period_key="2030-01-02"
                )
                self.assertEqual(len(next_report["active_incidents"]), 1)
                self.assertEqual(next_report["changes_since_prior"]["active_incident_delta"], -1)
            finally:
                store.close()

    def test_operational_report_health_excludes_other_scope_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "reports.db")
            try:
                iac = Actor("iac-agent", frozenset({"IAC"}))
                store.enqueue_work(iac, "NOOP", "IAC", {})
                store.enqueue_work(Actor.sean(), "NOOP", "PERSONAL", {})
                store.configure_budget(Actor.sean(), "IAC", 10)
                store.configure_budget(Actor.sean(), "PERSONAL", 20)
                report = ReportingService(store, iac).generate(
                    "DAILY", "IAC", period_key="2030-01-01"
                )
                self.assertEqual(report["health"]["queue"]["QUEUED"], 1)
                self.assertTrue(
                    all(item["owner_scope"] == "IAC" for item in report["health"]["budgets"])
                )
            finally:
                store.close()

    def test_primary_interface_queries_and_sean_resolves_incident_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "interface.db")
            try:
                monitor = Actor("monitor", frozenset({"IAC"}))
                plan = plan_alert_deliveries(
                    [{"code": "DEAD_LETTER", "severity": "CRITICAL", "summary": "failed"}],
                    route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    owner_scope="IAC",
                )[0]
                incident_id = store.record_alert_observation(monitor, plan)["incident"]["incident_id"]
                reader = CommandGateway(store, Actor("chatgpt-reader", frozenset({"IAC"})))
                self.assertEqual(reader.active_incidents()[0]["incident_id"], incident_id)
                with self.assertRaisesRegex(AuthorizationError, "Only Sean"):
                    reader.resolve_incident(incident_id, reason="Synthetic recovery verified")

                sean_gateway = CommandGateway(
                    store, Actor("sean-chatgpt-interface", frozenset({"IAC"}), is_sean=True)
                )
                first = sean_gateway.resolve_incident(
                    incident_id, reason="Synthetic recovery verified"
                )
                replay = sean_gateway.resolve_incident(
                    incident_id, reason="Synthetic recovery verified"
                )
                self.assertEqual(first, replay)
                self.assertEqual(first["status"], "RESOLVED")
                self.assertEqual(sean_gateway.active_incidents(), [])
                with self.assertRaisesRegex(ValidationError, "different evidence"):
                    sean_gateway.resolve_incident(incident_id, reason="Changed reason")
                actions = [event["action"] for event in store.audit_events()]
                self.assertIn("RESOLVE_ALERT_INCIDENT", actions)
            finally:
                store.close()

    def test_primary_interface_incidents_reject_non_iac_scope(self):
        store = SeanOSStore(":memory:")
        try:
            gateway = CommandGateway(store, Actor.sean())
            with self.assertRaisesRegex(AuthorizationError, "isolated to IAC"):
                gateway.active_incidents(scope="PERSONAL")
            with self.assertRaisesRegex(AuthorizationError, "isolated to IAC"):
                gateway.resolve_incident("missing", reason="none", scope="PERSONAL")
        finally:
            store.close()

    def test_monitor_snapshot_can_record_without_delivering(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "monitor.db", scope_profile="IAC")
            try:
                route = EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
                first = build_snapshot(store, backup_ok=False, route=route)
                second = build_snapshot(store, backup_ok=False, route=route)
                self.assertFalse(first["delivery_authorized"])
                self.assertTrue(first["recorded_observations"])
                counts = {item["plan_id"]: item["occurrence_count"] for item in second["recorded_observations"]}
                self.assertTrue(all(count == 2 for count in counts.values()))
            finally:
                store.close()

    def test_runtime_monitor_obeys_cadence_inside_existing_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SeanOSStore(Path(directory) / "monitor.db", scope_profile="IAC")
            try:
                store.heartbeat("worker-1", "IAC", "IDLE")
                monitor = RuntimeMonitor(
                    EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    interval_seconds=30,
                )
                first = monitor.tick(store, monotonic_now=100)
                skipped = monitor.tick(store, monotonic_now=129.9)
                second = monitor.tick(store, monotonic_now=130)
                self.assertIsNotNone(first)
                self.assertIsNone(skipped)
                self.assertIsNotNone(second)
                self.assertTrue(first["healthy"])
                self.assertFalse(first["delivery_authorized"])
            finally:
                store.close()

    def test_runtime_monitor_rejects_unbounded_cadence(self):
        with self.assertRaisesRegex(ValueError, "at least one second"):
            RuntimeMonitor(
                EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                interval_seconds=0,
            )


if __name__ == "__main__":
    unittest.main()
