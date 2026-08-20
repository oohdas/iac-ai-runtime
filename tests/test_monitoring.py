import unittest
import tempfile
import sqlite3
from pathlib import Path

from sean_os import (
    Actor, AuthorizationError, CommandGateway, EscalationRoute, ReportingService,
    RuntimeMonitor, SeanOSStore, ValidationError,
    acknowledge_alert_plan, classify_alerts,
    deduplicate_alert_plans, plan_alert_deliveries,
    synthetic_delivery_receipt,
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

    def test_approval_gated_outbox_runs_synthetic_adapter_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            store=SeanOSStore(Path(directory) / "delivery.db")
            try:
                monitor=Actor("monitor", frozenset({"IAC"}))
                plan=plan_alert_deliveries(
                    [{"code":"NO_ACTIVE_WORKER", "severity":"CRITICAL", "summary":"none"}],
                    route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    owner_scope="IAC",
                )[0]
                store.record_alert_observation(monitor, plan)
                staged=store.stage_alert_delivery(monitor, plan["plan_id"])
                self.assertEqual(staged["status"], "STAGED")
                self.assertEqual(store.stage_alert_delivery(monitor, plan["plan_id"]), staged)
                with self.assertRaisesRegex(AuthorizationError, "lacks exact approval"):
                    store.record_synthetic_alert_delivery(
                        monitor, staged["delivery_id"],
                        {"mode":"SYNTHETIC", "network_used":False,
                         "external_effect":False,
                         "delivery_id":staged["delivery_id"],
                         "payload_sha256":staged["payload_sha256"]},
                    )
                approval=store.create_approval(
                    Actor.sean(), action_type="DELIVER_ALERT", target=staged["delivery_id"],
                    scope="IAC", max_impact="one synthetic delivery", approver="sean",
                    expires_at="2099-01-01T00:00:00+00:00",
                )
                authorized=store.authorize_alert_delivery(
                    Actor.sean(), staged["delivery_id"], approval_id=approval
                )
                receipt=synthetic_delivery_receipt(
                    authorized, delivered_at="2030-01-01T00:00:00+00:00"
                )
                delivered=store.record_synthetic_alert_delivery(
                    monitor, staged["delivery_id"], receipt
                )
                self.assertEqual(delivered["status"], "SYNTHETIC_DELIVERED")
                self.assertEqual(delivered["attempt_count"], 1)
                self.assertFalse(delivered["receipt_payload"]["network_used"])
                self.assertEqual(
                    store.record_synthetic_alert_delivery(monitor, staged["delivery_id"], receipt),
                    delivered,
                )
            finally:
                store.close()

    def test_outbox_rejects_wrong_approval_and_real_delivery_receipt(self):
        store=SeanOSStore(":memory:")
        try:
            monitor=Actor("monitor", frozenset({"IAC"}))
            plan=plan_alert_deliveries(
                [{"code":"DEAD_LETTER", "severity":"CRITICAL", "summary":"failed"}],
                route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                owner_scope="IAC",
            )[0]
            store.record_alert_observation(monitor, plan)
            staged=store.stage_alert_delivery(monitor, plan["plan_id"])
            wrong=store.create_approval(
                Actor.sean(), action_type="DELIVER_ALERT", target="different-target",
                scope="IAC", max_impact="none", approver="sean",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            with self.assertRaisesRegex(AuthorizationError, "exact action and target"):
                store.authorize_alert_delivery(Actor.sean(), staged["delivery_id"], approval_id=wrong)
            self.assertEqual(store.get_alert_delivery(monitor, staged["delivery_id"])["status"], "STAGED")
            self.assertEqual(
                store.connection.execute(
                    "SELECT status FROM approvals WHERE record_id=?", (wrong,)
                ).fetchone()[0],
                "APPROVED",
            )
            wrong_scope=store.create_approval(
                Actor.sean(), action_type="DELIVER_ALERT", target=staged["delivery_id"],
                scope="PERSONAL", max_impact="none", approver="sean",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            with self.assertRaisesRegex(AuthorizationError, "action scope"):
                store.authorize_alert_delivery(
                    Actor.sean(), staged["delivery_id"], approval_id=wrong_scope
                )
            exact=store.create_approval(
                Actor.sean(), action_type="DELIVER_ALERT", target=staged["delivery_id"],
                scope="IAC", max_impact="one synthetic delivery", approver="sean",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            store.authorize_alert_delivery(Actor.sean(), staged["delivery_id"], approval_id=exact)
            with self.assertRaisesRegex(ValidationError, "no-network synthetic"):
                store.record_synthetic_alert_delivery(
                    monitor, staged["delivery_id"],
                    {"mode":"LIVE", "network_used":True,
                     "delivery_id":staged["delivery_id"],
                     "payload_sha256":staged["payload_sha256"]},
                )
        finally:
            store.close()

    def test_primary_interface_delivery_workflow_is_durable_and_sean_gated(self):
        store=SeanOSStore(":memory:")
        try:
            monitor=Actor("monitor", frozenset({"IAC"}))
            plan=plan_alert_deliveries(
                [{"code":"STALE_WORKER", "severity":"CRITICAL", "summary":"stale"}],
                route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                owner_scope="IAC",
            )[0]
            store.record_alert_observation(monitor, plan)
            interface=CommandGateway(store, Actor("chatgpt-interface", frozenset({"IAC"})))
            staged=interface.stage_delivery(plan["plan_id"])
            self.assertEqual(interface.deliveries(status="STAGED"), [staged])
            approval_id=interface.request_delivery_approval(
                staged["delivery_id"], max_impact="one alert to approved test route",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            self.assertEqual(
                interface.request_delivery_approval(
                    staged["delivery_id"], max_impact="one alert to approved test route",
                    expires_at="2099-01-01T00:00:00+00:00",
                ),
                approval_id,
            )
            with self.assertRaisesRegex(ValidationError, "different.*already pending"):
                interface.request_delivery_approval(
                    staged["delivery_id"], max_impact="changed impact",
                    expires_at="2099-01-01T00:00:00+00:00",
                )
            with self.assertRaisesRegex(AuthorizationError, "Only Sean"):
                interface.decide_delivery_approval(
                    staged["delivery_id"], approval_id=approval_id,
                    approve=True, reason="Synthetic route reviewed",
                )
            operator=CommandGateway(
                store, Actor("sean-chatgpt-operator", frozenset({"IAC"}), is_sean=True)
            )
            self.assertEqual(
                operator.decide_delivery_approval(
                    staged["delivery_id"], approval_id=approval_id,
                    approve=True, reason="Synthetic route reviewed",
                ),
                "APPROVED",
            )
            self.assertEqual(
                operator.deliveries(status="STAGED")[0]["delivery_id"], staged["delivery_id"]
            )
            with self.assertRaisesRegex(AuthorizationError, "Only Sean"):
                interface.authorize_delivery(staged["delivery_id"], approval_id=approval_id)
            authorized=operator.authorize_delivery(
                staged["delivery_id"], approval_id=approval_id
            )
            self.assertEqual(authorized["status"], "AUTHORIZED")
            self.assertEqual(
                operator.authorize_delivery(staged["delivery_id"], approval_id=approval_id),
                authorized,
            )
        finally:
            store.close()

    def test_delivery_operator_rejects_approval_for_another_delivery(self):
        store=SeanOSStore(":memory:")
        try:
            monitor=Actor("monitor", frozenset({"IAC"}))
            route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias")
            plans=plan_alert_deliveries(
                [
                    {"code":"DEAD_LETTER", "severity":"CRITICAL", "summary":"failed"},
                    {"code":"POLICY_BLOCKED", "severity":"HIGH", "summary":"blocked"},
                ], route=route, owner_scope="IAC",
            )
            interface=CommandGateway(store, Actor("chatgpt-interface", frozenset({"IAC"})))
            deliveries=[]
            for plan in plans:
                store.record_alert_observation(monitor, plan)
                deliveries.append(interface.stage_delivery(plan["plan_id"]))
            approval_id=interface.request_delivery_approval(
                deliveries[0]["delivery_id"], max_impact="one synthetic alert",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            operator=CommandGateway(
                store, Actor("sean-chatgpt-operator", frozenset({"IAC"}), is_sean=True)
            )
            with self.assertRaisesRegex(AuthorizationError, "exact IAC delivery"):
                operator.decide_delivery_approval(
                    deliveries[1]["delivery_id"], approval_id=approval_id,
                    approve=True, reason="wrong target",
                )
            self.assertEqual(
                store.connection.execute(
                    "SELECT status FROM approvals WHERE record_id=?", (approval_id,)
                ).fetchone()[0],
                "PENDING",
            )
        finally:
            store.close()

    def test_synthetic_delivery_leases_recover_and_retries_are_bounded(self):
        store=SeanOSStore(":memory:")
        try:
            worker=Actor("delivery-worker", frozenset({"IAC"}))
            plan=plan_alert_deliveries(
                [{"code":"DEAD_LETTER", "severity":"CRITICAL", "summary":"failed"}],
                route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                owner_scope="IAC",
            )[0]
            store.record_alert_observation(worker, plan)
            delivery=store.stage_alert_delivery(worker, plan["plan_id"])
            approval=store.create_approval(
                Actor.sean(), action_type="DELIVER_ALERT", target=delivery["delivery_id"],
                scope="IAC", max_impact="one synthetic alert", approver="sean",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            store.authorize_alert_delivery(
                Actor.sean(), delivery["delivery_id"], approval_id=approval
            )
            first=store.claim_authorized_alert_delivery(worker, "worker-1", lease_seconds=1)
            self.assertEqual(first["attempt_count"], 1)
            self.assertIsNone(store.claim_authorized_alert_delivery(worker, "worker-2"))
            store.connection.execute(
                "UPDATE alert_delivery_outbox SET lease_expires_at=? WHERE delivery_id=?",
                ("2000-01-01T00:00:00+00:00", delivery["delivery_id"]),
            )
            store.connection.commit()
            recovered=store.claim_authorized_alert_delivery(worker, "worker-2")
            self.assertEqual(recovered["attempt_count"], 2)
            receipt=synthetic_delivery_receipt(
                recovered, delivered_at="2030-01-01T00:00:00+00:00"
            )
            with self.assertRaisesRegex(AuthorizationError, "active alert delivery lease"):
                store.complete_claimed_synthetic_alert_delivery(
                    worker, delivery["delivery_id"], "worker-1", receipt
                )
            completed=store.complete_claimed_synthetic_alert_delivery(
                worker, delivery["delivery_id"], "worker-2", receipt
            )
            self.assertEqual(completed["status"], "SYNTHETIC_DELIVERED")
            self.assertIsNone(completed["lease_owner"])

            retry_plan=plan_alert_deliveries(
                [{"code":"POLICY_BLOCKED", "severity":"HIGH", "summary":"blocked"}],
                route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                owner_scope="IAC",
            )[0]
            store.record_alert_observation(worker, retry_plan)
            retry=store.stage_alert_delivery(worker, retry_plan["plan_id"])
            retry_approval=store.create_approval(
                Actor.sean(), action_type="DELIVER_ALERT", target=retry["delivery_id"],
                scope="IAC", max_impact="one synthetic alert", approver="sean",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            store.authorize_alert_delivery(
                Actor.sean(), retry["delivery_id"], approval_id=retry_approval
            )
            for attempt in range(1, 4):
                claimed=store.claim_authorized_alert_delivery(worker, "worker-3")
                self.assertEqual(claimed["attempt_count"], attempt)
                next_status=store.fail_claimed_alert_delivery(
                    worker, retry["delivery_id"], "worker-3", "Synthetic adapter fault",
                    retry_seconds=0,
                )
            self.assertEqual(next_status, "FAILED")
            health=store.runtime_health(scope="IAC")
            self.assertFalse(health["healthy"])
            self.assertEqual(health["delivery_outbox"]["FAILED"], 1)
            codes={item["code"] for item in classify_alerts(health)}
            self.assertIn("ALERT_DELIVERY_FAILED", codes)
            diagnostics=store.alert_delivery_diagnostics(worker, "IAC")
            self.assertEqual(diagnostics["failed"], 1)
            self.assertFalse(diagnostics["manual_execution_authorized"])
            report=ReportingService(store, worker).generate(
                "DAILY", "IAC", period_key="2030-01-03"
            )
            self.assertEqual(report["headline"], "ATTENTION REQUIRED")
            self.assertEqual(report["delivery_diagnostics"]["failed"], 1)
            self.assertIn(
                retry["delivery_id"],
                report["inferences"][0]["evidence_delivery_ids"],
            )
            interface=CommandGateway(store, Actor("chatgpt-interface", frozenset({"IAC"})))
            with self.assertRaisesRegex(AuthorizationError, "Only Sean"):
                interface.reset_failed_delivery(
                    retry["delivery_id"], reason="Synthetic failure reviewed"
                )
            operator=CommandGateway(
                store, Actor("sean-chatgpt-operator", frozenset({"IAC"}), is_sean=True)
            )
            reset=operator.reset_failed_delivery(
                retry["delivery_id"], reason="Synthetic failure reviewed"
            )
            self.assertEqual(reset["status"], "STAGED")
            self.assertIsNone(reset["approval_id"])
            self.assertEqual(reset["attempt_count"], 0)
            self.assertEqual(
                operator.reset_failed_delivery(
                    retry["delivery_id"], reason="Synthetic failure reviewed"
                ),
                reset,
            )
            self.assertIsNone(store.claim_authorized_alert_delivery(worker, "worker-4"))
            with self.assertRaisesRegex(AuthorizationError, "CONSUMED"):
                operator.authorize_delivery(
                    retry["delivery_id"], approval_id=retry_approval
                )
            fresh=interface.request_delivery_approval(
                retry["delivery_id"], max_impact="one fresh synthetic alert",
                expires_at="2099-01-01T00:00:00+00:00",
            )
            operator.decide_delivery_approval(
                retry["delivery_id"], approval_id=fresh, approve=True,
                reason="Fresh retry approved after review",
            )
            reauthorized=operator.authorize_delivery(
                retry["delivery_id"], approval_id=fresh
            )
            self.assertEqual(reauthorized["status"], "AUTHORIZED")
            store.connection.execute(
                """UPDATE alert_delivery_outbox SET attempt_count=max_attempts,
                   lease_owner='crashed-worker', lease_expires_at=? WHERE delivery_id=?""",
                ("2000-01-01T00:00:00+00:00", retry["delivery_id"]),
            )
            store.connection.commit()
            self.assertIsNone(store.claim_authorized_alert_delivery(worker, "worker-5"))
            self.assertEqual(
                store.get_alert_delivery(worker, retry["delivery_id"])["status"], "FAILED"
            )
            recovered_failures=[event for event in store.audit_events()
                                if event["action"] == "FAIL_ALERT_DELIVERY" and
                                event["details"].get("recovered_from_expired_lease")]
            self.assertTrue(recovered_failures)
        finally:
            store.close()

    def test_delivery_diagnostics_are_scope_filtered(self):
        store=SeanOSStore(":memory:")
        try:
            sean=Actor.sean()
            for scope, route_id in (("PERSONAL", "personal-route"), ("IAC", "iac-route")):
                plan=plan_alert_deliveries(
                    [{"code":"NO_ACTIVE_WORKER", "severity":"CRITICAL", "summary":"none"}],
                    route=EscalationRoute(route_id, scope, "EMAIL", f"{scope.lower()}-alias"),
                    owner_scope=scope,
                )[0]
                store.record_alert_observation(sean, plan)
                store.stage_alert_delivery(sean, plan["plan_id"])
            iac=Actor("iac-reader", frozenset({"IAC"}))
            diagnostics=store.alert_delivery_diagnostics(iac, "IAC")
            self.assertEqual(diagnostics["counts"], {"STAGED":1})
            with self.assertRaises(AuthorizationError):
                store.alert_delivery_diagnostics(iac, "PERSONAL")
        finally:
            store.close()

    def test_kill_switch_blocks_synthetic_delivery_claims(self):
        store=SeanOSStore(":memory:")
        try:
            worker=Actor("delivery-worker", frozenset({"IAC"}))
            store.set_kill_switch(Actor.sean(), True)
            self.assertIsNone(store.claim_authorized_alert_delivery(worker, "worker-1"))
            denied=[event for event in store.audit_events()
                    if event["action"] == "CLAIM_ALERT_DELIVERY" and event["result"] == "DENIED"]
            self.assertTrue(denied)
        finally:
            store.close()

    def test_schema_v10_outbox_migrates_without_losing_staged_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Path(directory) / "migration.db"
            store=SeanOSStore(database)
            try:
                actor=Actor("monitor", frozenset({"IAC"}))
                plan=plan_alert_deliveries(
                    [{"code":"DEAD_LETTER", "severity":"CRITICAL", "summary":"failed"}],
                    route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
                    owner_scope="IAC",
                )[0]
                store.record_alert_observation(actor, plan)
                delivery=store.stage_alert_delivery(actor, plan["plan_id"])
            finally:
                store.close()
            connection=sqlite3.connect(database)
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("ALTER TABLE alert_delivery_outbox RENAME TO outbox_v11")
            connection.execute(
                """CREATE TABLE alert_delivery_outbox (
                    delivery_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL, reopen_generation INTEGER NOT NULL,
                    owner_scope TEXT NOT NULL, route_id TEXT NOT NULL,
                    destination_kind TEXT NOT NULL, destination_ref TEXT NOT NULL,
                    alert_payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL, approval_id TEXT, attempt_count INTEGER NOT NULL,
                    receipt_payload TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    delivered_at TEXT, UNIQUE(incident_id, reopen_generation))"""
            )
            legacy_columns=(
                "delivery_id,plan_id,incident_id,reopen_generation,owner_scope,route_id,"
                "destination_kind,destination_ref,alert_payload,payload_sha256,status,"
                "approval_id,attempt_count,receipt_payload,created_at,updated_at,delivered_at"
            )
            connection.execute(
                f"INSERT INTO alert_delivery_outbox ({legacy_columns}) SELECT {legacy_columns} FROM outbox_v11"
            )
            connection.execute("DROP TABLE outbox_v11")
            connection.execute("DELETE FROM schema_migrations WHERE version=11")
            connection.commit(); connection.close()

            migrated=SeanOSStore(database)
            try:
                restored=migrated.get_alert_delivery(
                    Actor("auditor", frozenset({"IAC"})), delivery["delivery_id"]
                )
                self.assertEqual(migrated.schema_version, 12)
                self.assertEqual(restored["status"], "STAGED")
                self.assertEqual(restored["max_attempts"], 3)
                self.assertEqual(restored["available_at"], restored["created_at"])
                self.assertIn("lease_owner", restored)
            finally:
                migrated.close()

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
