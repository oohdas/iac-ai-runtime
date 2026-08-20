from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .store import Actor, SCOPES, SeanOSStore, ValidationError, now


class ReportingService:
    """Creates local, deterministic operational briefs without sending them externally."""

    def __init__(self, store: SeanOSStore, actor: Actor):
        self.store = store
        self.actor = actor

    def generate(self, cadence: str, scope: str, *, period_key: str | None = None) -> dict[str, Any]:
        cadence = cadence.upper(); scope = scope.upper()
        if cadence not in {"DAILY", "WEEKLY"} or scope not in SCOPES:
            raise ValidationError("Report requires DAILY/WEEKLY cadence and a valid scope")
        stamp = datetime.now(timezone.utc)
        key = period_key or (stamp.strftime("%Y-%m-%d") if cadence == "DAILY" else stamp.strftime("%G-W%V"))
        existing = self.store.connection.execute(
            "SELECT record_id FROM report_runs WHERE cadence=? AND period_key=? AND owner_scope=?",
            (cadence, key, scope),
        ).fetchone()
        if existing:
            return self.store.get_record(self.actor, existing["record_id"])["payload"]

        prior_row=self.store.connection.execute(
            """SELECT r.payload FROM report_runs rr JOIN records r ON r.id=rr.record_id
               WHERE rr.cadence=? AND rr.owner_scope=? ORDER BY rr.generated_at DESC LIMIT 1""",
            (cadence, scope),
        ).fetchone()
        prior=json.loads(prior_row["payload"]) if prior_row else None

        health = self.store.runtime_health(scope=scope)
        queue_rows = self.store.connection.execute(
            """SELECT id, task_type, status, last_error, updated_at FROM work_queue
               WHERE owner_scope=? AND status IN
               ('APPROVAL_BLOCKED','BUDGET_BLOCKED','POLICY_BLOCKED','DEAD_LETTER')
               ORDER BY updated_at, id""", (scope,),
        ).fetchall()
        attention = [dict(row) for row in queue_rows]
        incidents=(self.store.active_alert_incidents(self.actor, scope)
                   if scope in {"PERSONAL", "IAC"} else [])
        delivery_diagnostics=(self.store.alert_delivery_diagnostics(self.actor, scope)
                              if scope in {"PERSONAL", "IAC"} else None)
        delivery_attention=(delivery_diagnostics or {}).get("attention", [])
        approvals = [dict(row) for row in self.store.connection.execute(
            """SELECT record_id, action_type, target, max_impact, status, expires_at
               FROM approvals WHERE scope=? ORDER BY expires_at, record_id""",
            (scope,),
        )]
        decisions = []
        for record in self.store.list_records(self.actor, "DECISION"):
            if record["owner_scope"] == scope:
                decisions.append({"id": record["id"], **record["payload"]})
        lifecycle={row["state"]:row["count"] for row in self.store.connection.execute(
            """SELECT ps.state, COUNT(*) AS count FROM project_state ps
               JOIN records r ON r.id=ps.record_id WHERE r.owner_scope=? GROUP BY ps.state""",
            (scope,),
        )}
        active_projects=[]
        for row in self.store.connection.execute(
            """SELECT r.id, r.payload FROM records r JOIN project_state ps ON ps.record_id=r.id
               WHERE r.owner_scope=? AND ps.state='ACTIVE' ORDER BY r.updated_at DESC LIMIT 5""",
            (scope,),
        ):
            project=json.loads(row["payload"])
            active_projects.append({"id":row["id"], "name":project.get("name", "Unnamed project")})
        connectors=[dict(row) for row in self.store.connection.execute(
            """SELECT connector_name, enabled, mode FROM connector_config
               ORDER BY connector_name"""
        )]
        generated=now()
        recommendations=[]
        guidance={"APPROVAL_BLOCKED":"Review exact approval request",
                  "BUDGET_BLOCKED":"Review budget or leave work blocked",
                  "POLICY_BLOCKED":"Correct policy/configuration before retry",
                  "DEAD_LETTER":"Investigate terminal failure and decide recovery"}
        for item in attention:
            recommendations.append({"classification":"RECOMMENDATION",
                                    "work_id":item["id"], "recommendation":guidance[item["status"]],
                                    "confidence":1.0, "currentness":generated})
        for incident in incidents:
            recommendations.append({
                "classification":"RECOMMENDATION",
                "incident_id":incident["incident_id"],
                "recommendation":"Review incident evidence and resolve only after recovery",
                "confidence":1.0,
                "currentness":generated,
            })
        for delivery in delivery_attention:
            recommendations.append({
                "classification":"RECOMMENDATION",
                "delivery_id":delivery["delivery_id"],
                "recommendation":"Review failure evidence; Sean may reset to STAGED for fresh approval",
                "confidence":1.0,
                "currentness":generated,
            })
        previous_attention=len(prior.get("attention_items", [])) if prior else 0
        previous_incidents=len(prior.get("active_incidents", [])) if prior else 0
        previous_delivery_attention=len(
            (prior.get("delivery_diagnostics") or {}).get("attention", [])
        ) if prior else 0
        previous_decisions=len(prior.get("recent_decisions", [])) if prior else 0
        changes={"has_prior_report":bool(prior),
                 "attention_item_delta":len(attention)-previous_attention,
                 "active_incident_delta":len(incidents)-previous_incidents,
                 "delivery_attention_delta":len(delivery_attention)-previous_delivery_attention,
                 "decision_count_delta":len(decisions[-10:])-previous_decisions}
        payload = {
            "kind": "SEAN_OS_OPERATIONAL_REPORT", "cadence": cadence,
            "report_type":"MORNING_BRIEF" if cadence == "DAILY" else "WEEKLY_REVIEW",
            "period_key": key, "scope": scope, "generated_at": generated,
            "headline": "ATTENTION REQUIRED" if attention or incidents or delivery_attention else "SYSTEM NOMINAL",
            "health": health, "attention_items": attention,
            "active_incidents":incidents,
            "delivery_diagnostics":delivery_diagnostics,
            "active_approvals": approvals, "recent_decisions": decisions[-10:],
            "top_priorities":active_projects, "portfolio_by_lifecycle":lifecycle,
            "spend":health["budgets"], "changes_since_prior":changes,
            "facts":[
                {"classification":"FACT", "statement":"Runtime health snapshot",
                 "value":health, "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Blocked or failed work count",
                 "value":len(attention), "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Active monitoring incident count",
                 "value":len(incidents), "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Alert delivery items requiring attention",
                 "value":len((delivery_diagnostics or {}).get("attention", [])),
                 "confidence":1.0, "currentness":generated},
            ],
            "estimates":[],
            "inferences":[{"classification":"INFERENCE",
                           "statement":"Operator attention is required" if attention or incidents or delivery_attention else "No known runtime exception requires attention",
                           "confidence":.95, "currentness":generated,
                           "evidence_work_ids":[item["id"] for item in attention],
                           "evidence_incident_ids":[item["incident_id"] for item in incidents],
                           "evidence_delivery_ids":[item["delivery_id"] for item in delivery_attention]}],
            "recommendations":recommendations,
            "unavailable_sources":[name for name in ("EMAIL","CALENDAR")
                                   if not any(c["connector_name"] == name and c["enabled"] for c in connectors)],
            "delivery": "LOCAL_ONLY",
            "connectors": connectors,
        }
        record_id = self.store.create_record(
            self.actor, "KNOWLEDGE", scope, payload, source="automated-report",
        )
        self.store.connection.execute(
            """INSERT INTO report_runs(id, cadence, period_key, owner_scope, record_id, generated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), cadence, key, scope, record_id, now()),
        )
        self.store.connection.commit()
        self.store.record_policy_decision(
            self.actor, record_id, True, "Local operational report generated",
            {"cadence": cadence, "period_key": key, "scope": scope},
        )
        return payload
