from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
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
            """SELECT r.payload, rr.generated_at FROM report_runs rr
               JOIN records r ON r.id=rr.record_id
               WHERE rr.cadence=? AND rr.owner_scope=? ORDER BY rr.generated_at DESC LIMIT 1""",
            (cadence, scope),
        ).fetchone()
        prior=json.loads(prior_row["payload"]) if prior_row else None
        since=prior_row["generated_at"] if prior_row else "1970-01-01T00:00:00+00:00"

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
               FROM approvals WHERE scope=? AND status IN ('PENDING','APPROVED')
               AND expires_at>? ORDER BY expires_at, record_id""",
            (scope, stamp.isoformat()),
        )]
        approval_outcomes = [dict(row) for row in self.store.connection.execute(
            """SELECT a.record_id, a.action_type, a.target, a.max_impact, a.status,
                      a.expires_at, MAX(l.occurred_at) AS outcome_at
               FROM approvals a JOIN audit_log l ON l.affected_record_id=a.record_id
               WHERE a.scope=? AND a.status IN ('DENIED','EXPIRED','CONSUMED')
               AND l.occurred_at>? GROUP BY a.record_id, a.action_type, a.target,
               a.max_impact, a.status, a.expires_at
               ORDER BY outcome_at, a.record_id LIMIT 20""",
            (scope, since),
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
               WHERE r.owner_scope=? AND ps.state='ACTIVE' ORDER BY r.updated_at DESC LIMIT 100""",
            (scope,),
        ):
            project=json.loads(row["payload"])
            metrics=project.get("portfolio_metrics")
            score=None
            if isinstance(metrics, dict) and set(metrics) == {
                "strategic_fit","expected_value","urgency","confidence","effort","risk"
            } and all(
                not isinstance(value, bool) and isinstance(value, (int, float))
                and 0 <= float(value) <= 1 for value in metrics.values()
            ):
                score=round(
                    metrics["strategic_fit"]*.30 + metrics["expected_value"]*.25
                    + metrics["urgency"]*.15 + metrics["confidence"]*.15
                    - metrics["effort"]*.10 - metrics["risk"]*.05,
                    4,
                )
            active_projects.append({
                "id":row["id"], "name":project.get("name", "Unnamed project"),
                "portfolio_score":score,
            })
        active_projects.sort(key=lambda item:(
            item["portfolio_score"] is None,
            -(item["portfolio_score"] or 0),
            item["id"],
        ))
        active_projects=active_projects[:5]
        completed_work=[]; maintenance_attention=[]
        for row in self.store.connection.execute(
            """SELECT w.id, w.task_type, w.updated_at, ae.result
               FROM work_queue w JOIN action_executions ae ON ae.work_id=w.id
               WHERE w.owner_scope=? AND w.status='SUCCEEDED' AND w.updated_at>?
               ORDER BY w.updated_at, w.id LIMIT 20""",
            (scope, since),
        ):
            item={"work_id":row["id"], "task_type":row["task_type"],
                  "completed_at":row["updated_at"]}
            if row["task_type"] == "CHIEF_MAINTAIN_PORTFOLIO":
                result=json.loads(row["result"])
                item["reviewed_project_count"]=result.get("reviewed_project_count", 0)
                item["autonomously_paused"]=result.get("autonomously_paused", [])
                item["missing_metrics_project_ids"]=result.get(
                    "missing_metrics_project_ids", []
                )
                maintenance_attention.extend(item["missing_metrics_project_ids"])
            completed_work.append(item)
        project_changes=[]
        for row in self.store.connection.execute(
            """SELECT r.id, r.payload, r.created_at, ps.state, ps.reason, ps.changed_at
               FROM records r JOIN project_state ps ON ps.record_id=r.id
               WHERE r.owner_scope=? AND (r.created_at>? OR ps.changed_at>?)
               ORDER BY ps.changed_at, r.id LIMIT 20""",
            (scope, since, since),
        ):
            project=json.loads(row["payload"])
            project_changes.append({
                "project_id":row["id"],
                "name":project.get("name", "Unnamed project"),
                "state":row["state"],
                "reason":row["reason"],
                "created_at":row["created_at"],
                "changed_at":row["changed_at"],
                "change_kind":"CREATED" if row["created_at"] > since else "LIFECYCLE_CHANGED",
            })
        deadlines=[]; invalid_deadline_task_ids=[]
        horizon=stamp + timedelta(days=3 if cadence == "DAILY" else 7)
        for task in self.store.list_records(self.actor, "TASK"):
            if task["owner_scope"] != scope:
                continue
            payload=task["payload"]
            status=str(payload.get("status", "")).upper()
            if status in {"DONE", "COMPLETED", "CANCELLED"}:
                continue
            due_at=payload.get("due_at")
            blocked=status == "BLOCKED" or bool(payload.get("blocked"))
            due=None
            if due_at is not None:
                try:
                    due=datetime.fromisoformat(str(due_at))
                except ValueError:
                    invalid_deadline_task_ids.append(task["id"])
                    continue
                if due.tzinfo is None or due.utcoffset() is None:
                    invalid_deadline_task_ids.append(task["id"])
                    continue
            if blocked or (due is not None and due <= horizon):
                deadlines.append({
                    "task_id":task["id"],
                    "name":payload.get("name", "Unnamed task"),
                    "status":status or "UNKNOWN",
                    "due_at":due.isoformat() if due else None,
                    "blocked":blocked,
                    "risk":"OVERDUE" if due is not None and due < stamp else
                           "BLOCKED" if blocked else "DUE_SOON",
                })
        deadlines.sort(key=lambda item:(item["due_at"] is None, item["due_at"] or "", item["task_id"]))
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
        for approval in approvals:
            recommendations.append({
                "classification":"RECOMMENDATION",
                "approval_id":approval["record_id"],
                "recommendation":"Review the exact bounded approval before expiry",
                "confidence":1.0,
                "currentness":generated,
            })
        for deadline in deadlines:
            recommendations.append({
                "classification":"RECOMMENDATION",
                "task_id":deadline["task_id"],
                "recommendation":"Resolve the blocked commitment" if deadline["blocked"]
                                 else "Protect or renegotiate the approaching deadline",
                "confidence":1.0,
                "currentness":generated,
            })
        for project_id in sorted(set(maintenance_attention)):
            recommendations.append({
                "classification":"RECOMMENDATION",
                "project_id":project_id,
                "recommendation":"Add bounded portfolio metrics before autonomous ranking",
                "confidence":1.0,
                "currentness":generated,
            })
        for task_id in sorted(set(invalid_deadline_task_ids)):
            recommendations.append({
                "classification":"RECOMMENDATION",
                "task_id":task_id,
                "recommendation":"Correct the malformed or timezone-free task deadline",
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
                 "decision_count_delta":len(decisions[-10:])-previous_decisions,
                 "approval_outcome_count":len(approval_outcomes),
                 "completed_work_count":len(completed_work),
                 "project_change_count":len(project_changes),
                 "deadline_risk_count":len(deadlines)}
        requires_attention=bool(
            attention or incidents or delivery_attention or approvals or deadlines
            or maintenance_attention or invalid_deadline_task_ids
        )
        payload = {
            "kind": "SEAN_OS_OPERATIONAL_REPORT", "cadence": cadence,
            "report_type":"MORNING_BRIEF" if cadence == "DAILY" else "WEEKLY_REVIEW",
            "period_key": key, "scope": scope, "generated_at": generated,
            "headline": "ATTENTION REQUIRED" if requires_attention else "SYSTEM NOMINAL",
            "health": health, "attention_items": attention,
            "active_incidents":incidents,
            "delivery_diagnostics":delivery_diagnostics,
            "active_approvals": approvals, "approval_outcomes":approval_outcomes,
            "recent_decisions": decisions[-10:],
            "overnight_work":completed_work,
            "project_changes":project_changes,
            "deadlines_at_risk":deadlines,
            "invalid_deadline_task_ids":sorted(set(invalid_deadline_task_ids)),
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
                {"classification":"FACT", "statement":"Completed durable work since prior report",
                 "value":len(completed_work), "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Project changes since prior report",
                 "value":len(project_changes), "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Promises or deadlines at risk",
                 "value":len(deadlines), "confidence":1.0, "currentness":generated},
                {"classification":"FACT", "statement":"Approval outcomes since prior report",
                 "value":len(approval_outcomes), "confidence":1.0, "currentness":generated},
            ],
            "estimates":[],
            "inferences":[{"classification":"INFERENCE",
                           "statement":"Operator attention is required" if requires_attention else "No known runtime exception requires attention",
                           "confidence":.95, "currentness":generated,
                           "evidence_work_ids":[item["id"] for item in attention],
                           "evidence_incident_ids":[item["incident_id"] for item in incidents],
                           "evidence_delivery_ids":[item["delivery_id"] for item in delivery_attention],
                           "evidence_approval_ids":[item["record_id"] for item in approvals],
                           "evidence_task_ids":[item["task_id"] for item in deadlines],
                           "evidence_project_ids":sorted(set(maintenance_attention))}],
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
