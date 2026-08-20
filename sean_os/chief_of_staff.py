from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .store import Actor, AuthorizationError, SeanOSStore, ValidationError
from .policy import ActionPolicy, ActionRegistry
from .reporting import ReportingService


@dataclass(frozen=True)
class PlanningLimits:
    max_tasks_per_project: int = 5
    allowed_scopes: frozenset[str] = frozenset({"IAC"})


class ChiefOfStaff:
    """Deterministic, bounded planning loop. It creates records only; it causes no external effects."""

    def __init__(self, store: SeanOSStore, actor: Actor, limits: PlanningLimits | None = None):
        self.store = store
        self.actor = actor
        self.limits = limits or PlanningLimits()

    def create_project(
        self, goal_id: str, name: str, tasks: list[dict[str, Any]], *,
        success_metric: str, stop_condition: str,
        portfolio_metrics: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        goal = self.store.get_record(self.actor, goal_id)
        scope = goal["owner_scope"]
        if goal["entity_type"] != "GOAL":
            raise ValidationError("Chief of Staff projects must advance a GOAL")
        if scope not in self.limits.allowed_scopes:
            raise AuthorizationError(f"Chief of Staff cannot plan in {scope} scope")
        if not name.strip() or not success_metric.strip() or not stop_condition.strip():
            raise ValidationError("Project name, success metric, and stop condition are required")
        if not tasks or len(tasks) > self.limits.max_tasks_per_project:
            raise ValidationError(f"Projects require 1-{self.limits.max_tasks_per_project} bounded tasks")
        for task in tasks:
            if not str(task.get("name", "")).strip() or not str(task.get("done_when", "")).strip():
                raise ValidationError("Every task requires name and done_when")
        metrics=portfolio_metrics or {
            "strategic_fit":.5, "expected_value":.5, "urgency":.5,
            "confidence":.5, "effort":.5, "risk":.5,
        }
        required_metrics={"strategic_fit","expected_value","urgency","confidence","effort","risk"}
        if set(metrics) != required_metrics or any(not 0 <= float(value) <= 1 for value in metrics.values()):
            raise ValidationError("Portfolio metrics must contain six bounded 0-1 values")

        project_id = self.store.create_record(
            self.actor, "PROJECT", scope,
            {"name": name, "goal_id": goal_id, "success_metric": success_metric,
             "stop_condition": stop_condition, "created_by_agent": self.actor.id,
             "portfolio_metrics":{key:float(value) for key, value in metrics.items()}},
            source="chief-of-staff",
        )
        self.store.link_records(self.actor, project_id, "ADVANCES", goal_id)
        task_ids = []
        for position, task in enumerate(tasks, 1):
            task_id = self.store.create_record(
                self.actor, "TASK", scope,
                {"name": task["name"], "done_when": task["done_when"],
                 "project_id": project_id, "position": position, "status": "READY",
                 "created_by_agent": self.actor.id},
                source="chief-of-staff",
            )
            self.store.link_records(self.actor, task_id, "BELONGS_TO", project_id)
            task_ids.append(task_id)
        self.store.transition_project(
            self.actor, project_id, "ACTIVE", "Bounded plan passed internal policy checks"
        )
        return {"project_id": project_id, "task_ids": task_ids}

    def evaluate_project(
        self, project_id: str, *, completed_tasks: int, total_tasks: int,
        metric_value: float, minimum_viable_metric: float, evidence: str,
    ) -> str:
        project = self.store.get_record(self.actor, project_id)
        if project["entity_type"] != "PROJECT":
            raise ValidationError("Evaluation target must be a PROJECT")
        if project["created_by"] != self.actor.id or project["payload"].get("created_by_agent") != self.actor.id:
            raise AuthorizationError("Agent may only self-manage projects it created")
        if total_tasks < 1 or not 0 <= completed_tasks <= total_tasks or not evidence.strip():
            raise ValidationError("Valid task counts and evidence are required")

        if metric_value < minimum_viable_metric and completed_tasks == total_tasks:
            state = "KILLED"
            reason = f"Measured outcome below viability threshold: {evidence}"
            self.store.transition_project(
                self.actor, project_id, state, reason,
                reopen_trigger=f"New evidence predicts metric >= {minimum_viable_metric}",
            )
        elif metric_value < minimum_viable_metric:
            state = "PAUSED"
            reason = f"Early evidence is below threshold; preserve remaining effort: {evidence}"
            self.store.transition_project(self.actor, project_id, state, reason)
        else:
            state = "ACTIVE"
            reason = f"Evidence supports continuing: {evidence}"
            self.store.transition_project(self.actor, project_id, state, reason)

        decision_id = self.store.create_record(
            self.actor, "DECISION", project["owner_scope"],
            {"project_id": project_id, "decision": state, "evidence": evidence,
             "metric_value": metric_value, "minimum_viable_metric": minimum_viable_metric},
            source="chief-of-staff",
        )
        self.store.link_records(self.actor, decision_id, "GOVERNS", project_id)
        return state

    def review_portfolio(
        self, project_ids: list[str], *, capacity_limit: int = 3,
        low_fit_threshold: float = .35,
    ) -> dict[str, Any]:
        if not project_ids or len(project_ids) > 20:
            raise ValidationError("Portfolio review requires 1-20 projects")
        if capacity_limit < 1 or capacity_limit > 10 or not 0 <= low_fit_threshold <= 1:
            raise ValidationError("Portfolio capacity or low-fit threshold is invalid")
        ranked=[]
        for project_id in dict.fromkeys(project_ids):
            project=self.store.get_record(self.actor, project_id)
            if project["entity_type"] != "PROJECT" or project["owner_scope"] != "IAC":
                raise ValidationError("Portfolio review accepts IAC projects only")
            metrics=project["payload"].get("portfolio_metrics")
            if not metrics:
                raise ValidationError("Project lacks portfolio metrics")
            score=round(
                metrics["strategic_fit"]*.30 + metrics["expected_value"]*.25 +
                metrics["urgency"]*.15 + metrics["confidence"]*.15 -
                metrics["effort"]*.10 - metrics["risk"]*.05, 4
            )
            ranked.append({"project_id":project_id, "name":project["payload"].get("name"),
                           "score":score, "metrics":metrics,
                           "agent_owned":project["created_by"] == self.actor.id and
                           project["payload"].get("created_by_agent") == self.actor.id})
        ranked.sort(key=lambda item:(-item["score"], item["project_id"]))
        changed=[]
        for position, item in enumerate(ranked, 1):
            fit=item["metrics"]["strategic_fit"]
            if fit < low_fit_threshold:
                item["recommendation"]="CHALLENGE_NO"
                rationale=f"Strategic fit {fit:.2f} is below {low_fit_threshold:.2f}"
            elif position > capacity_limit:
                item["recommendation"]="PAUSE_FOR_CAPACITY"
                rationale=f"Rank {position} is outside capacity limit {capacity_limit}"
            else:
                item["recommendation"]="PRIORITIZE"
                rationale=f"Rank {position} is within capacity"
            item["rationale"]=rationale
            if item["recommendation"] != "PRIORITIZE" and item["agent_owned"]:
                self.store.transition_project(
                    self.actor, item["project_id"], "PAUSED",
                    f"Chief of Staff portfolio review: {rationale}",
                )
                changed.append(item["project_id"])
            elif item["recommendation"] != "PRIORITIZE":
                item["recommendation"] += "_HUMAN_REVIEW"
        decision_id=self.store.create_record(
            self.actor, "DECISION", "IAC",
            {"kind":"PORTFOLIO_REVIEW", "ranked_projects":ranked,
             "capacity_limit":capacity_limit, "low_fit_threshold":low_fit_threshold,
             "autonomously_paused":changed}, source="chief-of-staff", confidence=.9,
        )
        for item in ranked:
            self.store.link_records(self.actor, decision_id, "GOVERNS", item["project_id"])
        return {"decision_id":decision_id, "ranked_projects":ranked,
                "autonomously_paused":changed}


def chief_of_staff_registry(store: SeanOSStore, actor: Actor) -> ActionRegistry:
    """Worker registry containing only reversible, internal Chief of Staff actions."""
    chief = ChiefOfStaff(store, actor)
    reporter = ReportingService(store, actor)
    from .revenue_agent import RevenueAgent
    revenue = RevenueAgent(store, actor)
    from .integrations import ClaudeImportAdapter, ImportEnvelope
    claude_import = ClaudeImportAdapter(store, actor)

    def evaluate_idea(payload):
        idea=store.get_record(actor, payload["idea_id"])
        if idea["entity_type"] != "IDEA" or idea["owner_scope"] != "IAC":
            raise ValidationError("Evaluation requires an IAC idea")
        strength=float(payload["evidence_strength"])
        recommendation=str(payload["recommendation"]).upper()
        if not 0 <= strength <= 1 or recommendation not in {"ADVANCE","INCUBATE","REJECT"}:
            raise ValidationError("Idea evaluation requires bounded evidence and a valid recommendation")
        decision_id=store.create_record(
            actor, "DECISION", "IAC",
            {"idea_id":idea["id"], "recommendation":recommendation,
             "evidence_strength":strength}, source="chief-of-staff", confidence=strength,
        )
        store.link_records(actor, decision_id, "GOVERNS", idea["id"])
        return {"decision_id":decision_id, "recommendation":recommendation}

    def create_project_action(payload):
        idea=None
        if payload.get("idea_id"):
            idea=store.get_record(actor, payload["idea_id"])
            if idea["entity_type"] != "IDEA" or idea["owner_scope"] != "IAC":
                raise ValidationError("Project idea reference is invalid")
        result=chief.create_project(
            payload["goal_id"], payload["name"], payload["tasks"],
            success_metric=payload["success_metric"], stop_condition=payload["stop_condition"],
            portfolio_metrics=payload.get("portfolio_metrics"),
        )
        if idea:
            store.link_records(actor, result["project_id"], "EXPLORES", idea["id"])
        return result

    def create_iac_record(payload):
        entity_type=str(payload["entity_type"]).upper()
        if entity_type == "APPROVAL":
            raise AuthorizationError("Use a bounded approval-request command")
        record_id=store.create_record(
            actor, entity_type, "IAC", payload["payload"], source="command-interface",
            confidence=float(payload["confidence"]) if "confidence" in payload else None,
            effective_at=payload.get("effective_at"), expires_at=payload.get("expires_at"),
            retention_rule=payload.get("retention_rule", "retain"),
        )
        return {"record_id":record_id, "entity_type":entity_type}

    def update_iac_record(payload):
        record=store.get_record(actor, payload["record_id"])
        if record["owner_scope"] != "IAC":
            raise AuthorizationError("Interface updates are isolated to IAC")
        version=store.update_record(
            actor, record["id"], payload["payload"],
            expected_version=int(payload["expected_version"]),
        )
        return {"record_id":record["id"], "version":version}

    def link_iac_records(payload):
        source=store.get_record(actor, payload["from_record_id"])
        target=store.get_record(actor, payload["to_record_id"])
        if source["owner_scope"] != "IAC" or target["owner_scope"] != "IAC":
            raise AuthorizationError("Interface links are isolated to IAC")
        relationship_id=store.link_records(
            actor, source["id"], payload["relationship_type"], target["id"]
        )
        return {"relationship_id":relationship_id}
    registry = ActionRegistry()
    registry.register(
        ActionPolicy(
            "NOOP", frozenset({"IAC"}), external_effect=False, reversible=True,
            approval_required=False, cost_bearing=False,
        ),
        lambda payload: {"ok": True, "echo": payload},
    )
    registry.register(
        ActionPolicy(
            "CREATE_IAC_RECORD", frozenset({"IAC"}), False, True, False, False,
        ), create_iac_record,
    )
    registry.register(
        ActionPolicy(
            "UPDATE_IAC_RECORD", frozenset({"IAC"}), False, True, False, False,
        ), update_iac_record,
    )
    registry.register(
        ActionPolicy(
            "LINK_IAC_RECORDS", frozenset({"IAC"}), False, True, False, False,
        ), link_iac_records,
    )
    registry.register(
        ActionPolicy(
            "CAPTURE_IAC_IDEA", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: {"idea_id":store.create_record(
            actor, "IDEA", "IAC",
            {"name":payload["name"], "hypothesis":payload["hypothesis"],
             "evidence":payload["evidence"], "classification":"IDEA"},
            source="command-interface", confidence=.5,
        )},
    )
    registry.register(
        ActionPolicy(
            "EVALUATE_IAC_IDEA", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        evaluate_idea,
    )
    registry.register(
        ActionPolicy(
            "CREATE_IAC_GOAL", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: {"goal_id":store.create_record(
            actor, "GOAL", "IAC",
            {"name":payload["name"], "success_metric":payload["success_metric"]},
            source="command-interface",
        )},
    )
    registry.register(
        ActionPolicy(
            "CHIEF_CREATE_PROJECT", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        create_project_action,
    )
    registry.register(
        ActionPolicy(
            "CHIEF_REVIEW_PORTFOLIO", frozenset({"IAC"}), False, True, False, False,
        ),
        lambda payload: chief.review_portfolio(
            payload["project_ids"], capacity_limit=int(payload.get("capacity_limit", 3)),
            low_fit_threshold=float(payload.get("low_fit_threshold", .35)),
        ),
    )
    registry.register(
        ActionPolicy(
            "CHIEF_EVALUATE_PROJECT", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: {"state": chief.evaluate_project(
            payload["project_id"], completed_tasks=int(payload["completed_tasks"]),
            total_tasks=int(payload["total_tasks"]), metric_value=float(payload["metric_value"]),
            minimum_viable_metric=float(payload["minimum_viable_metric"]),
            evidence=payload["evidence"],
        )},
    )
    registry.register(
        ActionPolicy(
            "GENERATE_OPERATIONAL_REPORT", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: reporter.generate(
            payload["cadence"], "IAC", period_key=payload.get("period_key")
        ),
    )
    registry.register(
        ActionPolicy(
            "REVENUE_REGISTER_SIGNAL", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: {"signal_id":revenue.register_signal(
            name=payload["name"], evidence=payload["evidence"],
            source_reference=payload["source_reference"], synthetic=bool(payload["synthetic"]),
        )},
    )
    registry.register(
        ActionPolicy(
            "REVENUE_QUALIFY", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: revenue.qualify(
            payload["signal_id"], payload["goal_id"], account_alias=payload["account_alias"],
            icp_fit=float(payload["icp_fit"]), urgency=float(payload["urgency"]),
            evidence_strength=float(payload["evidence_strength"]),
            estimated_value=float(payload["estimated_value"]), synthetic=bool(payload["synthetic"]),
        ),
    )
    registry.register(
        ActionPolicy(
            "REVENUE_COMPARE_PORTFOLIO", frozenset({"IAC"}), False, True, False, False,
        ),
        lambda payload: revenue.compare_portfolio(
            payload["goal_id"], payload["candidates"],
            research_capacity=int(payload.get("research_capacity", 2)),
        ),
    )
    registry.register(
        ActionPolicy(
            "IMPORT_CLAUDE_ARTIFACT", frozenset({"IAC"}), external_effect=False,
            reversible=True, approval_required=False, cost_bearing=False,
        ),
        lambda payload: claude_import.ingest(ImportEnvelope(
            external_id=payload["external_id"], content=payload["content"],
            source_uri=payload["source_uri"], captured_at=payload["captured_at"],
            synthetic=bool(payload["synthetic"]), metadata=payload.get("metadata", {}),
        )),
    )
    registry.register(
        ActionPolicy(
            "REQUEST_CUSTOMER_CONTACT_APPROVAL", frozenset({"IAC"}),
            external_effect=False, reversible=True, approval_required=False,
            cost_bearing=False,
        ),
        lambda payload: {"approval_id":store.request_approval(
            actor, action_type="SEND_CUSTOMER_MESSAGE", target=payload["target"],
            scope="IAC", max_impact=payload["max_impact"],
            expires_at=payload["expires_at"],
            conditions={"draft_record_id":payload["draft_record_id"]},
        ), "external_action_executed":False},
    )
    return registry
