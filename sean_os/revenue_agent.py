from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .chief_of_staff import ChiefOfStaff
from .store import Actor, SeanOSStore, ValidationError


@dataclass(frozen=True)
class RevenueCharter:
    qualification_threshold: float = 0.65
    max_estimated_value: float = 1_000_000
    synthetic_only: bool = True


class RevenueAgent:
    """Internal-only opportunity analysis. It has no outreach, pricing, CRM, or spending authority."""

    def __init__(self, store: SeanOSStore, actor: Actor, charter: RevenueCharter | None = None):
        self.store=store; self.actor=actor; self.charter=charter or RevenueCharter()
        self.chief=ChiefOfStaff(store, actor)

    def register_signal(
        self, *, name: str, evidence: str, source_reference: str, synthetic: bool,
    ) -> str:
        if self.charter.synthetic_only and not synthetic:
            raise ValidationError("v0.1 Revenue Agent accepts synthetic signals only")
        if not name.strip() or not evidence.strip() or not source_reference.strip():
            raise ValidationError("Signal name, evidence, and source reference are required")
        return self.store.create_record(
            self.actor, "KNOWLEDGE", "IAC",
            {"kind":"REVENUE_SIGNAL", "name":name, "evidence":evidence,
             "source_reference":source_reference, "synthetic":synthetic},
            source="revenue-agent", source_locator=source_reference,
        )

    def qualify(
        self, signal_id: str, goal_id: str, *, account_alias: str,
        icp_fit: float, urgency: float, evidence_strength: float,
        estimated_value: float, synthetic: bool,
    ) -> dict[str, Any]:
        if self.charter.synthetic_only and not synthetic:
            raise ValidationError("v0.1 Revenue Agent accepts synthetic opportunities only")
        if "@" in account_alias or not account_alias.strip():
            raise ValidationError("Use a non-identifying account alias, not contact information")
        scores=(icp_fit, urgency, evidence_strength)
        if any(score < 0 or score > 1 for score in scores):
            raise ValidationError("Qualification scores must be between 0 and 1")
        if estimated_value < 0 or estimated_value > self.charter.max_estimated_value:
            raise ValidationError("Estimated value is outside the charter boundary")
        signal=self.store.get_record(self.actor, signal_id)
        goal=self.store.get_record(self.actor, goal_id)
        if signal["owner_scope"] != "IAC" or signal["payload"].get("kind") != "REVENUE_SIGNAL":
            raise ValidationError("Qualification requires an IAC revenue signal")
        if goal["entity_type"] != "GOAL" or goal["owner_scope"] != "IAC":
            raise ValidationError("Revenue opportunities must advance an IAC goal")
        score=round(icp_fit * 0.45 + urgency * 0.25 + evidence_strength * 0.30, 4)
        recommendation="PREPARE_INTERNAL_DRAFT" if score >= self.charter.qualification_threshold else "NO_ACTION"
        opportunity_id=self.store.create_record(
            self.actor, "IDEA", "IAC",
            {"kind":"REVENUE_OPPORTUNITY", "signal_id":signal_id,
             "account_alias":account_alias, "qualification_score":score,
             "estimated_value":estimated_value, "recommendation":recommendation,
             "synthetic":synthetic, "external_action_authorized":False},
            source="revenue-agent",
        )
        self.store.link_records(self.actor, opportunity_id, "SUPPORTED_BY", signal_id)
        decision_id=self.store.create_record(
            self.actor, "DECISION", "IAC",
            {"opportunity_id":opportunity_id, "decision":recommendation,
             "score":score, "threshold":self.charter.qualification_threshold,
             "external_action_authorized":False},
            source="revenue-agent",
        )
        self.store.link_records(self.actor, decision_id, "GOVERNS", opportunity_id)
        project_id=None
        if recommendation == "PREPARE_INTERNAL_DRAFT":
            plan=self.chief.create_project(
                goal_id, f"Internal opportunity brief — {account_alias}",
                [{"name":"Validate synthetic assumptions",
                  "done_when":"Assumptions and counter-evidence are recorded"},
                 {"name":"Prepare internal draft",
                  "done_when":"Draft is stored locally and marked NOT SENT"}],
                success_metric="validated opportunity score",
                stop_condition=f"validated score below {self.charter.qualification_threshold}",
            )
            project_id=plan["project_id"]
            self.store.link_records(self.actor, project_id, "EXPLORES", opportunity_id)
        return {"opportunity_id":opportunity_id, "decision_id":decision_id,
                "project_id":project_id, "score":score, "recommendation":recommendation,
                "external_action_authorized":False}

    def compare_portfolio(
        self, goal_id: str, candidates: list[dict[str, Any]], *, research_capacity: int = 2,
    ) -> dict[str, Any]:
        classes={"NEW_OUTBOUND","EXISTING_CUSTOMER","INACTIVE_CUSTOMER",
                 "UNCONVERTED_QUOTE","INBOUND_LEAD","NEW_CHANNEL"}
        if not candidates or len(candidates) > 20 or not 1 <= research_capacity <= 5:
            raise ValidationError("Revenue portfolio requires 1-20 candidates and capacity 1-5")
        goal=self.store.get_record(self.actor, goal_id)
        if goal["entity_type"] != "GOAL" or goal["owner_scope"] != "IAC":
            raise ValidationError("Revenue portfolio must advance an IAC goal")
        ranked=[]
        for candidate in candidates:
            required={"opportunity_class","account_alias","estimated_value","gross_margin",
                      "probability","strategic_fit","evidence_strength","sean_hours",
                      "implementation_cost","capacity_load","synthetic"}
            if set(candidate) != required:
                raise ValidationError("Revenue candidate fields are incomplete or unexpected")
            opportunity_class=str(candidate["opportunity_class"]).upper()
            if opportunity_class not in classes:
                raise ValidationError("Unknown revenue opportunity class")
            alias=str(candidate["account_alias"])
            if not candidate["synthetic"] or "@" in alias or not alias.strip():
                raise ValidationError("Revenue portfolio accepts synthetic non-identifying aliases only")
            bounded=[float(candidate[key]) for key in
                     ("gross_margin","probability","strategic_fit","evidence_strength","capacity_load")]
            if any(value < 0 or value > 1 for value in bounded):
                raise ValidationError("Revenue ratios must be between 0 and 1")
            value=float(candidate["estimated_value"]); cost=float(candidate["implementation_cost"])
            hours=float(candidate["sean_hours"])
            if value < 0 or value > self.charter.max_estimated_value or cost < 0 or hours < 0:
                raise ValidationError("Revenue value, cost, or Sean hours is outside charter")
            expected_return=value*bounded[0]*bounded[1]-cost
            capacity_adjusted=expected_return*(1-bounded[4]*.30)
            roi_per_sean_hour=capacity_adjusted/max(hours, 1)
            rank_score=round(roi_per_sean_hour*(.7+.2*bounded[2]+.1*bounded[3]), 2)
            ranked.append({**candidate, "opportunity_class":opportunity_class,
                           "expected_return":round(expected_return, 2),
                           "capacity_adjusted_return":round(capacity_adjusted, 2),
                           "roi_per_sean_hour":round(roi_per_sean_hour, 2),
                           "rank_score":rank_score})
        ranked.sort(key=lambda item:(-item["rank_score"], item["account_alias"]))
        max_value=max((item["estimated_value"] for item in ranked), default=1) or 1
        projects=[]; hypotheses=[]
        for position, item in enumerate(ranked, 1):
            selected=position <= research_capacity and item["expected_return"] > 0
            reopen=("Research capacity increases or new evidence raises expected return" if not selected
                    else None)
            hypothesis_id=self.store.create_record(
                self.actor, "IDEA", "IAC",
                {"kind":"REVENUE_HYPOTHESIS", "rank":position,
                 "opportunity_class":item["opportunity_class"],
                 "account_alias":item["account_alias"], "rank_score":item["rank_score"],
                 "expected_return":item["expected_return"],
                 "recommendation":"RESEARCH" if selected else "REJECT_FOR_NOW",
                 "reopen_trigger":reopen, "synthetic":True,
                 "external_action_authorized":False},
                source="revenue-agent", confidence=float(item["evidence_strength"]),
            )
            hypotheses.append(hypothesis_id)
            if selected:
                plan=self.chief.create_project(
                    goal_id, f"Revenue research — {item['opportunity_class']} — {item['account_alias']}",
                    [{"name":"Validate expected-return assumptions",
                      "done_when":"Margin, probability, cost, and capacity evidence are stored"},
                     {"name":"Prepare internal recommendation",
                      "done_when":"Recommendation is stored locally and marked NOT SENT"}],
                    success_metric="capacity-adjusted expected return",
                    stop_condition="validated expected return is non-positive",
                    portfolio_metrics={
                        "strategic_fit":float(item["strategic_fit"]),
                        "expected_value":min(1, float(item["estimated_value"])/max_value),
                        "urgency":float(item["probability"]),
                        "confidence":float(item["evidence_strength"]),
                        "effort":min(1, float(item["sean_hours"])/40),
                        "risk":1-float(item["evidence_strength"]),
                    },
                )
                self.store.link_records(self.actor, plan["project_id"], "EXPLORES", hypothesis_id)
                projects.append(plan["project_id"])
        decision_id=self.store.create_record(
            self.actor, "DECISION", "IAC",
            {"kind":"REVENUE_PORTFOLIO_ALLOCATION", "ranked_candidates":ranked,
             "research_capacity":research_capacity, "selected_project_ids":projects,
             "rejected_hypothesis_ids":[hypotheses[index] for index in range(len(hypotheses))
                                        if index >= research_capacity or ranked[index]["expected_return"] <= 0],
             "external_action_authorized":False},
            source="revenue-agent", confidence=.8,
        )
        return {"decision_id":decision_id, "ranked_candidates":ranked,
                "project_ids":projects, "hypothesis_ids":hypotheses,
                "external_action_authorized":False}
