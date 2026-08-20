from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from .store import Actor, AuthorizationError, SeanOSStore, ValidationError, now


@dataclass(frozen=True)
class CommandSpec:
    action_type: str
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


COMMANDS={
    "CREATE_RECORD":CommandSpec(
        "CREATE_IAC_RECORD", frozenset({"entity_type","payload"}),
        frozenset({"confidence","effective_at","expires_at","retention_rule"}),
    ),
    "UPDATE_RECORD":CommandSpec(
        "UPDATE_IAC_RECORD", frozenset({"record_id","payload","expected_version"})
    ),
    "LINK_RECORDS":CommandSpec(
        "LINK_IAC_RECORDS", frozenset({"from_record_id","relationship_type","to_record_id"})
    ),
    "CAPTURE_IDEA":CommandSpec("CAPTURE_IAC_IDEA", frozenset({"name","hypothesis","evidence"})),
    "EVALUATE_IDEA":CommandSpec(
        "EVALUATE_IAC_IDEA", frozenset({"idea_id","evidence_strength","recommendation"})
    ),
    "CREATE_IAC_GOAL":CommandSpec("CREATE_IAC_GOAL", frozenset({"name","success_metric"})),
    "CREATE_PROJECT":CommandSpec(
        "CHIEF_CREATE_PROJECT",
        frozenset({"goal_id","name","tasks","success_metric","stop_condition"}),
        frozenset({"idea_id","portfolio_metrics"}),
    ),
    "REVIEW_PORTFOLIO":CommandSpec(
        "CHIEF_REVIEW_PORTFOLIO", frozenset({"project_ids"}),
        frozenset({"capacity_limit","low_fit_threshold"}),
    ),
    "QUALIFY_REVENUE":CommandSpec(
        "REVENUE_QUALIFY",
        frozenset({"signal_id","goal_id","account_alias","icp_fit","urgency",
                   "evidence_strength","estimated_value","synthetic"}),
    ),
    "COMPARE_REVENUE_PORTFOLIO":CommandSpec(
        "REVENUE_COMPARE_PORTFOLIO", frozenset({"goal_id","candidates"}),
        frozenset({"research_capacity"}),
    ),
    "IMPORT_CLAUDE_ARTIFACT":CommandSpec(
        "IMPORT_CLAUDE_ARTIFACT",
        frozenset({"external_id","content","source_uri","captured_at","synthetic"}),
        frozenset({"metadata"}),
    ),
    "GENERATE_REPORT":CommandSpec(
        "GENERATE_OPERATIONAL_REPORT", frozenset({"cadence"}), frozenset({"period_key"}),
    ),
    "REQUEST_CUSTOMER_CONTACT_APPROVAL":CommandSpec(
        "REQUEST_CUSTOMER_CONTACT_APPROVAL",
        frozenset({"target","draft_record_id","max_impact","expires_at"}),
    ),
}


class CommandGateway:
    """Narrow interface boundary for ChatGPT or another UI. Never executes work inline."""

    def __init__(self, store: SeanOSStore, actor: Actor):
        self.store=store; self.actor=actor

    def submit(
        self, external_request_id: str, command_type: str, payload: dict[str, Any], *,
        scope: str = "IAC",
    ) -> dict[str, Any]:
        if scope != "IAC":
            raise AuthorizationError("v0.1 command interface is isolated to IAC scope")
        self.store._authorize(self.actor, scope, (), "write")
        command=command_type.upper(); spec=COMMANDS.get(command)
        if spec is None:
            raise AuthorizationError("Command type is not exposed by the interface")
        if not external_request_id.strip():
            raise ValidationError("External request ID is required")
        fields=set(payload); missing=spec.required-fields
        extras=fields-spec.required-spec.optional
        if missing or extras:
            raise ValidationError(
                f"Command fields invalid; missing={sorted(missing)}, extra={sorted(extras)}"
            )
        canonical=json.dumps(
            {"command_type":command, "scope":scope, "payload":payload},
            sort_keys=True, separators=(",",":"),
        )
        digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        existing=self.store.connection.execute(
            """SELECT request_sha256, work_id FROM command_requests
               WHERE external_request_id=?""", (external_request_id,),
        ).fetchone()
        if existing:
            if existing["request_sha256"] != digest:
                raise ValidationError("Request ID was reused with different command content")
            return {"work_id":existing["work_id"], "deduplicated":True, "status":self.status(existing["work_id"])}

        request_id=str(uuid.uuid4()); work_id=str(uuid.uuid4()); stamp=now()
        try:
            self.store.connection.execute("BEGIN IMMEDIATE")
            self.store.connection.execute(
                """INSERT INTO work_queue
                   (id, task_type, owner_scope, payload, status, priority, max_attempts,
                    available_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'QUEUED', 100, 3, ?, ?, ?)""",
                (work_id, spec.action_type, scope, json.dumps(payload, sort_keys=True),
                 stamp, stamp, stamp),
            )
            self.store.connection.execute(
                """INSERT INTO command_requests
                   (id, external_request_id, request_sha256, submitted_by, owner_scope,
                    command_type, work_id, submitted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (request_id, external_request_id, digest, self.actor.id, scope,
                 command, work_id, stamp),
            )
            self.store.connection.commit()
        except Exception:
            self.store.connection.rollback(); raise
        self.store.record_policy_decision(
            self.actor, work_id, True, "Whitelisted interface command queued",
            {"command_type":command, "external_request_id":external_request_id},
        )
        return {"work_id":work_id, "deduplicated":False, "status":"QUEUED"}

    def status(self, work_id: str) -> str:
        row=self.store.connection.execute(
            """SELECT q.status FROM command_requests c JOIN work_queue q ON q.id=c.work_id
               WHERE c.work_id=? AND c.submitted_by=?""", (work_id, self.actor.id),
        ).fetchone()
        if row is None:
            raise AuthorizationError("Command is not visible to this interface principal")
        return row["status"]

    def result(self, work_id: str) -> dict[str, Any] | None:
        row=self.store.connection.execute(
            """SELECT q.task_type, q.status FROM command_requests c
               JOIN work_queue q ON q.id=c.work_id
               WHERE c.work_id=? AND c.submitted_by=?""", (work_id, self.actor.id),
        ).fetchone()
        if row is None:
            raise AuthorizationError("Command is not visible to this interface principal")
        if row["status"] != "SUCCEEDED":
            return None
        return self.store.completed_action_result(work_id, row["task_type"])

    def get_record(self, record_id: str) -> dict[str, Any]:
        return self.store.get_record(self.actor, record_id)

    def list_records(self, entity_type: str | None = None) -> list[dict[str, Any]]:
        return self.store.list_records(self.actor, entity_type)

    def audit_trace(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.scoped_audit_events(self.actor, limit=limit)
