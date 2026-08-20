from __future__ import annotations

import json
import hashlib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .migrations import LATEST_SCHEMA_VERSION, apply_migrations
from .security import secret_findings

SCOPES = {"PERSONAL", "IAC", "SHARED"}
ENTITY_TYPES = {"GOAL", "IDEA", "PROJECT", "TASK", "DECISION", "KNOWLEDGE", "AGENT", "APPROVAL"}
PROJECT_STATES = {"ACTIVE", "INCUBATOR", "PAUSED", "KILLED"}
RETENTION_RULES = {"retain", "until_expired", "legal_hold"}


class AuthorizationError(PermissionError):
    pass


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    id: str
    scopes: frozenset[str]
    is_sean: bool = False

    @classmethod
    def sean(cls) -> "Actor":
        return cls("sean", frozenset(SCOPES), True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


class SeanOSStore:
    def __init__(
        self, path: str | Path = ":memory:", *, scope_profile: str = "DEVELOPMENT",
    ) -> None:
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        self.connection.executescript(schema)
        self.schema_version=apply_migrations(self.connection)
        profile=scope_profile.upper()
        profiles={"DEVELOPMENT":frozenset(SCOPES), "IAC":frozenset({"IAC"}),
                  "PERSONAL":frozenset({"PERSONAL","SHARED"})}
        if profile not in profiles:
            self.connection.close(); raise ValidationError("Unknown database scope profile")
        stored=self.connection.execute(
            "SELECT value FROM runtime_state WHERE key='scope_profile'"
        ).fetchone()[0]
        if stored == "UNBOUND":
            self.connection.execute(
                "UPDATE runtime_state SET value=?, updated_at=? WHERE key='scope_profile'",
                (profile, now()),
            )
            self.connection.commit(); stored=profile
        if stored != profile:
            self.connection.close()
            raise AuthorizationError(
                f"Database is bound to {stored} profile and cannot open as {profile}"
            )
        self.scope_profile=profile; self.allowed_scopes=profiles[profile]

    def close(self) -> None:
        self.connection.close()

    def _audit(
        self, actor: Actor, action: str, result: str, reason: str,
        record_id: str | None = None, details: dict[str, Any] | None = None,
        correlation_id: str | None = None, *, commit: bool = True,
    ) -> None:
        envelope={"evidence":[], "model":None, "tool":None, "cost_units":0,
                  "outcome":result, "rollback_status":"NOT_APPLICABLE"}
        envelope.update(details or {})
        self.connection.execute(
            """INSERT INTO audit_log
               (event_id, occurred_at, actor_id, action, result, policy_reason,
                affected_record_id, correlation_id, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), now(), actor.id, action, result, reason, record_id,
             correlation_id or str(uuid.uuid4()), json.dumps(envelope, sort_keys=True)),
        )
        if commit:
            self.connection.commit()

    def _authorize(self, actor: Actor, scope: str, principals: Iterable[str], action: str) -> None:
        if scope not in SCOPES:
            raise ValidationError(f"Unknown scope: {scope}")
        if scope not in self.allowed_scopes:
            raise AuthorizationError(
                f"{scope} is outside the database's {self.scope_profile} scope profile"
            )
        if actor.is_sean:
            return
        if scope not in actor.scopes:
            raise AuthorizationError(f"{actor.id} has no {scope} scope")
        if scope == "SHARED" and actor.id not in set(principals):
            raise AuthorizationError(f"{actor.id} is not explicitly permitted for SHARED record")
        if action == "write" and scope == "PERSONAL" and actor.id != "sean":
            raise AuthorizationError("Only Sean may write PERSONAL records in v0.1")

    def create_record(
        self, actor: Actor, entity_type: str, scope: str, payload: dict[str, Any], *,
        confidentiality: str | None = None, portable_on_sale: bool | None = None,
        source: str = "user", source_locator: str | None = None,
        permitted_principals: Iterable[str] = (), confidence: float | None = None,
        correlation_id: str | None = None, effective_at: str | None = None,
        expires_at: str | None = None, retention_rule: str = "retain",
    ) -> str:
        entity_type = entity_type.upper(); scope = scope.upper()
        principals = sorted(set(permitted_principals))
        record_id = str(uuid.uuid4())
        try:
            if entity_type not in ENTITY_TYPES:
                raise ValidationError(f"Unknown entity type: {entity_type}")
            findings=secret_findings(payload)
            if findings:
                raise ValidationError(
                    "Secret-like material is prohibited in canonical record payloads: "
                    + ", ".join(item["path"] for item in findings)
                )
            self._authorize(actor, scope, principals, "write")
            if scope == "SHARED" and not principals:
                raise ValidationError("SHARED records require explicit permitted principals")
            if scope == "SHARED" and portable_on_sale is None:
                raise ValidationError("SHARED portability must be explicit")
            if portable_on_sale is None:
                portable_on_sale = scope == "IAC"
            if scope == "PERSONAL" and portable_on_sale:
                raise ValidationError("PERSONAL records cannot be portable on IAC sale")
            if retention_rule not in RETENTION_RULES:
                raise ValidationError("Unknown retention rule")
            if confidence is None:
                confidence = 1.0 if source == "user" else 0.5
            if not 0 <= confidence <= 1:
                raise ValidationError("Confidence must be between 0 and 1")
            confidentiality = confidentiality or {
                "PERSONAL": "PRIVATE", "IAC": "EXECUTIVE", "SHARED": "CONFIDENTIAL"
            }[scope]
            stamp = now()
            effective_at = effective_at or stamp
            try:
                effective_dt=datetime.fromisoformat(effective_at)
                expires_dt=datetime.fromisoformat(expires_at) if expires_at else None
            except ValueError as exc:
                raise ValidationError("effective_at/expires_at must be ISO-8601 timestamps") from exc
            if effective_dt.tzinfo is None or (expires_dt and expires_dt.tzinfo is None):
                raise ValidationError("effective_at/expires_at must include a timezone")
            if expires_dt and expires_dt <= effective_dt:
                raise ValidationError("expires_at must be after effective_at")
            self.connection.execute(
                """INSERT INTO records
                   (id, entity_type, owner_scope, confidentiality, portable_on_sale,
                    source, source_locator, created_by, created_at, updated_at,
                    effective_at, expires_at, confidence, permitted_principals,
                    retention_rule, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record_id, entity_type, scope, confidentiality, int(portable_on_sale),
                 source, source_locator, actor.id, stamp, stamp, effective_at,
                 expires_at, confidence, json.dumps(principals), retention_rule,
                 json.dumps(payload, sort_keys=True)),
            )
            if entity_type == "PROJECT":
                self.connection.execute(
                    "INSERT INTO project_state(record_id, state, reason, changed_at) VALUES(?, 'INCUBATOR', ?, ?)",
                    (record_id, "Created", stamp),
                )
            self.connection.commit()
            self._audit(actor, "CREATE_RECORD", "ALLOWED", "Authorized scoped write", record_id,
                        {"entity_type": entity_type, "scope": scope}, correlation_id)
            return record_id
        except (AuthorizationError, ValidationError, sqlite3.Error) as exc:
            self.connection.rollback()
            self._audit(actor, "CREATE_RECORD", "DENIED", str(exc), record_id,
                        {"entity_type": entity_type, "scope": scope}, correlation_id)
            raise

    def get_record(self, actor: Actor, record_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
        if row is None:
            self._audit(actor, "READ_RECORD", "DENIED", "Record not found", record_id)
            raise KeyError(record_id)
        principals = json.loads(row["permitted_principals"])
        try:
            self._authorize(actor, row["owner_scope"], principals, "read")
        except AuthorizationError as exc:
            self._audit(actor, "READ_RECORD", "DENIED", str(exc), record_id)
            raise
        self._audit(actor, "READ_RECORD", "ALLOWED", "Authorized scoped read", record_id)
        result = dict(row); result["payload"] = json.loads(result["payload"])
        result["permitted_principals"] = principals
        point=datetime.now(timezone.utc)
        effective=datetime.fromisoformat(result["effective_at"])
        expires=datetime.fromisoformat(result["expires_at"]) if result["expires_at"] else None
        result["currentness"]=("FUTURE" if point < effective else
                               "EXPIRED" if expires and point >= expires else "CURRENT")
        return result

    def list_records(self, actor: Actor, entity_type: str | None = None) -> list[dict[str, Any]]:
        if entity_type is not None:
            entity_type = entity_type.upper()
            if entity_type not in ENTITY_TYPES:
                raise ValidationError(f"Unknown entity type: {entity_type}")
        rows = self.connection.execute(
            "SELECT id FROM records WHERE (? IS NULL OR entity_type=?) ORDER BY created_at, id",
            (entity_type, entity_type),
        ).fetchall()
        visible=[]
        for row in rows:
            try:
                visible.append(self.get_record(actor, row["id"]))
            except AuthorizationError:
                continue
        self._audit(actor, "LIST_RECORDS", "ALLOWED", "Returned authorized records only",
                    details={"entity_type": entity_type, "record_count": len(visible)})
        return visible

    def update_record(
        self, actor: Actor, record_id: str, payload: dict[str, Any], *,
        expected_version: int, correlation_id: str | None = None,
    ) -> int:
        findings=secret_findings(payload)
        if findings:
            self._audit(actor, "UPDATE_RECORD", "DENIED", "Secret-like material is prohibited",
                        record_id, {"finding_paths":[item["path"] for item in findings]})
            raise ValidationError("Secret-like material is prohibited in canonical record payloads")
        current = self.get_record(actor, record_id)
        principals = current["permitted_principals"]
        self._authorize(actor, current["owner_scope"], principals, "write")
        stamp = now()
        cursor = self.connection.execute(
            """UPDATE records SET payload=?, updated_at=?, version=version+1
               WHERE id=? AND version=?""",
            (json.dumps(payload, sort_keys=True), stamp, record_id, expected_version),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            self._audit(actor, "UPDATE_RECORD", "DENIED", "Version conflict", record_id,
                        {"expected_version": expected_version}, correlation_id)
            raise ValidationError("Version conflict: reload the record before updating")
        self.connection.commit()
        version = expected_version + 1
        self._audit(actor, "UPDATE_RECORD", "ALLOWED", "Authorized versioned update", record_id,
                    {"version": version}, correlation_id)
        return version

    def link_records(
        self, actor: Actor, from_record_id: str, relationship_type: str, to_record_id: str,
    ) -> str:
        source = self.get_record(actor, from_record_id)
        target = self.get_record(actor, to_record_id)
        self._authorize(actor, source["owner_scope"], source["permitted_principals"], "write")
        if source["owner_scope"] != target["owner_scope"] and "SHARED" not in {
            source["owner_scope"], target["owner_scope"]
        }:
            self._audit(actor, "LINK_RECORDS", "DENIED", "Direct PERSONAL-IAC links are prohibited",
                        from_record_id, {"to_record_id": to_record_id})
            raise AuthorizationError("Direct PERSONAL-IAC links are prohibited; use a SHARED gateway record")
        relationship_id = str(uuid.uuid4())
        self.connection.execute(
            """INSERT INTO relationships
               (id, from_record_id, relationship_type, to_record_id, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (relationship_id, from_record_id, relationship_type.upper(), to_record_id, now()),
        )
        self.connection.commit()
        self._audit(actor, "LINK_RECORDS", "ALLOWED", "Authorized relationship", from_record_id,
                    {"relationship_id": relationship_id, "to_record_id": to_record_id,
                     "relationship_type": relationship_type.upper()})
        return relationship_id

    def create_approval(
        self, actor: Actor, *, action_type: str, target: str, scope: str,
        max_impact: str, approver: str, expires_at: str,
        conditions: dict[str, Any] | None = None, reusable: bool = False,
    ) -> str:
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may create approvals in v0.1")
        if secret_findings({"action_type":action_type, "target":target,
                            "max_impact":max_impact, "conditions":conditions or {}}):
            raise ValidationError("Secret-like material is prohibited in approval records")
        approval_id = self.create_record(
            actor, "APPROVAL", scope, {"action_type": action_type, "target": target},
            source="approval-queue",
            portable_on_sale=(scope == "IAC"),
            permitted_principals=[approver] if scope == "SHARED" else [],
            expires_at=expires_at, retention_rule="until_expired",
        )
        self.connection.execute(
            """INSERT INTO approvals
               (record_id, action_type, target, scope, max_impact, conditions,
                approver, status, expires_at, reusable)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)""",
            (approval_id, action_type, target, scope, max_impact,
             json.dumps(conditions or {}, sort_keys=True), approver, expires_at, int(reusable)),
        )
        self.connection.commit()
        self._audit(actor, "CREATE_APPROVAL", "ALLOWED", "Explicit approval recorded", approval_id,
                    {"action_type": action_type, "target": target, "reusable": reusable})
        return approval_id

    def request_approval(
        self, actor: Actor, *, action_type: str, target: str, scope: str,
        max_impact: str, expires_at: str, conditions: dict[str, Any] | None = None,
    ) -> str:
        if secret_findings({"action_type":action_type, "target":target,
                            "max_impact":max_impact, "conditions":conditions or {}}):
            raise ValidationError("Secret-like material is prohibited in approval records")
        self._authorize(actor, scope, (), "write")
        approval_id=self.create_record(
            actor, "APPROVAL", scope, {"action_type":action_type, "target":target},
            source="approval-request", portable_on_sale=(scope == "IAC"),
            expires_at=expires_at, retention_rule="until_expired",
        )
        self.connection.execute(
            """INSERT INTO approvals
               (record_id, action_type, target, scope, max_impact, conditions,
                approver, status, expires_at, reusable)
               VALUES (?, ?, ?, ?, ?, ?, 'sean', 'PENDING', ?, 0)""",
            (approval_id, action_type, target, scope, max_impact,
             json.dumps(conditions or {}, sort_keys=True), expires_at),
        )
        self.connection.commit()
        self._audit(actor, "REQUEST_APPROVAL", "ALLOWED", "Bounded approval requested",
                    approval_id, {"action_type":action_type, "target":target,
                                  "max_impact":max_impact})
        return approval_id

    def decide_approval(self, actor: Actor, approval_id: str, *, approve: bool, reason: str) -> str:
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may decide approval requests")
        if not reason.strip():
            raise ValidationError("Approval decisions require a reason")
        if secret_findings({"reason":reason}):
            raise ValidationError("Secret-like material is prohibited in approval evidence")
        row=self.connection.execute(
            "SELECT scope, status, expires_at FROM approvals WHERE record_id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Approval not found")
        self._authorize(actor, row["scope"], (), "write")
        if row["status"] != "PENDING":
            raise ValidationError("Approval is not pending")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            self.connection.execute(
                "UPDATE approvals SET status='EXPIRED' WHERE record_id=?", (approval_id,)
            )
            self.connection.commit()
            self._audit(actor, "DECIDE_APPROVAL", "DENIED", "Approval request expired",
                        approval_id, {"status":"EXPIRED"})
            raise ValidationError("Approval request expired")
        status="APPROVED" if approve else "DENIED"
        cursor=self.connection.execute(
            "UPDATE approvals SET status=? WHERE record_id=? AND status='PENDING'",
            (status, approval_id),
        )
        if cursor.rowcount != 1:
            self.connection.rollback(); raise ValidationError("Approval is not pending")
        self.connection.commit()
        self._audit(actor, "DECIDE_APPROVAL", "ALLOWED", reason, approval_id,
                    {"status":status})
        return status

    def consume_approval(
        self, actor: Actor, approval_id: str, *, action_type: str, target: str,
        at: str | None = None, scope: str | None = None, commit: bool = True,
    ) -> None:
        row = self.connection.execute("SELECT * FROM approvals WHERE record_id=?", (approval_id,)).fetchone()
        timestamp = at or now()
        reason = None
        if row is None:
            reason = "Approval not found"
        elif row["scope"] not in self.allowed_scopes or row["scope"] not in actor.scopes:
            reason = "Approval scope is not authorized for this actor or database"
        elif scope is not None and row["scope"] != scope:
            reason = "Approval scope does not match the action scope"
        elif row["status"] != "APPROVED":
            reason = f"Approval status is {row['status']}"
        elif row["action_type"] != action_type or row["target"] != target:
            reason = "Approval does not match exact action and target"
        elif timestamp >= row["expires_at"]:
            reason = "Approval expired"
        if reason:
            self._audit(actor, "CONSUME_APPROVAL", "DENIED", reason, approval_id,
                        {"action_type": action_type, "target": target})
            raise AuthorizationError(reason)
        if not row["reusable"]:
            self.connection.execute("UPDATE approvals SET status='CONSUMED' WHERE record_id=?", (approval_id,))
        self._audit(actor, "CONSUME_APPROVAL", "ALLOWED", "Exact active approval matched", approval_id,
                    {"action_type": action_type, "target": target}, commit=commit)

    def stage_alert_delivery(self, actor: Actor, plan_id: str) -> dict[str, Any]:
        observation=self.get_alert_observation(actor, plan_id)
        plan=observation["plan_payload"]
        scope=observation["owner_scope"]
        self._authorize(actor, scope, (), "write")
        if plan.get("delivery_authorized") is not False or plan.get("approval_required") is not True:
            raise ValidationError("Only approval-gated non-delivering plans may be staged")
        route=plan.get("route")
        if not isinstance(route, dict) or route.get("route_id") != observation["route_id"]:
            raise ValidationError("Alert delivery route evidence is invalid")
        if route.get("destination_kind") not in {"EMAIL", "WEBHOOK"}:
            raise ValidationError("Alert delivery destination kind is invalid")
        if not isinstance(route.get("destination_ref"), str) or not route["destination_ref"].strip():
            raise ValidationError("Alert delivery destination reference is invalid")
        incident_identity={
            "owner_scope":scope, "route_id":observation["route_id"],
            "alert_code":plan.get("alert", {}).get("code"),
        }
        incident_id=hashlib.sha256(
            json.dumps(incident_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        incident=self.get_alert_incident(actor, incident_id)
        if incident["status"] != "ACTIVE":
            raise ValidationError("Resolved incidents cannot stage alert delivery")
        generation=int(incident["reopen_count"])
        identity={"incident_id":incident_id, "reopen_generation":generation}
        delivery_id=hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        alert_payload=json.dumps(plan["alert"], sort_keys=True, separators=(",", ":"))
        payload_sha256=hashlib.sha256(alert_payload.encode("utf-8")).hexdigest()
        stamp=now()
        self.connection.execute(
            """INSERT OR IGNORE INTO alert_delivery_outbox
               (delivery_id, plan_id, incident_id, reopen_generation, owner_scope,
                route_id, destination_kind, destination_ref, alert_payload,
                payload_sha256, status, available_at, created_at, updated_at)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'STAGED', ?, ?, ?)""",
            (delivery_id, plan_id, incident_id, generation, scope,
             observation["route_id"], route.get("destination_kind"),
             route.get("destination_ref"), alert_payload, payload_sha256,
             stamp, stamp, stamp),
        )
        self.connection.commit()
        row=self.get_alert_delivery(actor, delivery_id)
        if row["plan_id"] != plan_id or row["payload_sha256"] != payload_sha256:
            raise ValidationError("Alert delivery identity collision or payload mutation")
        self._audit(actor, "STAGE_ALERT_DELIVERY", "ALLOWED",
                    "Durable delivery awaiting exact approval", delivery_id,
                    {"scope":scope, "plan_id":plan_id, "delivery_authorized":False})
        return row

    def get_alert_delivery(self, actor: Actor, delivery_id: str) -> dict[str, Any]:
        row=self.connection.execute(
            "SELECT * FROM alert_delivery_outbox WHERE delivery_id=?", (delivery_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert delivery not found")
        self._authorize(actor, row["owner_scope"], (), "read")
        result=dict(row); result["alert_payload"]=json.loads(result["alert_payload"])
        if result["receipt_payload"]:
            result["receipt_payload"]=json.loads(result["receipt_payload"])
        return result

    def list_alert_deliveries(
        self, actor: Actor, scope: str, *, status: str | None = None
    ) -> list[dict[str, Any]]:
        if scope not in {"PERSONAL", "IAC"}:
            raise ValidationError("Alert deliveries require PERSONAL or IAC scope")
        self._authorize(actor, scope, (), "read")
        allowed={"STAGED", "AUTHORIZED", "SYNTHETIC_DELIVERED", "FAILED"}
        if status is not None and status not in allowed:
            raise ValidationError("Unknown alert delivery status")
        sql="SELECT delivery_id FROM alert_delivery_outbox WHERE owner_scope=?"
        parameters: list[Any]=[scope]
        if status is not None:
            sql += " AND status=?"; parameters.append(status)
        sql += " ORDER BY created_at DESC, delivery_id"
        return [self.get_alert_delivery(actor, row["delivery_id"])
                for row in self.connection.execute(sql, parameters)]

    def request_alert_delivery_approval(
        self, actor: Actor, delivery_id: str, *, max_impact: str, expires_at: str
    ) -> str:
        delivery=self.get_alert_delivery(actor, delivery_id)
        self._authorize(actor, delivery["owner_scope"], (), "write")
        if delivery["status"] != "STAGED":
            raise ValidationError("Only staged deliveries may request approval")
        if not max_impact.strip():
            raise ValidationError("Alert delivery approval requires a bounded impact")
        existing=self.connection.execute(
            """SELECT record_id, max_impact, expires_at FROM approvals
               WHERE action_type='DELIVER_ALERT' AND target=? AND scope=? AND status='PENDING'
               ORDER BY record_id""",
            (delivery_id, delivery["owner_scope"]),
        ).fetchall()
        active=[]
        for approval in existing:
            if datetime.fromisoformat(approval["expires_at"]) <= datetime.now(timezone.utc):
                self.connection.execute(
                    "UPDATE approvals SET status='EXPIRED' WHERE record_id=?",
                    (approval["record_id"],),
                )
            else:
                active.append(approval)
        if len(active) != len(existing):
            self.connection.commit()
        existing=active
        if existing:
            if len(existing) == 1 and existing[0]["max_impact"] == max_impact and existing[0]["expires_at"] == expires_at:
                return existing[0]["record_id"]
            raise ValidationError("A different alert delivery approval request is already pending")
        return self.request_approval(
            actor, action_type="DELIVER_ALERT", target=delivery_id,
            scope=delivery["owner_scope"], max_impact=max_impact, expires_at=expires_at,
            conditions={"delivery_id":delivery_id, "payload_sha256":delivery["payload_sha256"]},
        )

    def authorize_alert_delivery(
        self, actor: Actor, delivery_id: str, *, approval_id: str
    ) -> dict[str, Any]:
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may authorize alert delivery")
        row=self.get_alert_delivery(actor, delivery_id)
        if row["status"] != "STAGED":
            if row["status"] == "AUTHORIZED" and row["approval_id"] == approval_id:
                return row
            raise ValidationError("Alert delivery is not awaiting approval")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.consume_approval(
                actor, approval_id, action_type="DELIVER_ALERT", target=delivery_id,
                scope=row["owner_scope"], commit=False,
            )
            cursor=self.connection.execute(
                """UPDATE alert_delivery_outbox SET status='AUTHORIZED', approval_id=?,
                   updated_at=? WHERE delivery_id=? AND status='STAGED'""",
                (approval_id, now(), delivery_id),
            )
            if cursor.rowcount != 1:
                raise ValidationError("Alert delivery authorization raced with another update")
            self._audit(actor, "AUTHORIZE_ALERT_DELIVERY", "ALLOWED",
                        "Exact delivery approval consumed", delivery_id,
                        {"scope":row["owner_scope"], "approval_id":approval_id}, commit=False)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_alert_delivery(actor, delivery_id)

    def record_synthetic_alert_delivery(
        self, actor: Actor, delivery_id: str, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        row=self.get_alert_delivery(actor, delivery_id)
        self._authorize(actor, row["owner_scope"], (), "write")
        if receipt.get("mode") != "SYNTHETIC" or receipt.get("network_used") is not False:
            raise ValidationError("Only no-network synthetic delivery receipts are accepted")
        if receipt.get("external_effect") is not False:
            raise ValidationError("Synthetic delivery receipt must prove no external effect")
        if receipt.get("delivery_id") != delivery_id or receipt.get("payload_sha256") != row["payload_sha256"]:
            raise ValidationError("Synthetic delivery receipt does not match staged payload")
        payload=json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        if row["status"] == "SYNTHETIC_DELIVERED":
            if row["receipt_payload"] == receipt:
                return row
            raise ValidationError("Alert delivery already has different receipt evidence")
        if row["status"] != "AUTHORIZED":
            raise AuthorizationError("Alert delivery lacks exact approval")
        stamp=now()
        self.connection.execute(
            """UPDATE alert_delivery_outbox SET status='SYNTHETIC_DELIVERED',
               attempt_count=attempt_count+1, receipt_payload=?, delivered_at=?, updated_at=?
               WHERE delivery_id=? AND status='AUTHORIZED'""",
            (payload, stamp, stamp, delivery_id),
        )
        self.connection.commit()
        self._audit(actor, "SYNTHETIC_DELIVER_ALERT", "ALLOWED",
                    "No-network synthetic adapter completed", delivery_id,
                    {"scope":row["owner_scope"], "network_used":False})
        return self.get_alert_delivery(actor, delivery_id)

    def claim_authorized_alert_delivery(
        self, actor: Actor, worker_id: str, *, lease_seconds: int = 30
    ) -> dict[str, Any] | None:
        if not worker_id.strip():
            raise ValidationError("Alert delivery worker ID is required")
        if lease_seconds < 1 or lease_seconds > 300:
            raise ValidationError("Alert delivery lease must be between 1 and 300 seconds")
        if self.kill_switch_enabled():
            self._audit(actor, "CLAIM_ALERT_DELIVERY", "DENIED", "Kill switch is ON")
            return None
        allowed_scopes=sorted(actor.scopes & self.allowed_scopes & {"PERSONAL", "IAC"})
        if not allowed_scopes:
            self._audit(actor, "CLAIM_ALERT_DELIVERY", "DENIED",
                        "Worker has no authorized delivery scope")
            return None
        stamp=now()
        lease=(datetime.now(timezone.utc)+timedelta(seconds=lease_seconds)).isoformat()
        placeholders=",".join("?" for _ in allowed_scopes)
        self.connection.execute("BEGIN IMMEDIATE")
        self.connection.execute(
            f"""UPDATE alert_delivery_outbox SET status='FAILED',
                   last_error='Lease expired after maximum attempts', updated_at=?,
                   lease_owner=NULL, lease_expires_at=NULL
                   WHERE status='AUTHORIZED' AND attempt_count>=max_attempts
                   AND (lease_owner IS NULL OR lease_expires_at<=?)
                   AND owner_scope IN ({placeholders})""",
            (stamp, stamp, *allowed_scopes),
        )
        row=self.connection.execute(
            f"""SELECT delivery_id FROM alert_delivery_outbox
                WHERE status='AUTHORIZED' AND available_at<=?
                AND attempt_count<max_attempts
                AND (lease_owner IS NULL OR lease_expires_at<=?)
                AND owner_scope IN ({placeholders})
                ORDER BY created_at, delivery_id LIMIT 1""",
            (stamp, stamp, *allowed_scopes),
        ).fetchone()
        if row is None:
            self.connection.commit(); return None
        cursor=self.connection.execute(
            """UPDATE alert_delivery_outbox SET lease_owner=?, lease_expires_at=?,
               attempt_count=attempt_count+1, updated_at=?
               WHERE delivery_id=? AND status='AUTHORIZED'
               AND (lease_owner IS NULL OR lease_expires_at<=?)""",
            (worker_id, lease, stamp, row["delivery_id"], stamp),
        )
        if cursor.rowcount != 1:
            self.connection.rollback(); return None
        self.connection.commit()
        claimed=self.get_alert_delivery(actor, row["delivery_id"])
        self._audit(actor, "CLAIM_ALERT_DELIVERY", "ALLOWED",
                    "Authorized synthetic delivery lease acquired", row["delivery_id"],
                    {"scope":claimed["owner_scope"], "worker_id":worker_id,
                     "attempt":claimed["attempt_count"], "network_used":False})
        return claimed

    def complete_claimed_synthetic_alert_delivery(
        self, actor: Actor, delivery_id: str, worker_id: str, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        if self.kill_switch_enabled():
            raise AuthorizationError("Kill switch is ON; delivery completion denied")
        row=self.connection.execute(
            "SELECT * FROM alert_delivery_outbox WHERE delivery_id=?", (delivery_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert delivery not found")
        self._authorize(actor, row["owner_scope"], (), "write")
        if receipt.get("mode") != "SYNTHETIC" or receipt.get("network_used") is not False:
            raise ValidationError("Only no-network synthetic delivery receipts are accepted")
        if receipt.get("external_effect") is not False:
            raise ValidationError("Synthetic delivery receipt must prove no external effect")
        if receipt.get("delivery_id") != delivery_id or receipt.get("payload_sha256") != row["payload_sha256"]:
            raise ValidationError("Synthetic delivery receipt does not match staged payload")
        if secret_findings(receipt):
            raise ValidationError("Secret-like material is prohibited in delivery receipts")
        payload=json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        if row["status"] == "SYNTHETIC_DELIVERED":
            existing=json.loads(row["receipt_payload"]) if row["receipt_payload"] else None
            if existing == receipt:
                return self.get_alert_delivery(actor, delivery_id)
            raise ValidationError("Alert delivery already has different receipt evidence")
        cursor=self.connection.execute(
            """UPDATE alert_delivery_outbox SET status='SYNTHETIC_DELIVERED',
               receipt_payload=?, delivered_at=?, updated_at=?, lease_owner=NULL,
               lease_expires_at=NULL, last_error=NULL
               WHERE delivery_id=? AND status='AUTHORIZED' AND lease_owner=?""",
            (payload, receipt.get("delivered_at"), now(), delivery_id, worker_id),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            raise AuthorizationError("Worker does not hold the active alert delivery lease")
        self.connection.commit()
        self._audit(actor, "COMPLETE_ALERT_DELIVERY", "ALLOWED",
                    "Leased no-network synthetic delivery completed", delivery_id,
                    {"scope":row["owner_scope"], "worker_id":worker_id,
                     "network_used":False, "external_effect":False})
        return self.get_alert_delivery(actor, delivery_id)

    def fail_claimed_alert_delivery(
        self, actor: Actor, delivery_id: str, worker_id: str, error: str, *,
        retry_seconds: int = 5,
    ) -> str:
        if not error.strip():
            raise ValidationError("Alert delivery failure requires an error")
        if secret_findings({"error":error}):
            raise ValidationError("Secret-like material is prohibited in delivery failures")
        if retry_seconds < 0 or retry_seconds > 3600:
            raise ValidationError("Alert delivery retry must be between 0 and 3600 seconds")
        row=self.connection.execute(
            """SELECT owner_scope, attempt_count, max_attempts FROM alert_delivery_outbox
               WHERE delivery_id=? AND status='AUTHORIZED' AND lease_owner=?""",
            (delivery_id, worker_id),
        ).fetchone()
        if row is None:
            raise AuthorizationError("Worker does not hold the active alert delivery lease")
        self._authorize(actor, row["owner_scope"], (), "write")
        terminal=row["attempt_count"] >= row["max_attempts"]
        status="FAILED" if terminal else "AUTHORIZED"
        available=(datetime.now(timezone.utc)+timedelta(seconds=retry_seconds)).isoformat()
        self.connection.execute(
            """UPDATE alert_delivery_outbox SET status=?, available_at=?, lease_owner=NULL,
               lease_expires_at=NULL, last_error=?, updated_at=? WHERE delivery_id=?""",
            (status, available, error, now(), delivery_id),
        )
        self.connection.commit()
        self._audit(actor, "FAIL_ALERT_DELIVERY", "FAILED", error, delivery_id,
                    {"scope":row["owner_scope"], "worker_id":worker_id,
                     "next_status":status, "network_used":False})
        return status

    def transition_project(
        self, actor: Actor, record_id: str, state: str, reason: str, *,
        reopen_trigger: str | None = None, review_at: str | None = None,
    ) -> None:
        record = self.get_record(actor, record_id)
        state = state.upper()
        if record["entity_type"] != "PROJECT":
            raise ValidationError("Only PROJECT records have lifecycle state")
        if state not in PROJECT_STATES:
            raise ValidationError(f"Unknown project state: {state}")
        if not reason.strip():
            raise ValidationError("Lifecycle changes require a reason")
        if state == "KILLED" and not (reopen_trigger or "").strip():
            raise ValidationError("KILLED projects require a reopen trigger")
        self.connection.execute(
            """UPDATE project_state SET state=?, reason=?, review_at=?, reopen_trigger=?, changed_at=?
               WHERE record_id=?""",
            (state, reason, review_at, reopen_trigger, now(), record_id),
        )
        self.connection.commit()
        self._audit(actor, "TRANSITION_PROJECT", "ALLOWED", reason, record_id, {"state": state})

    def sale_export(self, actor: Actor) -> list[dict[str, Any]]:
        if not actor.is_sean and "IAC" not in actor.scopes:
            self._audit(actor, "SALE_EXPORT", "DENIED", "IAC scope required")
            raise AuthorizationError("IAC scope required for sale export")
        rows = self.connection.execute(
            """SELECT * FROM records
               WHERE (owner_scope='IAC' AND portable_on_sale=1)
                  OR (owner_scope='SHARED' AND portable_on_sale=1)
               ORDER BY created_at, id"""
        ).fetchall()
        output=[]
        for row in rows:
            item=dict(row); item["payload"]=json.loads(item["payload"])
            item["permitted_principals"]=json.loads(item["permitted_principals"])
            output.append(item)
        findings=secret_findings(output)
        if findings:
            self._audit(actor, "SALE_EXPORT", "DENIED", "Secret scan blocked export",
                        details={"finding_paths":[item["path"] for item in findings]})
            raise AuthorizationError("Sale export blocked by secret scan")
        self._audit(actor, "SALE_EXPORT", "ALLOWED", "Portable IAC/explicit SHARED only",
                    details={"record_count": len(output), "secret_scan_passed":True})
        return output

    def sale_export_package(self, actor: Actor) -> dict[str, Any]:
        records = self.sale_export(actor)
        serialized = json.dumps(records, sort_keys=True, separators=(",", ":"))
        return {
            "format": "sean-os-iac-sale-export/v1",
            "generated_at": now(),
            "record_count": len(records),
            "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            "secret_scan_passed": True,
            "secret_finding_count": 0,
            "records": records,
        }

    def backup(self, actor: Actor, destination: str | Path) -> Path:
        if not actor.is_sean:
            self._audit(actor, "BACKUP", "DENIED", "Only Sean may create a full local backup")
            raise AuthorizationError("Only Sean may create a full local backup")
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(target) as backup_connection:
            self.connection.backup(backup_connection)
        self._audit(actor, "BACKUP", "ALLOWED", "Verified local SQLite backup created",
                    details={"destination": str(target)})
        return target

    def backup_manifest(self, actor: Actor, destination: str | Path) -> dict[str, Any]:
        target=self.backup(actor, destination)
        with sqlite3.connect(target) as check:
            integrity=check.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys=[tuple(row) for row in check.execute("PRAGMA foreign_key_check")]
            version=check.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        digest=hashlib.sha256(target.read_bytes()).hexdigest()
        manifest={"path":str(target), "sha256":digest, "bytes":target.stat().st_size,
                  "schema_version":version, "integrity_ok":integrity == "ok" and not foreign_keys}
        if not manifest["integrity_ok"] or version != LATEST_SCHEMA_VERSION:
            raise sqlite3.DatabaseError("Backup verification failed")
        self._audit(actor, "VERIFY_BACKUP", "ALLOWED", "Backup integrity and schema verified",
                    details=manifest)
        return manifest

    def restore_backup(self, actor: Actor, source: str | Path, destination: str | Path) -> Path:
        if not actor.is_sean:
            self._audit(actor, "RESTORE_BACKUP", "DENIED", "Only Sean may restore a full backup")
            raise AuthorizationError("Only Sean may restore a full backup")
        source_path=Path(source); target=Path(destination)
        if target.exists():
            raise ValidationError("Restore destination must not already exist")
        if not source_path.is_file():
            raise ValidationError("Backup source does not exist")
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(f"file:{source_path}?mode=ro", uri=True) as source_connection:
                if source_connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise sqlite3.DatabaseError("Source backup failed integrity check")
                version=source_connection.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                if version != LATEST_SCHEMA_VERSION:
                    raise sqlite3.DatabaseError("Source backup schema version is unsupported")
                profile=source_connection.execute(
                    "SELECT value FROM runtime_state WHERE key='scope_profile'"
                ).fetchone()[0]
                with sqlite3.connect(target) as target_connection:
                    source_connection.backup(target_connection)
            restored=SeanOSStore(target, scope_profile=profile)
            result=restored.integrity_check(); restored.close()
            if not result["ok"]:
                raise sqlite3.DatabaseError("Restored database failed integrity check")
        except Exception:
            if target.exists():
                target.unlink()
            raise
        self._audit(actor, "RESTORE_BACKUP", "ALLOWED", "Backup restored and verified",
                    details={"source":str(source_path), "destination":str(target)})
        return target

    def integrity_check(self) -> dict[str, Any]:
        database = self.connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = [tuple(row) for row in self.connection.execute("PRAGMA foreign_key_check")]
        return {
            "database": database,
            "foreign_key_violations": foreign_keys,
            "ok": database == "ok" and not foreign_keys,
        }

    def set_kill_switch(self, actor: Actor, enabled: bool) -> None:
        if not actor.is_sean:
            self._audit(actor, "SET_KILL_SWITCH", "DENIED", "Only Sean controls the kill switch")
            raise AuthorizationError("Only Sean controls the kill switch")
        value = "ON" if enabled else "OFF"
        self.connection.execute(
            "UPDATE runtime_state SET value=?, updated_at=? WHERE key='kill_switch'", (value, now())
        )
        self.connection.commit()
        self._audit(actor, "SET_KILL_SWITCH", "ALLOWED", f"Kill switch {value}")

    def kill_switch_enabled(self) -> bool:
        return self.connection.execute(
            "SELECT value FROM runtime_state WHERE key='kill_switch'"
        ).fetchone()[0] == "ON"

    def configure_budget(self, actor: Actor, scope: str, limit_units: float, *, period_key: str | None = None) -> None:
        if not actor.is_sean:
            self._audit(actor, "CONFIGURE_BUDGET", "DENIED", "Only Sean configures budgets")
            raise AuthorizationError("Only Sean configures budgets")
        if scope not in SCOPES or limit_units < 0:
            raise ValidationError("Valid scope and non-negative limit required")
        period=period_key or current_period()
        self.connection.execute(
            """INSERT INTO budgets(owner_scope, period_key, limit_units, updated_at)
               VALUES(?, ?, ?, ?)
               ON CONFLICT(owner_scope, period_key)
               DO UPDATE SET limit_units=excluded.limit_units, updated_at=excluded.updated_at""",
            (scope, period, limit_units, now()),
        )
        self.connection.commit()
        self._audit(actor, "CONFIGURE_BUDGET", "ALLOWED", "Budget limit configured",
                    details={"scope": scope, "period": period, "limit_units": limit_units})

    def budget_status(self, scope: str, *, period_key: str | None = None) -> dict[str, Any] | None:
        row=self.connection.execute(
            "SELECT * FROM budgets WHERE owner_scope=? AND period_key=?",
            (scope, period_key or current_period()),
        ).fetchone()
        if row is None: return None
        result=dict(row); result["available_units"]=max(0, result["limit_units"]-result["used_units"]-result["reserved_units"])
        return result

    def heartbeat(
        self, worker_id: str, scope: str, status: str, *, current_work_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.connection.execute(
            """INSERT INTO worker_heartbeats
               (worker_id, owner_scope, status, current_work_id, last_seen_at, details)
               VALUES(?, ?, ?, ?, ?, ?)
               ON CONFLICT(worker_id) DO UPDATE SET owner_scope=excluded.owner_scope,
               status=excluded.status, current_work_id=excluded.current_work_id,
               last_seen_at=excluded.last_seen_at, details=excluded.details""",
            (worker_id, scope, status, current_work_id, now(), json.dumps(details or {}, sort_keys=True)),
        )
        self.connection.commit()

    def runtime_health(
        self, *, stale_after_seconds: int = 90, require_active_worker: bool = False,
        scope: str | None = None,
    ) -> dict[str, Any]:
        if scope is not None:
            scope=scope.upper()
            if scope not in SCOPES:
                raise ValidationError("Runtime health scope is invalid")
            if scope not in self.allowed_scopes:
                raise AuthorizationError(
                    f"{scope} is outside the database's {self.scope_profile} scope profile"
                )
        cutoff=(datetime.now(timezone.utc)-timedelta(seconds=stale_after_seconds)).isoformat()
        worker_sql="SELECT * FROM worker_heartbeats"
        worker_parameters: tuple[Any, ...]=()
        if scope is not None:
            worker_sql += " WHERE owner_scope=?"; worker_parameters=(scope,)
        worker_sql += " ORDER BY worker_id"
        workers=[dict(r) for r in self.connection.execute(worker_sql, worker_parameters)]
        for worker in workers:
            worker["stale"]=worker["status"] not in {"STOPPED"} and worker["last_seen_at"] < cutoff
            worker["details"]=json.loads(worker["details"])
        queue_sql="SELECT status, COUNT(*) AS count FROM work_queue"
        queue_parameters: tuple[Any, ...]=()
        if scope is not None:
            queue_sql += " WHERE owner_scope=?"; queue_parameters=(scope,)
        queue_sql += " GROUP BY status"
        counts={r["status"]: r["count"] for r in self.connection.execute(
            queue_sql, queue_parameters
        )}
        delivery_sql="SELECT status, COUNT(*) AS count FROM alert_delivery_outbox"
        delivery_parameters: tuple[Any, ...]=()
        if scope is not None:
            delivery_sql += " WHERE owner_scope=?"; delivery_parameters=(scope,)
        delivery_sql += " GROUP BY status"
        delivery_counts={r["status"]:r["count"] for r in self.connection.execute(
            delivery_sql, delivery_parameters
        )}
        budget_scopes=(scope,) if scope is not None else tuple(sorted(self.allowed_scopes))
        budgets=[self.budget_status(item_scope) for item_scope in budget_scopes]
        integrity=self.integrity_check()
        active_workers=[w for w in workers if w["status"] != "STOPPED" and not w["stale"]]
        healthy=(integrity["ok"] and not self.kill_switch_enabled()
                 and not any(w["stale"] for w in workers)
                 and counts.get("DEAD_LETTER", 0) == 0
                 and counts.get("POLICY_BLOCKED", 0) == 0
                 and delivery_counts.get("FAILED", 0) == 0
                 and (not require_active_worker or bool(active_workers)))
        needs_attention=sum(
            counts.get(status, 0)
            for status in ("APPROVAL_BLOCKED", "BUDGET_BLOCKED", "POLICY_BLOCKED", "DEAD_LETTER")
        )
        needs_attention += delivery_counts.get("FAILED", 0)
        return {"healthy": healthy, "kill_switch": self.kill_switch_enabled(),
                "integrity": integrity, "queue": counts, "workers": workers,
                "delivery_outbox":delivery_counts,
                "budgets": [b for b in budgets if b is not None],
                "needs_attention": needs_attention,
                "active_worker_count": len(active_workers)}

    def record_alert_observation(self, actor: Actor, plan: dict[str, Any]) -> dict[str, Any]:
        """Persist or count a scope-authorized, non-delivering alert plan."""
        scope=plan.get("owner_scope"); plan_id=plan.get("plan_id")
        if scope not in {"PERSONAL", "IAC"}:
            raise ValidationError("Alert observation requires PERSONAL or IAC scope")
        self._authorize(actor, scope, (), "write")
        if not isinstance(plan_id, str) or len(plan_id) != 64:
            raise ValidationError("Alert observation requires deterministic plan_id")
        if plan.get("delivery_authorized") is not False:
            raise ValidationError("Only non-delivering alert plans may be recorded")
        findings=secret_findings(plan)
        if findings:
            raise ValidationError("Secret-like material is prohibited in alert evidence")
        route_id=plan.get("action_target"); alert=plan.get("alert")
        if not isinstance(route_id, str) or not route_id.strip():
            raise ValidationError("Alert observation requires a route ID")
        if not isinstance(alert, dict):
            raise ValidationError("Alert observation requires alert evidence")
        code=alert.get("code"); severity=alert.get("severity"); summary=alert.get("summary")
        if not all(isinstance(value, str) and value.strip() for value in (code, summary)):
            raise ValidationError("Alert code and summary are required")
        if severity not in {"ATTENTION", "HIGH", "CRITICAL"}:
            raise ValidationError("Alert severity is unsupported")
        incident_identity={"owner_scope":scope, "route_id":route_id, "alert_code":code}
        incident_id=hashlib.sha256(
            json.dumps(incident_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        payload=json.dumps(plan, sort_keys=True, separators=(",", ":"))
        existing=self.connection.execute(
            "SELECT plan_payload FROM alert_observations WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if existing and existing["plan_payload"] != payload:
            raise ValidationError("Alert plan_id collision or payload mutation")
        stamp=now()
        prior_incident=self.connection.execute(
            "SELECT status FROM alert_incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        reopened=bool(prior_incident and prior_incident["status"] == "RESOLVED")
        self.connection.execute(
            """INSERT INTO alert_observations
               (plan_id, owner_scope, route_id, plan_payload, first_seen_at, last_seen_at)
               VALUES(?, ?, ?, ?, ?, ?)
               ON CONFLICT(plan_id) DO UPDATE SET
               last_seen_at=excluded.last_seen_at,
               occurrence_count=alert_observations.occurrence_count+1""",
            (plan_id, scope, route_id, payload, stamp, stamp),
        )
        self.connection.execute(
            """INSERT INTO alert_incidents
               (incident_id, owner_scope, route_id, alert_code, severity,
                current_summary, status, first_seen_at, last_seen_at)
               VALUES(?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
               ON CONFLICT(incident_id) DO UPDATE SET
               severity=excluded.severity,
               current_summary=excluded.current_summary,
               status='ACTIVE',
               last_seen_at=excluded.last_seen_at,
               occurrence_count=alert_incidents.occurrence_count+1,
               reopen_count=alert_incidents.reopen_count +
                   CASE WHEN alert_incidents.status='RESOLVED' THEN 1 ELSE 0 END,
               resolved_at=NULL, resolved_by=NULL, resolution_reason=NULL""",
            (incident_id, scope, route_id, code, severity, summary, stamp, stamp),
        )
        self.connection.commit()
        self._audit(actor, "RECORD_ALERT_OBSERVATION", "ALLOWED",
                    "Scoped non-delivering alert evidence recorded", plan_id,
                    {"scope":scope, "route_id":route_id, "incident_id":incident_id,
                     "incident_reopened":reopened})
        result=self.get_alert_observation(actor, plan_id)
        result["incident"]=self.get_alert_incident(actor, incident_id)
        return result

    def get_alert_incident(self, actor: Actor, incident_id: str) -> dict[str, Any]:
        row=self.connection.execute(
            "SELECT * FROM alert_incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert incident not found")
        self._authorize(actor, row["owner_scope"], (), "read")
        return dict(row)

    def active_alert_incidents(self, actor: Actor, scope: str) -> list[dict[str, Any]]:
        if scope not in {"PERSONAL", "IAC"}:
            raise ValidationError("Alert incidents require PERSONAL or IAC scope")
        self._authorize(actor, scope, (), "read")
        return [dict(row) for row in self.connection.execute(
            """SELECT * FROM alert_incidents WHERE owner_scope=? AND status='ACTIVE'
               ORDER BY CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 ELSE 1 END DESC,
               last_seen_at DESC, incident_id""",
            (scope,),
        )]

    def resolve_alert_incident(
        self, actor: Actor, incident_id: str, *, reason: str
    ) -> dict[str, Any]:
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may resolve an alert incident in v0.1")
        if not reason.strip():
            raise ValidationError("Alert resolution requires a reason")
        if secret_findings({"reason":reason}):
            raise ValidationError("Secret-like material is prohibited in resolution evidence")
        row=self.connection.execute(
            "SELECT * FROM alert_incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert incident not found")
        if row["status"] != "ACTIVE":
            if row["resolved_by"] == actor.id and row["resolution_reason"] == reason:
                self._audit(actor, "RESOLVE_ALERT_INCIDENT", "ALLOWED",
                            "Idempotent resolution replay", incident_id,
                            {"scope":row["owner_scope"], "outcome":"ALREADY_RESOLVED"})
                return dict(row)
            raise ValidationError("Alert incident is already resolved with different evidence")
        stamp=now()
        self.connection.execute(
            """UPDATE alert_incidents SET status='RESOLVED', resolved_at=?,
               resolved_by=?, resolution_reason=? WHERE incident_id=?""",
            (stamp, actor.id, reason, incident_id),
        )
        self.connection.commit()
        self._audit(actor, "RESOLVE_ALERT_INCIDENT", "ALLOWED",
                    reason, incident_id, {"scope":row["owner_scope"], "outcome":"RESOLVED"})
        return self.get_alert_incident(actor, incident_id)

    def get_alert_observation(self, actor: Actor, plan_id: str) -> dict[str, Any]:
        row=self.connection.execute(
            "SELECT * FROM alert_observations WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert observation not found")
        self._authorize(actor, row["owner_scope"], (), "read")
        result=dict(row); result["plan_payload"]=json.loads(result["plan_payload"])
        if result["acknowledgement_payload"]:
            result["acknowledgement_payload"]=json.loads(result["acknowledgement_payload"])
        return result

    def acknowledge_alert_observation(
        self, actor: Actor, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        """Attach one immutable acknowledgement receipt; delivery remains unauthorized."""
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may acknowledge an escalation in v0.1")
        plan_id=receipt.get("plan_id")
        row=self.connection.execute(
            "SELECT * FROM alert_observations WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ValidationError("Alert observation not found")
        if receipt.get("owner_scope") != row["owner_scope"]:
            raise ValidationError("Acknowledgement scope mismatch")
        if receipt.get("delivery_authorized") is not False:
            raise ValidationError("Acknowledgement cannot authorize delivery")
        payload=json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        if row["acknowledgement_payload"] and row["acknowledgement_payload"] != payload:
            raise ValidationError("Alert observation is already acknowledged")
        self.connection.execute(
            """UPDATE alert_observations SET acknowledgement_payload=?,
               acknowledged_at=?, acknowledged_by=? WHERE plan_id=?""",
            (payload, receipt.get("acknowledged_at"), receipt.get("acknowledged_by"), plan_id),
        )
        self.connection.commit()
        self._audit(actor, "ACKNOWLEDGE_ALERT", "ALLOWED",
                    "Immutable local acknowledgement attached", plan_id,
                    {"scope":row["owner_scope"], "delivery_authorized":False})
        return self.get_alert_observation(actor, plan_id)

    def _reserve_cost(self, work: sqlite3.Row) -> bool:
        payload=json.loads(work["payload"]); units=float(payload.get("estimated_cost_units", 0))
        if units <= 0: return True
        existing=self.connection.execute(
            "SELECT 1 FROM cost_reservations WHERE work_id=?", (work["id"],)
        ).fetchone()
        if existing:
            return True
        period=current_period()
        budget=self.connection.execute(
            "SELECT * FROM budgets WHERE owner_scope=? AND period_key=?",
            (work["owner_scope"], period),
        ).fetchone()
        if budget is None or budget["used_units"] + budget["reserved_units"] + units > budget["limit_units"]:
            self.connection.execute(
                "UPDATE work_queue SET status='BUDGET_BLOCKED', last_error=?, updated_at=? WHERE id=?",
                ("No configured budget or insufficient available units", now(), work["id"]),
            )
            return False
        self.connection.execute(
            "UPDATE budgets SET reserved_units=reserved_units+?, updated_at=? WHERE owner_scope=? AND period_key=?",
            (units, now(), work["owner_scope"], period),
        )
        self.connection.execute(
            "INSERT INTO cost_reservations(work_id, owner_scope, period_key, units, created_at) VALUES(?, ?, ?, ?, ?)",
            (work["id"], work["owner_scope"], period, units, now()),
        )
        return True

    def _settle_cost(self, work_id: str, *, consume: bool) -> None:
        row=self.connection.execute("SELECT * FROM cost_reservations WHERE work_id=?", (work_id,)).fetchone()
        if row is None: return
        if consume:
            self.connection.execute(
                """UPDATE budgets SET reserved_units=reserved_units-?, used_units=used_units+?, updated_at=?
                   WHERE owner_scope=? AND period_key=?""",
                (row["units"], row["units"], now(), row["owner_scope"], row["period_key"]),
            )
            self.connection.execute(
                "INSERT INTO usage_events(id, work_id, owner_scope, period_key, units, occurred_at) VALUES(?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), work_id, row["owner_scope"], row["period_key"], row["units"], now()),
            )
        else:
            self.connection.execute(
                "UPDATE budgets SET reserved_units=reserved_units-?, updated_at=? WHERE owner_scope=? AND period_key=?",
                (row["units"], now(), row["owner_scope"], row["period_key"]),
            )
        self.connection.execute("DELETE FROM cost_reservations WHERE work_id=?", (work_id,))

    def enqueue_work(
        self, actor: Actor, task_type: str, scope: str, payload: dict[str, Any], *,
        priority: int = 100, max_attempts: int = 3, available_at: str | None = None,
    ) -> str:
        self._authorize(actor, scope, (), "write")
        if max_attempts < 1 or max_attempts > 10:
            raise ValidationError("max_attempts must be between 1 and 10")
        work_id=str(uuid.uuid4()); stamp=now()
        self.connection.execute(
            """INSERT INTO work_queue
               (id, task_type, owner_scope, payload, status, priority, max_attempts,
                available_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?)""",
            (work_id, task_type, scope, json.dumps(payload, sort_keys=True), priority,
             max_attempts, available_at or stamp, stamp, stamp),
        )
        self.connection.commit()
        self._audit(actor, "ENQUEUE_WORK", "ALLOWED", "Authorized durable work item", work_id,
                    {"task_type": task_type, "scope": scope})
        return work_id

    def claim_work(self, actor: Actor, worker_id: str, *, lease_seconds: int = 60) -> dict[str, Any] | None:
        if self.kill_switch_enabled():
            self._audit(actor, "CLAIM_WORK", "DENIED", "Kill switch is ON")
            return None
        stamp=now(); lease=(datetime.now(timezone.utc)+timedelta(seconds=lease_seconds)).isoformat()
        self.connection.execute("BEGIN IMMEDIATE")
        allowed_scopes=sorted(SCOPES if actor.is_sean else actor.scopes & SCOPES)
        if not allowed_scopes:
            self.connection.commit()
            self._audit(actor, "CLAIM_WORK", "DENIED", "Worker has no authorized scopes")
            return None
        placeholders=",".join("?" for _ in allowed_scopes)
        query = f"""SELECT * FROM work_queue
                    WHERE ((status='QUEUED' AND available_at<=?)
                        OR (status='RUNNING' AND lease_expires_at<=?))
                    AND owner_scope IN ({placeholders})
                    ORDER BY priority ASC, created_at ASC LIMIT 1"""
        row=self.connection.execute(query, (stamp, stamp, *allowed_scopes)).fetchone()
        if row is None:
            self.connection.commit(); return None
        if not self._reserve_cost(row):
            self.connection.commit()
            self._audit(actor, "CLAIM_WORK", "DENIED", "Budget unavailable", row["id"])
            return None
        self.connection.execute(
            """UPDATE work_queue SET status='RUNNING', lease_owner=?, lease_expires_at=?,
               attempts=attempts+1, updated_at=? WHERE id=?""",
            (worker_id, lease, stamp, row["id"]),
        )
        self.connection.commit()
        claimed=dict(self.connection.execute("SELECT * FROM work_queue WHERE id=?", (row["id"],)).fetchone())
        claimed["payload"]=json.loads(claimed["payload"])
        self._audit(actor, "CLAIM_WORK", "ALLOWED", "Durable lease acquired", row["id"],
                    {"worker_id": worker_id, "attempt": claimed["attempts"]})
        return claimed

    def block_work(
        self, actor: Actor, work_id: str, worker_id: str, reason: str, *,
        approval_required: bool = False,
    ) -> str:
        status="APPROVAL_BLOCKED" if approval_required else "POLICY_BLOCKED"
        cursor=self.connection.execute(
            """UPDATE work_queue SET status=?, lease_owner=NULL, lease_expires_at=NULL,
               last_error=?, updated_at=?
               WHERE id=? AND status='RUNNING' AND lease_owner=?""",
            (status, reason, now(), work_id, worker_id),
        )
        if cursor.rowcount != 1:
            self.connection.rollback(); raise AuthorizationError("Worker does not hold the active lease")
        self._settle_cost(work_id, consume=False); self.connection.commit()
        self._audit(actor, "BLOCK_WORK", "DENIED", reason, work_id,
                    {"worker_id": worker_id, "next_status": status})
        return status

    def record_policy_decision(
        self, actor: Actor, work_id: str | None, allowed: bool, reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._audit(
            actor, "POLICY_DECISION", "ALLOWED" if allowed else "DENIED",
            reason, work_id, details or {},
        )

    def completed_action_result(self, work_id: str, task_type: str) -> dict[str, Any] | None:
        row=self.connection.execute(
            "SELECT task_type, result FROM action_executions WHERE work_id=?", (work_id,)
        ).fetchone()
        if row is None:
            return None
        if row["task_type"] != task_type:
            raise ValidationError("Work ID was previously executed as a different action type")
        return json.loads(row["result"])

    def record_action_result(
        self, actor: Actor, work_id: str, task_type: str, result: dict[str, Any],
    ) -> None:
        work=self.connection.execute("SELECT payload FROM work_queue WHERE id=?", (work_id,)).fetchone()
        payload=json.loads(work["payload"]) if work else {}
        cost=float(payload.get("estimated_cost_units", 0)) if isinstance(payload, dict) else 0
        self.connection.execute(
            """INSERT OR IGNORE INTO action_executions(work_id, task_type, result, completed_at)
               VALUES (?, ?, ?, ?)""",
            (work_id, task_type, json.dumps(result, sort_keys=True), now()),
        )
        self.connection.commit()
        self._audit(actor, "RECORD_ACTION_RESULT", "ALLOWED", "Durable execution receipt stored",
                    work_id, {"task_type":task_type, "tool":"registered_handler",
                              "cost_units":cost, "outcome":"SUCCEEDED",
                              "rollback_status":"AVAILABLE"})

    def complete_work(self, actor: Actor, work_id: str, worker_id: str, result: dict[str, Any]) -> None:
        reservation=self.connection.execute(
            "SELECT units FROM cost_reservations WHERE work_id=?", (work_id,)
        ).fetchone()
        cost=float(reservation["units"]) if reservation else 0
        cursor=self.connection.execute(
            """UPDATE work_queue SET status='SUCCEEDED', payload=?, lease_owner=NULL,
               lease_expires_at=NULL, updated_at=?
               WHERE id=? AND status='RUNNING' AND lease_owner=?""",
            (json.dumps(result, sort_keys=True), now(), work_id, worker_id),
        )
        if cursor.rowcount != 1:
            self.connection.rollback(); raise AuthorizationError("Worker does not hold the active lease")
        self._settle_cost(work_id, consume=True); self.connection.commit()
        self._audit(actor, "COMPLETE_WORK", "ALLOWED", "Work succeeded", work_id,
                    {"worker_id": worker_id, "cost_units":cost, "outcome":"SUCCEEDED",
                     "rollback_status":"AVAILABLE"})

    def fail_work(self, actor: Actor, work_id: str, worker_id: str, error: str, *, retry_seconds: int = 5) -> str:
        row=self.connection.execute(
            "SELECT attempts, max_attempts FROM work_queue WHERE id=? AND status='RUNNING' AND lease_owner=?",
            (work_id, worker_id),
        ).fetchone()
        if row is None:
            raise AuthorizationError("Worker does not hold the active lease")
        terminal=row["attempts"] >= row["max_attempts"]
        status="DEAD_LETTER" if terminal else "QUEUED"
        available=(datetime.now(timezone.utc)+timedelta(seconds=retry_seconds)).isoformat()
        self.connection.execute(
            """UPDATE work_queue SET status=?, available_at=?, lease_owner=NULL,
               lease_expires_at=NULL, last_error=?, updated_at=? WHERE id=?""",
            (status, available, error, now(), work_id),
        )
        self._settle_cost(work_id, consume=False); self.connection.commit()
        self._audit(actor, "FAIL_WORK", "FAILED", error, work_id,
                    {"worker_id": worker_id, "next_status": status})
        return status

    def audit_events(self) -> list[dict[str, Any]]:
        events=[]
        for row in self.connection.execute("SELECT * FROM audit_log ORDER BY sequence"):
            event=dict(row); event["details"]=json.loads(event["details"]); events.append(event)
        return events

    def scoped_audit_events(self, actor: Actor, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValidationError("Audit limit must be between 1 and 1000")
        visible=[]
        for event in reversed(self.audit_events()):
            allowed=actor.is_sean or event["actor_id"] == actor.id
            affected=event["affected_record_id"]
            if not allowed and affected:
                record=self.connection.execute(
                    "SELECT owner_scope, permitted_principals FROM records WHERE id=?", (affected,)
                ).fetchone()
                if record:
                    principals=json.loads(record["permitted_principals"])
                    try:
                        self._authorize(actor, record["owner_scope"], principals, "read")
                        allowed=True
                    except AuthorizationError:
                        pass
                else:
                    work=self.connection.execute(
                        "SELECT owner_scope FROM work_queue WHERE id=?", (affected,)
                    ).fetchone()
                    if work and work["owner_scope"] in actor.scopes:
                        allowed=True
            if allowed:
                visible.append(event)
            if len(visible) >= limit:
                break
        return list(reversed(visible))
