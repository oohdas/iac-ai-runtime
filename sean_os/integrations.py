from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .store import Actor, AuthorizationError, SeanOSStore, ValidationError, now


@dataclass(frozen=True)
class ImportEnvelope:
    external_id: str
    content: str
    source_uri: str
    captured_at: str
    synthetic: bool
    metadata: dict[str, Any]


class ConnectorGate:
    def __init__(self, store: SeanOSStore):
        self.store=store

    def configure(self, actor: Actor, connector_name: str, *, enabled: bool, mode: str) -> None:
        if not actor.is_sean:
            raise AuthorizationError("Only Sean may configure integration gates")
        name=connector_name.upper(); mode=mode.upper()
        supported={row["connector_name"] for row in self.store.connection.execute(
            "SELECT connector_name FROM connector_config"
        )}
        if name not in supported:
            raise ValidationError("Unknown connector")
        if mode not in {"SYNTHETIC_ONLY", "LIVE"}:
            raise ValidationError("Unknown connector mode")
        if enabled and (mode == "LIVE" or name != "CLAUDE_IMPORT"):
            raise AuthorizationError("Only synthetic Claude import may be enabled in v0.1")
        self.store.connection.execute(
            """UPDATE connector_config SET enabled=?, mode=?, updated_at=?, updated_by=?
               WHERE connector_name=?""",
            (int(enabled), mode, now(), actor.id, name),
        )
        self.store.connection.commit()
        self.store.record_policy_decision(
            actor, None, True, "Connector gate configured",
            {"connector_name":name, "enabled":enabled, "mode":mode},
        )

    def statuses(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.connection.execute(
            """SELECT connector_name, enabled, mode, updated_at, updated_by
               FROM connector_config ORDER BY connector_name"""
        )]

    def require_enabled(self, connector_name: str, *, synthetic: bool) -> None:
        row=self.store.connection.execute(
            "SELECT enabled, mode FROM connector_config WHERE connector_name=?",
            (connector_name.upper(),),
        ).fetchone()
        if row is None or not row["enabled"]:
            raise AuthorizationError(f"Connector {connector_name} is disabled")
        if row["mode"] == "SYNTHETIC_ONLY" and not synthetic:
            raise AuthorizationError("Connector permits synthetic artifacts only")


class ClaudeImportAdapter:
    """Offline import adapter. It never calls Claude and never executes imported instructions."""

    connector_name="CLAUDE_IMPORT"

    def __init__(self, store: SeanOSStore, actor: Actor):
        self.store=store; self.actor=actor; self.gate=ConnectorGate(store)

    def ingest(self, envelope: ImportEnvelope, *, scope: str = "IAC") -> dict[str, Any]:
        self.gate.require_enabled(self.connector_name, synthetic=envelope.synthetic)
        if scope != "IAC":
            raise AuthorizationError("v0.1 Claude import is isolated to IAC scope")
        if not envelope.external_id.strip() or not envelope.source_uri.strip() or not envelope.captured_at.strip():
            raise ValidationError("Import requires external ID, source URI, and capture time")
        if not envelope.content.strip():
            raise ValidationError("Empty artifacts are not imported")
        project_id=envelope.metadata.get("project_id")
        if project_id:
            project=self.store.get_record(self.actor, project_id)
            if project["entity_type"] != "PROJECT" or project["owner_scope"] != scope:
                raise ValidationError("Imported project reference is invalid")
        digest=hashlib.sha256(envelope.content.encode("utf-8")).hexdigest()
        existing=self.store.connection.execute(
            """SELECT content_sha256, record_id FROM imported_artifacts
               WHERE connector_name=? AND external_id=?""",
            (self.connector_name, envelope.external_id),
        ).fetchone()
        if existing:
            if existing["content_sha256"] != digest:
                raise ValidationError("External artifact changed; import under a new immutable ID")
            return {"record_id":existing["record_id"], "content_sha256":digest, "deduplicated":True}
        record_id=self.store.create_record(
            self.actor, "KNOWLEDGE", scope,
            {"kind":"CLAUDE_IMPORTED_ARTIFACT", "content":envelope.content,
             "content_sha256":digest, "captured_at":envelope.captured_at,
             "metadata":envelope.metadata, "synthetic":envelope.synthetic,
             "trust":"UNTRUSTED_EVIDENCE", "instruction_execution":"DISABLED"},
            source="claude-import", source_locator=envelope.source_uri,
        )
        self.store.connection.execute(
            """INSERT INTO imported_artifacts
               (connector_name, external_id, content_sha256, record_id, imported_at)
               VALUES (?, ?, ?, ?, ?)""",
            (self.connector_name, envelope.external_id, digest, record_id, now()),
        )
        self.store.connection.commit()
        if project_id:
            self.store.link_records(self.actor, record_id, "EVIDENCE_FOR", project_id)
        self.store.record_policy_decision(
            self.actor, record_id, True, "Synthetic Claude artifact imported as untrusted evidence",
            {"external_id":envelope.external_id, "sha256":digest},
        )
        return {"record_id":record_id, "content_sha256":digest, "deduplicated":False}


class CodingDeliveryAdapter:
    """Record a completed synthetic Claude Code delivery; never calls a model or Git host."""

    connector_name="CLAUDE_IMPORT"

    def __init__(self, store: SeanOSStore, actor: Actor):
        self.store=store; self.actor=actor; self.gate=ConnectorGate(store)

    def _ensure_link(self, record_id: str, relationship_type: str, target_id: str) -> None:
        exists=self.store.connection.execute(
            """SELECT 1 FROM relationships WHERE from_record_id=?
               AND relationship_type=? AND to_record_id=?""",
            (record_id, relationship_type, target_id),
        ).fetchone()
        if exists is None:
            self.store.link_records(self.actor, record_id, relationship_type, target_id)

    def record(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.gate.require_enabled(self.connector_name, synthetic=bool(payload["synthetic"]))
        if payload["synthetic"] is not True:
            raise AuthorizationError("v0.1 coding delivery accepts synthetic evidence only")
        project=self.store.get_record(self.actor, payload["project_id"])
        task=self.store.get_record(self.actor, payload["task_id"])
        if (project["entity_type"] != "PROJECT" or task["entity_type"] != "TASK" or
                project["owner_scope"] != "IAC" or task["owner_scope"] != "IAC"):
            raise ValidationError("Coding delivery requires IAC project and task records")
        linked=self.store.connection.execute(
            """SELECT 1 FROM relationships WHERE from_record_id=?
               AND relationship_type='BELONGS_TO' AND to_record_id=?""",
            (task["id"], project["id"]),
        ).fetchone()
        if linked is None:
            raise ValidationError("Coding delivery task is not linked to the project")

        text_fields=("external_id", "repository", "base_revision", "branch_name",
                     "review_ref", "summary")
        if any(not isinstance(payload[key], str) or not payload[key].strip() for key in text_fields):
            raise ValidationError("Coding delivery text fields must be non-empty")
        repository=payload["repository"].strip()
        if repository.count("/") != 1 or any(not part for part in repository.split("/")):
            raise ValidationError("Repository must use owner/name form")
        if payload["branch_name"].strip().lower() in {"main", "master"}:
            raise ValidationError("Coding delivery must use a review branch")
        paths=payload["changed_paths"]
        if (not isinstance(paths, list) or not paths or
                any(not isinstance(item, str) or not item.strip() for item in paths)):
            raise ValidationError("Coding delivery requires changed paths")
        for item in paths:
            path=PurePosixPath(item)
            if path.is_absolute() or ".." in path.parts:
                raise ValidationError("Changed paths must remain repository-relative")
        tests=payload["test_results"]
        if (not isinstance(tests, list) or not tests or
                any(not isinstance(item, str) or not item.strip() for item in tests)):
            raise ValidationError("Coding delivery requires test results")
        activity=payload["activity_units"]
        cost=payload["estimated_cost_units"]
        if isinstance(activity, bool) or not isinstance(activity, int) or activity <= 0:
            raise ValidationError("Coding activity units must be a positive integer")
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or float(cost) <= 0:
            raise ValidationError("Coding cost units must be positive")

        canonical=json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        existing=self.store.connection.execute(
            "SELECT content_sha256, delivery_id, artifact_record_id FROM coding_deliveries WHERE external_id=?",
            (payload["external_id"],),
        ).fetchone()
        if existing:
            if existing["content_sha256"] != digest:
                raise ValidationError("Coding delivery ID was reused with different evidence")
            self._ensure_link(existing["artifact_record_id"], "DELIVERS", task["id"])
            self._ensure_link(existing["artifact_record_id"], "EVIDENCE_FOR", project["id"])
            return {"delivery_id":existing["delivery_id"],
                    "record_id":existing["artifact_record_id"], "status":"DELIVERED",
                    "content_sha256":digest, "deduplicated":True}

        recovered_record=None
        for row in self.store.connection.execute(
            "SELECT id, payload FROM records WHERE source='claude-code-delivery'"
        ):
            candidate=json.loads(row["payload"])
            if candidate.get("external_id") == payload["external_id"]:
                recovered_record=(row["id"], candidate)
                break
        if recovered_record:
            record_id, candidate=recovered_record
            if candidate.get("content_sha256") != digest:
                raise ValidationError("Recovered coding delivery evidence has changed")
            delivery_id=candidate["delivery_id"]
        else:
            delivery_id=str(uuid.uuid4())
            record_id=self.store.create_record(
                self.actor, "KNOWLEDGE", "IAC",
                {"kind":"CLAUDE_CODE_DELIVERY", "status":"DELIVERED",
                 "delivery_id":delivery_id, "external_id":payload["external_id"],
                 "content_sha256":digest, "project_id":project["id"], "task_id":task["id"],
                 "repository":repository, "base_revision":payload["base_revision"],
                 "branch_name":payload["branch_name"], "review_ref":payload["review_ref"],
                 "summary":payload["summary"], "changed_paths":paths,
                 "test_results":tests, "activity_units":activity,
                 "cost_units":float(cost), "synthetic":True,
                 "network_used":False, "external_effect":False},
                source="claude-code-delivery", source_locator=payload["review_ref"], confidence=1.0,
            )
        stamp=now()
        self.store.connection.execute(
            """INSERT INTO coding_deliveries
               (delivery_id, external_id, content_sha256, project_id, task_id,
                repository, base_revision, branch_name, review_ref, artifact_record_id,
                status, activity_units, cost_units, delivered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'DELIVERED', ?, ?, ?)""",
            (delivery_id, payload["external_id"], digest, project["id"], task["id"],
             repository, payload["base_revision"], payload["branch_name"],
             payload["review_ref"], record_id, activity, float(cost), stamp),
        )
        self.store.connection.commit()
        self._ensure_link(record_id, "DELIVERS", task["id"])
        self._ensure_link(record_id, "EVIDENCE_FOR", project["id"])
        self.store.record_policy_decision(
            self.actor, record_id, True,
            "Synthetic coding delivery recorded without network or repository mutation",
            {"delivery_id":delivery_id, "project_id":project["id"], "task_id":task["id"],
             "tool":"claude-code-synthetic", "cost_units":float(cost),
             "activity_units":activity, "network_used":False, "external_effect":False},
        )
        return {"delivery_id":delivery_id, "record_id":record_id, "status":"DELIVERED",
                "content_sha256":digest, "deduplicated":bool(recovered_record)}
