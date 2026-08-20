from __future__ import annotations

import hashlib
from dataclasses import dataclass
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
