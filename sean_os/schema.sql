PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL CHECK (entity_type IN (
        'GOAL','IDEA','PROJECT','TASK','DECISION','KNOWLEDGE','AGENT','APPROVAL'
    )),
    owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
    confidentiality TEXT NOT NULL CHECK (confidentiality IN (
        'PRIVATE','CONFIDENTIAL','EXECUTIVE','MANAGEMENT','GENERAL'
    )),
    portable_on_sale INTEGER NOT NULL CHECK (portable_on_sale IN (0,1)),
    source TEXT NOT NULL,
    source_locator TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    expires_at TEXT,
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    permitted_principals TEXT NOT NULL DEFAULT '[]',
    retention_rule TEXT NOT NULL DEFAULT 'retain',
    payload TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    CHECK (owner_scope != 'PERSONAL' OR portable_on_sale = 0),
    CHECK (owner_scope != 'SHARED' OR confidentiality IN ('PRIVATE','CONFIDENTIAL'))
);

CREATE INDEX IF NOT EXISTS idx_records_type_scope ON records(entity_type, owner_scope);
CREATE INDEX IF NOT EXISTS idx_records_updated ON records(updated_at);

CREATE TRIGGER IF NOT EXISTS records_currentness_required_insert
BEFORE INSERT ON records
WHEN NEW.effective_at IS NULL OR length(trim(NEW.retention_rule)) = 0
BEGIN
    SELECT RAISE(ABORT, 'records require effective_at and retention_rule');
END;

CREATE TRIGGER IF NOT EXISTS records_currentness_required_update
BEFORE UPDATE ON records
WHEN NEW.effective_at IS NULL OR length(trim(NEW.retention_rule)) = 0
BEGIN
    SELECT RAISE(ABORT, 'records require effective_at and retention_rule');
END;

CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    from_record_id TEXT NOT NULL REFERENCES records(id),
    relationship_type TEXT NOT NULL,
    to_record_id TEXT NOT NULL REFERENCES records(id),
    created_at TEXT NOT NULL,
    UNIQUE(from_record_id, relationship_type, to_record_id)
);

CREATE TABLE IF NOT EXISTS project_state (
    record_id TEXT PRIMARY KEY REFERENCES records(id),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','INCUBATOR','PAUSED','KILLED')),
    reason TEXT NOT NULL,
    review_at TEXT,
    reopen_trigger TEXT,
    changed_at TEXT NOT NULL,
    CHECK (state != 'KILLED' OR length(trim(reason)) > 0),
    CHECK (state != 'KILLED' OR length(trim(reopen_trigger)) > 0)
);

CREATE TABLE IF NOT EXISTS approvals (
    record_id TEXT PRIMARY KEY REFERENCES records(id),
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('PERSONAL','IAC','SHARED')),
    max_impact TEXT NOT NULL,
    conditions TEXT NOT NULL DEFAULT '{}',
    approver TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','DENIED','EXPIRED','CONSUMED')),
    expires_at TEXT NOT NULL,
    reusable INTEGER NOT NULL DEFAULT 0 CHECK (reusable IN (0,1))
);

CREATE TABLE IF NOT EXISTS audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('ALLOWED','DENIED','FAILED')),
    policy_reason TEXT NOT NULL,
    affected_record_id TEXT,
    correlation_id TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS work_queue (
    id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'QUEUED','RUNNING','SUCCEEDED','FAILED','DEAD_LETTER',
        'BUDGET_BLOCKED','APPROVAL_BLOCKED','POLICY_BLOCKED'
    )),
    priority INTEGER NOT NULL DEFAULT 100,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_work_queue_claim
ON work_queue(status, available_at, priority, created_at);

CREATE TABLE IF NOT EXISTS runtime_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO runtime_state(key, value, updated_at)
VALUES ('kill_switch', 'OFF', '1970-01-01T00:00:00+00:00');

CREATE TABLE IF NOT EXISTS budgets (
    owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
    period_key TEXT NOT NULL,
    limit_units REAL NOT NULL CHECK (limit_units >= 0),
    used_units REAL NOT NULL DEFAULT 0 CHECK (used_units >= 0),
    reserved_units REAL NOT NULL DEFAULT 0 CHECK (reserved_units >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(owner_scope, period_key)
);

CREATE TABLE IF NOT EXISTS cost_reservations (
    work_id TEXT PRIMARY KEY REFERENCES work_queue(id),
    owner_scope TEXT NOT NULL,
    period_key TEXT NOT NULL,
    units REAL NOT NULL CHECK (units >= 0),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_events (
    id TEXT PRIMARY KEY,
    work_id TEXT,
    owner_scope TEXT NOT NULL,
    period_key TEXT NOT NULL,
    units REAL NOT NULL CHECK (units >= 0),
    occurred_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    owner_scope TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('STARTING','IDLE','WORKING','STOPPING','STOPPED','ERROR')),
    current_work_id TEXT,
    last_seen_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS report_runs (
    id TEXT PRIMARY KEY,
    cadence TEXT NOT NULL CHECK (cadence IN ('DAILY','WEEKLY')),
    period_key TEXT NOT NULL,
    owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
    record_id TEXT NOT NULL REFERENCES records(id),
    generated_at TEXT NOT NULL,
    UNIQUE(cadence, period_key, owner_scope)
);

CREATE TABLE IF NOT EXISTS schedule_dispatches (
    schedule_name TEXT NOT NULL,
    period_key TEXT NOT NULL,
    work_id TEXT NOT NULL REFERENCES work_queue(id),
    dispatched_at TEXT NOT NULL,
    PRIMARY KEY(schedule_name, period_key)
);

CREATE TABLE IF NOT EXISTS action_executions (
    work_id TEXT PRIMARY KEY REFERENCES work_queue(id),
    task_type TEXT NOT NULL,
    result TEXT NOT NULL,
    completed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connector_config (
    connector_name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    mode TEXT NOT NULL CHECK (mode IN ('SYNTHETIC_ONLY','LIVE')),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('CLAUDE_IMPORT', 0, 'SYNTHETIC_ONLY', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('EMAIL', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('CALENDAR', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('SHOPVOX', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('QUICKBOOKS_ONLINE', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('QNAP', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');
INSERT OR IGNORE INTO connector_config(connector_name, enabled, mode, updated_at, updated_by)
VALUES ('RBC_READ_ONLY', 0, 'LIVE', '1970-01-01T00:00:00+00:00', 'system');

CREATE TABLE IF NOT EXISTS imported_artifacts (
    connector_name TEXT NOT NULL REFERENCES connector_config(connector_name),
    external_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    record_id TEXT NOT NULL REFERENCES records(id),
    imported_at TEXT NOT NULL,
    PRIMARY KEY(connector_name, external_id)
);

CREATE TABLE IF NOT EXISTS command_requests (
    id TEXT PRIMARY KEY,
    external_request_id TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    owner_scope TEXT NOT NULL CHECK (owner_scope IN ('PERSONAL','IAC','SHARED')),
    command_type TEXT NOT NULL,
    work_id TEXT NOT NULL REFERENCES work_queue(id),
    submitted_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
