# IAC AI Runtime v0.1

IAC-owned company automation runtime implementing the IAC side of Sean OS v0.1.

This build uses Python and SQLite and can be tested without accounts, paid services,
production credentials, or real PERSONAL/IAC data. The optional backup path pins PyCA
cryptography and Boto3 for authenticated encryption and the S3-compatible provider port;
both remain default-off and injectable in tests.

## Included

- Canonical records for Goals, Ideas, Projects, Tasks, Decisions, Knowledge, Agents, Approvals, and Audit Log
- Mandatory PERSONAL / IAC / SHARED scope metadata
- Fail-closed authorization checks
- Scope-filtered listing and optimistic version checks for updates
- Explicit record relationships with direct PERSONAL↔IAC links prohibited
- ACTIVE / INCUBATOR / PAUSED / KILLED project lifecycle
- Exact-target, expiring, single-use or reusable approval records
- Append-only audit log protected by database triggers
- Deterministic IAC sale export that excludes PERSONAL records and unapproved SHARED records
- Manifested sale-export package with record count and SHA-256 integrity hash
- Local backup/restore and database/foreign-key integrity checks
- Durable work queue with priorities, leases, retry limits, dead-letter state, and a Sean-controlled kill switch
- Local continuous-worker prototype with graceful shutdown
- Registered action policies that fail closed for unknown, prohibited, wrong-scope, or misclassified work
- Exact approval enforcement before any registered external or irreversible handler can run
- Separate approval-blocked and policy-blocked queues, with every policy decision audited
- Bounded Chief of Staff planning that converts an authorized IAC goal into an ACTIVE project and ordered tasks
- Evidence-based project continuation, pausing, and self-cancellation with preserved rationale and reopen triggers
- Durable queue handlers for Chief of Staff project creation and evaluation
- Automatic daily and Monday-weekly local operational reports, dispatched exactly once per period
- Attention routing for approvals, budget blocks, policy blocks, and dead-letter work
- Non-root container packaging and a Railway worker manifest with bounded restart policy
- Machine-readable health command suitable for supervision and deployment gates
- Restart-safe schema migrations that preserve legacy queued work
- Fail-closed production migration guard with verified same-volume pre-migration
  backup, automatic rollback, and a database-closed operator recovery hold
- SHA-256 manifested backups and verified, non-overwriting restores
- Fail-closed secret scanning for durable queue inputs and worker results, plus
  redacted operational/audit error evidence
- Deterministic, hash-bound, non-executing approval packages for a future independent
  encrypted backup/isolated-restore drill
- A path-free, provider-neutral backup transfer plan that re-verifies the local IAC
  snapshot and produces only a deterministic no-network synthetic adapter receipt
- Schema-v16 durable backup-transfer outbox with no-network preflight evidence,
  terminal manual-reconciliation holds for ambiguous writes, and
  atomic, exact-condition, single-use Sean authorization before any future adapter
- Default-off backup-transfer leases with crash recovery, three-attempt exhaustion,
  kill-switch enforcement, secret-safe failures, and critical health escalation
- Exact production receipt verification for Backblaze identity, authenticated IAC
  encryption, provider AES-256, compliance retention, timestamps, and no overwrite;
  the provider client remains disabled unless the complete explicit worker contract,
  exact authorization, local source, and managed values are all present
- A default-off, port-injected backup execution boundary that binds the exact Canada
  endpoint, writer/key references, window, byte and CAD ceilings, active lease, and
  live kill-switch checks before encryption, before upload, and after upload
- A single existing-worker backup path that validates private same-volume source
  evidence before managed values are resolved, never auto-retries an ambiguous write,
  and stays absent from the worker command when backup execution is disabled
- A deterministic synthetic activation command that creates only an isolated sentinel
  database, writes private non-overwriting evidence, durably binds its revalidated
  synthetic-only attestation, stages a no-network preflight, and leaves push, keys,
  managed values, approval, upload, and restore as distinct gates
- A hash-bound state-only operator command that rejects stale reviews, absent or changed
  synthetic evidence, wrong identity/conditions/window, and any preconfigured backup
  runtime; authorization cannot claim, encrypt, upload, restore, or resolve a secret
- A deterministic non-creating first-drill key contract restricted to one bucket,
  the `backups/` prefix, six read/verify/upload capabilities, and four hours; it
  explicitly excludes downloads, deletes, key/bucket administration, retention writes,
  legal holds, and governance bypass
- Primary-interface backup review/request routes with decision and authorization
  restricted to the separate Sean operator identity
- Automated recovery drill with integrity and sentinel-record verification
- Explicit production gate checklist for ownership, security, monitoring, storage, and approvals
- Synthetic-only Revenue Agent qualification with bounded scoring and value limits
- Internal opportunity briefs for qualified signals, explicitly marked as not authorized for outreach
- Automatic rejection of live or identifying revenue inputs in v0.1
- Durable execution receipts that suppress completed-handler replay after worker recovery
- Disabled-by-default Claude/Claude Code import with synthetic-only activation
- Immutable external IDs, SHA-256 content provenance, and duplicate suppression for imports
- Imported text is explicitly stored as untrusted evidence with instruction execution disabled
- Synthetic Claude Code deliveries are linked to an IAC project and task with an
  immutable repository/review reference, changed-path and test evidence, activity,
  budgeted cost trace, and a durable `DELIVERED` status; no Git host is called
- Locked, visible gates for email, calendar, ShopVox, QuickBooks Online, QNAP, and RBC read-only
- Idempotent, scope-isolated command gateway for the future ChatGPT primary interface
- Whitelisted asynchronous commands with strict field schemas and no arbitrary action passthrough
- Local bearer-authenticated HTTP boundary with separate interface/operator credentials, body limits, no-store responses, and audited authentication failures
- Enforced effective/expiry timestamps, confidence, retention rules, and derived currentness on every record
- Standard material-action audit envelope covering evidence, model/tool, cost, outcome, and rollback status
- Morning/weekly reports with explicit fact, estimate, inference, and recommendation sections
- Passing end-to-end scenario from idea capture through research, approval boundary, Sean decision, and report
- Recursive secret-pattern rejection on record create/update and fail-closed sale-export scanning
- Scoped ChatGPT-interface create, retrieve, list, update, and link operations across IAC core records
- Scope-filtered audit retrieval that prevents PERSONAL audit disclosure to the IAC interface
- Schema-v12 durable alert-delivery outbox keyed by incident generation, with exact
  scope-matched approval and a deterministic no-network synthetic adapter
- Primary-interface outbox review and restart-safe stage/request/decide/authorize
  flow with ordinary IAC and Sean-operator credentials kept separate
- Default-off single-worker synthetic outbox processing with durable leases, crash
  recovery, bounded retry exhaustion, kill-switch enforcement, and failed-work health
- Scope-safe backlog/lease diagnostics in the primary interface and reports, plus a
  Sean-only failed-item reset that revokes prior authorization and requires fresh approval
- Chief of Staff portfolio scoring, capacity allocation, low-fit challenge, and safe agent-only pausing
- Revenue comparison across outbound, existing/inactive customers, quotes, inbound, and new channels
- Capacity-adjusted expected return using margin, probability, cost, Sean time, strategic fit, and evidence
- Retained rejected revenue hypotheses with explicit reopen triggers
- IAC-owned private Git repository and review artifact; the deployed Railway pilot
  tracks `main`, while every new push remains an explicit production approval
- Permanently bound DEVELOPMENT, IAC, or PERSONAL database profiles; profile mismatch fails closed
- IAC worker and interface always open the database in IAC-only mode
- Per-scope monthly budgets with cost reservation, settlement, usage events, and fail-closed blocking
- Worker heartbeats and runtime health reporting with stale-worker, dead-letter, integrity, and kill-switch checks
- Synthetic seed data and automated tests

## Run

```bash
python3 -m unittest discover -s tests -v
python3 scripts/demo.py
python3 scripts/status.py
python3 scripts/worker.py --once
python3 scripts/healthcheck.py --database sean-os-local.db --scope-profile DEVELOPMENT
python3 scripts/recovery_drill.py
python3 scripts/verify_release.py
python3 scripts/prepare_backup_transfer.py APPROVAL.json MANIFEST.json \
  --object-ref backups/OPAQUE-ID.db.enc \
  --provider-endpoint s3.ca-east-006.backblazeb2.com \
  --writer-identity-ref iac-vault-writer:backup-only-v1 \
  --client-encryption-key-ref iac-keyring:backup-key-v1
python3 scripts/prepare_backup_writer_key.py backup-writer-key-proposal.example.json
python3 scripts/prepare_supervised_backup_pilot.py FULL_CANDIDATE_COMMIT \
  2026-08-21T09:00:00-04:00 --duration-minutes 120
python3 scripts/prepare_supervised_backup_activation.py IAC_DB DATA_VOLUME_WORKSPACE \
  FULL_CANDIDATE_COMMIT WINDOW_START --duration-minutes 120
python3 scripts/backup_operator.py review IAC_DB PLAN_SHA256
SEAN_OS_INTERFACE_TOKEN='<32+ random characters>' \
SEAN_OS_OPERATOR_TOKEN='<different 32+ random characters>' python3 scripts/interface.py
```

`scripts/verify_release.py` is the canonical fail-closed release gate. The included
GitHub Actions workflow runs it and builds the production container on every push
and pull request. It has read-only repository permissions and contains no deployment,
secret access, live connector, or external-action step.

See [OPERATIONS.md](OPERATIONS.md) for health, shutdown, recovery, and production-readiness procedures.
See [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) for the explicit production gate.
See [BACKUP_PROVIDER_DECISION.md](BACKUP_PROVIDER_DECISION.md) for the reviewed,
non-executing independent-backup recommendation and exact approval boundary.
See [SUPERVISED_BACKUP_ACTIVATION_RUNBOOK.md](SUPERVISED_BACKUP_ACTIVATION_RUNBOOK.md)
for the separate staging, state-approval, credential, activation, and verification gates.
See [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) for connector ordering and activation boundaries.
See [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) for the ChatGPT authority boundary.

The local SQLite files created by the scripts are disposable. An isolated, private,
one-replica Railway worker pilot exists with a persistent `/data` volume, but it has
no real data or live integrations and broader production use is not approved.
Authentication, live model workers, real integrations, production alert delivery,
and every new deployment remain approval-gated. The outbox adapter only produces
synthetic receipts and has no network implementation. The Revenue Agent handles
synthetic inputs only and has no outreach, CRM, pricing, quoting, or spending
authority. Unknown actions never execute; approval-blocked work waits for an
explicit, exact authorization rather than retrying. A reviewed Backblaze network port
now exists locally, but it remains unconfigured and default-off; its supervised package
authorizes no push, deployment, managed value, upload, restore, network, or execution.
