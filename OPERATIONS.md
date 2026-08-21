# Sean OS Continuous Runtime — Operator Runbook

## Current state

The continuous runtime is implemented and verified locally. An isolated private
Railway worker pilot runs continuously with an empty/synthetic IAC database; it is
not approved for broader production use. No real data, model API, live connector,
customer action, or paid model service is connected.

## Safety invariants

1. Missing or exhausted budget blocks cost-bearing work.
2. The kill switch prevents new work from being claimed.
3. Work requires a durable lease; expired leases may be recovered by another worker.
4. Failures retry only up to the task's configured maximum, then move to `DEAD_LETTER`.
5. Runtime health is unhealthy when integrity fails, the kill switch is on, a worker is stale, or dead-letter work exists.
6. PERSONAL, IAC, and SHARED authorization is enforced before work is queued or data is read.
7. Approval-gated effects remain outside the worker's authority.
8. Every executable task type must have a registered policy and handler; unknown or prohibited actions fail closed.
9. External and irreversible handlers require an exact, unexpired approval before invocation.
10. Every policy allow or deny decision is appended to the audit log.
11. The Chief of Staff may create and lifecycle-manage only its own bounded IAC projects.
12. Self-cancellation requires completed evaluation evidence and always preserves a reopen trigger.
13. Cadence dispatch is atomic and idempotent for each daily or weekly period.
14. Reports remain local records; report generation has no delivery or messaging authority.
15. Schema upgrades are ordered, recorded, restart-safe, and must preserve queued work.
16. Restore never overwrites an existing destination and rejects corrupt or unsupported backups.
17. Expired paid leases reuse their existing cost reservation rather than reserving twice.
18. The Revenue Agent accepts synthetic, non-identifying inputs only and cannot perform outreach.
19. Qualified opportunities create internal preparation work only; all records state that external action is unauthorized.
20. Completed action results are durably receipted so lease recovery suppresses handler replay.
21. Connectors are disabled by default; credentials alone cannot activate them.
22. Claude imports are synthetic-only, immutable, content-hashed, and treated as untrusted evidence.
23. Email, calendar, ShopVox, QBO, QNAP, and RBC gates cannot be enabled in v0.1.
24. The ChatGPT-facing gateway exposes named commands only and cannot pass arbitrary task types.
25. Command request IDs are immutable and idempotent; extra fields and PERSONAL scope fail closed.
26. Interface authentication failures are audited without recording tokens or request bodies.
27. Every record has timezone-aware effectiveness metadata, confidence, retention, and derived currentness.
28. Reports label facts, estimates, inferences, and recommendations and disclose unavailable sources.
29. Customer contact remains a requestable approval boundary, not an executable v0.1 action.
30. Secret-like keys and token/private-key patterns are rejected on create/update and rescanned before sale export.
31. Interface audit queries are scope-filtered; IAC principals cannot retrieve PERSONAL traces.
32. Portfolio capacity changes may pause agent-created work only; human projects receive recommendations.
33. Rejected revenue hypotheses are retained with reopen triggers and no external action authority.
34. The source remote is the IAC-owned private `oohdas/iac-ai-runtime` repository;
    `main` auto-deploys the Railway pilot, so every push requires explicit approval.
35. A database binds permanently to DEVELOPMENT, IAC, or PERSONAL; reopening under another profile fails closed.
36. IAC worker/interface processes explicitly require the IAC profile, even for Sean-level actors.
37. The monitoring loop persists evidence only, enforces matching route/database
    ownership, and has no network or delivery adapter.
38. Integrated worker monitoring is disabled by default, runs within the existing
    single worker when explicitly configured, and cannot create another replica.
39. Alert incidents are keyed by scope, route, and alert class; only Sean can
    resolve them, and a recurring condition automatically reopens the same incident.
40. Daily and weekly reports include only active incidents and health data from
    their own scope, remain local-only, and exclude resolved incident history.
41. Incident reads use the ordinary IAC interface identity; resolution requires a
    distinct optional Sean operator credential. Missing, weak, or reused operator
    credentials fail closed, and rejected attempts are audited without secrets.
42. Alert delivery is staged once per incident generation in a durable outbox. Its
    exact approval must match action, delivery ID, and scope atomically; v0.1 accepts
    only deterministic synthetic receipts that prove no network or external effect.
43. The primary interface separates safe staging/request operations from Sean's
    decision/authorization operations. A crash between decision and authorization
    leaves durable `APPROVED` evidence and does not repeat or silently consume it.
44. Synthetic outbox processing is default-off and may run only inside the existing
    single worker under exact `SYNTHETIC_ONLY` configuration. Claims are leased,
    crash-recoverable, bounded to three attempts by default, and kill-switch aware.
45. Exhausted synthetic delivery becomes `FAILED`, makes scoped runtime health
    unhealthy, and emits a local `ALERT_DELIVERY_FAILED` classification; it never
    falls through to a live adapter, network call, or external effect.
46. Delivery diagnostics derive scope-filtered backlog, lease, retry, and terminal
    state without exposing another ownership scope or granting execution authority.
47. Only Sean may reset `FAILED` delivery to `STAGED`; reset clears the consumed
    approval and attempt state, performs no execution, and requires a fresh exact
    approval before the worker can claim it again.
48. Synthetic coding-delivery evidence requires a review branch, an IAC-linked
    project and task, repository-relative changed paths, tests, activity units, and
    a positive reserved cost; it never invokes Claude, GitHub, or a network client.
49. An older production schema is verified and copied to a mode-0600, SHA-256
    manifested backup before migration. Migration failure restores that backup and
    denies worker startup; explicit recovery restores and enters a database-closed hold.
50. The direct container entrypoint bootstraps `/app` before application imports,
    and continuous verification must run the built image, observe migration-guard
    evidence, confirm it remains running, and reject every startup traceback.
51. Durable work payloads and handler/completion results reject secret-like material.
    Heartbeat, audit, policy-block, and failure evidence redact sensitive detail,
    and unexpected worker exceptions persist only their class plus fixed context.
    Interface validation never reflects secret-like input, and authentication audit
    records only the URL path—not its potentially sensitive query string.
52. Independent-backup production work starts from a deterministic, provider-neutral,
    IAC-only approval package. The package requires encryption, retention lock,
    restore isolation, bounded cost/window, Sean operation/rollback, no connectors,
    and no real data while always remaining explicitly non-executing.
53. A backup transfer plan re-verifies the SQLite file, SHA-256, byte count, schema,
    integrity, foreign keys, and permanent IAC profile. It drops the source path,
    contains no credentials, is hash-bound to the exact drill proposal, and leaves
    encryption, network, upload, and execution false. Its only adapter is synthetic.
54. Schema v15 durably stages that plan and its synthetic preflight receipt. Local
    schema v16 adds a terminal `RECONCILIATION_REQUIRED` state that is never claimable
    or automatically retried after an ambiguous provider write. The
    approval request is bound to the plan, proposal, database hash, destination,
    provider endpoint, writer/key references, object reference, retention mode,
    retention period, execution window, and CAD ceiling. Only Sean can atomically
    consume the exact single-use approval; authorization itself performs no upload.
55. Authorized backup transfers use bounded durable leases. Expired leases are
    recoverable, attempts stop at three by default, the kill switch prevents claims,
    secret-like failure text is rejected, and exhausted work becomes `FAILED` and
    raises a critical `BACKUP_TRANSFER_FAILED` health classification. No worker mode
    or live adapter is enabled by this local contract.
56. Completion accepts only a hash-valid production receipt matching the exact plan,
    Backblaze provider, object, database hash/size, IAC authenticated encryption plus
    provider AES-256, compliance lock, full approved retention period, upload time,
    and non-overwrite flags. Preflight and provider receipts are retained separately;
    credentials and source paths are prohibited. Receipt verification performs no call.
57. The default-off execution boundary rejects partial configuration and raw secret
    values. It requires an active exact-plan lease, approved time window, byte and CAD
    ceilings, the exact Canada endpoint and non-secret writer/key references, and a
    live store guard before encryption, before upload, and after upload. The boundary
    contains no provider SDK, secret resolver, or network client. The separately
    injected local AES-256-GCM port streams into a new mode-0600 artifact, binds the
    exact plan as authenticated data, wipes mutable key buffers best-effort, and holds
    restore output in quarantine until its tag and plaintext hash verify. No production
    managed key exists; all live ports remain separately reviewed and approval-gated.
58. The first-drill Backblaze writer-key contract is non-creating, bucket-restricted,
    prefix-restricted to `backups/`, expires within four hours, and permits only bucket
    discovery, encryption/retention reads, upload, and file-retention reads. It excludes
    downloads, deletes, key/bucket administration, retention/legal-hold writes, and
    governance bypass. A distinct restore credential is required later.
59. The disconnected Backblaze port accepts only an injected S3-compatible client. It
    verifies default SSE-B2 and 30-day compliance retention, performs one conditional
    `backups/` Put Object with explicit AES-256, and checks the returned version's exact
    retention. Its reviewed client factory is bound to three fixed Railway managed
    variable names, the exact HTTPS Canada endpoint, signed payloads, and one total SDK
    attempt. It contains no file listing, download, deletion, retention write, or
    automatic network retry. Any uncertain result after the write starts is a manual-
    reconciliation condition. No managed values or live configuration are deployed.
60. The existing worker now has one complete, default-off backup execution path. The
    container adds it only when the exact non-secret runtime, bucket, private manifest,
    and private output-directory contract is complete. The worker confines source and
    output to the database volume, validates the plan/window/source before resolving
    managed values, binds bucket name to destination reference, and converts ambiguous
    writes into the terminal reconciliation state. Current Railway variables leave it off.

## Local verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/status.py
python3 scripts/healthcheck.py --database sean-os-local.db --scope-profile DEVELOPMENT
python3 scripts/recovery_drill.py
python3 scripts/kill_switch_drill.py
python3 scripts/monitor_snapshot.py --database sean-os-local.db
python3 scripts/verify_release.py
python3 scripts/prepare_backup_approval.py backup-drill-proposal.example.json
python3 scripts/prepare_backup_writer_key.py backup-writer-key-proposal.example.json
python3 scripts/prepare_backup_transfer.py APPROVAL.json MANIFEST.json \
  --object-ref backups/OPAQUE-ID.db.enc \
  --provider-endpoint s3.ca-east-006.backblazeb2.com \
  --writer-identity-ref iac-vault-writer:backup-only-v1 \
  --client-encryption-key-ref iac-keyring:backup-key-v1
```

The transfer command requires an already verified local IAC backup manifest. It
prints a path-free plan and synthetic receipt only. It cannot encrypt a file, read
credentials, call a provider, upload data, or authorize execution.

For the private IAC worker, the equivalent read-only health command must select the
permanently bound production profile:

```bash
python3 scripts/healthcheck.py --database /data/iac-ai.db --scope-profile IAC
```

To persist non-delivering IAC observations in an IAC-profile database, provide
the complete non-secret route contract explicitly:

```bash
python3 scripts/monitor_snapshot.py --database iac-ai.db --scope-profile IAC \
  --record-route-id iac-operator --owner-scope IAC \
  --destination-kind EMAIL --destination-ref iac-ops-alias
```

Partial route arguments fail closed. This records deduplicated local evidence
only and cannot send a message.

For supervised continuous local monitoring, use the same complete route contract:

```bash
python3 scripts/monitor_worker.py --database iac-ai.db --scope-profile IAC \
  --route-id iac-operator --owner-scope IAC \
  --destination-kind EMAIL --destination-ref iac-ops-alias \
  --interval-seconds 30
```

The loop uses an interruptible wait, exits cleanly on `SIGINT`/`SIGTERM`, and
lets unexpected failures reach the process supervisor. It is optional local
code and is not configured as a Railway service. Running it does not authorize
alert delivery.

Expected evidence:

- all tests pass;
- database integrity is `ok`;
- foreign-key violations are empty;
- no real data or newly authorized production change is reported.
- the isolated kill-switch drill blocks work, records audit evidence, and recovers.
- monitoring classifies stale-worker, policy, dead-letter, budget, approval,
  integrity, kill-switch, no-worker, and backup failures without delivering alerts.
- escalation routes produce scope-bound, severity-filtered delivery plans that
  remain unauthorized; `PRODUCTION_DRILL_PLAN.md` defines the approval and evidence
  required for production backup, restore, kill-switch, and recovery testing.
- identical alert plans receive deterministic IDs, repeats can be suppressed across
  runs, and acknowledgements produce hashed, timezone-aware local evidence while
  keeping `delivery_authorized=false`.
- schema v16 durably stores PERSONAL or IAC alert observations, counts identical
  occurrences, scope-filters reads, and permits one immutable Sean-only local
  acknowledgement; it also maintains resolvable/reopenable incidents without adding
  a delivery capability.
- daily/weekly reports rank active incidents by severity, show changes since the
  prior report, and never expose another scope's workers, queue, or budgets.
- the primary interface can query IAC active incidents; local resolution requires
  the distinct `SEAN_OS_OPERATOR_TOKEN`, is idempotent only for identical evidence,
  and does not authorize alert delivery or any external action.
- the outbox deduplicates each active incident generation, refuses resolved incidents,
  preserves an exact payload hash, leaves mismatched approvals unconsumed, and rejects
  every receipt that claims live mode or network use.
- the in-memory HTTP contract test proves the ordinary interface credential receives
  `403` at the operator decision route, while the operator credential can decide and
  separately authorize the exact staged delivery; no socket or external service is used.
- a schema-v10 fixture migrates through v16 without losing its staged delivery; the new
  lease, retry, and availability fields are initialized deterministically.
- an isolated worker-process test consumes an exactly approved outbox item only when
  `--synthetic-delivery` is explicit and records a receipt proving both
  `network_used=false` and `external_effect=false`.
- operational reports and the primary interface expose delivery attention without
  destination secrets; the ordinary credential cannot reset failed work, while a
  separately authenticated reset remains staged and unclaimable until fresh approval.
- a synthetic Claude Code completion is accepted only through the connector gate,
  linked to its canonical IAC project/task, and durably records review, changed-path,
  test, activity, and cost evidence without mutating a repository or using a network.

## Continuous verification

The repository includes `.github/workflows/verify.yml`. It runs on pushes, pull
requests, and manual dispatch with `contents: read` only. The workflow:

1. verifies the versioned ownership-bridge schema hash;
2. compiles the runtime and tests;
3. runs the complete unit/integration suite;
4. performs a backup/restore recovery drill; and
5. builds the production container without publishing or deploying it.

Any failure blocks the verification job. Deployment remains a separate,
explicitly approved production action.

The local release gate also asserts that the container remains non-root, uses
an explicit persistent data volume, and that the workflow cannot publish an
image or deploy. A local Docker build is optional; the clean GitHub runner is
the canonical container-build check.

## Start a local worker

```bash
python3 scripts/worker.py --database sean-os-local.db
```

The process polls the durable queue, emits heartbeats, leases work, evaluates its registered action policy, settles reserved cost, retries bounded runtime failures, and exits cleanly on `SIGINT` or `SIGTERM`. Policy denials do not retry: they move to `APPROVAL_BLOCKED` or `POLICY_BLOCKED`.

Authorized synthetic alert receipts may be processed by that same worker only with:

```bash
python3 scripts/worker.py --database sean-os-local.db --synthetic-delivery
```

The equivalent container contract is
`SEAN_OS_ALERT_DELIVERY_MODE=SYNTHETIC_ONLY`; the entrypoint rejects every other
configured value.

This mode has no delivery library, socket call, webhook client, email client, or live
destination adapter. Any other configured mode aborts startup.

Monitoring may be integrated into that same process without adding a service or
replica. It remains disabled unless all three route arguments are supplied:

```bash
python3 scripts/worker.py --database iac-ai.db \
  --monitor-route-id iac-operator \
  --monitor-destination-kind EMAIL \
  --monitor-destination-ref iac-ops-alias \
  --monitor-interval-seconds 30
```

Partial configuration fails startup. The integrated monitor writes only local
scope-safe evidence and exposes no delivery adapter.

The container entrypoint accepts the same configuration through non-secret
environment variables, all unset by default:

- `SEAN_OS_MONITOR_ROUTE_ID`
- `SEAN_OS_MONITOR_DESTINATION_KIND` (`EMAIL` or `WEBHOOK`)
- `SEAN_OS_MONITOR_DESTINATION_REF` (an alias, never a credential or real address)
- `SEAN_OS_MONITOR_INTERVAL_SECONDS` (optional; defaults to 30, minimum 1)

The first three variables are all-or-none. An interval without a route, partial
route, unsupported kind, non-finite interval, or control character aborts startup.
No monitoring variable is currently configured in Railway, and this document
does not authorize adding one.

## Alert incident lifecycle

Each observation updates one durable incident identified by owner scope, route,
and alert code. Changing queue counts or summary text updates that incident rather
than creating operational noise. Sean may resolve an active incident only after
the underlying condition and recovery evidence have been reviewed:

```python
store.resolve_alert_incident(
    Actor.sean(), incident_id, reason="Recovery evidence reviewed"
)
```

Resolution never deletes observations or acknowledgement evidence. If the same
condition is observed again, the incident returns to `ACTIVE`, clears its former
resolution fields, and increments `reopen_count`. PERSONAL/IAC reads remain
scope-filtered, and resolution reasons reject secret-like material.

## Stop all new execution

Use `SeanOSStore.set_kill_switch(Actor.sean(), True)`. Existing infrastructure should also stop the supervised worker process. The kill switch does not delete queued work or history.

## Recovery procedure

1. Enable the kill switch.
2. Stop worker processes.
3. Run database integrity and foreign-key checks.
4. Review stale leases, dead-letter items, recent audit events, and budget usage.
5. Correct the underlying fault using a reviewed change.
6. Run the full test suite.
7. Disable the kill switch only after the checks pass.
8. Restart one worker and observe health before scaling.

## Guarded schema release and rollback

The container entrypoint performs the production schema guard after dropping to the
worker uid/gid and before starting the worker. For an older schema it:

1. verifies the source integrity and schema ledger;
2. creates `/data/iac-ai.db.pre-migration-v7-to-v12.db` plus a mode-0600 manifest;
3. verifies the backup's integrity, foreign keys, schema, size, and SHA-256;
4. migrates and verifies schema v12; and
5. starts the worker only after every check passes.

Any migration exception restores v7 from the verified backup, quarantines the failed
database for later diagnosis, and exits before worker startup. If migration succeeds
but later release verification fails, stop the service and obtain exact approval to
set `SEAN_OS_RESTORE_SCHEMA_VERSION=7`. The candidate restores v7 and starts only
`MIGRATION_RECOVERY_HOLD`, which does not open the database. Then select Railway's
known-good baseline deployment so its source and variables return together.

Never start baseline `1aa8762` against schema v12. Never clear the recovery hold by
starting the candidate worker against restored schema v7. This file-level copy is on
the same Railway volume and protects only migration rollback; it is not the independent
encrypted backup required before real data or broader production.

## Production prerequisites requiring Sean

- Sean-owned private source-control and cloud account for PERSONAL production.
- Explicit production budget ceilings.
- Approval of the chosen hosting/database/monitoring services and their cost.
- Production identity, secret storage, backups, alerts, and independent restore test.
- Separate approval before any real email, calendar, IAC, QNAP, QBO, ShopVox, RBC, or customer-facing connection.

The bounded production recovery procedure and pass/fail evidence are specified
in `PRODUCTION_DRILL_PLAN.md`. That plan does not itself authorize execution.

## Next production gate

All v0.1 behavior that can be proven safely with synthetic data is implemented
locally. The source is owned by IAC and the private Railway pilot has persistent
storage. Remaining proof is production-owned: verified encrypted backup/restore,
least-privilege identities and secrets, the controlled kill-switch drill, alert
routing, live Claude/Claude Code execution, and later connectors. Each requires an
exact approval and must preserve the IAC/PERSONAL ownership boundary.
