# Sean OS Continuous Runtime — Operator Runbook

## Current state

The continuous runtime is implemented and verified locally. It is not yet a 24/7 production service. No real data, model API, external connector, account, or paid service is connected.

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
34. The local Git repository has no remote; destination and ownership require explicit approval.
35. A database binds permanently to DEVELOPMENT, IAC, or PERSONAL; reopening under another profile fails closed.
36. IAC worker/interface processes explicitly require the IAC profile, even for Sean-level actors.

## Local verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/status.py
python3 scripts/healthcheck.py --database sean-os-local.db
python3 scripts/recovery_drill.py
python3 scripts/kill_switch_drill.py
python3 scripts/monitor_snapshot.py --database sean-os-local.db
python3 scripts/verify_release.py
```

Expected evidence:

- all tests pass;
- database integrity is `ok`;
- foreign-key violations are empty;
- no real data or production deployment is reported.
- the isolated kill-switch drill blocks work, records audit evidence, and recovers.
- monitoring classifies stale-worker, policy, dead-letter, budget, approval,
  integrity, kill-switch, no-worker, and backup failures without delivering alerts.
- escalation routes produce scope-bound, severity-filtered delivery plans that
  remain unauthorized; `PRODUCTION_DRILL_PLAN.md` defines the approval and evidence
  required for production backup, restore, kill-switch, and recovery testing.

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

## Production prerequisites requiring Sean

- Sean-owned private source-control and cloud account for PERSONAL production.
- Explicit production budget ceilings.
- Approval of the chosen hosting/database/monitoring services and their cost.
- Production identity, secret storage, backups, alerts, and independent restore test.
- Separate approval before any real email, calendar, IAC, QNAP, QBO, ShopVox, RBC, or customer-facing connection.

The bounded production recovery procedure and pass/fail evidence are specified
in `PRODUCTION_DRILL_PLAN.md`. That plan does not itself authorize execution.

## Next implementation gap

Chief of Staff and Revenue portfolio semantics now pass locally, and the source has a reviewable local Git history with no remote. The remaining acceptance gates are production-owned: correct repository destination, live Claude/Claude Code delivery workflow, separated cloud environments, identity/secrets, persistent storage, encryption, alerts, and deployment. These require Sean's explicit production choices and approval.
