# Sean OS Build Status

This file is the visible progress ledger for the automated Sean OS builder.
Every automation run updates it, even when no notification is sent.

## Current snapshot

- Last continuous-goal checkpoint started: 2026-08-20 19:20 EDT
- Last continuous-goal checkpoint completed: 2026-08-20 19:26 EDT
- Milestone selected: guarded schema-v12 release execution and startup regression
- Run state: Production safely rolled back; tested hotfix awaits exact retry approval
- Last meaningful milestone: the failed candidate never opened the database, the
  baseline recovered automatically, and the exact container startup gap now has regression proof
- Deployed commit: `1aa8762`
- Runtime: Online on rollback deployment `416bd9e9-7220-42a5-95b6-bca5c44a249f`,
  private, one replica, original persistent volume attached
- Remote main: `710b197`; GitHub verification run #7 passed, but Railway candidate
  `e4fcd3f8-c5fb-4d8c-8f25-53610650023c` failed before database open because the
  direct script could not resolve the application package
- Concrete changes: added an explicit application-root bootstrap before package
  import, a direct-script regression test that reproduces Railway's launch context,
  a release-gate invariant, and a clean-container runtime smoke test after image build
- Verification: canonical gate passes compilation, 126 tests, bridge, container,
  migration guard, recovery hold, workflow safety, and manifested restore checks
- Real data connected: No
- Live integrations enabled: No
- Current blocker: retrying production requires an exact approval for the new hotfix commit
- Next milestone: push the exact hotfix head, observe automatic deployment, verify
  pre-migration evidence/schema v12/health, and invoke recovery only on a failed gate
- Sean action required: Yes — approve the exact hotfix retry in
  `PRODUCTION_DECISION.md`; production is healthy and unchanged at schema v7

## Recent verified milestones

1. IAC-owned repository and private Railway service established.
2. Persistent SQLite volume mounted at `/data` and verified across restart.
3. GitHub App restricted to `oohdas/iac-ai-runtime`.
4. Railway production branch connected to `main`; automatic deployment verified.
5. Synthetic kill-switch drill added with audit and recovery evidence.
6. Deterministic monitoring covers integrity, kill-switch, worker, queue, approval,
   budget, and backup escalation classes without sending alerts.
7. Alert routing now fails closed across ownership scopes, filters by severity, and
   produces approval-gated plans only; the production drill has explicit pass/abort criteria.
8. Alert plans now deduplicate deterministically and generate hashed, timezone-aware
   acknowledgement evidence without authorizing delivery.
9. Schema v8 durably stores scoped alert observations, counts repeats, and permits
   one immutable Sean-only acknowledgement while preserving audit evidence.
10. The monitoring CLI can now persist deduplicated observations only when a complete,
    scope-owned, non-secret route contract is supplied; it still cannot deliver alerts.
11. A supervisor-friendly monitoring loop now runs at bounded cadence, exits cleanly
    on signals, fails visibly, and remains an optional non-deployed local process.
12. The existing worker can now run monitoring at monotonic cadence inside its one
    process; default startup remains unchanged and complete-contract tests prove no delivery.
13. The container accepts a default-off monitoring environment contract that aborts
    startup on partial, malformed, unsafe, or unbounded values; Railway is unchanged.
14. Schema v9 groups observations into durable scoped incidents, supports Sean-only
    resolution, and reopens recurring conditions without losing historical evidence.
15. Daily and weekly reports now rank active incidents, show incident deltas, exclude
    resolved incidents, and prevent health/queue/budget leakage across scopes.
16. The primary interface now queries active IAC incidents and resolves them only with
    a distinct Sean operator credential; identical replay is safe and changed evidence fails.
17. Schema v10 now stages one delivery per incident generation, atomically consumes
    exact scope-matched approval, and accepts only deterministic no-network receipts.
18. The primary interface now reviews/stages deliveries, requests bounded approval,
    and keeps Sean's decision and exact authorization as separate recoverable steps.
19. Schema v11 adds default-off leased synthetic processing to the existing worker,
    bounded crash recovery/retries, kill-switch enforcement, and terminal health alerts.
20. Reports and the primary interface now expose scope-safe delivery diagnostics;
    Sean-only reset revokes prior authorization and leaves work staged for fresh approval.
21. The full v0.1 acceptance audit is reconciled to the real IAC GitHub/Railway state;
    synthetic coding delivery and the deployed v7→v12 migration are now directly tested,
    and the release/rollback package is ready for an explicit production decision.
22. The failed native-backup attempt was aborted without a source change, baseline
    was restored, and the release now fails closed around migration using a verified
    same-volume backup, automatic restore, and recovery hold; all 125 tests pass.
23. Exact commit `710b197` passed GitHub but failed its direct container import before
    touching the database. The approved rollback restored baseline `1aa8762`; a direct-
    script regression and post-build container runtime smoke now close that test gap.

## Update contract

Each automated run must record:

- run timestamp;
- milestone selected;
- files or behavior changed;
- tests and checks run;
- blockers or approvals required;
- next milestone;
- whether Sean must act.

The ledger never contains credentials, real personal/IAC records, or secret values.
