# Sean OS Build Status

This file is the visible progress ledger for the automated Sean OS builder.
Every automation run updates it, even when no notification is sent.

## Current snapshot

- Last continuous-goal checkpoint started: 2026-08-20 21:15 EDT
- Last continuous-goal checkpoint completed: 2026-08-20 21:36 EDT
- Milestone selected: complete the safe local implementation needed for a supervised,
  synthetic-only Backblaze pilot without creating a key, deploying, or using the network
- Run state: Milestone verified locally; deployed production remains unchanged and healthy
- Last meaningful milestone: streaming client encryption, the disconnected provider and
  managed-value boundaries, and the exact non-executing supervised package are complete
- Deployed commit: `139daf3`
- Runtime: Online on deployment `5b6f3a83-404a-45e9-928a-2cf500d330d6`, private,
  one replica, original persistent `/data` volume attached
- Remote main: `139daf3`; GitHub verification run #8 passed in 25 seconds, including
  the built-container startup smoke check
- Concrete changes: locked the first-drill Backblaze writer to the exact bucket/prefix,
  six capabilities, and four-hour maximum; implemented streaming AES-256-GCM with fresh
  nonces, exact-plan authenticated data, mode-0600 artifacts, no overwrite, key-buffer
  wiping, quarantine restore, and tamper rejection; implemented an injected Backblaze S3
  port that rechecks SSE-B2 and compliance retention, conditionally creates one object,
  verifies its version/retention, and prohibits ambiguous retries; implemented fixed-name
  Railway managed-value adapters with exact HTTPS endpoint/signing-region binding, signed
  payloads, and one SDK attempt; pinned reviewed crypto/SDK versions and container install;
  added a deterministic supervised package binding the actual Railway/Canada resources
  to synthetic IAC data while authorizing no external action
- Verification: production guard reported source schema 7, schema 12, integrity OK,
  backup SHA-256 `6dc6a8acfe2a036b87eab9ca73387cb07ba21116a15dcc2ec87898fe1da9102c`;
  live health is healthy with one non-stale IAC worker; canonical local gate passes
  compilation, 197 tests, bridge, container, migration guard, recovery hold, durable
  secret/approval/execution contracts, streaming encryption, disconnected provider,
  managed-value and non-executing pilot invariants, workflow safety, and manifested
  restore checks; the Backblaze console reports the selected bucket
  private, encryption enabled, Object Lock default 30 days, zero files, zero bytes,
  and exact Canada East endpoint `s3.ca-east-006.backblazeb2.com`
- Real data connected: No
- Live integrations enabled: No
- Current blocker: the verified candidate is local; local Docker is unavailable, so the
  pinned dependency/container build must be proven by the read-only GitHub verification
  workflow after a separately approved push. No key or managed value exists, and the
  deployed service contains none of this candidate code.
- Next milestone: obtain explicit approval to push the local candidate (which auto-deploys),
  verify GitHub/container/Railway health, then request the distinct
  supervised writer-key and managed-value approval for one synthetic-only upload.
- Sean action required: the next external action is candidate push/deployment approval.
  Do not create an application key yet. Key creation, Railway managed values, upload,
  restore, billing changes,
  real IAC data, and deletion of the unused US East pilot remain separately gated.

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
24. Exact hotfix `139daf3` passed GitHub run #8 and deployed successfully. Railway
    created and verified the v7 backup, migrated to v12, started one healthy IAC
    worker as uid/gid 10001 with no effective capabilities, and stayed private.
25. Durable work inputs and outputs now fail closed on secret-like material, while
    heartbeat, audit, policy, and failure evidence redact sensitive details. The
    worker persists only a bounded exception class/context summary. Interface errors
    cannot reflect secret-like input and authentication audit drops query strings;
    seven adversarial regressions and release-gate invariants prove the boundary locally.
26. A provider-neutral independent-backup drill contract now rejects wrong scope,
    weak ownership, missing encryption/lock/isolation, production overwrite, connectors,
    real data, excessive cost/window, secrets, extra fields, and package tampering. Its
    deterministic hash can bind a future Approval record, but the package cannot execute.
27. Current official storage evidence was compared. An IAC-owned private Backblaze B2
    bucket with default provider encryption, additional IAC-owned client encryption,
    and 30-day compliance-mode Object Lock is the documented v0.1 recommendation;
    no provider or production action was taken.
28. A provider-neutral transfer contract now independently verifies an IAC backup's
    file hash, size, schema, integrity, foreign keys, and scope profile, strips its
    local path, binds the plan to the exact approval package, and emits a deterministic
    receipt proving no credentials, encryption, upload, network, or execution occurred.
29. Local schema v15 now stages backup transfer plans and preflight evidence durably.
    Approval conditions bind the plan, proposal, database hash, destination, object,
    and retention settings; only Sean can atomically consume the exact single-use
    authorization, and that transition itself cannot contact a provider or upload.
30. The primary IAC interface can review backup transfers and request an approval;
    only the separate Sean operator identity can decide and authorize. HTTP contract
    tests prove the ordinary interface receives a 403 and authorization still leaves
    network and execution disabled.
31. Authorized backup transfers now use bounded durable leases with crash recovery,
    three-attempt exhaustion, kill-switch enforcement, and secret-safe failure text.
    Exhausted work becomes `FAILED`, makes runtime health unhealthy, and creates a
    critical local `BACKUP_TRANSFER_FAILED` classification; no live adapter is enabled.
32. Backup completion now rejects weak, shortened, mismatched, secret-bearing, or
    modified provider evidence. A valid receipt must prove Backblaze B2, exact object
    and source hash/size, authenticated IAC encryption plus provider AES-256, compliance
    lock for the full period, upload/network success, no overwrite, and no restore;
    the earlier no-network preflight remains separately durable.
33. Sean approved the IAC-owned Backblaze B2 pilot with a CAD 15/month ceiling. One
    empty bucket is now private, SSE-B2 encrypted by default, Object Lock enabled,
    and protected by a 30-day default compliance retention period. No application key,
    upload, restore, Railway change, or deployment occurred; its US East endpoint is
    an explicit decision gate before production use.
34. Backup approval contract v2 now binds `BACKBLAZE_B2` and the exact data region
    into the proposal hash, path-free transfer plan, single-use approval conditions,
    and provider receipt. A US East receipt cannot satisfy a Canada East approval;
    all 160 tests and the canonical release gate pass.
35. A separate IAC-owned Canada East account now contains one empty private bucket at
    `s3.ca-east-006.backblazeb2.com` with SSE-B2, Object Lock, and 30-day default
    retention. Transfer contract v3 additionally binds the exact endpoint, writer/key
    references, approved window, and CAD ceiling. A default-off port boundary rechecks
    the active lease and kill switch around each irreversible stage; all 168 tests and
    the canonical release gate pass. No key, upload, Railway change, or deployment occurred.
36. The first-drill writer-key contract now permits only exact bucket/prefix discovery,
    control reads, upload, and retention verification for at most four hours. Download,
    version deletion, administration, and retention mutation remain excluded.
37. Streaming AES-256-GCM now encrypts in bounded memory, binds the plan as authenticated
    data, produces new private artifacts, wipes mutable key buffers, and authenticates a
    quarantined restore before publishing it. Tampering and wrong key/plan references fail.
38. The disconnected Backblaze port and fixed Railway managed-value adapters now bind the
    exact Canada endpoint, signed payloads, conditional create, provider SSE/retention,
    and one total SDK attempt. Uncertain writes prohibit automatic retry.
39. The supervised pilot package binds the actual Railway project/environment/service,
    named volume, Canada bucket/endpoint, candidate, window, cost, and nested drill/key
    packages to synthetic IAC data only. It authorizes no external action. All 197 tests
    and the canonical release gate pass; production remains unchanged.

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
