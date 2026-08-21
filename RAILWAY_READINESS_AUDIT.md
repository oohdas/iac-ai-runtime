# IAC Railway Readiness Audit

Audit date: 2026-08-20
Mode: approved isolated pilot; synthetic/empty IAC data only

## Verified facts

- Railway access is owned through the IAC identity and workspace.
- Workspace plan: Hobby, usage-based.
- The workspace currently has one unrelated project; the IAC AI runtime should
  use a new, separate project rather than sharing that project's resources.
- One workspace administrator is present.
- Railway authenticator-app 2FA was enabled and verified on 2026-08-20.
- Compute limits were configured and verified on 2026-08-20: $10 email-alert
  soft limit and $15 workspace-wide hard stop.
- An agent usage hard limit exists, but it does not cap ordinary compute usage.
- The current plan supports shared persistent disk sufficient for the v0.1 pilot.
- Private Railway project `iac-ai-runtime` exists in the IAC workspace.
- Private worker service `iac-ai-runtime` is connected to
  `oohdas/iac-ai-runtime` with one replica in US West.
- Persistent volume `iac-ai-runtime-volume` is attached at `/data` and the
  service variable is `SEAN_OS_DATABASE=/data/iac-ai.db`.
- No public domain is configured; Railway reports the service as unexposed.
- Deployment baseline `1aa8762` was the pre-release rollback point. The worker
  successfully opened the volume-backed database after its entrypoint prepared
  `/data` and dropped to uid/gid 10001.
- A controlled restart on 2026-08-20 returned the same deployment Online and
  Railway remounted the same persistent volume before container startup.
- The Railway GitHub App is restricted to `oohdas/iac-ai-runtime`; production
  tracks `main` and automatic deployments on approved pushes are enabled.
- The Hobby Backups page was checked while the worker was stopped on 2026-08-20.
  It showed backups/PITR as Pro-only and contained no backup. The release was
  aborted without a push, upgrade, variable change, or substitute production action.
- Baseline `1aa8762` was restored immediately as successful deployment
  `e1e91a4c-7ee0-47cd-b2b9-880575d4e457`; one running instance and the original
  `/data` volume were reverified.
- Approved commit `710b197` passed GitHub workflow run #7 and built on Railway, but
  runtime logs showed `ModuleNotFoundError: No module named 'sean_os'` before the
  database was opened. The already-approved rollback restored baseline `1aa8762`
  as successful deployment `416bd9e9-7220-42a5-95b6-bca5c44a249f` with one running
  instance, private exposure, and the original `/data` volume.
- The local container entrypoint now has a default-off, all-or-none environment
  contract for integrated non-delivering monitoring. No monitoring route variable
  has been added to Railway, and no alert destination or delivery is authorized.
- Sean approved exact hotfix `139daf3`; GitHub verification run #8 passed and
  Railway deployed it as `5b6f3a83-404a-45e9-928a-2cf500d330d6`.
- The production guard created a mode-0600 same-volume backup and manifest,
  verified SHA-256 `6dc6a8acfe2a036b87eab9ca73387cb07ba21116a15dcc2ec87898fe1da9102c`,
  migrated schema v7→v12, and reported integrity OK before worker startup.
- A live scope-correct check reported healthy database and foreign keys, one active
  non-stale IAC worker, kill switch off, and no attention items. PID 1 runs as
  uid/gid 10001 with zero effective capabilities.
- A delayed status/log recheck showed the same running instance, no restart or
  traceback, one replica, no domain, and the original ready `/data` volume.
- Sean approved exact commit `f6bb665`; Railway deployment `bb7b47da` succeeded on
  2026-08-20 after a guarded v15→v16 backup/migration with integrity OK. The service
  remains private, one replica, and backup execution remains unconfigured and disabled.
- Sean approved exact commit `c9a400d`; Railway deployment `56f211f5` succeeded on
  2026-08-21 after a guarded v16→v17 backup/migration with integrity OK. The original
  volume remains attached, and staging, credentials, managed values, upload, and restore
  remain unconfigured and disabled.
- This same-volume guard protects this release but does not satisfy independent
  disaster recovery.

## Required pre-deployment controls

1. [x] Create a separate `iac-ai-runtime` project in the IAC workspace.
2. [x] Connect only `oohdas/iac-ai-runtime` and deploy a release-gated commit.
3. [x] Create one worker service and exactly one replica while SQLite is in use.
4. [x] Attach persistent storage at `/data`; reject deployment without it.
5. [x] Set `SEAN_OS_DATABASE=/data/iac-ai.db`.
6. [x] Keep the worker unexposed with no public domain.
7. [x] Verify successful startup against the volume-backed IAC database.
8. [ ] Verify production kill switch, independent production backup, isolated
   restore, and alert delivery before broader production approval. Runtime uid/gid
   10001 with zero effective capabilities, restart, and
   volume-remount persistence have been verified. Deterministic local alert
   classification now covers stale workers, blocked work, dead letters, budget
   stops, integrity failures, kill-switch activation, and backup failure;
   external delivery is intentionally not configured. A local fail-closed migration
   guard now covers the release-specific v7→v12 rollback path.
9. [ ] Create `SEAN_OS_INTERFACE_TOKEN` only if a separate authenticated
   interface service is approved; the private worker pilot does not require it.

## Explicitly excluded from the pilot

- PERSONAL or SHARED-personal data
- live Claude/Claude Code delivery
- email or calendar access
- ShopVox, QuickBooks Online, QNAP, or RBC access
- customer contact or external-record mutations
- model/API spending
- deployment bypassing the connected Railway `main` source and release gates

## Approval boundary

2FA, spending controls, private service isolation, one-replica enforcement,
volume attachment, and initial worker startup are verified. The approved pilot
contains no real data or live integrations. Broader production use remains a
separate explicit action.
