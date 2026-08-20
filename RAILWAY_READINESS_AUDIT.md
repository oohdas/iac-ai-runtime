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
- Commit `59c89a4` deployed successfully on 2026-08-20 and Railway reported the
  service Online. The worker successfully opened the volume-backed database
  after its entrypoint prepared `/data` and dropped to uid/gid 10001.
- A controlled restart on 2026-08-20 returned the same deployment Online and
  Railway remounted the same persistent volume before container startup.
- The Railway GitHub App is restricted to `oohdas/iac-ai-runtime`; production
  tracks `main` and automatic deployments on approved pushes are enabled.
- The local container entrypoint now has a default-off, all-or-none environment
  contract for integrated non-delivering monitoring. No monitoring route variable
  has been added to Railway, and no alert destination or delivery is authorized.

## Required pre-deployment controls

1. [x] Create a separate `iac-ai-runtime` project in the IAC workspace.
2. [x] Connect only `oohdas/iac-ai-runtime` and deploy a release-gated commit.
3. [x] Create one worker service and exactly one replica while SQLite is in use.
4. [x] Attach persistent storage at `/data`; reject deployment without it.
5. [x] Set `SEAN_OS_DATABASE=/data/iac-ai.db`.
6. [x] Keep the worker unexposed with no public domain.
7. [x] Verify successful startup against the volume-backed IAC database.
8. [ ] Verify runtime uid, production kill switch, production backup, isolated
   restore, and alert delivery before broader production approval. Restart and
   volume-remount persistence have been verified. Deterministic local alert
   classification now covers stale workers, blocked work, dead letters, budget
   stops, integrity failures, kill-switch activation, and backup failure;
   external delivery is intentionally not configured.
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
