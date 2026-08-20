# IAC Railway Readiness Audit

Audit date: 2026-08-20
Mode: read-only; no Railway resource or setting was changed

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
- No `iac-ai-runtime` Railway project, service, volume, variable, domain, or
  deployment exists yet.

## Required pre-deployment controls

1. Create a separate `iac-ai-runtime` project in the IAC workspace.
2. Connect only `oohdas/iac-ai-runtime` and deploy only commit `a67b5d3` or a
   later commit that passes the release gate.
3. Create one worker service and exactly one replica while SQLite is in use.
4. Attach persistent storage at `/data`; reject deployment without it.
5. Set `SEAN_OS_DATABASE=/data/iac-ai.db`.
6. Generate `SEAN_OS_INTERFACE_TOKEN` in Railway's secret manager; never place
   its value in GitHub, logs, chat, or source files.
7. Do not add a public domain to the worker service.
8. Verify non-root execution, IAC-only database binding, health, kill switch,
    backup, isolated restore, and alert delivery before production approval.

## Explicitly excluded from the pilot

- PERSONAL or SHARED-personal data
- live Claude/Claude Code delivery
- email or calendar access
- ShopVox, QuickBooks Online, QNAP, or RBC access
- customer contact or external-record mutations
- model/API spending
- automatic production deployment from GitHub Actions

## Approval boundary

2FA and spending controls are verified. Service and volume creation remain a
separate, explicit production action.
