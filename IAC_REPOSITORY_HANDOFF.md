# IAC AI Runtime — Release Handoff

## Verified destination

- Owner/repository: `oohdas/iac-ai-runtime`
- Visibility: private
- Deployment branch: `main`
- Railway behavior: existing automatic deployment on an approved `main` push
- Former rollback baseline: `1aa8762`
- Deployed release: exact commit `139daf3`
- Railway deployment: `5b6f3a83-404a-45e9-928a-2cf500d330d6`

## Release evidence

- Canonical gate: `python3 scripts/verify_release.py`
- Runtime tests: 159 passing in the canonical post-deployment local release gate
- Schema: deployed production remains v12; the unpushed local follow-up adds a
  restart-safe v15 backup-transfer outbox, lease, and receipt migration
- Migration recovery: verified SHA-256 same-volume backup, automatic restore on
  migration failure, and explicit database-closed recovery hold
- Recovery and kill-switch drills: included in the canonical gate
- GitHub workflow: read-only verification plus container build; no deploy step
- Container proof: the workflow now starts the built image, requires migration-guard
  evidence, requires the process to remain running, and rejects any traceback
- Bridge contract: unchanged and verified by its committed schema hash
- Durable secret boundary: queued inputs and worker outputs reject secret-like
  material; operational/audit failures redact sensitive detail; raw exception
  messages are not persisted; interface validation cannot reflect secret-like input
  and unauthenticated query strings are excluded from audit evidence
- Independent-backup drill gate: deterministic IAC-only proposal validation and an
  exact hash-bound package that always requires approval and cannot execute

## Controlled handoff result

1. The local release gate passed and Sean approved exact hotfix `139daf3`.
2. The exact commit was pushed once to the existing IAC remote.
3. GitHub run #8 passed, including the built-container runtime smoke test.
4. Railway created and verified its v7 backup, migrated to v12, and started the worker.
5. Live checks proved healthy IAC scope, integrity, one active worker, uid/gid 10001,
   zero effective capabilities, one replica, no public domain, and the original volume.
6. Deployment and backup evidence was preserved without record content or secrets.

If recovery is required, follow the exact automatic or approval-gated recovery path
in `PRODUCTION_DECISION.md`, then use Railway's selected baseline-deployment rollback
so source and variables return together. The migration backup is same-volume and is
not a substitute for independent broader-production backup and restore testing.

## Not authorized by handoff

- bypassing the release gate or deploying a different commit;
- live Claude/model use, model spending, or GitHub mutation by an agent;
- public exposure, new services/replicas, or environment changes;
- real data, production alerts, email/calendar, ShopVox, QBO, QNAP, or RBC;
- customer contact, external record mutation, deployment handlers, or money movement.
