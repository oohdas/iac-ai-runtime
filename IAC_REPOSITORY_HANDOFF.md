# IAC AI Runtime — Release Handoff

## Verified destination

- Owner/repository: `oohdas/iac-ai-runtime`
- Visibility: private
- Deployment branch: `main`
- Railway behavior: existing automatic deployment on an approved `main` push
- Deployed baseline: `1aa8762`
- Local release candidate: clean local `main`; record `git rev-parse HEAD` at approval

## Release evidence

- Canonical gate: `python3 scripts/verify_release.py`
- Runtime tests: 126 passing in the canonical release gate
- Schema: restart-safe additive migration from deployed v7 to release v12
- Migration recovery: verified SHA-256 same-volume backup, automatic restore on
  migration failure, and explicit database-closed recovery hold
- Recovery and kill-switch drills: included in the canonical gate
- GitHub workflow: read-only verification plus container build; no deploy step
- Container proof: the workflow now starts the built image, requires migration-guard
  evidence, requires the process to remain running, and rejects any traceback
- Bridge contract: unchanged and verified by its committed schema hash

## Controlled handoff sequence

1. Confirm the local tree is clean and record the exact head and commit list after
   `1aa8762`.
2. Obtain Sean's explicit approval for the revised guarded-deploy package.
3. Push the reviewed local `main` to the existing IAC remote once.
4. Confirm the entrypoint created and verified its v7 backup before migration.
5. Observe Railway automatic deployment and run the checks in
   `PRODUCTION_DECISION.md` without enabling any optional variable or connector.
6. Preserve the deployment, backup, and verification evidence without record content
   or secrets.

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
