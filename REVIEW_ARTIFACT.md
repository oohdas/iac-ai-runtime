# Sean OS v0.1 — Release Review Artifact

## Release scope

The IAC-owned local `main` branch is a release candidate against deployed baseline
`1aa8762`. It adds only internal, reversible, synthetic-safe runtime capabilities:

- secure incident and alert-delivery operations with distinct operator authority;
- durable approval-gated outbox, leases, bounded retries, diagnostics, and recovery;
- synthetic-only Claude Code delivery evidence linked to canonical project/task,
  repository review, changed paths, tests, activity, and budgeted cost;
- tested deployed-baseline schema v7→v12 migration, updated operational evidence,
  fail-closed same-volume migration backup/restore, recovery hold, and no live adapter.

## Canonical verification

```bash
python3 scripts/verify_release.py
```

The gate compiles source/tests, runs the full suite, performs recovery and kill-switch
drills, checks container safety, verifies the ownership bridge, and rejects any CI
publish/deploy step. The working tree must be clean and the exact local head hash must
be recorded immediately before approval and push.

## Proven boundaries

- Remote: private IAC repository `oohdas/iac-ai-runtime`.
- Deployment: private one-replica Railway pilot; `main` auto-deploys.
- Data: synthetic/empty only; no PERSONAL or live IAC data is authorized.
- Connectors: all live connectors disabled.
- Delivery: no email/webhook/network implementation; synthetic receipts only and
  default off.
- Interface: no production service or token is configured by this release.
- Infrastructure: no public domain, new service, new replica, new variable, or spend
  change is included.

## Deployment and rollback gate

No push is authorized by this artifact. Railway native backups are Pro-only on the
current Hobby plan, so the candidate must create and verify its schema-v7 backup
before migration and automatically restore it if migration fails. A separately
approved recovery flag restores that backup and enters a database-closed hold before
Railway rolls source and variables back to baseline `1aa8762`. This same-volume guard
is not an independent disaster-recovery backup. See `PRODUCTION_DECISION.md` and
`PRODUCTION_DRILL_PLAN.md` for the exact boundaries.
