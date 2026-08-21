# Sean OS v0.1 — Release Review Artifact

## Release scope

The IAC-owned release is deployed at exact commit `3a5ea9db5ee3574c64599d9171fb122bbcc861f8`
against former baseline `1aa8762`. It adds only internal, reversible, approval-gated
runtime capabilities:

- secure incident and alert-delivery operations with distinct operator authority;
- durable approval-gated outbox, leases, bounded retries, diagnostics, and recovery;
- synthetic-only Claude Code delivery evidence linked to canonical project/task,
  repository review, changed paths, tests, activity, and budgeted cost;
- tested deployed-baseline schema v7→v12 migration, updated operational evidence,
  fail-closed same-volume migration backup/restore and recovery hold;
- default-off independent-backup approval, encryption, provider, and managed-value
  boundaries with no key, managed value, upload, restore, or real data enabled;
- schema-v16 reconciliation holds, exact private source checks, and deterministic
  synthetic-only activation staging behind separately approved production gates;
- schema-v17 durable activation evidence and a hash-bound, state-only approval operator
  that refuses configured execution or secrets and performs no claim, upload, or restore;
- schema-v18 isolated-restore authorization, distinct read-only identity, exact-version
  provider port, authenticated non-overwriting verification, and a separate default-off
  one-shot worker that the continuous container cannot invoke;
- bounded daily Chief of Staff portfolio maintenance before complete local-only reports,
  with human-ownership and missing-metric fail-safe behavior;
- direct Railway-style script import bootstrap, an exact regression test, and a
  post-build container runtime smoke check that rejects tracebacks or early exit.

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

## Deployment and rollback result

Sean approved exact commit `139daf3`; GitHub run #8 passed and Railway deployment
`5b6f3a83-404a-45e9-928a-2cf500d330d6` migrated v7→v12 behind a verified backup,
then passed live health, isolation, privilege, and delayed-stability checks. A
separately approved recovery flag can still restore that backup and enter a
database-closed hold before Railway rolls source and variables back to baseline
`1aa8762`. This same-volume guard is not an independent disaster-recovery backup.
Sean later approved exact commit `f6bb665`; Railway deployment `bb7b47da` created a
verified v15 backup, migrated to v16, passed integrity checking, and left every backup
execution and credential value disabled.
Sean then approved exact commit `c9a400d`; Railway deployment `56f211f5` created a
verified v16 backup, migrated to v17, passed integrity checking, and left production
staging, execution, credentials, managed values, upload, and restore disabled.
Sean then approved exact commit `3a5ea9d`; Railway deployment `71463ab0` created a
verified v17 backup, migrated to v18, passed live IAC health and integrity checking,
and left all backup/restore configuration and execution disabled.
See `PRODUCTION_DECISION.md` and `PRODUCTION_DRILL_PLAN.md` for the exact boundaries.
