# Sean OS v0.1 — Release Review Artifact

## Release scope

The IAC-owned release is deployed at exact commit `5eb51c2e650d8223b4b06ae90f0a5e90f0b72154`
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
See `PRODUCTION_DECISION.md` and `PRODUCTION_DRILL_PLAN.md` for the exact boundaries.
