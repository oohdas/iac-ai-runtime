# Sean OS v0.1 — Production Retry Record

## Current status

- Sean approved exact candidate `3a5ea9d` on 2026-08-21. GitHub and Railway report
  success; deployment `71463ab0-e310-4323-9982-15eb4aee0694` is Active and Online.
  The guarded startup created a verified v17 backup, migrated production to schema v18,
  and retained the private one-replica service and original ready volume. A live IAC
  health check reported integrity OK, a current IDLE worker, kill switch off, zero
  attention, and three succeeded scheduled tasks.
- The deployed release contains the default-off reconciliation-safe backup/restore
  boundaries, synthetic activation command, hash-bound state-only operators, and bounded
  internal portfolio/report scheduling. No production activation command has been run.
- Backup execution remains disabled: no Backblaze application key, encryption key,
  Railway managed value, upload, or restore has been added.
- Sean approved the exact guarded retry for hotfix `139daf3` on 2026-08-20.
- GitHub verification run #8 passed, including the built-container startup smoke check.
- Railway deployment `5b6f3a83-404a-45e9-928a-2cf500d330d6` is Online on exact
  commit `139daf3`, with one replica and the original `/data` volume attached.
- The approved native-backup release was stopped before any push after Railway's
  Backups page showed that backups/PITR require Pro. No backup, plan upgrade,
  variable change, or new-source deployment occurred.
- Exact commit `710b197` passed GitHub verification but its Railway container failed
  before database open because direct script execution could not resolve `sean_os`.
  Schema v7 was untouched and the approved rollback completed.
- The hotfix bootstraps the application root before import and adds both an exact
  direct-script regression and a post-build container runtime smoke test.
- The production guard created a mode-0600 v7 backup and manifest, verified SHA-256
  `6dc6a8acfe2a036b87eab9ca73387cb07ba21116a15dcc2ec87898fe1da9102c`,
  migrated to schema v12, and reported integrity OK.
- A scope-correct live health query reported healthy, one active non-stale IAC
  worker, no kill switch, no attention items, and database/foreign-key integrity OK.
- PID 1 is Python under uid/gid 10001 with no effective Linux capabilities. The
  service remains unexposed and its single instance stayed running on delayed recheck.

## Approved package executed

The approved no-upgrade retry package was executed as follows:

1. pushed the clean, release-gated hotfix on top of `710b197` to
   `oohdas/iac-ai-runtime/main`, allowing the existing automatic deployment;
2. before schema migration, the entrypoint created a verified SHA-256 backup and
   manifest beside the database on the attached `/data` volume;
3. retained automatic schema-v7 restore and denied worker startup on migration failure;
4. left every optional monitoring, delivery, interface, operator, and connector
   variable unchanged and disabled;
5. verified one replica, private exposure, `/data`, schema v12, IAC scope profile,
   integrity, uid/gid 10001, backup evidence, and healthy startup;
6. if import or migration fails, select Railway's known-good baseline deployment and roll
   back only after confirming the automatic restore returned the database to v7;
7. if migration succeeds but a later release check fails, stop the worker, set
   `SEAN_OS_RESTORE_SCHEMA_VERSION=7` for one candidate deployment, verify its
   recovery-hold evidence, then roll back to the baseline deployment, which also
   restores the baseline variables and removes the recovery flag.

This completed package does not authorize a Pro upgrade, higher spend, a public endpoint,
new services or replicas, live Claude/model use, real data, external messages, or
any connector.

## Recovery limits

The same-volume file protects this specific schema migration; it is not an
independent disaster-recovery backup. A separate encrypted off-volume backup and
isolated restore drill remain mandatory before broader production or real data.
Native Railway backups are unavailable on the current Hobby plan.

The reviewed follow-up recommendation is an IAC-owned Backblaze B2 private bucket
with 30-day compliance-mode Object Lock, default provider encryption, and IAC-owned
client-side encryption. `BACKUP_PROVIDER_DECISION.md` records the non-executing
decision and its approval boundary. The IAC-owned Canada East account and protected
empty bucket are configured. The deployed adapter code is default-off; no credential,
Railway managed value, upload, or restore has been authorized by that record.

Railway documents that rollback/redeploy of a selected prior deployment uses that
deployment's source, image, and variables. The v7 database must never be opened by
the new worker after recovery, and the v12 database must never be opened by baseline
`1aa8762`.

Platform procedure: [Railway deployment actions](https://docs.railway.com/deployments/deployment-actions).

## Ownership boundary

1. `seansadhoo/sean-os-personal` remains Sean-owned and outside an IAC sale.
2. `oohdas/iac-ai-runtime`, its deployment, and IAC records remain IAC-owned.
3. Cross-domain direction uses only the versioned allowlisted bridge; neither
   runtime receives the other domain's private database or secrets.

## Still separately approval-gated

- broader-production backup service, retention, and independent restore drill;
- live model/API usage or Claude/Claude Code repository mutation;
- production monitoring routes or alert delivery;
- interface/operator credentials or any public service;
- email, calendar, ShopVox, QuickBooks Online, QNAP, RBC, or customer data;
- customer contact, external-record mutation, deployment handlers, or money movement.
