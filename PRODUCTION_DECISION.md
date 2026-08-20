# Sean OS v0.1 — Revised Production Decision

## Current status

- The private IAC Railway pilot is back on healthy baseline `1aa8762`, deployment
  `e1e91a4c-7ee0-47cd-b2b9-880575d4e457`, with one replica and `/data` attached.
- The approved native-backup release was stopped before any push after Railway's
  Backups page showed that backups/PITR require Pro. No backup, plan upgrade,
  variable change, or new-source deployment occurred.
- The reviewed local release now includes a fail-closed v7→v12 migration guard.
  It is not yet pushed.

## Revised decision required

Approve one controlled no-upgrade release package:

1. push the clean, release-gated local `main` range after `1aa8762` to
   `oohdas/iac-ai-runtime/main`, allowing the existing automatic deployment;
2. before schema migration, let the entrypoint create a verified SHA-256 backup
   and manifest beside the database on the attached `/data` volume;
3. automatically restore schema v7 and deny worker startup if migration fails;
4. leave every optional monitoring, delivery, interface, operator, and connector
   variable unchanged and disabled;
5. verify one replica, private exposure, `/data`, schema v12, IAC scope profile,
   integrity, uid/gid 10001, backup evidence, and healthy startup;
6. if migration fails, select Railway's known-good baseline deployment and roll
   back only after confirming the automatic restore returned the database to v7;
7. if migration succeeds but a later release check fails, stop the worker, set
   `SEAN_OS_RESTORE_SCHEMA_VERSION=7` for one candidate deployment, verify its
   recovery-hold evidence, then roll back to the baseline deployment, which also
   restores the baseline variables and removes the recovery flag.

This package does not authorize a Pro upgrade, higher spend, a public endpoint,
new services or replicas, live Claude/model use, real data, external messages, or
any connector.

## Recovery limits

The same-volume file protects this specific schema migration; it is not an
independent disaster-recovery backup. A separate encrypted off-volume backup and
isolated restore drill remain mandatory before broader production or real data.
Native Railway backups are unavailable on the current Hobby plan.

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
