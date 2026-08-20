# Sean OS v0.1 — Next Production Decision

## Current status

- IAC source is in the private `oohdas/iac-ai-runtime` repository.
- A private, unexposed Railway worker pilot runs one replica with a persistent
  volume at `/data` and tracks repository branch `main`.
- Railway automatic deployment means a push to `main` is also a production change.
- Deployed source baseline is `1aa8762`; the reviewed local branch contains the
  later security, monitoring, delivery-recovery, and schema-v12 work. That baseline
  supports schema v7, so the controlled release performs the tested v7→v12 upgrade.
- The pilot contains no approved real data or live connector.

## Exact decision required next

Approve one controlled release package covering:

1. stop the single worker so SQLite is quiescent, then create and lock one manual
   Railway volume backup from the service's Backups tab without inspecting records;
2. record the completed backup timestamp, keep the original volume, and verify the
   backup is available for Railway's staged same-project/environment restore;
3. push the clean, release-gated local `main` range after `1aa8762` to
   `oohdas/iac-ai-runtime/main`, allowing Railway's existing automatic deployment;
4. leave all monitoring, synthetic-delivery, interface, operator, and connector
   environment variables unchanged and disabled;
5. verify one replica, private exposure, `/data` volume attachment, schema v12,
   IAC scope profile, database integrity, worker uid 10001, and healthy startup;
6. stop and stage the locked pre-release backup restore if migration or health
   verification fails; review the staged replacement volume before deploying it.

Railway documents manual backups for any volume, including SQLite; restores are staged
to a replacement volume while the former volume is retained. Incremental backup
storage remains subject to the existing $10 soft/$15 hard workspace controls. This
decision does not authorize live Claude, alerts, external messages, real data, new
credentials, a public domain, new services, additional replicas, or higher spend.

## Ownership boundary

1. `seansadhoo/sean-os-personal` remains Sean-owned and outside an IAC sale.
2. `oohdas/iac-ai-runtime`, its IAC deployment, and IAC records remain IAC-owned.
3. Cross-domain direction uses only the versioned allowlisted bridge; neither
   runtime receives the other domain's private database or secrets.

## Rollback constraint

Schema v12 is forward-only for this release. Rolling source back to `1aa8762`
without restoring the matching pre-release database is prohibited because the older
v7 runtime rejects newer schema versions. Recovery therefore means: kill switch or stop
worker, use Railway's staged restore of the locked pre-release backup, review the new
volume mapping, then deploy the restored source/database pair. Railway backups restore
only within the same project and environment and restoring removes newer backups, so
the exact pre-release backup must be selected deliberately.

Platform procedure: [Railway volume backups](https://docs.railway.com/volumes/backups).

## Still separately approval-gated

- live model/API usage or Claude/Claude Code repository mutation;
- production monitoring routes or alert delivery;
- interface/operator credentials or any public service;
- email, calendar, ShopVox, QuickBooks Online, QNAP, RBC, or customer data;
- customer contact, external-record mutation, deployment handlers, or money movement.
