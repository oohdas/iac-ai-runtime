# Sean OS v0.1 — Production Gate

No deployment is authorized by this document. Every item must have evidence before production is enabled.

Current Railway evidence and unresolved controls are recorded in
`RAILWAY_READINESS_AUDIT.md`.

## Ownership and isolation

- [ ] IAC worker is deployed only in the IAC-owned Railway account.
- [ ] PERSONAL runtime uses separately owned infrastructure and credentials.
- [ ] No PERSONAL data, secret, backup, or identifier is present in IAC infrastructure.
- [ ] IAC production database reports the permanent `IAC` scope profile; mismatch-start failure is observed.
- [ ] PERSONAL production database reports the permanent `PERSONAL` scope profile and is separately owned.
- [ ] Production database and backups have explicit sale-portability classification.

## Runtime

- [ ] Persistent storage is mounted at `/data`; ephemeral filesystem use is rejected.
- [ ] Exactly one SQLite worker replica is configured. Scaling requires migration to a managed database.
- [ ] Worker starts as the non-root `sean-os` user and becomes healthy within 90 seconds.
- [ ] Restart policy and maximum retries are reviewed.
- [ ] Kill-switch activation and worker termination are tested in production without live external actions.

## Security and approvals

- [x] IAC Railway administrator 2FA is enabled and verified.
- [x] Railway compute hard limit ($15) and email-alert soft limit ($10) are configured.
- [ ] Production identities use least privilege and separate worker/operator credentials.
- [ ] Secrets are stored in the hosting secret manager and never committed or logged.
- [ ] External and irreversible handlers remain disabled until individually reviewed.
- [ ] Exact-target approvals expire and are single-use by default.
- [ ] Budget ceilings are configured before any cost-bearing handler is enabled.

## Recovery and monitoring

- [ ] Encrypted automatic backups have defined retention and access ownership.
- [ ] A restore into an isolated destination passes integrity and sentinel checks.
- [ ] Stale worker, policy block, dead letter, budget block, and backup failure alerts are tested.
- [ ] Operational report cadence and Sean escalation route are approved.
- [ ] Rollback owner, process, and recovery-time target are documented.

## Sean approval required

- [ ] Hosting/database/monitoring choices and monthly maximum spend.
- [ ] Production deployment and persistent-volume creation.
- [ ] Any connection to Claude, email, calendar, ShopVox, QuickBooks Online, QNAP, RBC, or customers.
- [ ] Any handler capable of sending messages, changing external records, deploying code, or moving money.
