# Sean OS v0.1 — Production Gate

No deployment is authorized by this document. Every item must have evidence before production is enabled.

The existing isolated pilot is authorized and deployed at baseline `1aa8762`.
Unchecked items apply to the next release or broader production activation; a push
to `main` is a deployment and still requires explicit approval.

Current Railway evidence and unresolved controls are recorded in
`RAILWAY_READINESS_AUDIT.md`.

## Ownership and isolation

- [x] IAC worker is deployed only in the IAC-owned Railway account.
- [ ] PERSONAL runtime uses separately owned infrastructure and credentials.
- [ ] No PERSONAL data, secret, backup, or identifier is present in IAC infrastructure.
- [x] IAC pilot database is opened with the permanent `IAC` scope profile; mismatch-start failure remains a pre-broader-production drill.
- [ ] PERSONAL production database reports the permanent `PERSONAL` scope profile and is separately owned.
- [ ] Production database and backups have explicit sale-portability classification.

## Runtime

- [x] Persistent storage is mounted at `/data`; ephemeral filesystem use is rejected.
- [x] Exactly one SQLite worker replica is configured. Scaling requires migration to a managed database.
- [x] Optional monitoring can run inside the existing worker and is disabled by
  default, so it does not require another SQLite-connected service or replica.
- [x] Container monitoring configuration is all-or-none and fails startup on
  partial, malformed, unsafe, or unbounded values; Railway remains unconfigured.
- [x] Worker starts through a privilege-dropping entrypoint and becomes Online within 90 seconds.
- [x] Restart policy is On Failure with a maximum of 10 retries.
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

- [x] The release candidate creates and verifies a SHA-256 same-volume v7 backup
  before migration, restores it automatically on migration failure, and denies
  worker startup; explicit restore enters a database-closed recovery hold.
- [ ] An independently stored encrypted production backup is completed and locked;
  Railway native backups are Pro-only on the current Hobby plan.
- [ ] A restore into an isolated destination passes integrity and sentinel checks.
- [x] Stale worker, policy block, dead letter, budget block, and backup failure
  classifications and non-delivering route envelopes are tested locally.
- [ ] Production alert delivery is tested after a route-specific approval.
- [ ] Operational report cadence and Sean escalation route are approved.
- [ ] Rollback owner, process, and recovery-time target are documented.

## Further Sean approval required

- [x] Isolated IAC Railway pilot, one persistent volume, and $10/$15 spend controls.
- [ ] Push and automatic deployment of the revised guarded schema-v12 candidate.
- [ ] Production backup destination, encryption ownership, retention, and restore drill.
- [ ] Any connection to Claude, email, calendar, ShopVox, QuickBooks Online, QNAP, RBC, or customers.
- [ ] Any handler capable of sending messages, changing external records, deploying code, or moving money.
