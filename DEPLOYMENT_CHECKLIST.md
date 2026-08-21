# Sean OS v0.1 — Production Gate

No deployment is authorized by this document. Every item must have evidence before production is enabled.

The existing isolated pilot is authorized and deployed at exact commit `5eb51c2`.
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
- [x] Worker starts through a privilege-dropping entrypoint, becomes Online within
  90 seconds, and PID 1 runs as uid/gid 10001 with no effective capabilities.
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
- [x] A deterministic local contract validates the exact IAC-only encrypted backup/
  isolated-restore approval package and always remains non-executing.
- [x] Approval contract v2 binds the selected Backblaze provider and exact data region
  through the plan, single-use approval conditions, and required provider receipt.
- [x] Current official provider evidence is reviewed and an IAC-owned Backblaze B2
  bucket with 30-day compliance-mode Object Lock is the documented recommendation.
- [x] The approved IAC-owned Backblaze pilot account contains one empty private
  bucket with default SSE-B2 encryption and 30-day Object Lock verified in the
  provider console; no application key or upload exists.
- [x] The selected production-backup pilot is verified in Canada East at exact endpoint
  `s3.ca-east-006.backblazeb2.com`; the unused US East bucket remains empty and isolated.
- [x] A path-free transfer contract re-verifies the local IAC backup and approval
  binding while proving credentials, encryption, upload, and network remain disabled.
- [x] Schema v15 durably stages backup preflight evidence and consumes only a Sean-
  approved, exact-condition, single-use authorization without performing an upload.
- [x] The local schema-v16 follow-up adds a terminal reconciliation hold for ambiguous
  provider writes; it is not deployed and cannot retry those transfers automatically.
- [x] Authorized backup transfers use crash-safe bounded leases, fail after three
  attempts by default, obey the kill switch, and surface critical local health evidence.
- [x] Completion requires exact production provider/encryption/lock/retention/upload
  evidence and preserves the earlier no-network preflight separately.
- [x] A non-creating first-drill application-key contract is bucket/prefix restricted,
  expires within four hours, and excludes download, delete, administration, retention
  mutation, legal-hold mutation, and governance bypass capabilities.
- [x] Streaming AES-256-GCM client encryption and authenticated quarantine restore are
  implemented locally with exact-plan AAD, fresh nonces, private files, non-overwrite,
  tamper rejection, and best-effort mutable-key wiping.
- [x] The Backblaze port and Railway managed-value adapters are implemented locally with
  exact endpoint/region binding, signed payloads, conditional create, no SDK retry,
  provider encryption/retention checks, and manual reconciliation after uncertain writes.
- [x] The local worker follow-up is wired behind a complete default-off activation
  contract, validates private source/manifest paths before resolving managed values,
  and requires the bucket to match the exact approved destination reference.
- [x] An exact hash-bound supervised package binds the real Railway and Canada bucket
  identifiers to a synthetic-only pilot while authorizing no key, secret, push, deploy,
  upload, restore, network, or execution action.
- [ ] Create and place the exact approved writer key in the reviewed managed-secret
  destination; do not expose it in chat, files, logs, receipts, or source control.
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
- [x] Push and automatic deployment of exact guarded hotfix `139daf3`.
- [x] Production backup region and empty protected Canada East destination.
- [x] Least-privilege credential, client-encryption, provider, and managed-value
  boundaries are implemented and verified locally.
- [ ] Approve the exact candidate push/deploy, writer-key creation and managed-value
  placement, one synthetic upload, and isolated synthetic restore as separate gates.
- [ ] Any connection to Claude, email, calendar, ShopVox, QuickBooks Online, QNAP, RBC, or customers.
- [ ] Any handler capable of sending messages, changing external records, deploying code, or moving money.
