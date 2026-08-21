# Sean OS Production Drill Plan

This plan is evidence only. It does not authorize a production drill, alert
delivery, live data, a new service, or spending.

## Recommended destination

The reviewed v0.1 destination is an IAC-owned private Backblaze B2 bucket with
30-day default Object Lock in compliance mode, default SSE-B2 encryption, and an
additional IAC-owned client-side encryption layer. The dedicated writer credential
must be bucket-restricted and unable to administer retention. Object names must be
opaque. `BACKUP_PROVIDER_DECISION.md` records the comparison, cost evidence, and
remaining approval boundary; this recommendation is not execution authorization.

The selected provider pilot now has one empty private bucket with SSE-B2 and default
30-day Object Lock verified at the Canada East endpoint
`s3.ca-east-006.backblazeb2.com`. No application key, encrypted payload, upload,
restore, Railway variable, adapter, schedule, or deployment exists. The production
drill cannot proceed until a new hash-bound approval covers the exact endpoint,
least-privilege identity and encryption-key references, window, cost, and real target.

The local client-encryption port is now production-shaped but deliberately disconnected:
it streams AES-256-GCM into a new private artifact, authenticates the exact plan metadata,
and only publishes restored plaintext after authentication and hash verification. Its
key resolver is injected. Its reviewed Railway adapter reads one fixed managed variable
only after exact activation and wipes its mutable working copy. The Backblaze factory
similarly reads two fixed managed variables, binds an S3-compatible client to the exact
HTTPS Canada endpoint, and disables SDK retries. The port verifies the bucket controls, conditionally
creates one `backups/` object with SSE-B2, verifies the exact version's compliance
retention, and never retries an uncertain write. Until both factories are reviewed and
injected and the release is explicitly activated, no upload can occur. No managed secret
or live configuration has been added to Railway.

## Approval package

Before scheduling the drill, Sean approves one exact package containing:

- IAC environment and worker service identifier;
- drill window and operator;
- independent backup destination, identifier, lock/retention policy, access owner,
  data region, and at-rest encryption evidence appropriate to the approved environment;
- escalation route ID and non-secret destination reference;
- maximum expected cost and rollback owner;
- permission to activate and clear the production kill switch.

PERSONAL infrastructure, records, destinations, and credentials are excluded.

## Exact local approval contract

The provider-neutral contract can be prepared without contacting a service:

```bash
python3 scripts/prepare_backup_approval.py backup-drill-proposal.example.json
```

The example is synthetic and is not an approval. Before Sean reviews a real package,
replace its synthetic references with the reviewed IAC project/environment/service,
an independently owned encrypted destination alias, a distinct isolated restore target,
the exact drill window, retention/lock evidence, and a maximum cost no greater than
CAD 15. Never put a credential, URL token, encryption key, or record content in it.

Validation fails closed unless the package is IAC-only, encrypted at rest, independent
from the primary volume, retention-locked, restore-isolated, non-overwriting, operated
and rolled back by Sean, connector-free, real-data-free, and bounded to a four-hour
window. Contract v2 also binds `BACKBLAZE_B2` and the exact approved data region into
the proposal hash, transfer plan, approval conditions, and provider receipt. Transfer
contract v3 also binds the exact provider endpoint, writer-identity reference,
client-encryption-key reference, approved window, and CAD ceiling; a receipt from
another region, endpoint, identity, key, or time window fails verification. The
deterministic output always says
`approval_required=true` and
`execution_authorized=false`. Sean's future Approval record must use action type
`RUN_INDEPENDENT_BACKUP_RESTORE_DRILL` and the exact hash-bound `approval_target`;
the package itself cannot run a backup, change the kill switch, or call a provider.

After a verified candidate has a full commit SHA, prepare the outer supervised package:

```bash
python3 scripts/prepare_supervised_backup_pilot.py FULL_CANDIDATE_COMMIT \
  2026-08-21T09:00:00-04:00 --duration-minutes 120
```

This binds the actual Railway project/environment/service, named volume, exact Canada
bucket and endpoint, object prefix, writer/key references, managed-variable names,
candidate and baseline commits, cost, window, and nested drill/key packages. It permits
synthetic IAC data only and explicitly leaves key creation, managed-value placement,
push, deployment, upload, restore, network, and execution unauthorized. The example
timestamp is illustrative; generate a fresh package for the approved window.

## Ordered drill

| Phase | Controlled action | Required evidence | Abort condition |
|---|---|---|---|
| Baseline | Confirm one private worker, IAC profile, healthy database, attached volume, and zero live connectors | Timestamped health snapshot and configuration review | Any ownership, scope, exposure, or integrity mismatch |
| Backup | Stop the single worker, create and lock one approved independent backup without inspecting records | Completed backup timestamp/identifier, lock state, owner, and stopped-worker evidence | Worker cannot be quiesced, backup fails, or access/at-rest protection cannot be proven |
| Restore | Restore to a new isolated destination | Integrity check, foreign-key check, schema version, sentinel verification | Existing destination would be overwritten or any check fails |
| Kill switch | Activate switch and submit synthetic `NOOP` work | Work is not claimed; audit event records denial | Any external handler is enabled or work executes |
| Worker recovery | Stop/restart the single worker while switch remains active | Stale/no-worker alert classifications and clean restart evidence | Multiple workers appear or volume is absent |
| Alert route | Generate synthetic escalation envelopes only | Correct severity filtering, IAC route ownership, deterministic deduplication, hashed acknowledgement, `delivery_authorized=false` | A message is delivered or a secret appears in evidence |
| Recovery | Clear switch, process one synthetic `NOOP`, then return to idle | Successful work receipt, healthy snapshot, no dead letters | Integrity or policy check fails |

## Pass criteria

The drill passes only if every phase has timestamped audit evidence, the restore
never overwrites production, no real record content is copied into evidence, no
external alert is delivered, the IAC/PERSONAL boundary remains intact, and the
worker returns healthy with one replica. Any failure leaves the kill switch on
until the rollback owner reviews the evidence.

Railway native backups/PITR are Pro-only and unavailable to the current Hobby pilot.
The release-specific same-volume migration guard does not satisfy this drill. Sean
must separately approve either a plan change or a reviewed encrypted off-volume
backup mechanism before real data or broader production.

## Separate future approval

Actual alert delivery requires a reviewed adapter plus an exact, expiring,
single-use approval for action type `DELIVER_ALERT`, the selected `delivery_id`,
the matching owner scope, and the already reviewed immutable payload hash. A route
ID or route configuration alone is not an execution target and never authorizes
delivery, other messaging, connectors, or customer contact.
