# Sean OS Production Drill Plan

This plan is evidence only. It does not authorize a production drill, alert
delivery, live data, a new service, or spending.

## Approval package

Before scheduling the drill, Sean approves one exact package containing:

- IAC environment and worker service identifier;
- drill window and operator;
- independent backup destination, identifier, lock/retention policy, access owner,
  and at-rest encryption evidence appropriate to the approved environment;
- escalation route ID and non-secret destination reference;
- maximum expected cost and rollback owner;
- permission to activate and clear the production kill switch.

PERSONAL infrastructure, records, destinations, and credentials are excluded.

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
