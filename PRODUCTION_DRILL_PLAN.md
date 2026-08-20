# Sean OS Production Drill Plan

This plan is evidence only. It does not authorize a production drill, alert
delivery, live data, a new service, or spending.

## Approval package

Before scheduling the drill, Sean approves one exact package containing:

- IAC environment and worker service identifier;
- drill window and operator;
- backup destination, retention, and encryption owner;
- escalation route ID and non-secret destination reference;
- maximum expected cost and rollback owner;
- permission to activate and clear the production kill switch.

PERSONAL infrastructure, records, destinations, and credentials are excluded.

## Ordered drill

| Phase | Controlled action | Required evidence | Abort condition |
|---|---|---|---|
| Baseline | Confirm one private worker, IAC profile, healthy database, attached volume, and zero live connectors | Timestamped health snapshot and configuration review | Any ownership, scope, exposure, or integrity mismatch |
| Backup | Create encrypted production backup without inspecting records | Backup identifier, size, hash, retention, owner, and success result | Encryption, ownership, or destination cannot be proven |
| Restore | Restore to a new isolated destination | Integrity check, foreign-key check, schema version, sentinel verification | Existing destination would be overwritten or any check fails |
| Kill switch | Activate switch and submit synthetic `NOOP` work | Work is not claimed; audit event records denial | Any external handler is enabled or work executes |
| Worker recovery | Stop/restart the single worker while switch remains active | Stale/no-worker alert classifications and clean restart evidence | Multiple workers appear or volume is absent |
| Alert route | Generate synthetic escalation envelopes only | Correct severity filtering, IAC route ownership, `delivery_authorized=false` | A message is delivered or a secret appears in evidence |
| Recovery | Clear switch, process one synthetic `NOOP`, then return to idle | Successful work receipt, healthy snapshot, no dead letters | Integrity or policy check fails |

## Pass criteria

The drill passes only if every phase has timestamped audit evidence, the restore
never overwrites production, no real record content is copied into evidence, no
external alert is delivered, the IAC/PERSONAL boundary remains intact, and the
worker returns healthy with one replica. Any failure leaves the kill switch on
until the rollback owner reviews the evidence.

## Separate future approval

Actual alert delivery requires a reviewed adapter plus an exact, expiring,
single-use approval for action type `DELIVER_ALERT` and the selected route ID.
Enabling a route does not authorize other messaging, connectors, or customer
contact.
