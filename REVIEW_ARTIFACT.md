# Sean OS v0.1 — Local Review Artifact

This change set is local-only. It has not been pushed, deployed, connected to real data, or assigned to a production owner.

## Scope

- Canonical scoped database and deterministic migrations
- Durable queues, leases, retries, budgets, receipts, scheduling, and workers
- Approval policies, kill switch, immutable audit, secret scanning, and sale export
- Chief of Staff and Revenue Agent synthetic internal loops
- Scheduled reports, recovery drills, locked connectors, and ChatGPT command boundary

## Required verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/recovery_drill.py
python3 scripts/status.py
python3 -m compileall -q sean_os scripts
```

## Review boundaries

- No live connector is enabled.
- No external or irreversible action handler is registered.
- No production deployment is authorized.
- No GitHub remote is configured.
- Repository ownership and destination must be decided before any push.

## Rollback

The local source tree may be copied or archived. Database upgrades require a verified backup; restore refuses overwrite and validates integrity. Production rollback is not yet applicable because no production environment exists.
