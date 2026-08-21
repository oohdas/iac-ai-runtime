# Sean OS v0.1 — Acceptance Audit

Audit date: 2026-08-21. Source: approved Master Specification §14. “Partial” is not treated as accepted.

| # | Acceptance criterion | Status | Current evidence | Remaining proof/work |
|---:|---|---|---|---|
| 1 | Every core entity through primary interface | Proven locally | Scoped create/retrieve/list/update/link for IAC core records; Approval creation only through bounded request flow; Audit records created automatically and scope-filtered for retrieval | Production Sean identity and approval UX verification |
| 2 | Enforced metadata and scope isolation | Proven locally | Scope, confidentiality, provenance, portability, principals, versioning, effective/expiry timestamps, confidence, retention, derived currentness, and fail-closed tests | Production verification only |
| 3 | Deterministic sale export excludes PERSONAL/secrets | Proven locally | Deterministic scoped export, SHA-256 manifest, recursive secret rejection, pre-export rescan, legacy-secret fail-closed test | Production data-classification verification |
| 4 | Complete project state machine | Proven locally | ACTIVE/INCUBATOR/PAUSED/KILLED tests; KILLED requires rationale/reopen trigger | Production verification only |
| 5 | Chief of Staff full charter and reports | Proven locally | Capture/evaluation, bounded projects, portfolio scoring, capacity limits, low-fit challenge, lifecycle control, and once-daily durable portfolio maintenance dispatched before scheduled morning/weekly reports; only agent-owned work can be paused automatically and missing metrics are surfaced without mutation | Live deadline/calendar conflict inputs remain connector-gated |
| 6 | Revenue Agent ROI portfolio and boundaries | Proven locally | All six opportunity classes; margin/probability/cost/capacity/Sean-time/fit/evidence comparison; internal projects; retained rejections/reopen triggers; no external authority | Live opportunity inputs remain connector-gated |
| 7 | AI project self-pause/kill and visibility | Proven locally | Ownership checks, evidence decisions, agent-only pause/kill, human-review recommendations, audit trace, report-visible lifecycle and decision | Production verification only |
| 8 | Risky actions blocked pending approval | Proven locally | Registered policies, exact expiring approval, budgets, prohibited action tests, kill switch | Reverify per live connector before activation |
| 9 | Immutable material-action trace | Proven locally | Append-only audit, allow/deny/fail, policy result, evidence IDs, tool/model fields, costs, outcomes, rollback status, execution receipts, scoped trace query; durable work/result boundaries reject secret-like content, operational error/audit evidence redacts it, and interface errors/authentication audit cannot reflect secret-bearing input | Production tool/model identifiers require live worker configuration |
| 10 | Claude/Claude Code repository delivery | Proven locally | IAC-owned private repository; synthetic-only, no-network coding delivery through durable queue; exact project/task links; immutable branch/review/path/test evidence; durable status; activity and budgeted cost trace; duplicate suppression | Live Claude/model and Git-host mutation require separate identity, budget, and approval |
| 11 | ChatGPT canonical query/commands and model portability | Proven locally | Authenticated scoped CRUD/link/query/audit gateway; active-incident query; separate Sean-operator incident resolution; restart-safe delivery stage/request/decide/authorize flow; backup-transfer review/request plus separate Sean-only decision/authorization over exact conditions; in-memory HTTP contract proof; asynchronous commands; canonical DB independent of model; arbitrary actions blocked | Approved production identity and ChatGPT connection |
| 12 | Cloud deployment security/recovery/monitoring | Partial | Private IAC Railway pilot at exact commit `3a5ea9d`, one replica, persistent volume, no public domain, permanent IAC profile, and guarded production v17→v18 migration; live health proves integrity, current IAC worker, kill switch off, and zero attention. Deployed schema v18 includes the default-off reconciliation-safe upload worker, hash-bound operators, distinct read-only restore identity, durable exact restore authorization/leases/health, exact-version read port, authenticated non-overwriting IAC database verification, and a separate one-shot worker that the continuous container cannot invoke; the IAC-owned Backblaze destination remains an empty private Canada East bucket with SSE-B2 and 30-day Object Lock. A verified local follow-up removes a stale schema-incompatible source baseline from future pilot packages | Deploy the exact rollback-binding follow-up before staging. Production synthetic staging, writer-key creation, upload managed values, one approved synthetic upload, restore staging, restore-key creation, restore managed values, one-shot isolated restore, secret review/rotation, and the controlled drill require separate Sean approvals; real IAC data remains prohibited |
| 13 | Scheduled reports with semantic distinctions | Proven locally | Idempotent daily/weekly scheduling; facts/estimates/inferences/recommendations; confidence/currentness; score-ranked priorities; active approvals separated from terminal outcomes; completed durable work, project/lifecycle changes, deadline risks, exceptions, scope-filtered health/incidents, spend, and unavailable-source disclosure | Live deadline/calendar content remains connector-gated |
| 14 | Full end-to-end scenario | Proven locally | Automated scenario: capture idea → evaluate → create project → import reversible research → request customer-contact approval → Sean denies → report records outcome | Production verification only |

## Current conclusion

All fourteen criteria now have complete local synthetic proof except the production-
environment portions of criterion 12. Repository ownership and the isolated Railway
pilot are established. The remaining acceptance gate is operational evidence from an
approved encrypted backup/restore, least-privilege identity review, and controlled
production drill; live integrations remain later, separately approved activations.

## Canonical reproduction

Run `python3 scripts/verify_release.py`. The 2026-08-21 local candidate passes
compilation, 253 automated tests, bridge-integrity, durable secret-boundary,
independent-backup approval, encryption, managed-value, disconnected provider, and
non-executing supervised-pilot/operator contracts, distinct restore identity, durable
restore authorization, exact-version read, state-only restore operator, and one-shot
worker contracts, continuous internal portfolio maintenance, complete operational-report
coverage, plus container/workflow safety and a manifested schema-v18 recovery drill.
Direct regression anchors
include `test_primary_interface_can_create_query_update_and_link_core_records`,
`test_full_idea_to_approval_decision_to_report_scenario`,
`test_synthetic_coding_delivery_links_project_task_review_cost_and_activity`, and
`test_guard_backs_up_deployed_v17_and_adds_restore_outbox`.
