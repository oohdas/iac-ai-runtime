# Sean OS v0.1 — Acceptance Audit

Audit date: 2026-08-20. Source: approved Master Specification §14. “Partial” is not treated as accepted.

| # | Acceptance criterion | Status | Current evidence | Remaining proof/work |
|---:|---|---|---|---|
| 1 | Every core entity through primary interface | Proven locally | Scoped create/retrieve/list/update/link for IAC core records; Approval creation only through bounded request flow; Audit records created automatically and scope-filtered for retrieval | Production Sean identity and approval UX verification |
| 2 | Enforced metadata and scope isolation | Proven locally | Scope, confidentiality, provenance, portability, principals, versioning, effective/expiry timestamps, confidence, retention, derived currentness, and fail-closed tests | Production verification only |
| 3 | Deterministic sale export excludes PERSONAL/secrets | Proven locally | Deterministic scoped export, SHA-256 manifest, recursive secret rejection, pre-export rescan, legacy-secret fail-closed test | Production data-classification verification |
| 4 | Complete project state machine | Proven locally | ACTIVE/INCUBATOR/PAUSED/KILLED tests; KILLED requires rationale/reopen trigger | Production verification only |
| 5 | Chief of Staff full charter and reports | Proven locally | Capture/evaluation, bounded projects, portfolio scoring, capacity limits, low-fit challenge, lifecycle control, scheduled morning/weekly reports | Live deadline/calendar conflict inputs remain connector-gated |
| 6 | Revenue Agent ROI portfolio and boundaries | Proven locally | All six opportunity classes; margin/probability/cost/capacity/Sean-time/fit/evidence comparison; internal projects; retained rejections/reopen triggers; no external authority | Live opportunity inputs remain connector-gated |
| 7 | AI project self-pause/kill and visibility | Proven locally | Ownership checks, evidence decisions, agent-only pause/kill, human-review recommendations, audit trace, report-visible lifecycle and decision | Production verification only |
| 8 | Risky actions blocked pending approval | Proven locally | Registered policies, exact expiring approval, budgets, prohibited action tests, kill switch | Reverify per live connector before activation |
| 9 | Immutable material-action trace | Proven locally | Append-only audit, allow/deny/fail, policy result, evidence IDs, tool/model fields, costs, outcomes, rollback status, execution receipts, scoped trace query; durable work/result boundaries reject secret-like content, operational error/audit evidence redacts it, and interface errors/authentication audit cannot reflect secret-bearing input | Production tool/model identifiers require live worker configuration |
| 10 | Claude/Claude Code repository delivery | Proven locally | IAC-owned private repository; synthetic-only, no-network coding delivery through durable queue; exact project/task links; immutable branch/review/path/test evidence; durable status; activity and budgeted cost trace; duplicate suppression | Live Claude/model and Git-host mutation require separate identity, budget, and approval |
| 11 | ChatGPT canonical query/commands and model portability | Proven locally | Authenticated scoped CRUD/link/query/audit gateway; active-incident query; separate Sean-operator incident resolution; restart-safe delivery stage/request/decide/authorize flow; backup-transfer review/request plus separate Sean-only decision/authorization over exact conditions; in-memory HTTP contract proof; asynchronous commands; canonical DB independent of model; arbitrary actions blocked | Approved production identity and ChatGPT connection |
| 12 | Cloud deployment security/recovery/monitoring | Partial | Private IAC Railway pilot at exact commit `139daf3`, one replica, persistent volume, no public domain, permanent IAC profile, live healthy worker as uid/gid 10001 with no effective capabilities, production v7→v12 migration behind a verified same-volume backup, automatic restore and recovery hold, local backup/restore and kill-switch drills, deterministic incidents, default-off monitor, exact approval-gated outbox, leased no-network synthetic processor, diagnostics and fresh-approval reset; the selected IAC-owned Backblaze destination is an empty private Canada East bucket with SSE-B2 and default 30-day Object Lock verified; transfer contract v3 and single-use authorization bind the exact endpoint, identities, window, cost, object, hashes, and provider receipt; the non-creating writer-key contract is bucket/prefix/four-hour restricted; streaming AES-256-GCM and authenticated quarantine restore are implemented locally; the injected Backblaze port enforces conditional create, SSE-B2, compliance retention, and no ambiguous retry; fixed Railway managed-value adapters bind the exact HTTPS Canada endpoint; a hash-bound supervised package binds the actual infrastructure to synthetic-only data and authorizes nothing | Exact candidate push/deployment, writer-key creation, three Railway managed values, one approved synthetic upload, isolated synthetic restore, secret review/rotation, and the controlled production drill require Sean approval; real IAC data remains prohibited |
| 13 | Scheduled reports with semantic distinctions | Proven locally | Idempotent daily/weekly scheduling; facts/estimates/inferences/recommendations; confidence/currentness; priorities, approvals, exceptions, scope-filtered health and active incidents, spend, lifecycle, portfolio decisions, changes, unavailable-source disclosure | Live deadline/calendar content remains connector-gated |
| 14 | Full end-to-end scenario | Proven locally | Automated scenario: capture idea → evaluate → create project → import reversible research → request customer-contact approval → Sean denies → report records outcome | Production verification only |

## Current conclusion

All fourteen criteria now have complete local synthetic proof except the production-
environment portions of criterion 12. Repository ownership and the isolated Railway
pilot are established. The remaining acceptance gate is operational evidence from an
approved encrypted backup/restore, least-privilege identity review, and controlled
production drill; live integrations remain later, separately approved activations.

## Canonical reproduction

Run `python3 scripts/verify_release.py`. The 2026-08-20 release candidate passes
compilation, 197 automated tests, bridge-integrity, durable secret-boundary,
independent-backup approval, encryption, managed-value, disconnected provider, and
non-executing supervised-pilot contracts, plus container/workflow safety checks and a
manifested schema-v15 backup/restore drill.
Direct regression anchors
include `test_primary_interface_can_create_query_update_and_link_core_records`,
`test_full_idea_to_approval_decision_to_report_scenario`,
`test_synthetic_coding_delivery_links_project_task_review_cost_and_activity`, and
`test_deployed_schema_v7_migrates_to_v15_without_losing_state`.
