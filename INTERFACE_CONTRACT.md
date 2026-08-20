# Sean OS v0.1 — ChatGPT Interface Contract

ChatGPT is the intended primary conversational interface, not a database administrator or autonomous credential holder.

## Boundary

- The interface submits authenticated commands to `/v1/commands` and receives a durable work ID.
- Commands execute asynchronously through the same queue, policy registry, budgets, approvals, audit log, and kill switch as all other work.
- The interface may read only the status or result of commands submitted by its own principal.
- Request IDs are immutable and idempotent. Reusing an ID with different content is rejected.
- Request bodies are capped at 1 MB and response caching is disabled.
- Failed authentication is audited without logging the bearer token or request body.

## Exposed commands

| Command | Effect |
|---|---|
| `CREATE_RECORD` | Creates a validated IAC core record except direct Approval bypass |
| `UPDATE_RECORD` | Performs optimistic-versioned IAC payload replacement |
| `LINK_RECORDS` | Creates a validated relationship between IAC records |
| `CAPTURE_IDEA` / `EVALUATE_IDEA` | Captures and evaluates a durable idea |
| `CREATE_IAC_GOAL` | Creates an IAC goal after queued policy execution |
| `CREATE_PROJECT` | Creates a bounded Chief of Staff project |
| `QUALIFY_REVENUE` | Runs synthetic-only Revenue Agent qualification |
| `IMPORT_CLAUDE_ARTIFACT` | Imports a synthetic artifact only when its connector gate is enabled |
| `GENERATE_REPORT` | Creates a local operational report |

Arbitrary action names, extra fields, PERSONAL scope, approvals, credentials, external sends, deployments, financial transfers, and connector activation are not exposed.

Scoped reads are available for individual records, filtered record lists, command status/results, and the audit trace. PERSONAL records and audit events are not visible to the IAC interface principal.

## Production prerequisites

- Replace the local static token with managed identity or a rotated secret stored outside source control.
- Terminate TLS at an approved private ingress and restrict network access.
- Run an independent authentication, rate-limit, abuse, and penetration review.
- Approve the exact ChatGPT integration method and data-retention behavior.
