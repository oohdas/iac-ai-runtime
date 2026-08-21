# Sean OS v0.1 — Isolated Restore Runbook

This runbook describes the reviewed control sequence; it authorizes nothing. The code is
local only until an exact commit is separately approved for push/deployment. Production
staging, restore-key creation, managed values, state authorization, network download, and
execution are distinct approvals.

## Non-negotiable boundary

- IAC scope and IAC-owned infrastructure only; no PERSONAL data or credentials.
- Use synthetic IAC sentinel data for the first drill.
- Restore only one exact retention-locked Backblaze object version from Canada East.
- Use a restore identity distinct from the upload writer. It may read files and retention
  evidence but cannot list files, write, delete, administer keys/buckets, mutate retention
  or legal holds, or bypass governance.
- Publish only a new mode-0600 SQLite file inside a private isolated directory. Never
  overwrite or attach it as the production database during the drill.
- Keep the ordinary continuous worker unaware of this path. Run at most one explicitly
  invoked restore worker after every preceding gate is evidenced.
- Keep the CAD ceiling at or below 15 and the key/approval window at or below four hours.

## Gate sequence

1. Verify the upload is complete and the durable upload receipt proves the exact object
   version, ciphertext/plaintext hashes and sizes, AES-256-GCM client encryption, provider
   AES-256, compliance retention, no overwrite, and the IAC profile.
2. Prepare the non-creating restore-key package and hash-bound restore plan with
   `scripts/prepare_backup_restore.py`. This performs no database mutation, credential
   lookup, network call, download, decryption, or restore.
3. With a separate approval to mutate the production database, run
   `scripts/restore_operator.py stage ...`. It re-verifies the authoritative upload
   evidence, records schema-v18 durable state, and records a no-action preflight only.
4. Run `scripts/restore_operator.py review IAC_DB RESTORE_PLAN_SHA256`. Confirm the exact
   object version, hashes, restore identity, isolated target, window, cost ceiling, and
   `PREFLIGHT_VALIDATED` status. Retain the returned `review_sha256`.
5. The IAC restore interface may request one exact approval using the current review hash.
   Sean separately decides that request. A stale review or changed condition fails closed.
6. While every restore execution and managed-secret value is absent, Sean may authorize
   state using the newly reviewed hash and an exact plan-hash confirmation. Authorization
   consumes the single-use approval but does not claim work or resolve a secret.
7. With separate approvals, create the short-lived read-only restore key and place only
   the reviewed managed values. Never copy secret values into chat, source, receipts, logs,
   command history, or durable database payloads.
8. Configure the complete non-secret restore contract and explicitly invoke
   `scripts/restore_worker.py` once. Partial configuration or raw direct secrets abort.
   The worker claims one exact authorized lease before resolving managed values.
9. Accept completion only if the receipt re-proves the exact version and retention,
   ciphertext and plaintext hashes/sizes, authenticated client decryption, SQLite
   integrity, zero foreign-key violations, exact schema, permanent IAC profile, isolated
   target, no overwrite, and no persisted credential/path.
10. Turn off/remove the temporary execution configuration and expire/rotate the restore
    credential under a separate approved operational action. Preserve receipts and audit.

The full operator sequence is deliberately verbose: `review` must be run again after each
state mutation, and every `request`, `decide`, and `authorize` command must use the newest
review hash.

## Failure and recovery

- Before a plaintext destination exists, a failure releases the lease for a bounded retry;
  attempts stop at three and health reports `BACKUP_RESTORE_FAILED`.
- If a plaintext destination may exist, or durable completion fails after publication,
  the item becomes `RECONCILIATION_REQUIRED`. Automatic retry is prohibited and health
  reports a critical reconciliation alert.
- Enable the Sean kill switch to block new claims and every execution guard.
- Do not delete, overwrite, attach, or promote any artifact during investigation. Verify
  the isolated file and durable receipt first, then obtain an exact approval for any
  cleanup, promotion, or credential change.

## Required evidence

- Exact approved commit and successful schema migration to v18.
- Current review hashes for request, decision, and state authorization.
- Separate key-creation and managed-value approvals with no secret disclosure.
- One bounded one-shot worker result and a path-free completion receipt.
- Healthy runtime evidence with zero failed or reconciliation-required restore items.
- Sentinel record recovered from the isolated database while production remains unchanged.
