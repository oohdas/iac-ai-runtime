# Supervised Synthetic Backup Activation Runbook

Status: **reviewed local procedure; no production action authorized**

Scope: IAC only. The first upload must use the isolated synthetic source created by
`scripts/prepare_supervised_backup_activation.py`; it must not copy the production
database or contain customer, employee, financial, or other real IAC data.

## Preconditions

- the exact candidate commit has passed `python3 scripts/verify_release.py`;
- Sean has separately approved its push and Railway deployment;
- Railway reports that exact commit healthy, private, one replica, and attached to the
  original `/data` volume;
- the package's candidate and deployed-baseline commits both equal that exact healthy
  release; an older release must never be used against the newer database schema;
- the Canada East bucket is still empty, private, SSE-B2 enabled, and protected by
  30-day compliance retention;
- no application key or Railway managed value is created before its distinct approval.

## Stage the synthetic plan — separate approval required

Only after the candidate is deployed, run one supervised console command inside the
IAC Railway service, replacing the placeholders with the exact reviewed commit and
timezone-aware window:

```text
python scripts/prepare_supervised_backup_activation.py \
  /data/iac-ai.db \
  /data/backup-staging \
  <FULL_CANDIDATE_SHA> \
  <WINDOW_START_ISO8601> \
  --duration-minutes 120
```

The command creates a private synthetic SQLite source, mode-0600 manifest and activation
package, a durable synthetic-only activation attestation, and a `PREFLIGHT_VALIDATED`
transfer row. It prints only bounded hashes/status and performs no network request, key
creation, secret placement, upload, restore, or approval. Existing files are never
overwritten. Recovery remains bound to the guarded pre-migration database backup; the
package never treats older source code as a schema rollback target.

Stop if the command reports any other data mode, transfer status, or external action.

## Review and authorize durable state — separate approval required

Keep every backup execution, worker-path, direct-secret, and managed-secret environment
value absent. During the exact active window, use the hashes printed by each immediately
preceding review. Replace only the bracketed values:

```text
python scripts/backup_operator.py review /data/iac-ai.db <PLAN_SHA256>

python scripts/backup_operator.py request /data/iac-ai.db <PLAN_SHA256> \
  --expected-review-sha256 <REVIEW_SHA256> \
  --expires-at <TIMEZONE_AWARE_EXPIRY_WITHIN_WINDOW>

python scripts/backup_operator.py review /data/iac-ai.db <PLAN_SHA256>

python scripts/backup_operator.py decide /data/iac-ai.db <PLAN_SHA256> <APPROVAL_ID> \
  --expected-review-sha256 <REVIEW_SHA256> \
  --approve --reason "Exact synthetic transfer reviewed"

python scripts/backup_operator.py review /data/iac-ai.db <PLAN_SHA256>

python scripts/backup_operator.py authorize /data/iac-ai.db <PLAN_SHA256> <APPROVAL_ID> \
  --expected-review-sha256 <REVIEW_SHA256> \
  --confirm-plan-sha256 <PLAN_SHA256>
```

The review revalidates the private source, manifest, activation package, synthetic data
attestation, transfer plan, preflight, approval conditions, window, retention, endpoint,
identity references, byte count, and cost ceiling. Every mutation rejects a stale review.
The final command only consumes durable approval state; it refuses to run outside the
window or while any backup execution or secret value is present, and it neither claims
the transfer nor encrypts or uploads anything. Run `review` again after every mutation.

## Remaining distinct gates

1. Verify the state-only authorization reports `AUTHORIZED`, the approval reports
   `CONSUMED`, and all three operation flags remain false.
2. Separately approve and create the exact four-hour Backblaze writer key. Do not expose its value
   in chat, files, source control, logs, or receipts.
3. Approve placing the two writer values and one 32-byte encryption-key value into the
   three fixed Railway managed-variable names while execution remains disabled.
4. Approve applying the reviewed, complete non-secret runtime contract for one supervised
   window. This restarts the service and enables the worker path only for the already
   authorized synthetic plan.
5. Verify the provider receipt, exact Canada endpoint, conditional create, SSE-B2,
   compliance retention, worker health, and that the bucket contains exactly one object.
6. Separately approve disabling execution and removing or rotating pilot managed values.
7. Request a new approval before any isolated restore. Real IAC data remains prohibited.

## Automatic aborts

- incomplete or mismatched runtime values;
- path outside `/data`, symlink, non-private source, or changed source hash/size;
- wrong bucket, endpoint, region, object key, identity reference, window, cost, or lease;
- missing/changed synthetic activation evidence, stale review, configured runtime during
  state authorization, kill switch active, or approval absent/expired;
- missing SSE-B2 or exact 30-day compliance retention;
- existing object or unsupported conditional create;
- any ambiguous or post-upload failure. Such a transfer becomes
  `RECONCILIATION_REQUIRED` and cannot retry automatically.

Do not delete a possible provider object during reconciliation. Inspection, cleanup,
restore, billing changes, and any real-data use each require a new explicit approval.
