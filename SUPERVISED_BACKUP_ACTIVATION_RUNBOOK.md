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
package, and a `PREFLIGHT_VALIDATED` transfer row. It prints only bounded hashes/status
and performs no network request, key creation, secret placement, upload, restore, or
approval. Existing files are never overwritten.

Stop if the command reports any other data mode, transfer status, or external action.

## Remaining distinct gates

1. Review the activation hash, exact plan hash, object key, window, byte ceiling, and
   CAD 15 ceiling.
2. Approve and create the exact four-hour Backblaze writer key. Do not expose its value
   in chat, files, source control, logs, or receipts.
3. Approve placing the two writer values and one 32-byte encryption-key value into the
   three fixed Railway managed-variable names.
4. Create, decide, and consume the exact single-use transfer approval bound to the staged
   plan. A conversational approval is not a substitute for the stored approval record.
5. Approve applying the reviewed non-secret runtime contract for one supervised window.
   This restarts the service and enables the worker path only for the staged synthetic plan.
6. Verify the provider receipt, exact Canada endpoint, conditional create, SSE-B2,
   compliance retention, worker health, and that the bucket contains exactly one object.
7. Separately approve disabling execution and removing or rotating pilot managed values.
8. Request a new approval before any isolated restore. Real IAC data remains prohibited.

## Automatic aborts

- incomplete or mismatched runtime values;
- path outside `/data`, symlink, non-private source, or changed source hash/size;
- wrong bucket, endpoint, region, object key, identity reference, window, cost, or lease;
- kill switch active or approval absent/expired;
- missing SSE-B2 or exact 30-day compliance retention;
- existing object or unsupported conditional create;
- any ambiguous or post-upload failure. Such a transfer becomes
  `RECONCILIATION_REQUIRED` and cannot retry automatically.

Do not delete a possible provider object during reconciliation. Inspection, cleanup,
restore, billing changes, and any real-data use each require a new explicit approval.
