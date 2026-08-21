# Independent Backup Provider Decision

Status: **pilot account and empty protected bucket configured; production use not authorized**

Scope: **IAC only**
Decision owner: **Sean**

## Recommendation

Use an IAC-owned **Backblaze B2** private bucket for the v0.1 independent
backup pilot. Enable Object Lock when the bucket is created, use a 30-day
default retention period in **compliance mode**, enable default SSE-B2
encryption, and upload only a client-side encrypted backup whose key remains
IAC-owned.

This is the best v0.1 fit because it provides the strongest simple retention
boundary of the reviewed low-cost options: compliance-mode retention cannot be
removed by any user or shortened before expiry. B2 is S3-compatible, so the
runtime can use a replaceable provider adapter instead of provider-specific
business logic.

## Reviewed options

| Option | Encryption | Retention protection | Pilot economics | Decision |
|---|---|---|---|---|
| Backblaze B2 | Optional default AES-256 server-side encryption; add IAC-owned client-side encryption | Compliance-mode Object Lock cannot be removed or shortened before expiry | First 10 GB free; then USD 6.95/TB per 30 days | **Recommended** |
| Cloudflare R2 Standard | Automatic AES-256 encryption of objects and metadata | Bucket lock blocks overwrite/delete, but a privileged configuration owner can remove lock rules | 10 GB-month, 1M writes, and 10M reads free; no R2 egress fee | Good fallback; weaker administrator-resistant retention |
| Amazon S3 | Default server-side encryption; optional customer-managed keys | Mature compliance-mode Object Lock | No minimum charge, but more account/IAM/KMS complexity for this small pilot | Revisit if IAC standardizes on AWS |

## Exact proposed control set

| Control | Required value |
|---|---|
| Account owner | IAC; never Sean's PERSONAL account |
| Bucket | Private, dedicated to Sean OS IAC backups, with no public URL |
| Object names | Opaque identifiers only; no customer, employee, or record content |
| Retention | 30-day default Object Lock in compliance mode |
| Provider encryption | Default SSE-B2 enabled before the first upload |
| Client encryption | Authenticated encryption before upload; key owned by IAC and stored only in an approved secret store |
| Writer access | Dedicated bucket-restricted application key; never the master key; no retention-administration capability |
| Restore access | Separate least-privilege credential available only for an approved restore window |
| Backup validation | SQLite integrity and foreign-key checks plus size and SHA-256 manifest before upload |
| Restore validation | New isolated target only; never overwrite `/data/iac-ai.db` |
| Cadence | Daily after the first supervised drill; retain 30 days |
| Cost boundary | Expected provider charge USD 0 at current size; Railway egress is USD 0.05/GB; hard approval ceiling remains CAD 15/month |
| Failure behavior | Keep production unchanged, record a scoped health incident, and require Sean for any recovery action |

The current database is well below the 10 GB free-storage allowance. Even after
normal growth, the CAD 15 ceiling provides ample margin. Any estimate approaching
that ceiling must pause new backup work and request a fresh approval.

## Configured Canada East pilot evidence — 2026-08-20

Sean approved the IAC-owned Backblaze B2 pilot with a CAD 15/month ceiling. A
separate IAC-owned Canada East account now contains one empty bucket,
`iac-sean-os-ca-east-20260820-v01-9k4m`,
with the following provider-console evidence:

| Control | Observed value |
|---|---|
| Bucket privacy | Private |
| Default provider encryption | Enabled (SSE-B2) |
| Object Lock | Enabled |
| Default retention | 30 days; each production receipt must separately prove COMPLIANCE mode |
| Files / size | 0 / 0 bytes |
| Application key | Not created or viewed in this setup run |
| Upload or restore | Not performed |
| Railway change or deployment | Not performed |
| Provider endpoint | `s3.ca-east-006.backblazeb2.com` |

The endpoint proves that the selected destination is in **Canada East (Toronto)**.
The earlier US East account and empty bucket remain untouched and out of scope; they
contain no files or application key. Deleting either requires a separate explicit
approval and is not necessary for the Canadian pilot.

## Approval boundary

The approved account and bucket setup in the evidence section is complete. The
following actions remain separately approval-gated:

1. adding billing information or incurring any charge;
2. generating, storing, or rotating application and encryption credentials;
3. adding Railway variables, deploying an adapter, or scheduling automatic uploads;
4. uploading any data or stopping the production worker;
5. running the isolated restore drill or deleting the unused US East pilot.

The exact production drill must still be represented by the deterministic package
from `scripts/prepare_backup_approval.py`. A conversational “approved” is not a
substitute for the package's exact hash-bound approval target.

## Proposed first-drill writer key — not created

The reviewed local contract restricts the first supervised key to the selected
bucket, the `backups/` prefix, and a maximum four-hour lifetime. Its exact allowlist
is `listBuckets`, `listAllBucketNames`, `readBucketEncryption`,
`readBucketRetentions`, `writeFiles`, and `readFileRetentions`. This permits SDK
bucket resolution, upload, preflight verification, and post-upload retention checks.

It excludes file download/list/delete, key administration, bucket mutation/deletion,
retention or legal-hold writes, governance bypass, replication, notification,
logging, and lifecycle administration. The uploader must rely on the already
configured default retention and cannot weaken it. A separate, expiring restore key
will be required for the isolated restore drill. The proposal/package generator is
non-creating and always emits `creation_authorized=false`.

Backblaze groups upload and hide-file operations under `writeFiles`; the credential
cannot delete a stored version, but the provider capability itself is broader than one
HTTP verb. The reviewed port calls only bucket-control reads, conditional Put Object,
and Get Object Retention. It contains no hide, delete, download, list-file, retention-
write, or credential-management operation, and release verification fixes that surface.

## Client-encryption implementation — local only

The reviewed local implementation uses streaming AES-256-GCM with a fresh random
96-bit nonce for every artifact and authenticates the canonical plan-bound envelope
header as additional data. It verifies the approved plaintext hash and byte count,
creates ciphertext with mode `0600` and no overwrite, and never records a filesystem
path or credential in its evidence. A restore decrypts into a private quarantine file;
only a valid authentication tag, exact plan/key references, and exact plaintext hash
can publish the new file, and an existing destination is never overwritten.

The encryption-key resolver remains an injected interface. Its reviewed Railway adapter
reads one fixed managed variable only after exact activation, yields a mutable 32-byte
buffer, and wipes that buffer on success or failure. Railway retains the original managed
value for the process lifetime, so production still depends on Railway's hosting-secret
boundary and a short-lived activation window. No key is present now. The exact reviewed
dependency is `cryptography==50.0.0`.

The local Backblaze port is also disconnected by default. Its reviewed factory reads two
fixed Railway managed variables, binds them to the exact HTTPS Canada endpoint and
`ca-east-006` signing region, forces signed payloads and one total request attempt, and
passes the constructed client into the port without persisting the values. Before writing
the port rechecks default SSE-B2 and exact
30-day compliance retention, uses a conditional create under `backups/`, explicitly
requests SSE-B2, and verifies the returned object version and compliance expiry. Any
uncertain result after the write begins requires manual reconciliation and prohibits an
automatic retry. Provider support for the conditional-create header remains a first-drill
compatibility gate; an unsupported response aborts activation.

The SDK is pinned to `boto3==1.43.76` and is deployed in the default-off runtime at
exact commit `5eb51c2`. None of the three managed values exists, so the provider client
cannot be constructed and no upload or restore is enabled.

## Official evidence reviewed

- [Backblaze B2 pricing](https://www.backblaze.com/cloud-storage/pricing)
- [Backblaze B2 Object Lock](https://www.backblaze.com/docs/cloud-storage-object-lock)
- [Backblaze B2 server-side encryption](https://www.backblaze.com/docs/cloud-storage-server-side-encryption)
- [Backblaze B2 S3-compatible API](https://www.backblaze.com/apidocs/introduction-to-the-s3-compatible-api)
- [Backblaze B2 data regions](https://www.backblaze.com/docs/cloud-storage-data-regions)
- [Backblaze B2 application-key capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities)
- [Backblaze B2 S3-compatible app keys](https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys)
- [PyCA cryptography authenticated AES-GCM guidance](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)
- [PyCA cryptography 50.0.0 release](https://pypi.org/project/cryptography/)
- [Backblaze Boto3 configuration guide](https://www.backblaze.com/docs/cloud-storage-get-started-with-a-backblaze-integration)
- [Botocore client configuration and retry controls](https://botocore.amazonaws.com/v1/documentation/api/latest/reference/config.html)
- [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/)
- [Cloudflare R2 data security](https://developers.cloudflare.com/r2/reference/data-security/)
- [Cloudflare R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
- [Amazon S3 encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryption.html)
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [Railway pricing](https://docs.railway.com/pricing)
