# Horizontal scale operations and evidence

## Deployment topology

RouteCairn scales the PostgreSQL fleet ingress (`routecairn fleet`) independently of the dashboard. Fleet replicas own no SQLite database. PostgreSQL shares worker enrollment, bound identities, nonces, durable jobs, lease generations, the transactional outbox, object metadata and leader leases. Claims use `FOR UPDATE SKIP LOCKED`; completion and renewal require a live lease and an eligible worker generation.

The administrative dashboard still owns sessions, organizations, plans, approvals, vault metadata and scan execution in SQLite. Run **one dashboard with persistent storage**. A dedicated PostgreSQL session advisory lock prevents two distributed dashboards from starting concurrently; losing that session shuts down the owner. The Helm chart uses a PVC and `Recreate`. This is not a migration of all administrative state to PostgreSQL and does not provide active-active dashboard availability.

Scale fleet replicas or distinct enrolled workers. Never clone a signing identity across worker pods. Each Helm `workerPools[].workers[]` member references its own enrollment Secret and state file; jobs select exact network zones and required capabilities. Workers use HTTPS with trusted CA configuration and can add OIDC or mTLS alongside Ed25519 request signatures. Bind the expected issuer/subject or certificate fingerprint when approving enrollment. Unbound OIDC identities must include the exact `routecairn_worker_id` claim.

## Storage, events and scheduling

Create the object bucket explicitly with `routecairn initialize-evidence-storage`; this idempotent command enables versioning. It needs administrative bucket privileges once. Fleet readiness checks connectivity without creating buckets. Runtime evidence access needs only the configured prefix and object operations. Uploads bind tenant, artifact, digest and size; downloads verify streamed size and SHA-256 before publication. Configure `AES256` or `aws:kms` encryption for production. `provider` delegates encryption to the storage deployment and is used by the unencrypted isolated MinIO acceptance fixture; it does not assert server-side encryption.

PostgreSQL outbox events commit with job changes. `LISTEN/NOTIFY` carries only an event identifier and wakes bounded polls. A connected consumer recovers from its in-memory cursor after reconnect; a newly started consumer takes an authoritative state snapshot. This is not an exactly-once durable subscription API. Maintenance retains events for seven days. Dashboard SSE reads persisted scan-event sequence numbers, handles write backpressure, and drains terminal backlogs before closing.

Leader leases have increasing fencing tokens. `fencedTransaction` locks and verifies the leader row before protected writes; losing leadership prevents a stale fenced transaction from committing. External side effects require a downstream fencing/idempotency contract of their own. Lease recovery is bounded in batches of 100 and exhausted attempts receive terminal timestamps. Draining workers retain outstanding leases but cannot claim new work; revocation invalidates their generation and leases.

Draining fleet instances close refused connections so ingress stops reusing them. Workers retry HTTP 503 refusals for heartbeat, renewal and completion at most three times within the original request deadline, signing each attempt with a fresh nonce. Lost successful claims recover through leases rather than automatic claim replay.

## Compose and Helm

Build `deploy/control-plane/Dockerfile` and `deploy/control-plane/Minio.Dockerfile`. The latter builds pinned MinIO community source `07c3a429bfed`; legacy MinIO registry images may be unavailable. MinIO is AGPL licensed; its license is included in the resulting source-built image.

Use the base Compose file plus `deploy/control-plane/compose.distributed.yaml`. Supply the named credential files outside version control. The overlay creates two fleet replicas, a persistent dashboard, PostgreSQL, MinIO, the bucket initializer, an OTLP collector and HTTPS Caddy routing. Set owned domain/DNS/TLS values before public use. For Kubernetes, see [Helm setup](../deploy/helm/routecairn/README.md). Provision PostgreSQL, an encrypted bucket and an OTLP endpoint separately. Restrict CIDRs to those services and use an ingress that preserves authenticated identity proofs. Size total PostgreSQL connections as fleet replicas multiplied by pool size, plus listeners, dashboard and maintenance connections. Back up both PostgreSQL and the dashboard PVC; object versioning is not a substitute for backup.

Direct TLS mode requires a client CA. Proxy-attested mTLS requires a configured proof secret, freshness, and enrolled certificate binding. HTTPS alone is transport encryption, not workload mTLS. KMS envelope encryption uses authenticated context and bounded envelopes; production KMS and HSM key policies remain operator-managed.

## Reproducible acceptance

On Windows, with Node, Python and Git OpenSSL available:

```powershell
powershell -File scripts/setup-scale-lab.ps1
npm run build:release
npm run acceptance:scale -- --output .routecairn-scale-lab/fresh-native-run
```

The setup script verifies pinned archive SHA-256 values and builds MinIO from a pinned Go module. The acceptance runner refuses existing output directories, hashes source inputs before and after, requires every selected test to pass, requires runtime proof and confirmed process cleanup, and retains checksums. It creates fresh loopback PostgreSQL, MinIO, Moto and OTLP collector instances. It executes concurrent claims across four workers, independent CLI ingress processes, PostgreSQL restart, lost notifications, stale leases, replay rejection, fencing, storage corruption and real OIDC/mTLS handshakes. Moto exercises the AWS SDK request/response path; it is not managed AWS KMS or an HSM.

Kubernetes acceptance requires a disposable cluster, Helm, kubectl and a preloaded application image plus the pinned MinIO image:

```console
npm run acceptance:scale:kubernetes -- --context routecairn-scale-local \
  --kubeconfig /path/to/isolated/kubeconfig --image routecairn/scale-lab:local \
  --output .routecairn-scale-lab/fresh-kubernetes-run
```

Only explicitly named `routecairn-scale-*` contexts are accepted. The runner owns a random namespace, creates private ephemeral credentials, installs the actual chart, verifies zone-bound signed worker pods over HTTPS, replaces a fleet pod, scales three replicas to four and back, restarts the persistent dashboard, and confirms namespace deletion. Results record actual pod image identifiers and cluster version. Secrets and private setup files stay under the ignored lab folder; retain only sanitized proof and checksums. Do not present a partial/failed run as deployment proof.

The retained local acceptance is self-maintained, on a single-node K3s cluster. It does not prove multi-node failover, production throughput, public deployment, managed AWS KMS, HSM operation or independent review. The administrative singleton remains a material availability limitation.
