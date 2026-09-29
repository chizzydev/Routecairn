# RouteCairn Helm deployment

The chart runs multiple stateless control-plane pods backed by PostgreSQL and S3-compatible evidence storage. PostgreSQL provides durable fleet jobs, `SKIP LOCKED` claims, replay state, the transactional event outbox, leader leases, and fencing tokens. PostgreSQL `LISTEN/NOTIFY` wakes long-polling workers and dashboard event streams while the outbox remains the durable event record.

## Required services

- PostgreSQL 15 or newer with TLS and a dedicated database/user.
- S3-compatible object storage. Configure a KMS key for server-side encryption; AWS KMS keys backed by a custom key store can use CloudHSM without changing RouteCairn.
- An OTLP HTTP collector for traces and metrics.
- An OIDC issuer for projected workload identity, a mutually authenticated TLS ingress, or both.

Create the named PostgreSQL and application secret objects outside Helm, preferably with External Secrets or a CSI secret-store driver. Do not put credentials in a values file.

To keep the dashboard vault key under KMS or an HSM-backed KMS custom key store, encrypt its base64 key string with encryption context `purpose=routecairn-dashboard-master-key`. Store the base64 KMS ciphertext in a Kubernetes Secret and set `keyManagement.masterKeyKmsKeyId` plus `keyManagement.ciphertextSecretName`. The plaintext exists only in process memory after startup decryption.

```console
helm upgrade --install routecairn ./deploy/helm/routecairn \
  --namespace routecairn --create-namespace \
  --set image.repository=registry.example/routecairn \
  --set image.tag=0.1.0 \
  --set publicOrigin=https://routecairn.example.com \
  --set objectStorage.bucket=routecairn-evidence \
  --set workloadIdentity.required=true \
  --set workloadIdentity.issuers=https://kubernetes.default.svc
```

Each worker-pool entry binds jobs to a `networkZone` and a capability set. Enroll the pool once, store its `agent-state.json` in the named Kubernetes Secret, and set `transport.workloadIdentityTokenFile` in that state to `/var/run/secrets/routecairn/token`. RouteCairn still verifies the per-request Ed25519 signature; the projected identity is an additional proof.

Use an ingress or service mesh that supports mTLS when certificate identity is required. Direct TLS client certificates are accepted when Node terminates TLS. A trusted proxy may pass a certificate fingerprint only when it also supplies the HMAC proof configured with `ROUTECAIRN_MTLS_PROXY_SECRET_FILE`.
