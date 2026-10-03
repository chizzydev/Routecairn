# RouteCairn control plane

This deployment runs the dashboard, signed-worker control plane, automatic safe-data synchronization, and a Caddy TLS edge.

1. Point the hostname at the Docker host.
2. Copy `.env.example` to `.env` and replace every placeholder.
3. Create `secrets/session-secret.txt` and `secrets/mutation-coordinator-secret.txt` with at least 32 cryptographically random characters each, plus `secrets/bootstrap-owner-password.txt` with the initial strong owner password. Do not commit these files.
4. Run `docker compose up --build -d` from this directory.
5. Sign in with the one-time bootstrap owner. After the first owner is stored, remove `ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN` from `.env`, overwrite the bootstrap password file with an unrelated random value, and recreate the control-plane container. Existing installations never reapply bootstrap credentials while an enabled owner exists.

The application container is not published directly. Caddy terminates HTTPS and forwards traffic on the private Compose network. Persistent dashboard state and TLS material use named volumes. `/healthz` is the liveness endpoint and `/readyz` verifies database readiness.

Remote workers enroll over the public HTTPS origin, keep target credentials and input manifests in their own workspace, and run with `routecairn agent run --state <file> --workspace <directory>`. Back up the `routecairn-data` volume and the master-key material together.

Mutation-capable workers must also set `ROUTECAIRN_MUTATION_COORDINATOR_URL` to this public origin, set one shared `ROUTECAIRN_MUTATION_COORDINATOR_NAMESPACE` for the target environment, and mount the same coordinator secret through `ROUTECAIRN_MUTATION_COORDINATOR_SECRET_FILE`. Read-only workers do not need coordinator credentials.

## Distributed infrastructure profile

`compose.distributed.yaml` adds PostgreSQL durable worker queues, S3-compatible evidence storage, and an OTLP collector while retaining the original Compose file as the single-node default. Create the four additional secret files referenced by the overlay. `database-url.txt` must contain the full PostgreSQL URL using the password in `postgres-password.txt`.

The bundled profile reads MinIO credentials through `AWS_ACCESS_KEY_ID_FILE` and `AWS_SECRET_ACCESS_KEY_FILE`. Production Kubernetes deployments should omit static credentials and use workload identity.

Run the overlay with:

```console
docker compose -f compose.yaml -f compose.distributed.yaml up --build -d
```

The overlay adds two stateless `fleet` replicas and routes signed worker requests to them. One persistent dashboard retains SQLite administrative state and holds a PostgreSQL ownership lock. Compose remains a single-host deployment. Helm scales fleet and independently enrolled worker members, while retaining a singleton dashboard PVC. See [horizontal scale operations and verified limits](../../docs/HORIZONTAL_SCALE_OPERATIONS.md).
