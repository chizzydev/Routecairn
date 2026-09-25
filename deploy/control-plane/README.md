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
