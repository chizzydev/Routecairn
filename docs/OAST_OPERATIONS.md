# Native OAST operation and public verification

## What is verified

The retained OAST lab executes RouteCairn's full active engine against Python urllib,
Python SAX/Expat with external entities enabled and disabled, a real shell, and
Jinja2 3.1.6 with normal and sandboxed execution. HTTPS uses an isolated one-day
CA with hostname and chain verification; no system trust changes. On Windows the
shell case uses PowerShell over HTTP. Jinja's HTTPS curl command uses a temporary
CA adapter because Windows Schannel ignores `CURL_CA_BUNDLE`. Linux also runs the
POSIX shell case over HTTPS. Absence of a callback stays inconclusive.

UDP and TCP DNS tests exercise authoritative SOA/NS/glue, A/AAAA identities,
NODATA, NXDOMAIN, refusal outside the zone, replay correlation and revocation.
Hosted-mode tests exercise HTTPS-only management, wrong tenant tokens, untrusted
certificates, protocol-specific signatures, restart persistence, certificate
reload, bounded shutdown and secret-free summaries. These are controlled local
fixtures, not evidence of a public or independently operated deployment.

```powershell
python -m pip install --target .routecairn-oast-lab/python Jinja2==3.1.6 MarkupSafe==3.0.3
npm run acceptance:oast -- --python-path .routecairn-oast-lab/python --output acceptance/oast/NEW-RUN
```

The runner requires the pinned runtime and a fresh output directory, checks source
digests before and after execution, fails on skipped runtime cells, records
cleanup and writes artifact hashes. It does not install dependencies implicitly.

## Public authoritative deployment

Use an owned delegated subdomain on a dedicated Linux host with a stable public
address. This Compose deployment is one service instance with one persistent
SQLite volume; do not start multiple replicas against separate databases. DNS
and HTTPS must reach the same lease store. A tunnel that carries only HTTP does
not provide public authoritative DNS. Shared SaaS web hosting cannot supply UDP
or TCP port 53 unless the provider explicitly exposes them.

1. Build and review the release. Copy `examples/oast-service.hosted.example.json`
   to `deploy/oast/oast.json`. Replace every example origin/address, configure
   `dnsNameServers`, and retain the release artifact and config SHA-256 digests.
2. At the **parent zone**, add `callbacks.your-domain NS
   ns1.callbacks.your-domain` and in-bailiwick glue `ns1.callbacks.your-domain A
   PUBLIC_IPV4`. Delegate only the new subdomain; preserve the application's
   existing apex nameservers. Add AAAA only when the host has working public IPv6.
   Native OAST serves the child zone's SOA/NS and callback A records.
3. Install a publicly trusted certificate for the public HTTPS origin. Obtain it
   with your existing approved ACME/DNS-01 workflow before starting OAST. Put the
   private key and full certificate chain in `deploy/oast/tls` at the config's
   filenames. Keep them readable by container UID 1000 and not public.
4. Create `deploy/oast/secrets/service.env` (permissions 0600) with a persistent
   random signing key of at least 32 bytes and distinct random tenant bearer
   tokens of 24–200 URL-safe characters. This directory is ignored. Never put
   credentials in Compose, manifests, logs or evidence. Do not change the signing
   key on an existing database; the service fails closed on unexpected rotation.
5. Open ingress TCP 80/443 and **UDP and TCP 53** for this dedicated host. Ensure
   no local resolver binds public port 53. Allow callback clients' public ingress;
   restrict SSH and administrative host access using your existing policy.
6. Run `docker compose -f deploy/oast/compose.yaml up --build -d`. Check `/readyz`,
   then verify from a separate network. `healthz` only confirms liveness.

The container drops capabilities, runs as an unprivileged user with a read-only
root, has CPU/memory/process/log limits, and persists only fingerprints and leases.
Requests, live sockets, DNS packets, request bodies, retained leases and retention
are bounded. Default limits are 200 connections, 500 requests/second, 10,000
leases and seven days of evidence after expiry. DNS does not provide recursion;
UDP answers are capped at 512 bytes with TCP retry for larger RRsets. Query packets
are capped at 4096 bytes. Malformed packets and exhausted DNS budgets are dropped.
Resolvers' retries are correlated once per lease/protocol; later attempts set the
replay flag rather than creating additional proof. A DNS event proves resolution,
not a subsequent network connection or code execution by itself.

If IPv6 is not routed, set `publishIpv6` to false; never publish a loopback or
documentation AAAA address on a public deployment. If using IPv6 ingress, bind
the service to a host/container IPv6 interface and configure the container network
and firewall explicitly. The supplied Compose file is the IPv4 deployment.

## Renewal, persistence and incident handling

Renew TLS files atomically at the same paths and send `SIGHUP` to the service
process (`docker compose -f deploy/oast/compose.yaml kill -s HUP oast`). A failed
reload keeps the previous certificate. Readiness fails near certificate expiry.
The callback DNS zone does not serve ACME TXT challenges. For DNS-01 renewal, use
an appropriate wildcard certificate issued through the existing **parent** zone
(for example `*.your-domain` covers `callbacks.your-domain`), or your existing
certificate issuer's approved challenge delegation. An alternative is to drain
active leases, stop OAST briefly and use standalone HTTP-01 on the dedicated host;
restart with the renewed certificate before admitting new scans. Do not assume a
DNS-01 TXT record added at the parent is visible beneath an already delegated child.
Keep signing keys and tenant tokens persistent across restarts. Back up the SQLite
database with its supported online backup facility or while the service is stopped;
copying only the live `.sqlite` file can omit WAL data. Encrypt backups and apply
the same retention policy. Restore the database and original signing key together.
Key rotation requires draining/revoking leases and a reviewed database migration or
a new service database. Tenant token rotation does not change existing polling
capabilities; revoke their leases separately when needed.

Management endpoints require HTTPS in HOSTED mode. Polling and revocation require
the lease's unguessable polling token, not a tenant token. Polling after expiry is
available during retention; expired/revoked identities never accept new callbacks.
Active cases report failed revocation as failed cleanup instead of silently hiding it.
Lease revocation gets its own bounded timeout even when the scan was cancelled.

## Retained public acceptance

Complete `examples/oast-deployment-verification.example.json` with current owner
authorization, real public addresses, digests and approved credential environment
names. The checked-in template intentionally fails validation.

```text
routecairn oast verify-deployment --manifest reviewed-oast.json --output public-oast-result.json
```

The verifier checks the running service's config digest, recursive NS delegation and glue/address bindings, public HTTPS
readiness with system CA validation, direct authoritative UDP/TCP NS and SOA,
signed callbacks and delayed polling, HTTP(S) replay rejection, recursive callback
resolution and lease revocation. It never falls back to loopback, disables TLS
verification, overwrites retained evidence or labels operator-supplied release
digests as server attestations. It fails unless all checks and cleanup complete.
Public verification is owner-operated and does not manufacture an independent
operator signature. Keep the report together with deployment logs/config digests
and any independent operator attestation obtained separately.

DNS authority and negative answers follow [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
and [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308). The real template runtime is
[Jinja2 3.1.6](https://pypi.org/project/Jinja2/3.1.6/).
