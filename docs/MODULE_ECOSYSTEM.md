# Module distribution and trust operations

RouteCairn provides a native registry and package signing workflow for its version 2 capability SDK. This is a self-hostable service with anonymous discovery and verified downloads. It does not assert a public deployment, external maintainers, independent review or community adoption. The three shipped packs are first-party reference detectors.

## Boundaries and compatibility

Publisher trust, package approval and target authorization are separate decisions. A signature never grants request permission. Install does not approve or execute code. The dashboard requires an organization member with `modules.manage` to register, approve, execute or disable a module. Package bytes, manifest permissions, declared capabilities and entrypoint are covered by the digest. A changed digest requires new review. An approved state does not carry over to a replacement version.

Distribution schema 1 uses SDK 2 and explicitly supports Node 20, 22 and 24. New runtime majors require compatibility review and schema evolution. Packages expire after at most 90 days; keys have separate operator-configured validity windows. Signature verification checks both windows, publisher identity, namespace ownership, runtime compatibility, public-key fingerprints and revoked package/key lists. Detached [DSSE signatures](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) cover the exact canonical payload and media type; sealing never changes the package afterward. Ed25519 keys are obtained from an operator-controlled trust file, never from the downloaded bundle.

Bundles contain uncompressed, canonical base64 files: no npm install, lifecycle hooks, dependency downloads or archive extraction. Limits are 256 files, 2 MiB per file, 10 MiB decoded total, 16 path levels and 24 MiB transport total. Traversal, drive/alternate-stream paths, reserved device names, symlinks, case-insensitive file collisions, file/directory collisions, native addons, binaries and private-key file extensions are rejected. Install stages within the configured root, validates the sandbox contract and digest again, then renames atomically. Existing directories are never overwritten. Store packages in an administrator-controlled directory.

The registry binds versions immutably and serves digest-specific URLs. Discovery metadata is advisory; fetch requires a reviewed exact digest, version, module identity and locally trusted signature. There is no automatic `latest` update. A registry may omit entries or deny availability; it cannot establish publisher trust. Revoked, expired and invalid bundles are excluded on each listing and download. Updating the trust file applies to the next operation and dashboard execution. Signed evidence is retained in SQLite migration 44; verification is repeated after restart. Lost trust configuration fails closed for signed modules. Execution after failed verification quarantines the package. Disabling blocks subsequent runs; it does not cancel a run already in progress.

## Author and review a pack

Implement `export async function analyze(input, sdk)` in an `.mjs` entrypoint. See `examples/modules/security-headers`, `framework-fingerprint` and `graphql-response`. The published `dist/core/plugins/ModuleSdk.d.ts` describes the complete injected SDK. Do not import RouteCairn into the restricted process. Return bounded observations, findings and notes. Findings need direct evidence and appropriate severity; framework hints alone do not prove a vulnerability. Use only `sdk.request()` for transmission.

```powershell
routecairn modules keygen --private-key publisher.key --public-key publisher.pub
routecairn modules build --directory examples/modules/security-headers --publisher my-team --expires-at 2026-11-01T00:00:00Z --output headers.payload.json
routecairn modules sign --payload headers.payload.json --private-key publisher.key --output headers.bundle.json
routecairn modules review --bundle headers.bundle.json --trust module-trust.json
```

Supply a future expiry within 90 days of the actual build date. Obtain the public key and publisher identity over an independent trusted channel. The `keygen` result includes the SPKI SHA-256 key ID. A trust file has this shape (replace all placeholders before use):

```json
{
  "schemaVersion": 1,
  "publishers": [{
    "publisher": "my-team",
    "modulePrefixes": ["reference"],
    "publicKeyPem": "<approved Ed25519 public PEM>",
    "keyId": "<SPKI SHA-256 from keygen>",
    "notBefore": "<key activation ISO timestamp>",
    "expiresAt": "<key expiry ISO timestamp>"
  }],
  "revokedKeyIds": [],
  "revokedPackageDigests": []
}
```

Prefixes are matched as an exact module ID or with a following hyphen. Pin the namespace explicitly. Do not accept public keys supplied by an index response. Add a compromised key ID or package digest to the corresponding revoked list, replace the trust file atomically, then verify discovery and dashboard quarantine. Key rotation adds an independently approved new key and retires the previous one. Keep the registry/trust/key volumes and database in backups. Immutable versions need a new version for renewed publication.

## Registry and signing service

`routecairn modules serve --config registry.json` starts native HTTP on loopback or HTTPS when certificate paths are supplied. See `examples/module-registry.example.json`. Paths resolve relative to the configuration. Public/wildcard binding requires native TLS. Use an actual CA certificate for a public service; for an owned private CA use `NODE_EXTRA_CA_CERTS` before starting clients. Certificate verification cannot be disabled through the CLI.

Publishing and signing use different environment-referenced bearer credentials of at least 32 characters. Generate high-entropy credentials and provision through the deployment secret manager. Tokens/private keys never appear in results or audit events. `/v1/index` and `/v1/packages/{moduleId}/{version}/{packageDigest}` allow anonymous reads. `POST /v1/publish` requires the publication role. `POST /v1/sign` requires the signing role and an administrator-reviewed digest allowlist for one publisher. The signing service will not sign a new digest until the administrator reviews its manifest and source and adds it to `approvedDigests`. Separate signing into a private registry process/configuration; the public registry needs only trust roots and its publication credential. There is no key generation API or private-key retrieval endpoint. This implementation uses a local Ed25519 key; hardware-backed remote signing is not claimed.

Each process defaults to 100 versions and 256 MiB total stored bundles, 4 active handlers, 32 sockets, 60 requests/minute per remote IP, bounded bodies, 10-second header and 15-second request timeouts. Source IP is the actual socket peer; forwarded headers do not affect authorization or rate limits. With a reverse proxy, configure additional edge rate limits and allow only the proxy to reach the service. Audit records contain action, timestamp, publisher, version, digest and expiry; the 4 MiB audit ceiling fails closed and requires offline archival by the administrator. There is no automatic deletion of signed artifacts or rotation of trust keys.

```powershell
routecairn modules request-signature --registry https://signer.owned-domain.test --payload headers.payload.json --trust module-trust.json --credential-env ROUTECAIRN_MODULE_SIGN_TOKEN --output headers.bundle.json
routecairn modules publish --registry https://registry.owned-domain.test --bundle headers.bundle.json --trust module-trust.json --credential-env ROUTECAIRN_MODULE_PUBLISH_TOKEN
routecairn modules index --registry https://registry.owned-domain.test
routecairn modules fetch --registry https://registry.owned-domain.test --module reference-security-headers --version 1.0.0 --digest REVIEWED_SHA256 --trust module-trust.json --output DASHBOARD_MODULE_ROOT/headers.bundle.json
routecairn modules install --bundle DASHBOARD_MODULE_ROOT/headers.bundle.json --trust module-trust.json --root DASHBOARD_MODULE_ROOT --digest REVIEWED_SHA256
```

Outputs use exclusive creation; choose fresh paths. Credentials are read from the named environment variables, never command-line secret values. Downloads do not follow redirects or accept credentials in registry URLs. Plain HTTP is limited to exact loopback IPs. Replacement provider domains and digests in these examples are placeholders.

## Dashboard execution

Set administrator-controlled `ROUTECAIRN_MODULE_TRUST_PATH` before starting the dashboard. Set `ROUTECAIRN_REQUIRE_SIGNED_MODULES=true` to disallow unsigned registration and execution, including old unsigned approvals. Existing manual unsigned packages remain available when strict mode is off. Do not modify the trust file based on module input.

The Operations → Modules view accepts the installed package directory and signed bundle path, both under the configured module root. Registration verifies their digests and persists the signature. Review the publisher, key ID, expiry, permissions, input schema, capability methods/prefixes, budgets and risk class before clicking Approve. Execution accepts only validated input and the separately reviewed broker binding. It displays observations, findings and aggregate transmission evidence. Disable prevents later execution; quarantined artifacts require fresh registration and review.

API requests use the existing session, CSRF and organization RBAC controls:

- `POST /api/operations/modules`: `organizationId`, `packageDirectory`, optional `bundlePath` (required in strict mode).
- `POST /api/operations/modules/{id}/approve`: separate review.
- `POST /api/operations/modules/{id}/execute`: `input`, optional `broker`.
- `POST /api/operations/modules/{id}/disable`: block future runs.

The request broker restricts reads to the exact approved origin even when the broader scope permits another origin. It rejects encoded paths with ambiguous normalization, credential/override headers and undeclared methods/paths. POST needs MODERATE risk, an exact body/header digest, canonical path and non-mutating declaration. A fresh digest/origin approval lasts at most one hour. Expiry aborts queued/in-flight work; process timeout and protocol failure cancel its broker. Existing DNS pinning, budgets, concurrency, rates, redirect denial and response redaction apply. Body previews redact known sensitive fields and credential patterns; reviewers must still assess whether a response is appropriate to expose to a detector. The SDK does not supply raw credentials, sockets, TLS handles or DNS answers.

## Isolation

Default process mode is for explicitly reviewed code. Node's [permission model is not a security boundary against malicious code](https://nodejs.org/api/permissions.html). Runtime API denials and Node permissions reduce accidental authority but are not sufficient for arbitrary hostile community packages.

For untrusted code set `ROUTECAIRN_MODULE_CONTAINER_IMAGE` to an operator-reviewed Node runtime **repository@sha256:digest**. The image must have a compatible Node binary and no custom entrypoint. Docker must be available to the host. The host then runs each snapshot with `--network=none`, a read-only root and mounts, unprivileged UID/GID 65534, all capabilities dropped, no new privileges, bounded PID/memory/CPU and no Docker socket. The RPC broker remains outside the container and mediates all requests over stdin/stdout. Timeout cancels broker work and force-removes only the uniquely named container. Cleanup failure is reported; execution never falls back to process mode. Protect the Docker daemon as a privileged host component. Additional kernel/VM isolation is an operator deployment choice.

`deploy/module-registry/compose.yaml` provides a non-root, capability-dropped, bounded registry container with read-only secret/config mounts and persistent package storage. Supply a digest-pinned RouteCairn image, TLS configuration and secrets; local writable directories need ownership for UID 1000. The container configuration must listen on `0.0.0.0` with native TLS on port 8788, store bundles in `/packages`, and use trust/certificate/key paths under `/configuration`. Mount the certificate CA as `/configuration/tls/ca.pem` and set `ROUTECAIRN_REGISTRY_TLS_NAME` for verified health checks. The host port stays on loopback for a TLS reverse proxy; expose it only after configuring owned routing and access controls. It does not mount a Docker socket. Use a separate signing instance for key isolation. Certificate/key renewal and public DNS/reachability remain deployment responsibilities.

## Verification and contributions

`npm run acceptance:modules -- --output FRESH_DIRECTORY` exercises native registry/signing HTTP, HTTPS certificate trust, all three reference packs, dashboard APIs and separate review, exact digests, revocation after database restart, tamper/namespace/expiry/path controls, storage limits, redaction, cleanup and UI permission controls. The result retains source hashes and SHA256SUMS and explicitly identifies loopback/self-maintained provenance. CI also runs a digest-pinned container exercise on Linux; that is distinct evidence from a local process run. A public deployment or outside community is not inferred from these tests.

Contributors should submit source, manifest, examples, supported framework versions, read-only fixtures, vulnerable/secure controls where appropriate, expected outcomes and bounded request contracts. Run the ecosystem gate and inspect the produced review output. Maintainers review code/permissions, verify publisher identity and namespace independently, execute controls in isolated infrastructure, then authorize a digest for signing/publication. Security fixes withdraw trust for affected digests and publish a reviewed replacement version; users explicitly review upgrades. Report trust/sandbox issues through SECURITY.md. External contributors and hosted service operation require real participants and infrastructure; they cannot be created by labeling reference code as community work.
