# Changelog

All notable changes to RouteCairn are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Engineering and release assurance

- Decomposed the five oversized server, migration and UI modules; enforced an exception-free 1,800-line ceiling.
- Added dashboard type checking, coordinator recycling with source-change rejection, merged coverage gates and retained CI candidate archives.
- Hardened review schemas, report digest and Ed25519 verification, source ancestry binding and rejection of unreviewed changes. Added a reproducible source handoff without self-issued independent attestations.
- Fixed the branch/PR release-policy mismatch, included every infrastructure job and mutation testing in the required assurance gate, and required signed tags plus current remote assurance before publication.
- Addressed file-read races, persistent-key overwrites and regex ambiguity reported by CodeQL; added adversarial release and file/key tests.

### Official standards accounting

- Imported complete pinned WSTG 4.2, ASVS 5.0.0, API Security 2023, CWE 4.20 and CAPEC 3.9 datasets with publisher provenance, schema validation, source integrity checks and offline build/CI gates.
- Replaced draft/placeholder identifiers with published versioned identities and corrected XXE, deserialization, CRLF, session and GraphQL associations.
- Added strict version-2 coverage, full catalog denominators, mapping hashes, consistency checks, failure on unmapped cases and CSV formula protection; completed modules without findings are observations.
- Added catalog/verification/report CLI commands, dashboard/report denominators, package gates, runtime acceptance and adversarial import/accounting tests. Historical version-1 reports are not silently relabeled; coverage remains bounded case evidence, not certification.

### Distributed fleet deployment and acceptance

- Added a stateless fleet ingress CLI, independently scalable signed workers, exact workload identity bindings and direct/proxy mTLS verification.
- Made PostgreSQL job transitions and outbox publication atomic, bounded lease recovery, rejected stale worker generations, fixed listener recovery and added transaction fencing.
- Enforced one persistent administrative dashboard with a PostgreSQL advisory ownership lock; corrected Helm/Compose routing, storage and distinct worker identities.
- Hardened streamed object verification and KMS envelopes, initialized versioned buckets explicitly, and verified actual OTLP traces and metrics.
- Added native PostgreSQL/MinIO/Moto/collector acceptance, actual multi-replica Kubernetes and TLS worker-pool exercises, source/digest evidence and CI gates. Managed AWS KMS, HSM, multi-node HA and public deployment are not asserted.

### Module distribution and trust

- Added a bounded native registry, immutable signed publication, digest-specific downloads and a separately authenticated digest-reviewed signing service.
- Added Ed25519 DSSE packages, independent trust roots, namespace checks, key/package revocation, expiry, safe atomic installs and CLI authoring/distribution commands.
- Persisted signed module evidence in migration 44; added strict signing policy, dashboard contract review, displayed execution results and disable controls.
- Added three first-party reference detector packs, typed SDK contracts, optional digest-pinned network-isolated container execution, cancellation and canonical-origin/path checks.
- Added native HTTP/HTTPS lifecycle acceptance, trust and extraction controls, retained local evidence, CI gates and deployment/contribution documentation. Public operation and outside community adoption are not asserted.

### Protocol semantics operation

- Added real full-module gRPC, GraphQL, WebSocket, interrupted upload, compression, identity and WebTransport acceptance with negative controls and restoration.
- Added native Caddy/nginx intermediary deployment matrices across H1/H2/H3 ingress and H1/H2 upstream forwarding, deployment hashes and bound backend traces.
- Fixed native QUIC trust verification and WebTransport TLS option forwarding; added public CA configuration and explicit CONNECT scope/authorization.
- Enforced aggregate datagram bounds, true partial upload flushing, real identity evidence, complete incremental delivery, read-only GraphQL operations and shared protocol request limits.
- Added reproducible retained acceptance, CI gates, operating documentation and installed-package WebTransport acceptance.

### Attack-state graph operation

- Bound response evidence to exact request identities, preserved origin boundaries, and separated browser session actors from anonymous traffic.
- Corrected GraphQL comment/string masking so hash-containing literals cannot hide a later mutation or subscription.
- Added conservative GraphQL operation classification, ordered capture dependencies, closed bounded paths and strict cleanup/outcome verification.
- Bound approved replay and execution evidence to current target/model contracts, rejected stale or unbound scans, and added plain HTTP lifecycle replay.
- Added dashboard path filtering, pagination and relationship/evidence inspection, real HTTP replay/restoration proof, reproducible retained evidence and CI gates.

### Native OAST operation

- Added authoritative DNS SOA/NS/glue, NODATA/NXDOMAIN, out-of-zone refusal, EDNS query handling, bounded packet parsing and UDP-to-TCP truncation.
- Added verified HTTPS management/callback runtime coverage, private CA configuration, certificate renewal, readiness and bounded shutdown.
- Added connection/request/lease/retention limits, persistent signing-key/zone checks and cancellation-independent lease revocation with explicit cleanup outcomes.
- Added real urllib, SAX/Expat, PowerShell/POSIX and Jinja2 execution proofs with secure controls, retained source commitments and secret-free evidence.
- Added an isolated Compose deployment, public DNS/HTTPS acceptance command and operating documentation. Public and independent deployment proof remains separate from local hosted-mode evidence.

### Active vulnerability interoperability

- Added native scoped OAuth authorization-code journeys with fresh codes, positive/invalid-code controls, PKCE binding, issuer/provider/account checks, expiring approval and cleanup.
- Added ZIP/TAR/TAR.GZ traversal, symlink and duplicate-entry fixtures plus XML/SVG/CSV/JSON/PDF parser fixtures with bounded canary-bound processing receipts and SVG browser execution.
- Added deployment-digest and actual-hop-trace proof for proxy matrices; clean pipelining or accepted ambiguity alone cannot become a proxy-chain finding.
- Added a reproducible native OIDC, independent parser and real Caddy/nginx H1/H2/H3 lab, source/binary commitments and honest local evidence labels.
- Fixed response Location-header secret redaction and native HTTP/3 worker result completion.

### External acceptance

- Added operational hosted Supabase Auth/RLS/Storage/RPC exercise and exact-resource recovery with verified project-bound database TLS, request/window bounds and secret-free evidence.
- Retained a real hosted Supabase run with 26 passing receipts, one schema-cache propagation observation and verified zero remaining resources; retained the initial failure and separate recovery.
- Verified the local Decide refresh correction with 12 focused authentication tests and six real database checks; deployed refresh rotation/replay still requires remediation.
- Added an owner-authorized Decide exercise that provisions two disposable accounts over verified database TLS, performs account/session checks, and verifies exact-identity cleanup with crash recovery.
- Retained a fresh production Decide run: 20 requests, 18 passing cases, two failing refresh lifecycle contracts, and verified account/session removal.
- Added blocked/ready preparation, independent operator trust, and actual authorization/reproduction/deployment file commitments.
- Added native GraphQL WebSocket/SSE subscription authorization execution and stronger signed evidence, time, cleanup and credential checks.
- Separated fixture signature verification from independent acceptance verification.
- Retained real partial Decide owned-target evidence and two bounded public availability checks without promoting missing providers or remediation to passes.

### Detection credibility

- Expanded the public behavior corpus to 576 cases, 12 categories, three languages and four server frameworks, with three required repetitions and per-category stability and quality gates.
- Added unique-case Wilson intervals and separate signed publisher/operator workflows for blinded external benchmark submissions, trust revocation, digest commitments and replay rejection.
- Corrected signing after blind manifest preparation and authenticated the public envelope of new encrypted packs.
- Documented the distinction between self-maintained fixture results and independently verified evidence.

### Added

- Coverage thresholds, deterministic formatting, static analysis, property tests, parser fuzzing, and mutation testing for safety decisions.
- Sharded test execution and a release policy gate.
- An independently signed security review intake and verification contract.

## [0.1.0] - 2026-09-28

### Added

- Initial RouteCairn command line scanner, dashboard, controlled active testing, evidence handling, distributed workers, native OAST service, protocol testing, attack state graphs, standards coverage, and deployment artifacts.

[Unreleased]: https://github.com/routecairn/routecairn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/routecairn/routecairn/releases/tag/v0.1.0
