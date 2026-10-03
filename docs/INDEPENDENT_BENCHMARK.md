# Independent detection evidence

## Evidence currently available

The public v2 corpus contains 576 executable behavior fixtures: 288 vulnerable cases, 144 secure controls and 144 near-miss controls, across TypeScript `node:http`, Python `http.server`, Python `wsgiref` and Go `net/http`. It covers 12 categories and includes 48 multi-step and 48 second-order cases. Python's two transports share fixture logic. These are self-maintained detector regression fixtures; they do not establish independent real-world accuracy. Some injection fixtures simulate vulnerable responses rather than execute a database, template runtime or filesystem vulnerability.

`benchmark credibility` requires Python 3 and Go on PATH (or `--python` and `--go`). It builds the Go fixture into its output directory, starts only loopback listeners and shuts down the owned fixture processes. Three repetitions are the default and the minimum passing gate. The scorecard includes per-category quality gates, composition, stability, cleanup, resource usage, unique-case Wilson 95% intervals and machine-readable JSON/JUnit evidence. Related mutants are correlated; repetitions do not increase the statistical sample size. Preserve the raw scan reports alongside the scorecard.

An independent corpus and independently signed execution have not been supplied. No bundled result asserts external or blinded verification.

## Roles and trust

An independently administered trust registry authorizes separate Ed25519 publisher and operator keys. It records key IDs, organizations, roles, validity and revocation. Register only keys whose ownership and independence have been established outside RouteCairn. Signatures establish integrity and signer identity, not the truthfulness of an operator or organizational independence.

The publisher owns the private manifest and truth key. The operator receives a sealed pack, approved execution contracts and targets, with no truth key. The evaluator receives the committed operator submission and subsequently the truth key. Keep timestamped delivery records and restrict evaluator access: encryption cannot prove an operator never saw the truth.

## Publisher

Prepare a manifest using `BenchmarkSchemas.ts`. Each case needs a stable selector matching the approved scan contract. Declare an actual external publisher, source URL and source commit, `independence: "EXTERNAL"`, and versioned provenance. The verifier requires at least 500 cases, three languages, four frameworks, 12 balanced categories, three repetitions, 95% stability and per-category recall, at most 1% per-category false positives and inconclusive results. Additional manifest gates can be stricter.

Seal and sign the prepared truth together. Signing before sealing changes the manifest and requires signing it again; the CLI rejects resealing a signed manifest without a signer.

```powershell
routecairn benchmark corpus seal --manifest private-manifest.json --key-env CORPUS_TRUTH_KEY --private-key publisher-private.pem --key-id lab-publisher --output blind-pack.json
```

Use a random truth secret of at least 32 bytes; provision it through the named environment variable. New packs authenticate the public envelope with AES-GCM additional authenticated data. Old unsigned blind packs remain readable by the general evaluator, but do not establish independent evidence.

## Operator

Prepare a JSON plan conforming to `independentExecutionSchema` in `IndependentBenchmark.ts`. All paths resolve against the CLI working directory. Its fields are:

| Field | Meaning |
|---|---|
| `schemaVersion` | `1` |
| `operatorKeyId` | Trusted operator key ID |
| `repetitions` | 3–10 distinct executions |
| `releaseVersion`, `sourceCommit` | Executed release identity and full Git SHA |
| `targets` | 1–20 approved external targets |
| Target `id`, `url` | Unique ID and HTTP(S) target |
| Target `scope`, `targetAuthorization` | `{ "path": "...", "sha256": "..." }` bindings to RouteCairn scope and authorization contracts |
| Target `inputs` | Digest bindings for `auth`, `authA`, `authB`, `apiGraphql`, `activeVulnerability`, `authenticationLifecycle`, `protocolSecurity`, `supabaseAuthorization`, `businessInvariants` as needed |
| Target `maxRequests`, `cleanupReservedRequests` | Per-target/per-repetition bounded scanner budget and reserved cleanup budget |

At least one execution contract is required per target. No arbitrary fixture code is loaded from a corpus. All input digests and initial target DNS addresses are checked before scanning. Verified inputs are snapshotted into the private output directory. Existing scope, DNS, authorization, mutation and cleanup policies govern transmission; declaring an independent benchmark never grants an approval. The runner requests the modules associated with supplied contracts; scanner prerequisites remain subject to scope and budgets.

Prepare a trust file conforming to `independentTrustSchema`. Each key has `id`, `organization`, `role` (`PUBLISHER` or `OPERATOR`), `publicKeyPem`, ISO timestamps `validFrom`/`validUntil`, `revoked` and `independence: "INDEPENDENT_THIRD_PARTY"`. Keep private keys outside the registry and repository.

```powershell
routecairn benchmark independent run --plan approved-plan.json --pack blind-pack.json --trust independent-trust.json --release-artifact routecairn.tgz --signing-key operator-private.pem --output private-execution
```

The runner creates a fresh `independent-execution-*` directory under `--output`, hashes the pack, release artifact and each repetition's report, records measured telemetry and signs `independent-submission.json`. Its JSON response identifies the exact submission path. It does not score its own execution or decrypt truth. Archive the submission before truth disclosure. Preserve private input snapshots securely: they may contain credentials. Files are created with restricted POSIX modes; Windows deployments must set corresponding directory ACLs.

## Evaluator

```powershell
routecairn benchmark independent evaluate --submission <submission-path-from-run> --pack blind-pack.json --key-env CORPUS_TRUTH_KEY --trust independent-trust.json --release-artifact routecairn.tgz --output independently-evaluated
```

Evaluation rejects untrusted, expired or revoked signers, the same publisher/operator key under different IDs, changed artifacts, changed reports, replayed report digests, incomplete runs, release-version mismatches, loopback/reserved target names, missing or inconsistent telemetry and weak corpus policies. It emits the scorecard plus `independent-verification.json`, with key IDs, organizations and artifact commitments. Failed quality gates exit with code 2 and remain failed in the verification artifact.

An artifact hash binds the operator's declaration to release bytes; it does not attest which binary actually ran. Signed reports attest the operator's execution claim. Report URLs alone cannot prove historical DNS routing or physical target ownership. Use independently controlled runners, published target source commits, signed build provenance and infrastructure logs to establish these stronger claims. Never edit a self-maintained corpus's provenance to present it as independent evidence.
