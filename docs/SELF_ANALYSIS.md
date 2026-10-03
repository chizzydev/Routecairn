# Maintainer security analysis

This is maintainer analysis and remediation, not an independent security review or release attestation. The independent publication gate remains mandatory.

## Corrected findings

- File reads now validate and read the same opened descriptor with bounded allocation and no-follow flags where supported. Persistent keys use exclusive creation and reject corrupt existing values instead of overwriting them.
- Secret-name and asset/debug regex alternatives have explicit boundaries.
- Report badge classes are HTML escaped as well as their text. The report safety test executes generated HTML with hostile attribute and script values and checks the resulting DOM.
- Clean release builds explicitly emit the public module SDK declaration. The installed-package gate checks the declaration and the published dependency lock.

## Registry routing findings

CodeQL's `js/user-controlled-bypass` findings on `ModuleRegistry.handle` concern HTTP method/path dispatch. `/health`, `/v1/index` and signed, digest-bound package downloads are intentionally public. Private publication and signing independently call `authorize` before parsing or mutating state. It compares SHA-256 digests of the exact configured bearer token with `timingSafeEqual`; forwarded roles and method overrides cannot substitute for that token. The signing token and publication token are separate capabilities, and signing additionally requires a reviewed digest and matching publisher.

`tests/integration/module-ecosystem.test.ts` exercises anonymous POST, GET on private paths, method/role overrides, cross-use of signer/publisher tokens, public metadata and absence of unauthorized publication. These dispatch alerts are classified as false positives after that review. This classification is limited to those exact findings; it does not exempt other registry findings or replace outside review.

## Analysis inputs

CodeQL analyzes product source, dashboard source, tooling and tests. Immutable acceptance output, scorecards and official publisher datasets are retained by digest and excluded as generated/input data. Source report generation is checked by adversarial DOM execution; excluding an old generated artifact does not establish that every historical report is safe for arbitrary modified input.

## Digest and authentication query findings

The five `js/insufficient-password-hash` alerts are not password database derivation:

- `agent.signedRequest` computes the SHA-256 digest of the whole canonical request body and signs the request transcript with Ed25519, including timestamp and nonce.
- `TargetAuthorization.digest` binds an approved exact request body to a scope contract; it is not an account password verifier.
- `ScanWorkerManager.envelopeHmac` authenticates a complete worker message with HMAC-SHA-256 and a separate worker capability key. Credentials are transported in the encrypted envelope, not verified against this digest as passwords.
- `BrowserNetworkBoundary.constantEqual` compares a transient, randomly generated 192-bit local proxy capability using fixed-length SHA-256 digests and `timingSafeEqual`; there is no persisted user password hash.
- `BroaderAcceptanceValidation.hash` fingerprints disposable acceptance request/response evidence, canonical lane receipts and attestations. This fixture exercise does not implement user password authentication.

These exact alerts are classified as false positives for the password-storage query. This does not justify fast unsalted hashing for stored human passwords. The authorization, browser network boundary, signed worker and broader acceptance suites exercise the corresponding contracts.

Additional fixes remove a redundant potentially exponential backup filename regex, replace blacklist URL checks with parsed HTTP/HTTPS allowlists, bound export/key-file reads through opened descriptors, use SHA-256 for finding identifiers, and serve reflected fixture values with explicit non-HTML content types. POSIX reproduction command quoting is verified by executing a shell function with hostile URL metacharacters and observing one unchanged argument.

Native intermediary fixtures resolve Windows short-path aliases before passing paths to nginx. OAST and protocol acceptance retain the full test result JSON on failure as well as success, including cleanup and source identity checks.

The pinned QUIC dependency's default dual-stack fixture listener binds an additional wildcard IPv6 socket even when a loopback IPv4 host is supplied. Acceptance now provides an externally owned IPv4 socket bound only to `127.0.0.1`, waits for its actual close acknowledgement and verifies conflicting-port rejection and port reuse. This changes fixture hosting; scanner transmission continues through the existing scope and certificate policy.
