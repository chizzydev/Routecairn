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
