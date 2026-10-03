# Independent security reviews

Release review attestations live here. A reviewer must be organizationally independent from RouteCairn's implementation team, review the source commit named by the attestation, and sign the canonical JSON payload with Ed25519.

Trusted reviewer keys are maintained in `trusted-reviewers.json`. Changes to that registry require security owner review. A tag is publishable only when `scripts/verify-security-review.mjs` verifies all of the following:

- the release and package version match, the reviewed Git commit is an ancestor of the candidate, and only the signed attestation and its report were added after review;
- the disposition is `ACCEPTED` and no unresolved critical or high finding remains;
- the review covers the core safety broker, scope and authorization controls, secrets and evidence, dashboard trust boundaries, worker/control plane, OAST, and release supply chain;
- the review has not expired;
- the signature belongs to an active trusted independent reviewer.

No placeholder attestation is accepted. The repository intentionally contains no self-issued substitute for an external review.

Attestations use schema version 2 and include `reportPath`, restricted to `security-reviews/vX.Y.Z.report.md`, `.pdf`, or `.json`. The verifier hashes the actual committed report, validates every field, rejects future/invalid dates and duplicate keys, and requires an Ed25519 signature. Version-1 attestations require a fresh version-2 signature; they are not silently upgraded.

Register the assessor's trusted public key **before** the reviewed source commit. After review, commit only that release's attestation and report. A change to the reviewer registry, source, dependencies, documentation or any other file requires a new review of that source. Verification requires a clean checkout and complete Git history. This avoids the impossible requirement for an attestation to sign the commit that contains itself.

The reviewer can generate the exact bytes to sign with `npm run security:review:payload -- --input security-reviews/vX.Y.Z.review.json`. The `signature` property is excluded from that canonical payload. Sign the emitted bytes with the Ed25519 private key corresponding to the protected registry entry, then store the base64 signature in the attestation.
