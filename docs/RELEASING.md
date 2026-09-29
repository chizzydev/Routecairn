# Release process

1. Update `CHANGELOG.md`, `package.json`, and `package-lock.json` to the same Semantic Versioning value.
2. Run `npm ci`, `npm run quality`, `npm run test:coverage`, `npm run test:mutation`, `npm run security:dependencies`, and `npm run package:smoke`.
3. Obtain an independent review using `security-reviews/REVIEW-BRIEF.md`. Place the signed attestation at `security-reviews/vX.Y.Z.review.json` and add the reviewer's public key to the protected trusted reviewer registry.
4. Run `npm run release:verify -- --tag vX.Y.Z` and `npm run security:review:verify -- --release vX.Y.Z`.
5. Create a signed, annotated `vX.Y.Z` tag at the reviewed commit and push it.

The tag workflow rebuilds from the lockfile, reruns the suite, verifies the review attestation, creates SBOM and provenance attestations, and publishes an immutable GitHub release. A failed gate leaves the tag without a release artifact.

Release branches are not a compatibility boundary. The package version, changelog entry, tag, provenance subject, security review commit, and generated archive must identify the same source revision.
