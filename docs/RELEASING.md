# Release process

1. Update `CHANGELOG.md`, `package.json`, and `package-lock.json` to the same Semantic Versioning value.
2. Run `npm ci`, `npm run quality`, `npm run test:coverage`, `npm run test:mutation`, `npm run security:dependencies`, and `npm run package:smoke`.
3. Register an independently verified assessor's public key before the reviewed source commit. Obtain an independent review using `security-reviews/REVIEW-BRIEF.md`. Commit only the version-2 signed attestation at `security-reviews/vX.Y.Z.review.json` and its digest-bound report after that commit. Any other change requires renewed review.
4. Run `npm run release:verify -- --tag vX.Y.Z` and `npm run security:review:verify -- --release vX.Y.Z`.
5. Require successful continuous assurance and CodeQL for the candidate commit. Create a signed, annotated `vX.Y.Z` tag at the candidate commit and push it.

The tag workflow verifies the GitHub-verified tag signature and exact commit, checks current remote assurance, rebuilds from the lockfile, enforces merged coverage and mutation thresholds, verifies the review attestation and actual report digest, installs the exact archive, creates SBOM and provenance attestations, and publishes a GitHub release. A failed gate leaves the tag without a release artifact. GitHub release immutability must be enabled in repository settings before calling releases immutable.

Release branches are not a compatibility boundary. The package version, changelog entry, tag, provenance subject and generated archive identify the same candidate revision. The reviewed ancestor must have identical tracked content apart from the release attestation and its report.

## Candidate verification

`npm run test:complete` recycles the coordinator through four serial forked shards. `npm run test:coverage` merges Vitest blob reports and enforces the original global thresholds once; each shard's partial coverage is never accepted as whole-suite coverage. A failed process stops the runner. Logs and merged JSON results are retained under `.routecairn-engineering-lab/test-runs/`, with final coverage in `.routecairn-coverage/`.

Continuous assurance retains an installed, verified candidate archive as `candidate-package-<commit>`. It is a CI artifact, not a reviewed public release. The independent-review gate remains mandatory for publication.
