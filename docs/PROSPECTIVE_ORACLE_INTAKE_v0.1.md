# Global prospective oracle intake v0.1

This offline protocol supplements the existing PracticalAssessmentBenchmark and HeldOutDiscoveryEvaluation. It executes no target request. It binds all applications, cases and repetitions before a separately pinned oracle publisher can sign a label release. It never certifies who owns that key, whether an implementer already knows labels or whether a local wall clock is trustworthy.

## Independent operator procedure

1. A separately controlled publisher defines a public prospectiveStudySchema manifest: immutable study/source-version IDs, exact run IDs, benchmark source hashes and oracle SHA256, complete case IDs and denominators, bounded request ceilings, separate implementation source paths/digests for every application, and the exact PEM SHA256 of its Ed25519 public key. Retain its private key and labels outside the implementer's environment. Review independence/near-duplicate application families separately; two files are not proof of two independent designs.
2. Review and pin public manifest bytes out of band. Run the admitted assessment under existing owner authority. Store every prediction, including explicit UNTESTED for a missing case, and evidence/source hashes. The existing commitPracticalRun constructs each exact run receipt. Do not omit a missed case, application or repetition.
3. Freeze the actual product and application sources in a read-only source tree. With existing Node/tsx dependencies, from the repository run:

   node --import tsx scripts/prospective-assessment-intake.ts seal public-study.json EXPECTED_MANIFEST_SHA256 all-run-receipts.json FROZEN_SOURCE_ROOT sealed-predictions.json

The seal command accepts no oracle filename. It reads ordinary bounded source files, refuses lexical traversal, aliases, missing or changed source digests, incomplete run/application/case membership and changed budgets. Its output uses exclusive creation; it will not overwrite earlier predictions/evidence. No dependency installation is required or authorized by this document. 4. Send the entire seal to the separately controlled oracle operator. That operator independently verifies source, execution and prediction custody, freezes the global bundle hash, and only then signs an oracle release. The message returned by oracleReleaseMessage contains version, studyFingerprint, predictionBundleSha256, oracleSha256 and sourceVersionId. Sign the ASCII hex string heldOutHash(message) with Ed25519; put its64-byte signature in signatureBase64 alongside the message fields. The publisher must never sign a changed prediction bundle after label release. The tool does not provide the external private key or simulate independent ownership. 5. Receive the signed release and labels. Run:

    node --import tsx scripts/prospective-assessment-intake.ts reveal public-study.json EXPECTED_MANIFEST_SHA256 sealed-predictions.json signed-release.json publisher-public.pem private-oracle.json scored-study.json

The CLI revalidates the entire global seal and verifies the pinned release BEFORE opening the oracle file. It then validates the exact oracle digest/case membership and reuses existing scoring, FP review cells, FN, unsafe uncertain conclusions, abstentions, untested/missed cases, fixed opportunities, per-run repeatability and always-abstain baseline. Duplicate outputs refuse overwrite. Inputs/outputs are bounded8MiB ordinary files. Source roots and parent paths must be ordinary directories.

## Interpretation

All-app/run membership and a release signature bind bytes and the publisher's acknowledgement of that bundle. They cannot prove label secrecy, an untampered execution environment, trusted event timing or independent authorship. Output therefore remains independentAcceptance=false,blinded=false and independence HOLD pending separate oracle ownership/prospective custody review. A same-author protocol exercise is never relabelled blinded.

The current engineering delivery uses a frozen self-maintained16-case/two-application oracle and two actual native repetitions. Predictions precede the scoring stage across the whole study; the implementer already knows the fixture labels. Raw native results, explicit misses and cost scope govern the score. Unit counterexamples deliberately exercise TP/TN/FP/FN and uncertainty independently of the runtime score; they are not extra accuracy observations. No genuinely independent publisher or private corpus has been supplied.
