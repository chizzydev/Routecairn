# Real owned-application intake, deeper reference validation and analyst handoff v0.1

Use existing Application Authorization → guided mapping → owned onboarding to register an authorized exact 127.0.0.1 origin and three saved target-bound actor contracts. Credentials are encrypted by the existing vault. An operator may use an already running owned local app; this feature does not start, deploy or authenticate an external application. Existing targets and credentials can be reused without editing test fixtures.

## Offline metadata preparation

Never paste raw HAR, cookies, bearer tokens or response bodies into the intake form. From an operator-owned export, prepare a separate JSON metadata file with version 1, exact origin, provenance (OWNER_LOCAL_APPLICATION, SEPARATELY_MAINTAINED_TEST_APPLICATION or SELF_MAINTAINED_FIXTURE), three actors and selected routes. Each actor has slot primary/account_a/account_b, principalFingerprint/tenantFingerprint/roleFingerprint (SHA-256 of UTF-8 'routecairn-identity-v1' followed by a NUL and the declared value, first 16 hex), and sessionEvidenceSha256 of an operator-retained non-secret session provenance record. Each route has id, kind OBJECT/FUNCTION, method GET, exact url and literal pathTemplate, identityPath, tenantPath and up to two statePaths. State fields, such as record.parent and record.version, must be non-secret.

Run from C:\Users\HP\RouteCairn with the already installed runtime:

    node --import tsx scripts/prepare-owned-intake.ts --i-own-this-offline-export C:\owned-review\export.har C:\owned-review\metadata.json C:\owned-review\NEW-minimized.json

The command reads only ordinary bounded files, selects explicit observed GETs, drops all headers, cookies, response bodies and unrelated operations, hashes the original export and writes CreateNew output. It performs zero network operations and never overwrites a retained export. Original secret-bearing HAR stays with its owner. Metadata is validated again by the server; input hashes are declarations, not independently authenticated session proof.

Paste the minimized output into the offline intake section, confirm ownership and secret removal, retain its immutable receipt, then explicitly apply its routes. Intake creates no scan and grants no execution authority. Exact target/credential/route/context changes invalidate its binding. Current identity, role and tenant must be verified by the existing separately authorized native observation. An owner-prepared evidence export can use the same contract directly (kind OWNER_EVIDENCE_EXPORT, exportSha256, capturedAt within seven days). This freshness is declared time, not a trusted clock attestation. OpenAPI suggestions remain available through the existing schema import.

## Three/four-step review

Choose up to four observed GET operations and up to three unique forward producer/consumer edges. Every declared step must be reachable from the first step; disconnected steps abstain and cannot enter reviewed proof. Declare precise producer identity, consumer reference, resource tenant and separate entity versions. Missing producer, duplicate/non-scalar references, typed ID disagreement, stale actor version and tenant drift remain missing evidence or counterevidence. Equal tenant labels are not an entity link. Different roles can observe the same resource without establishing that access is legitimate: explicit owner policy is still required.

These are correlated read-only observations, not causal transitions or a transactionally consistent database snapshot. Existing state-transition/observed-state workflows remain separately governed. A v1 relationship snapshot is retained historically; new v2-connected admission requires a fresh proposal/review if its recomputed relationship digest differs. No old record is rewritten or automatically replayed.

## Analyst handoff

In evidence-centered triage, search all linked proof or note metadata by ID, native state or disposition; twenty entries per page. A membership/status snapshot binds each continuation. New/reclassified records require a fresh search. Each proof detail is checked through the real workbench result service; unreadable proof stays UNKNOWN. Native COMPLETED is a process state, not proof of a healthy result. History above 10,000 rows refuses safe export/paging and requires review rather than returning a quiet truncated list. The existing triage summary remains bounded and explicitly incomplete.

Prepare/download the redacted analyst JSON case: exact source/proposal/evidence hashes, typed actor/entity/version fingerprints, question and reviewed policy contracts, native checks/findings, complete bounded history references, comparisons, historical deviations and unresolved uncertainty. Notes are dispositions plus evidence hashes; free-text rationale and raw request/session/body data are omitted. Historical findings survive remediation. The body checksum excludes packetSha256 and integrityMeaning; it detects byte/body changes, not author identity. The packet grants no authority and cannot be imported as an execution plan. For histories beyond the detail limit, use snapshot-bound pages; exported completeness is explicitly false where details are omitted.

## Prospective independent-oracle handoff

Use scripts/prospective-assessment-intake.ts seal/reveal and docs/PROSPECTIVE_ORACLE_INTAKE_v0.1.md. A separate corpus owner must supply the public complete case/run denominator, product/application commitments, oracle digest and pinned Ed25519 public key without sending labels to the implementer. Seal every application/case/run (including explicit UNTESTED) before requesting a release bound to that seal. The reveal verifies the pinned signed release BEFORE opening the private oracle. Preserve operator custody, label secrecy and external signature evidence for independent review; signatures alone do not establish independence or trusted wall-clock ordering. No independent operator/private corpus was supplied in this increment. Same-author fixture controls remain unblinded, and no independent accuracy claim is made.

## Reproduce the owned Windows engineering slice

    node scripts/run-owned-intake-review-tests.mjs --confirm-owned-fixtures

New uniquely owned roots are retained with raw test JSON/stdout/native SQLite/worker records and source hashes. Original 30-second test/hook and 20-second wait limits are unchanged; no legacy destructive global teardown is used. Tests are controlled synthetic engineering evidence. Neither a green selected profile nor an isolated rerun closes historical combined-run failures or full application acceptance. No ordinary fixture run proves non-fixture production migration, sustained reliability, novice accessibility or independent detection accuracy.

All holds remain: Ubuntu paused; Trusted Discovery execution OFF; Stage D; A1B/real609/A1C; target mutation/unrestricted/external scans; full release/production packaging. No cleanup, replay, suppression, reset, quarantine clearance or new deletion authority.

## Read-only receipt recovery and complete comparison history

After an uncertain intake acknowledgement, explicitly inspect retained intakes, then open the exact receipt by ID; no POST is automatically retried. The newest20 references carry an explicit total/truncation flag; exact-ID read remains available for older records. Receipt custody is rechecked, current target/profile/explicit identity metadata is revalidated, and stale receipts remain readable but cannot be applied. Missing, blank and duplicate actor contexts are rejected rather than hashing undefined placeholders. The analyst packet links intake hashes/provenance separately from actual native proof.
Proof, note AND comparison histories can be searched/paged independently; comparisons are selected through both org-bound linked proof scans across all retained revisions, not only the latest100 summary. Failed/incomplete comparisons stay nonquiet and retain their native identifiers and coverage status. Index bounds and packet-size refusal remain explicit.
