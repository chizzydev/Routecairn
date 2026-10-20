# Bounded collection ownership — exact next-stage contract

## Decision at v0.21

DEFERRED / HOLD, not implemented. The explicit-identity increment first passed both native identity modes and missing/conflicting/revoked controls. Source investigation found that ApplicationMappingContracts accepts scalar field paths and ApiGraphqlModule.authorizationObservation retains scalar observedMarkers. ApiResponseContractPlan has no collection owner-rule or pagination-completeness witness; maxItems alone is not evidence that every item was checked. ObservedActorEvidence validates exact actor/route/request/scalar-marker tuples, and hypotheses/reviewed ALLOW controls assume an exact scalar object or function marker. Introducing data[0].user_id or hashing a few entries would leave later entries, empty results, truncated responses and pagination unproved. No wildcard/index workaround was added.

Implement the following as a separate reviewed product increment in existing classes, not a new scanner. No target setup or traffic is authorized by this document.

## Scope and contracts

- Extend ApplicationMappingContracts route observations with a discriminated scalar-versus-collection contract; preserve scalar behavior and historical digests when absent. The collection variant explicitly declares collection path, per-item identity path, owner path, expected actor-principal ownership rule, item ceiling (1–64), response-byte ceiling and pagination policy. Owner and identity paths must use the existing non-secret/prototype-safe field policy. No credentials, raw bodies, arbitrary expressions, wildcards or executable transformations in evidence.
- One authorized GET response only; no implicit follow, cursor replay or expanding path inference. Define THIS_RESPONSE_ONLY versus explicit owner-declared UNPAGINATED_RESPONSE coverage. Never infer full collection completeness from an absent pagination field. A reviewed pagination field/Link control indicating more data makes whole-collection status INCOMPLETE. Without a completeness contract, abstain from global isolation conclusions.
- Require the existing three distinct saved actors, principal/role verification and exact target/org/credential/mode binding. Apply real tenant requirements only in TENANT_AWARE mode. Never map principal IDs into tenant fields. Identify saved-entry IDs separately from shared public phone IDs.

## Native observation and provenance

Extend ApiGraphqlPlanner/Types and ApiGraphqlModule.authorizationObservation in the existing response path. Bind evidence to immutable check comparison fingerprint, mode-aware actor/credential slot, route URL fingerprint, HTTP request/response/body fingerprint, parser algorithm version and declared coverage. Use the existing transient-response analysis; derive an explicit truncation/oversize/incomplete flag from transport evidence, not JSON parse success alone. Reject conflicting or missing byte evidence. Never retain secrets or unbounded body data.

Check EVERY entry within the declared response boundary, up to the ceiling. Do not silently slice to the first N then call the remainder verified. More than the ceiling is BOUND_EXCEEDED/INCOMPLETE, not PASS. Retain bounded entry identity/owner fingerprints and types, checked count, total parsed count, owner mismatch count, duplicate-ID/unknown-field flags, body/evidence binding and coverage classification. Compare each owner to that exact actor's verified native principal using a documented typed normalization/hash contract. A principal hash and observed-marker hash currently use different domains; do not compare them directly or coerce arbitrary values into a match.

EMPTY is a distinct observation: it establishes no nonempty ownership control. Missing/non-scalar owner, duplicate/ambiguous IDs, contradictory metadata, partial pagination, response truncation and unknown coverage remain INCONCLUSIVE/ABSTAIN. No array property/prototype inheritance can satisfy an entry field.

## Mapping, policy and analyst integration

Extend ObservedActorEvidence, ApplicationMappingEvidence, ApplicationSecurityHypotheses and AuthorizationWorkbenchService with explicit collection control semantics. A 200 for another actor's own /me is SELF_COLLECTION_OBSERVED, not foreign-object access or successful denial. A foreign-owner item may become a reviewable candidate only with verified native actor and bounded exact entry evidence; an executed finding still needs explicit owner policy and matching native proof. Cross-user denial requires a real approved foreign-resource endpoint and cannot be manufactured from /me.

Make reviewed plan digests, binding/context freshness, native source validation, immutable comparison and handoff carry collection algorithm, item/byte bounds, owner rule, coverage and identity mode. Unknowns must propagate to triage/continuous assurance. Keep old scalar, tenant-aware and case-history meaning unchanged. Update the existing operator panels to explain empty, incomplete, mismatched and untested collections without creating a new approval or execution bypass.

## Required falsification and acceptance

Use fresh exclusively owned synthetic Windows fixtures and SQLite stores; preserve deadlines. Prove RED before a necessary repair where a real contract defect is found. Cover: nonempty correct ownership; a mismatched owner in the final retained item; a mismatched item just after the cap; empty arrays; missing/typed-wrong fields; duplicate IDs; array/object confusion; inherited keys; malicious paths; cursor/Link indicates more data; undeclared pagination; oversized and byte-truncated responses; invalid JSON; transport errors; actor switch; different role same principal; changed credentials; target/org/mode replay; wrong response/check/source hash; authenticated own collection returning 200 for every actor; genuine denied foreign-resource endpoint; shared public object IDs; no decryption/requests on readiness.

Demonstrate at least one native map → explicit ownership/policy review → bounded proof → redacted analyst handoff, plus negative controls, with retained raw results and no independent accuracy claim. Add selected tenant-aware scalar/hypothesis/native/UI regressions. If item/pagination/response provenance cannot be made exact, remain HOLD rather than widening authority.

## Operational exclusions

Do not modify or start Decide, provision PostgreSQL/users, obtain tokens, send mail/payments/scraping/OAuth traffic or permit target requests under this contract. Actual Decide setup and session-housekeeping approval require a separate owner authorization. Ubuntu, Trusted Discovery, Stage D, mutation execution, external scanning and release remain held. Deliver reviewed canonical Git source plus ONE lean checksummed review packet; preserve ten historical timing failures and all prior evidence. This specification is the next scope proposal, not activation authority.
