# RouteCairn v0.22 — bounded collection ownership

## Delivered scope

Continues 90148e1d68eacbf18501a934ecad91b2dd5b6e63 on canonical main. No Decide process, database, account, credential or endpoint is used. The v0.21 scalar contract remains the default when route.observation is absent; explicit SCALAR is also supported. A collection route retains kind OBJECT and its per-item identityPath for backward-compatible route structures, but requires observation.kind COLLECTION; the native route is COLLECTION. Scalar tenant/state assertions cannot be mixed into collection evidence.

## Exact contract and limits

Each collection observation declares algorithm bounded-native-collection-v1, collectionPath, itemIdentityPath, ownerPath, ownerRule EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING, maxItems (1–64), maxResponseBytes (512–65536), coverage and pagination. Paths use own data properties only, no array indexing, wildcards, getters, prototype or secret paths. The item identity must identify the saved entry, separately from any shared public resource identifier. No implicit pagination, additional targets or requests are derived. A single authorized GET is evaluated completely or abstains; an over-cap response has zero accepted prefix entries.

THIS_RESPONSE_ONLY makes no global collection claim, even when the declared pagination witness says no more. HAS_MORE_BOOLEAN requires false; NEXT_CURSOR requires null or the empty string. An absent witness is incomplete. UNPAGINATED_RESPONSE requires the owner's explicit unpaginated declaration. Link next and recognized contradictory pagination metadata override that declaration. Arbitrary undeclared pagination conventions cannot be discovered reliably: coverage is the owner's reviewed assertion, not independent proof of server completeness. Encoded bodies are conservatively incomplete.

## Typed ownership and byte provenance

String owners of 1–256 characters compare to the exact actor's verified canonical principal using the existing routecairn-identity-v1 NUL hash domain, truncated to the existing 16-hex identity fingerprint. No owner coercion occurs. Item strings/numbers use the typed observed-marker domain and are never compared directly to principal hashes. Owner numbers, objects, null, missing fields and duplicate typed item IDs are inconclusive. These compact existing identity fingerprints are evidence references, not authentication or signatures.

Native transport must provide requestId, bytesRead, streamTruncated=false, exact transient body SHA-256 and complete UTF-8 bytes. Declared length conflicts, unsupported compression, transport interruption, preview truncation, oversize or malformed JSON cannot become complete ownership proof. Evidence is bounded to 64 hashed entries and carries actor/slot/model/role binding, exact route/check fingerprint, request ID, byte/body hash, counts, mismatch/unknown/duplicate flags, declared coverage and algorithm. Canonical key ordering survives report normalization. Mapping validation also requires exact immutable manifest/credential reference, current authority context, native artifact custody/hash and a matching sent GET audit entry.

## Policy and product integration

Every actor's own collection returning 200 is SELF_COLLECTION_OBSERVED, not foreign-resource access or denial. Foreign-owner entries can produce reviewable questions only after a nonempty clean primary control, all three verified exact actors, immutable native source and adaptive case provenance. Policy is never inferred. Collection review explicitly declares that authenticated actors may read their own entries, that each returned entry must belong to that requesting actor, and anonymous access must be denied. This increment does not approve cross-user endpoint-denial policies using /me. A separate genuinely approved foreign endpoint is observed in a negative control; its 403 is not inferred from own-collection success.

Existing workbench review and dispatch bind the full contract and source; source refresh, actor/model/role or credential replacement invalidates review. Native proof rechecks complete collection ownership and exact request audit. Findings require that explicit policy and fresh matching evidence. Empty/partial/ambiguous later responses remain INCONCLUSIVE, including in triage and handoff. Immutable map comparison retains collection contracts and semantic entry differences; request IDs alone do not imply a content regression. Source hashes and existing comparison history are unchanged. Multi-step state/tenant workflows without collection-specific policy contracts remain conservatively unsupported.

## Verification scope

See the lean review packet's TEST_MATRIX.json and genuine raw receipts for actual runs and failures. Owned Windows native workers and SQLite were used; no full application acceptance or independent/blinded detection accuracy is claimed. Edge checks cover real bundled operator components offline; they are not a production dashboard deployment.

## Operational holds

Decide pilot, Ubuntu, Trusted Discovery execution, Stage D, state-changing execution, external scanning and release remain HOLD. No real setup, session-housekeeping, PostgreSQL provisioning, production credential or traffic authorization is supplied here. All original ten combined-suite 30-second timing failures remain unresolved historical evidence. No timeout or original assertion is weakened.
