# Native identity admission — Gate 0 v0.22

## Actual reachable RED

A fresh owned loopback server and real CLI scan load a legacy profile with a principal verification mapping but no tenant/role mappings. The explicit API manifest supplies principal, tenant and role. The planner previously allowed metadata omitted by that legacy profile. verifyScanIdentities genuinely sets verified=true for its configured principal-only contract. ApiGraphqlModule.identityBlocked previously checked tenant/principal only if both hashes existed and enforced complete role proof only for PRINCIPAL_ROLE. The wire receipt records /identity, /, /object although nativeApplicationProofMatches returns false. This is a native admission gap, not a finding or an authentication bypass of the test application.

The initial harness used the wrong module ID and failed before execution. It is retained separately and is not the RED. GATE0_RED_ACTUAL contains the actual failing no-/object assertion and two passing complete-mode controls. This CLI path is reachable. Guided application mapping already requires all declared principal/role/tenant fields, so that particular legacy incomplete profile cannot pass guided mapping admission; no fabricated dashboard exploit is claimed.

## Structurally shared repair

Move the unchanged strict predicate to core/auth/NativeIdentityAdmission.ts, re-export it from ApplicationIdentity and invoke the same predicate before required authenticated native API/GraphQL requests. Both explicit identity models require exact principal and role matches; tenant-aware also requires exact tenant proof, while principal-role forbids tenant evidence. Generic identity verification semantics remain unchanged. An incomplete legacy identity may still be generally verified for its configured contract but cannot authorize a native check requiring application identity. Anonymous checks and explicitly non-required identity checks keep their existing meaning; collection plans cannot opt out of required identity.

## Other challenge boundaries

Real native tests cover healthy tenant-aware/principal-role and changed principal/role/missing-role (both modes) plus changed tenant. Constructed-state tests separately challenge missing flags/hashes, actor-plan mismatch, wrong roles, tenant contradictions and model replay; these are not represented as external API paths. Reports are generated from current scan identity endpoints, not supplied through the dashboard request as verified reports. Immutable mapping/source hashes, exact actor/credential slots, current vault context and reviewed plan digests reject stale source/credential/model substitutions. Constructed mutated report copies test validators, while independently owned SQLite tests exercise actual credential replacement and retained-source hash refusal. No generalized privilege or verification weakening was introduced.
