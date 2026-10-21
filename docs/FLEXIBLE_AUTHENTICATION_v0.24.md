# Flexible authentication and capability assessment v0.24

Read DELIVERY_AND_STORAGE_POLICY.md and ENGINEERING_CONTINUITY_v0.24.md. This increment uses the existing planner, request broker, native API/GraphQL engine, browser boundary, encrypted vault, executable-plan store, Windows custodian and report pipeline. It creates no independent scanner or target-discovery authority.

## Canonical contract

An explicit actor registry contractVersion 2 contains registryId, organizationId, exact targetOrigin, ordered actors and reviewed workflows. Capacity is eight declared actors, including declared anonymous actors; the native API manifest can additionally represent one implicit anonymous actor. Zero actors is valid. Stable actor IDs and credential references are unique. Anonymous actors carry no credential or identity claims. Roles and tenants are optional fingerprints. Existing v1 primary/account_a/account_b plans retain their original semantics and digests; they cannot be mixed with a registry. The legacy API planner retains its four-actor capacity.

Authenticated actors declare BEARER, COOKIE, API_KEY or BROWSER_SESSION, credential availability and expiry, fresh-disposable or owner-approved-existing-test provenance, and suitability for testing. A private 32-byte binding key creates HMAC-SHA256 profile bindings. Dashboard keys are derived from the encrypted vault's master key and exact organization/target/registry context. The key and profiles travel only in the existing encrypted executable snapshot and authenticated worker secret envelope. Reports retain opaque bindings, never the key or secret. CLI registry/profile files are bounded to 256 KiB each and remain private.

Authentication mechanism, presence of credentials, actual authentication success, principal, role, tenant, ownership and test authority are distinct. A 200 response, browser label or decoded JWT does not establish identity. An optional endpoint is used only for workflows that need it. Principal-only native identity is valid without role or tenant declarations. Independent fields must not alias principal/role/tenant evidence. Complete bounded responses, expected native values, registry/actor/profile fingerprints and a fresh execution epoch bind stronger identity proof. Earlier reports cannot supply a fresh native identity epoch. The v0.21 legacy native predicate is unchanged.

## Shared prerequisite families

| Family                    | Authenticated actors | Additional authority/evidence                                                                               |
| ------------------------- | -------------------: | ----------------------------------------------------------------------------------------------------------- |
| PUBLIC_OBSERVATION        |                    0 | Exact reviewed read scope and budgets                                                                       |
| AUTHENTICATED_OBSERVATION |                    1 | Bound available credential, expiry and reviewed session housekeeping; endpoint optional                     |
| PRINCIPAL_OBSERVATION     |                    1 | Current native principal proof                                                                              |
| OWNERSHIP_COMPARISON      |                   2+ | Distinct current principals, explicit reviewed owner-policy fingerprint and exact resource assertions       |
| ROLE_COMPARISON           |                   2+ | Above plus independently verified roles                                                                     |
| TENANT_COMPARISON         |                   2+ | Above plus independently verified tenants                                                                   |
| BROWSER_OBSERVATION       |                    1 | One explicitly selected actor, existing origin/write/budget/cancellation gates; HTTP native acceptance only |
| LEGACY_SPECIALIZED        | Original v1 contract | Explicit original identity/recovery adapter; registry execution BLOCKED                                     |

ELIGIBLE means prerequisites are available, never that a test ran. Missing evidence is NOT_ASSESSED; expired/revoked/invalid or unsupported contexts are BLOCKED; reviewed irrelevant workflows are NOT_APPLICABLE. Runtime coverage distinguishes OBSERVED, TESTED and INCONCLUSIVE, with the underlying native PASS/FAIL/BLOCKED case outcomes retained separately. Missing credentials or network errors never prove a secure application or access denial. More actors create no extra authority. The five-actor fixture executes all reviewed owner/foreign ownership cells, beyond five superficial logins.

Specialized v1 engines remain available through their original reviewed contracts. In a registry assessment, their missing adapter blocks those modules while ordinary public/API observations continue. This is an explicit compatibility boundary, not evidence that all specialized engines now consume flexible actors. Strictly invalid mixed-version contracts are rejected before traffic.

## CLI and dashboard

The existing scan command accepts --actor-registry <private-wrapper.json> and --organization <exact-id>. The wrapper contains registry, bindingKey and profiles mapping actor IDs to private profile paths. Do not commit these runtime files. Use exported schemas and private operator tooling to construct an explicit reviewed API/GraphQL matrix. Its matrixId binds the reviewed registry workflow. Observation-only workflows cannot silently authorize a stronger ownership/role/tenant assertion.

The existing web-assessment prepare command accepts the same flags, --reference and --output. Preparation/review sends no target traffic. Review the complete campaign and exact digest, then use web-assessment run with --campaign, --approved-digest, --output-parent and the same private registry/organization flags. Generated checks observe only explicitly approved requests; stronger ownership policies are never invented from /me. A native Commander prepare/review plus one-account campaign exercise is retained in the review packet.

New Scan Studio assessments default to the flexible registry. Select or register an authorized target, use its approved scope, configure only available saved credentials, review exact GET/session-housekeeping authority, inspect missing capability prerequisites, resolve the immutable plan, launch and inspect evidence. Public checks require zero accounts. Registry identity assurance does not show legacy mandatory role/tenant fields. Existing saved/retest/adaptive/provider drafts retain their explicit legacy mode. Changing target, input or unmounting rejects an obsolete in-flight registry response. Browser-capability gaps are shown explicitly. Advanced policy/relationship proof continues to use the existing reviewed native manifests/workbench, not an automatic policy oracle.

Native report JSON and Markdown/HTML include capability coverage. The dashboard persists bounded per-actor/workflow records instead of overflowing the existing 4,000-character event limit. Full evidence is retained in the JSON artifact; compact inline evidence explicitly identifies its coverage and links to that artifact. Human-review instructions remain labeled HUMAN_REVIEW_ONLY and cannot mint native proof.

## Authentication and lifetime limits

Bearer, cookie and API-key HTTP acceptance use actual owned native applications. Imported cookies and an explicit form-login flow have actual Windows Edge acceptance with the expiring HTTP request boundary. Locale metadata is explicitly bound before continuation; credential/header equality is preserved. Third-party identity providers never become test scope through a redirect. This increment does not implement or validate a live OAuth/SSO provider integration. Only separately reviewed existing application sessions/bootstrap can be reused.

HTTPS browser authentication remains BLOCKED by the expiring CONNECT transport HOLD. No CONNECT bypass was introduced. Browser bootstrap success is not principal proof. Browser observations with no bound native transmission remain unassessed. Native 401 invalidates later authenticated workflows. Vault disable/invalid-health/metadata/secret/renewal changes notify the owning execution service and request existing safe cancellation; a queued STOP is not described as acknowledged termination. In-flight requests or previously authorized cleanup still require actual terminal receipts. Direct database tampering and cross-process changes outside the supported vault API are not an instantaneous distributed revocation channel.

No Decide service was started, changed, provisioned, queried or assessed in v0.24. A production pilot requires a separate exact campaign and owner-approved effects/accounts. Three accounts are not a universal requirement. Existing tenant-aware, principal-role and bounded collection contracts remain distinct and strict.
