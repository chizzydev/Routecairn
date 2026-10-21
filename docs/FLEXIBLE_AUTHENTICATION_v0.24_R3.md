# Flexible authentication v0.24-R3: reviewed resources and honest coverage

Source baseline: `032efe71f6a5acb6eac81ddd7463f1fa0832ff2b`. The source-first delivery policy applies. R3 is an engineering increment, **not full flexible-authentication or production HTTPS acceptance**.

## Operator journey

Scan Studio continues to accept zero through eight accounts. Zero-account public observation needs no invented identity. One account can observe a session response or test an exact reviewed field policy when principal proof is available. Two through eight distinct verified principals can compare an owner's exact object with foreign-access denials or review bounded collection ownership. Roles and tenants remain optional unless a selected assertion requires them.

The authentication step now includes reviewed resource forms, not only a generic read path. Choose object ownership, collection ownership, field exposure, business-state reads or session response observation. Supply exact paths and policy references and confirm each policy explicitly. The server checks registered scope and vault context without target traffic, compiles existing native API checks, fingerprints the policies and binds them into the registry and campaign. Plan review, worker custody, cancellation, immutable source binding and reports use the existing architecture.

At most four resource policies are accepted per preparation. Policy IDs are bounded to 40 characters; each selected actor can produce one matrix cell per resource. The existing campaign remains capped at 60 requests, three requests per second, one concurrent request and 16 KiB per response. No path discovery becomes authority. Session housekeeping remains separately approved. Resource paths are canonical exact GET paths; writes, provisioning, rotation, revocation and provider effects are not added.

### Object, collection, field and business contracts

An object policy identifies the exact owner actor, bound principal, response owner path, resource URL and safe path template. The owner must receive the exact resource; other actors must be denied. Missing or contradictory identity evidence blocks the stronger workflow. An anonymous `/me` or successful login cannot prove foreign-object access.

Collections use the frozen `bounded-native-collection-v1` algorithm and explicit item, owner, identity, byte and pagination contracts. The server rejects collection byte budgets beyond the campaign's 16 KiB boundary. Every entry in the declared response is checked. Empty arrays, incomplete pagination, duplicate IDs, malformed or unknown owners, truncation and excessive items remain inconclusive. The UI declares this-response-only coverage; it does not automatically paginate or assert global completeness. Registry collection witnesses include the registry identity and exact comparison fingerprint; legacy collection role requirements and bindings remain unchanged.

Field policies explicitly identify the field and permitted actors. Principal proof is required; role proof is required only when independently selected. Business reads bind exact state markers and may require a prior reviewed ALLOW read for the same actor. They observe states; they do not execute state transitions. Session reads are observations, not a claim to test all authentication-lifecycle properties.

## Authority freshness and transport

Changes to credential versions, expiry, enabled state, health, identity metadata or target association invalidate pending and accepted UI preparations. Input/target/unmount protection remains. The existing immutable preview and credential binding refuse altered resources, owner policies, expired approval data, replaced credentials and changed scope before worker activation.

At the shared HTTP broker, a cross-origin redirect cannot forward explicitly supplied headers or a body, even if the new origin is independently in scope. Header names are not assumed to identify secrets: arbitrary custom headers may carry API keys. The broker stops and retains an out-of-scope redirect outcome instead of silently changing the authentication context. Public requests without supplied material retain ordinary scoped redirect handling, and same-origin redirects retain their original behavior. Native API requests continue to disable redirects, and registry API dispatch independently checks the exact credential origin.

A separate genuine Windows Edge RED demonstrated a browser cookie crossing ports on the same host. Authenticated crawler and browser-proof contexts now refuse secondary-origin requests until an explicit credential-use grant architecture exists. Browser cookie domain rules are not treated as origin consent. The original same-origin cookie and form-login controls remain positive controls. Header-variant test-control failures are retained separately from the confirmed cookie disclosure; they do not establish three different disclosures.

**Authenticated split-origin campaigns remain HOLD.** The current target-authorization schema deliberately rejects authenticated campaigns with another origin. R3 does not weaken this rule. A later separately reviewed origin-grant contract must bind actor material, exact secondary scope, explicit credential use, lifetime, budgets, redirects and immutable provenance. The new denial controls are not positive split-origin acceptance.

**Expiring HTTPS browser authentication remains HOLD.** Opaque CONNECT does not expose the final method, path, headers or body for per-request authorization. The existing denial remains. A real Windows Edge test with a generated TLS application and a certificate-validating native HTTPS control records the refusal and zero private requests. It is not a successful HTTPS browser assessment. No certificate verification, CONNECT guard or request broker was disabled to manufacture acceptance.

## Reporting and module compatibility

Native coverage now includes actual HTTP response statuses. Credential-bound 401/403 responses are explicitly labeled observed denials, never successful authenticated sessions. Coverage accepts only observations with matching check, actor and comparison fingerprints. Missing evidence remains unassessed or inconclusive. Dashboard, persistent read model and portable reports retain these native distinctions. Human review does not become native proof.

The versioned resource adapter compiles into the existing API/GraphQL engine, covering exact object/field/collection matrices, session responses and read-state prerequisites. Static parameter analysis and manual vulnerability-workflow generation are also available to registry assessments; they create no new transmission or finding authority. `AUTHENTICATION_MODULE_AUDIT_v0.24_R3.json` inventories every catalog module and its source bindings. Legacy specialized contracts remain strict. Original bulk/summary/file/provider/lifecycle/protocol schemas are not all registry adapted; universal module integration remains incomplete. Do not interpret an equivalent bounded read primitive as full acceptance of an entire legacy engine.

## Limits

The full development dependency audit identified high-severity advisories in the original Vite and source-map-js graph. R3 pins Vite 8.3.3 and overrides source-map-js to 1.2.2, with install lifecycle scripts disabled and reviewed/published locks synchronized. The failed audit and installation/final audit receipts are retained in the packet. These fixes follow the [Vite/launch-editor advisory](https://github.com/advisories/GHSA-587h-7wmj-h5pm) and [source-map-js advisory](https://github.com/advisories/GHSA-68fv-2mgg-jv7q). Dependency remediation is distinct from application or independent acceptance.

The R3 test matrix and raw source-pinned receipts belong in the review packet. All fixtures are generated and owned; they establish conformance, not independent or blinded accuracy. The original ten combined-run timeout failures remain unresolved. No original test deadlines or assertions were weakened. No Decide traffic or credentials, Ubuntu access, held Trusted Discovery/Stage D execution, mutation execution, release build/package or evidence deletion is authorized by this increment.
