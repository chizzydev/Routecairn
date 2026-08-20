# RouteCairn

Web attack surface intelligence for serious security testing.

RouteCairn is an engine-first TypeScript security tool for authorized web application testing. The long-term goal is to help security learners, bug bounty hunters, and engineering teams map, prioritize, document, and monitor web attack surface evidence.

Batch 1 establishes the foundation:

- strict TypeScript project setup
- `routecairn init` CLI command
- zod-backed config and scope validation
- URL normalization
- scope matching and disallowed path checks
- central logger and application errors
- file storage interfaces and local storage base
- unit tests for URL and scope behavior

Batch 2 adds the first working scan path:

- `routecairn scan <target>`
- undici-based HTTP client
- concurrency queue and global rate limiter
- timeout and retry policy
- response metadata, body preview, title extraction, and body hashing
- scan context/state/orchestration
- initial `report.json` output
- local integration test for the scan command

Batch 3 makes quick scans useful:

- soft-404 baseline probes before path discovery
- common, admin, and API wordlist path discovery
- scope checks before every discovered path request
- response analysis with `likely-valid`, `maybe-false-positive`, and `likely-false-positive` marking
- structured `report.json`
- human-readable `report.md`

Batch 4 makes modules extensible:

- shared plugin interface for scan modules
- plugin registry with scan-plan-based selection
- module runner with phase ordering
- central finding model with severity, confidence, evidence, recommendations, and manual testing suggestions
- path discovery now emits central findings for interesting surfaces

Batch 5 adds technology-aware intelligence:

- detects common frameworks, CMSs, commerce stacks, platforms, servers, CDNs, and cloud references
- records detected technologies in JSON and Markdown reports
- expands path discovery with technology-specific paths for Next.js, Laravel, WordPress, Shopify, Firebase, Supabase, Vercel, Netlify, and S3/CloudFront patterns

Batch 6 adds JavaScript intelligence:

- extracts script URLs from HTML with a parser
- downloads same-origin JavaScript only
- mines endpoints, routes, absolute URLs, websocket URLs, cloud references, and config-looking values
- detects source map references
- queues in-scope JS-discovered endpoints for normal scoped path discovery
- classifies public frontend variables such as `NEXT_PUBLIC_` and `VITE_` as public frontend config, not secrets

Batch 7 adds API and auth intelligence:

- classifies discovered API endpoints by route purpose and risk tags
- detects GraphQL endpoints
- detects auth surfaces such as login, registration, password reset, OTP, OAuth, magic-link, logout, and session routes
- adds manual testing hints for IDOR/BOLA, authorization, rate limits, GraphQL, exports, account enumeration, and reset/OTP abuse
- adds API Manual Testing Map and Auth Surface Map sections to reports

Batch 8 adds security review modules:

- reviews security headers with realistic severity
- parses cookies and scores issues based on session/auth sensitivity
- probes CORS with controlled Origin headers and avoids overstating wildcard CORS without credentials
- checks OPTIONS responses for advertised dangerous HTTP methods
- emits central findings for header, cookie, CORS, and method issues

Batch 9 adds exposure review and risk scoring:

- checks for sensitive files, config files, backups, debug/log paths, source maps, and directory listings
- stores limited previews through the existing HTTP body preview controls
- detects secret-like patterns without storing full sensitive bodies
- adds recommendation rules for exposure findings
- attaches numeric risk scores to findings

Batch 10 adds browser intelligence:

- renders the target with Playwright in profiles or legacy compatibility plans that include `browser-crawler`
- captures screenshots under the scan output directory
- extracts rendered links and queues them for scoped discovery
- captures console warnings/errors and basic network requests
- detects forms but does not submit them by default
- includes integration coverage for screenshot capture and rendered browser evidence

Browser mode requires Playwright's browser binary:

```bash
npx playwright install chromium
```

Batch 11 adds monitoring and report polish:

- `routecairn show <report.json>` for clean scan summaries
- `routecairn diff <old/report.json> <new/report.json>` for monitoring changes
- compares new/removed URLs, changed statuses, new/resolved findings, severity changes, technologies, JS endpoints, API endpoints, and auth surfaces

Batch 28 adds true scan planning:

- scan profiles resolve into immutable engine-level plans before execution
- module selection, module settings, limits, retry behavior, auth requirements, evidence policy, and output expectations are validated up front
- the engine executes the resolved plan rather than reinterpreting legacy modes
- reports include `scanPlan` metadata with selected modules, skipped modules, effective limits, auth availability, evidence policy, and legacy translation details

Batch 29 adds browser hardening:

- browser policy is resolved from `ResolvedScanPlan` module settings before Playwright starts
- Playwright contexts are created with downloads disabled and service workers blocked by default
- browser requests are intercepted before network transmission, checked for safe protocol/resource type, scoped through the shared `RequestSafetyBroker`, and bounded by the same scan-wide request budget as direct HTTP
- unsafe browser methods such as `POST`, `PUT`, `PATCH`, and `DELETE` are blocked during the hardened crawl phase
- blocked browser activity is reported as structured policy events with sensitive URL parameters redacted

Batch 30 adds controlled object-pair authorization testing:

- operators can supply Account A, Account B, Account A-owned objects, Account B-owned objects, and fixed read-only request templates
- the planner resolves a complete four-entry request matrix before execution and rejects ranges, wildcards, generators, unsafe methods, out-of-scope templates, and embedded auth headers
- owner baselines are requested before cross-account requests; cross-account directions are marked inconclusive and not sent when ownership is not confirmed
- Account A and Account B requests use the shared `RequestSafetyBroker` with authentication-aware cache partitioning, scope checks, redirect checks, rate limits, retry limits, and redacted audit metadata
- findings are emitted only when a supplied foreign-owned object returns private-field evidence after owner baseline confirmation; public and intentionally shared access is not reported as IDOR/BOLA
- object identifiers are hashed or redacted in serialized plans, evidence, reports, and reproduction commands

Batch 33 adds controlled role and state authorization matrix testing:

- operators can supply exact actors, roles, tenants, account states, object states, object IDs, request templates, and expected authorization decisions
- the planner resolves a complete fixed `GET` request matrix before execution and rejects discovery patterns, unsafe endpoints, mutating methods, out-of-scope URLs, embedded auth material, identity conflicts, unknown actors, missing references, and impossible state checks
- Account A, Account B, and optional public requests use the shared `RequestSafetyBroker`; public requests carry no auth headers, cookies, CSRF headers, or tenant headers
- identity requirements gate affected authenticated cases before request execution, and object identity plus configured object state must be confirmed before access can become a finding
- findings are emitted only when a declared denial boundary is bypassed by a confirmed protected object; reports hash or redact raw object IDs, identity values, auth material, and response bodies

Batch 34 adds controlled equivalent-route authorization testing:

- operators can supply a canonical route, explicit alternate routes, exact actors, one exact object ID, object identity/state fields, equivalence policies, and expected decisions
- the planner resolves a complete actor-route request matrix before execution and rejects route generation, unsafe methods, out-of-scope templates, wildcard/range/generator inputs, missing canonical routes, invalid references, and embedded auth material
- every request uses the shared `RequestSafetyBroker`, preserving scope, redirect, retry, cache-partition, rate-limit, and global request-budget controls
- findings require a canonical/reference route to enforce a protected boundary and an explicitly supplied alternate route to return the same confirmed object
- field-level differences, status differences, and JSON-shape differences alone are recorded as observations rather than route-authorization findings

Batch 35 adds controlled collection authorization testing:

- operators can supply exact collection/list/search/summary endpoints, explicit actors, exact known object IDs, membership expectations, completeness semantics, and safe response paths
- the planner resolves a fixed `GET` request matrix and rejects pagination, generators, unsafe methods, discovery, auth material in templates, unknown references, duplicate object IDs, and out-of-scope URLs
- every request uses the shared `RequestSafetyBroker`; public cases carry no auth material
- findings require a prohibited supplied object to appear in the configured bounded response with matching metadata where configured
- unknown returned IDs, pagination links, cursors, unmatched objects, full response bodies, auth material, and raw object IDs are not persisted

Batch 36 adds controlled bulk authorization testing:

- operators can supply exact non-mutating bulk preview, validation, dry-run, summary, or simulation requests with exact object IDs and expected per-object decisions
- the planner resolves a fixed bulk request matrix before execution and rejects real mutations, unsafe methods, missing dry-run/preview markers, wildcards, ranges, generators, body auth material, unknown placeholders, duplicates, and out-of-scope URLs
- JSON `POST` is allowed only for controlled non-mutating bodies with a fixed safety marker; `GET` supports repeated-query or comma-query object-list templates
- every baseline and cross-account request uses the shared `RequestSafetyBroker`, including body-sensitive and auth-partitioned cache keys, scope checks, redirect checks, retry/rate/budget controls, and redacted audit metadata
- findings are emitted only for positive prohibited supplied-object matches or configured metadata exposure after the safety contract is satisfied; safety-contract failures are observations, not authorization findings

Batch 37 adds controlled file authorization testing:

- operators can supply exact file references, actors, metadata/download/preview/signed-URL endpoints, expected decisions, identity strategies, and bounded content-proof modes
- the planner resolves a fixed `GET`/`HEAD` request matrix and rejects mutating methods, discovery patterns, traversal-like references, wildcards, generators, auth material in templates, unknown placeholders, duplicate file refs, and out-of-scope URLs
- file content probes use bounded streaming through the shared `RequestSafetyBroker`; raw bytes are fingerprinted only and are not written, opened, rendered, extracted, or persisted
- metadata, content, preview, signed-URL issuance, and headers-only observations remain distinct, and `HEAD` never becomes complete content proof
- findings require an explicit denial expectation plus exact file identity or configured fingerprint evidence for the supplied actor/file/endpoint only

Batch 38 adds DNS-to-socket destination pinning for shared HTTP:

- every broker-managed Node HTTP request uses a pinned Undici connector underneath `RequestSafetyBroker`
- RouteCairn resolves the destination hostname, validates every returned address, selects one deterministic approved IP, connects directly to that IP, verifies the socket remote address, then transmits the request
- mixed public/private, loopback, metadata, link-local, multicast, unresolved, timeout, and excessive DNS answer sets fail closed before request bytes are sent
- original HTTP Host authority, HTTPS SNI, and normal TLS certificate verification against the original hostname are preserved; TLS verification is not disabled
- redirects and retry attempts receive fresh DNS resolution and fresh pins; file probes, signed-URL follows, identity verification, bulk POST, and all other shared broker requests inherit the same pinned transport

## Install

```bash
npm install
```

## Build

```bash
npm run build
```

## Test

```bash
npm test
```

## Initialize A Workspace

```bash
npm run build
node dist/cli/index.js init
```

After package linking in a later workflow, the command will be:

```bash
routecairn init
```

## Run A Quick Authorized Scan

```bash
npm run build
node dist/cli/index.js scan https://example.com --scope ./examples/scope.example.json --profile quick --output ./reports/example
```

The scan writes:

- `report.json`
- `report.md`

## Scan Profiles And Planning

RouteCairn profiles are declarative scan definitions. The CLI resolves a requested profile into a validated `ResolvedScanPlan`; the engine receives that plan and executes its ordered modules exactly. Legacy `--mode` is accepted only at the CLI boundary and translated once to a profile (`quick` stays `quick`; other legacy modes map to `full`). The translation is recorded in `report.json` under `scanPlan.metadata`.

| Profile | Purpose | Auth | Relative intensity | Evidence | Important limits |
| --- | --- | --- | --- | --- | --- |
| `quick` | Fast initial feedback with baseline, tech, JS hints, path/API/auth mapping, parameters, and workflow leads. | Not required | Low | Minimal request audit; body previews stripped from serialized reports | depth 1, 4 rps, concurrency 3, 80 requests, 1 retry attempt |
| `full` | Broad unauthenticated coverage including browser, security header/cookie/CORS/method checks, exposure review, Next.js review, and workflow templates. | Not required | Medium/high | Normal evidence for findings | depth 2, 8 rps, concurrency 5, 300 requests, 2 retry attempts |
| `authenticated` | Logged-in review with public modules plus authenticated comparison, optional Account A/B comparison, state-aware API review, and proof blocks. | Requires `--auth`; Account A/B modules require `--auth-a` and `--auth-b` when selected | High but bounded | Strong reproducible evidence and proof blocks | depth 2, 12 rps, concurrency 3, 360 requests, 2 retry attempts |
| `monitor` | Repeatable low-noise monitoring for stable diffable results. | Not required | Low | Minimal stable evidence; body previews stripped; no browser/proof/auth comparison | depth 1, 2 rps, concurrency 2, 120 requests, 1 retry attempt |
| `proof` | Re-test high-signal targets and produce reproducible evidence packs without unsafe actions. | Optional | High where useful | Strong evidence and proof blocks | depth 2, 10 rps, concurrency 4, 260 requests, 3 retry attempts |

Authenticated requirements are validated before any request is sent. The `authenticated` profile requires one primary auth profile. Modules that compare Account A and Account B declare their own account-pair requirement; if Account A/B profiles are absent, those optional modules are excluded with a `skippedModules` explanation. If an operator explicitly requests an account-pair module without Account A/B context, planning fails. Auth material is passed through the shared auth profile abstractions and redacted from request audits, reports, curl proof commands, and serialized plans.

### Legacy Mode Compatibility

Legacy `--mode` is translated once at the CLI boundary into a resolved plan. Narrow legacy modes preserve narrow intent by applying a validated module subset; no scanner below the CLI interprets legacy modes.

| Legacy mode | Previous behavior | New profile | New module selection | Limits | Breadth |
| --- | --- | --- | --- | --- | --- |
| `quick` | Quick mode modules | `quick` | Quick profile modules | Quick limits | Equivalent |
| `full` | Full mode modules | `full` | Full profile modules | Full limits | Equivalent |
| `api` | API-focused discovery/probing | `full` + subset | baseline, tech, path discovery with API sources, API mapper/probe, auth surface, parameters, workflows | Full limits unless overridden | Narrower than full |
| `admin` | Admin-focused discovery | `full` + subset | baseline, tech, path discovery with admin sources, API/auth/parameter/workflow analysis | Full limits unless overridden | Narrower than full |
| `backup` | Backup/exposure-oriented checks | `full` + subset | baseline, tech, common path discovery, exposure review | Full limits unless overridden | Narrower than full |
| `headers` | Header review | `full` + subset | baseline, tech, header review | Full limits unless overridden | Narrower than full |
| `cookies` | Cookie review | `full` + subset | baseline, tech, cookie review | Full limits unless overridden | Narrower than full |
| `cors` | CORS review | `full` + subset | baseline, tech, CORS review | Full limits unless overridden | Narrower than full |
| `methods` | Method review | `full` + subset | baseline, tech, method review | Full limits unless overridden | Narrower than full |
| `js` | JavaScript/API route intelligence | `full` + subset | baseline, tech, JS intelligence, path discovery, API mapper/probe | Full limits unless overridden | Narrower than full |
| `browser` | Browser rendering plus JS/API analysis | `full` + subset | baseline, tech, browser crawler, JS intelligence, API/auth/parameter/Next.js/state-aware/workflow analysis, proof-mode skip marker | Full limits unless overridden | Narrower than full; preserves old browser intent |

### Configuration Precedence

Effective plans use this precedence:

1. System defaults in `src/config/defaults.ts`.
2. Profile defaults in `src/core/planning/ProfileDefinitions.ts`.
3. Module defaults in `src/core/planning/ModuleCatalog.ts`.
4. Repository/project config and scope files.
5. CLI/API overrides such as `--rate` and `--concurrency`.
6. Per-module planner overrides such as legacy compatibility path sources.
7. Hard safety ceilings enforced by the planner.

Unknown module settings, unsupported module settings, invalid limits, missing dependencies, and values above hard safety ceilings fail during planning.

### Next.js Deep Review

The existing `nextjs-review` module performs a bounded, evidence-driven review of modern Next.js applications. It combines multiple detection signals, classifies Pages Router, App Router, mixed, or unknown architecture, and builds a normalized surface model for HTML, `__NEXT_DATA__`, public build/SSG metadata, exact Pages data URLs, browser-observed RSC/Flight requests, JavaScript chunks, explicitly referenced source maps, runtime configuration, and cache metadata.

The review parses JSON and common browser manifest assignment wrappers without executing remote JavaScript. It records property paths, types, bounded counts, redacted source paths, scan-scoped HMAC presence attestations, and safe fingerprints instead of persisting complete props trees, source code, credentials, or private values. `NEXT_PUBLIC_*` values, build IDs, public route names, RSC metadata, Server Action identifiers, source-map availability, `Cache-Control: public`, missing `Vary`, and `x-nextjs-cache` are observations rather than vulnerabilities unless concrete sensitive exposure is demonstrated.

Pages data URLs are derived only when both an evidenced build ID and an already observed concrete route are available. Dynamic templates such as `[id]`, `[...slug]`, and `[[...slug]]` remain templates. App Router analysis reuses exact browser/network observations and does not generate `_rsc` values or router-state trees. Source maps are processed only from `sourceMappingURL`, direct links, or supplied exact artifact evidence; inline maps have encoded and decoded limits, and `sourcesContent` is analyzed in memory without being copied into reports.

Default full-profile secondary request ceiling is 16: 4 manifest, 8 data-surface, 4 source-map, and 0 cache-differential requests. The proof/deep profile ceiling is 38: 8 manifest, 16 data-surface, 8 source-map, and 6 reserved cache-differential requests; controlled cache review remains disabled unless explicitly selected. These module ceilings are subordinate to the global broker budget. Scan Studio exposes the ordinary settings through the Next.js module card, and the same settings are available in `routecairn.config.json` under `nextJsReview`.

Controlled cache differential mode uses exact known URLs, configured actors with distinct declared identities, `GET` only, and `skipCache` so RouteCairn's own response cache cannot create a false leak. It does not inject cache-poisoning headers, alter host/proxy headers, add random cache busters, invoke Server Actions, or perform mutation requests.

Known limitations include future unknown Next.js artifact shapes, server-only manifests that are never public, unobserved dynamic route values, intentionally unfuzzed RSC internals, intentionally uninvoked Server Actions, and source maps that are neither referenced nor explicitly supplied. Browser-managed traffic retains the documented Playwright DNS pinning residual.

> RouteCairn does not brute-force Next.js routes, fuzz RSC internals, invoke Server Actions, or perform cache-poisoning attacks.

### Browser Hardening

Browser crawling uses `browser-crawler` settings declared in `src/core/planning/ModuleCatalog.ts` and overridden by profiles in `src/core/planning/ProfileDefinitions.ts`. Supported settings include `browserMaxPages`, `browserMaxLinksPerPage`, `browserMaxPolicyEvents`, `browserMaxRequestsPerPage`, `browserBlockThirdParty`, `browserAllowedResourceTypes`, `browserAllowedThirdPartyOrigins`, screenshot capture, popup/download/upload, private-network, service-worker, and WebSocket controls. Unsupported browser settings fail during planning.

Scope is evaluated with the shared normalized URL matcher, including protocol, hostname, port, path, same-origin, subdomain, disallowed-path, and safe-method checks. Browser-only policy decisions happen before broker budget spending for prohibited protocols, prohibited private/internal destinations, unsupported resource types, download-like URLs, third-party resources, and per-page browser request limits. Destination checks block loopback, private IPv4 ranges, IPv6 loopback/local ranges, link-local addresses, cloud metadata-style addresses, `localhost`, single-label/internal hostnames, trailing-dot variants, and common alternate IPv4 literals. Public-looking hostnames are DNS-resolved before transmission where the runtime resolver can resolve them; every returned address is checked and mixed public/private answers fail closed. Local/private test targets require both `browserAllowPrivateNetwork: true` and exact `browserAllowedPrivateOrigins` entries. The boolean alone is not permission to browse arbitrary internal destinations.

Third party means a different origin from the target origin: scheme, host, and port must all match. Same registrable-domain subdomains and same host on a different port are third party under this model. Narrow exceptions can be declared as exact origins in `browserAllowedThirdPartyOrigins`.

Allowed browser resource types are `document`, `stylesheet`, `script`, `xhr`, `fetch`, and `manifest` by default. Other Playwright resource types (`image`, `media`, `font`, `texttrack`, `eventsource`, `websocket`, `other`) are blocked unless explicitly allowed by the resolved plan; all intercepted resource types count as browser attempts, and transmitted ones consume the global request budget. The attempt budget is separate from the network request budget and bounds blocked third-party resources, blocked resource types, mutating requests, out-of-scope requests, popup attempts, download/upload attempts, WebSocket attempts, frame requests, and worker/service-worker attempts where observable. Policy-event retention is capped by the same browser-attempt ceiling.

Frames inherit the context route policy. Popups are closed unless explicitly allowed, and their requests still pass through context-level routing. Downloads are disabled at context creation, download-like navigations are blocked, and download events are cancelled. File input clicks are denied in the browser init script; file chooser events are recorded as upload policy events; scanner modules are not given raw page/context APIs that upload files.

Service workers are disabled by default with Playwright context `serviceWorkers: "block"` and a browser init-script guard that rejects `navigator.serviceWorker.register`. `browserAllowServiceWorkers` is false by default and must be explicitly resolved through the plan for any future reviewed workflow.

WebSockets are controlled with Playwright `browserContext.routeWebSocket`, not ordinary HTTP route interception. `browserAllowWebSockets` is false by default. Blocked sockets are closed by policy before connecting to the server. Allowed sockets still require scope approval, destination approval, request-budget reservation, and any necessary exact origin exceptions. RouteCairn controls WebSocket connection destinations and teardown; it does not inspect or log permitted WebSocket message payloads.

Crawl depth is traversal distance from the seed: the initial page is depth `0`, links discovered there are depth `1`, and nested links are depth `2`. The crawler uses deterministic breadth-first scheduling, conservative canonical URL de-duplication, a maximum page count, a maximum links-per-page count, per-page request limits, and the global broker request budget. Browser crawl identity removes fragments, lowercases hostnames, removes default ports, and normalizes repeated path slashes. It preserves query parameter order, duplicate parameters, empty parameters, parameters without values, and query encoding as serialized by the browser URL parser. It does not sort signed or security-looking query strings and prefers duplicate crawling over collapsing potentially different application states. It extracts anchors only and does not click buttons or submit forms. Applications that mutate state through `GET` remain a residual risk and findings should be manually verified.

DNS checks are policy-time checks. RouteCairn does not currently pin the browser connection to the exact approved DNS answer or route traffic through a scanner-controlled proxy, so DNS rebinding between policy evaluation and browser connection remains a documented residual limitation. Do not describe the browser layer as complete SSRF-grade network isolation.

Authenticated browser bootstrap is separate from the hardened crawl phase. The current scanner does not use a browser login automation workflow. When a resolved plan requires authentication, `browser-crawler` skips with an explicit note rather than browsing anonymously and implying authenticated browser coverage. If browser login is added later, mutating bootstrap exceptions must be scoped to that phase and removed before normal crawling begins.

### Object Pair Testing

Object-pair testing is an explicit authorization verification workflow for IDOR/BOLA-style checks. It is not an object scanner. It never guesses identifiers, mutates identifiers, increments or decrements IDs, extracts IDs from responses, follows pagination for discovery, or expands test cases at runtime.

Run it by supplying two separate authentication profiles and a JSON object-pair file. Each Account A/B auth profile must declare non-secret identity metadata: `principalId`, optional `tenantId`, optional `role`, and optional `safeAlias`. RouteCairn rejects identical auth material and also rejects different sessions that declare the same `principalId`.

Auth profiles may also configure optional server-side identity verification. This verifies the application principal represented by the authenticated session, not a human's real-world identity. Verification uses only the configured endpoint and explicit field mappings; RouteCairn does not discover identity endpoints or infer fields.

```json
{
  "label": "account-a",
  "safeAlias": "Account A",
  "principalId": "fictional-principal-a",
  "tenantId": "fictional-tenant-a",
  "role": "member",
  "headers": {
    "Cookie": "session=<redacted>"
  },
  "identityVerification": {
    "mode": "required",
    "endpoint": "/api/me",
    "method": "GET",
    "principalIdField": "user.id",
    "tenantIdField": "organization.id",
    "roleField": "user.role",
    "safeAliasField": "user.username",
    "anonymousMarkers": [{ "field": "authenticated", "value": false }]
  }
}
```

Verification modes are `disabled`, `optional`, and `required`. Optional failures are reported but do not appear as verified success. Required failures block dependent modules such as object-pair tests that require verified Account A/B principals. Identity requests use the same `RequestSafetyBroker` as scanner modules, so scope, redirects, retries, rate limits, cache partitioning, and global request budgets apply. Reports store categories, match booleans, status metadata, response hashes, and stable hashes of identity values; they do not store raw principal IDs, tenant IDs, cookies, authorization headers, or full identity responses.

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --object-pairs ./examples/object-pairs.example.json \
  --output ./reports/object-pair-example
```

The first implementation supports fixed `GET` and `HEAD` URL templates with exactly one `{{OBJECT_ID}}` placeholder. URL APIs may encode the placeholder as `%7B%7BOBJECT_ID%7D%7D`; RouteCairn treats that as the same single placeholder. Templates must be in scope, use `http` or `https`, avoid obvious state-changing endpoint names such as delete, transfer, reset, publish, logout, or consume-on-read, and must not embed `Cookie`, `Authorization`, or CSRF headers. Authentication comes only from the supplied Account A and Account B profiles.

For each case, the resolved plan contains this fixed matrix:

| Direction | Requesting principal | Target object | Purpose |
| --- | --- | --- | --- |
| `A_TO_A` | Account A | Account A object | Confirm legitimate owner baseline |
| `B_TO_B` | Account B | Account B object | Confirm legitimate owner baseline |
| `A_TO_B` | Account A | Account B object | Test cross-account access |
| `B_TO_A` | Account B | Account A object | Test cross-account access |

Execution sends the two owner baseline requests first. A `200` alone is not enough: the response must contain configured object identity evidence and configured ownership evidence. Object identity can be proven by the supplied identifier appearing in the body, a configured JSON field, or an explicit safe response header. Ownership can be proven by a configured owner field, tenant field, safe marker, or explicit safe response header. Private-content evidence is tracked separately through configured field names, safe body markers, or explicit safe headers. If either owner baseline is not confirmed, cross-account requests for that case are not sent and the result is inconclusive. When both baselines are confirmed, each cross-account direction is sent independently through the shared request broker. Retry attempts repeat the exact same planned request; they do not alter identifiers or request shape.

Visibility expectations are declared per case: `PRIVATE_TO_OWNER`, `SHARED_WITH_SPECIFIC_PRINCIPALS`, `TENANT_VISIBLE`, `ROLE_VISIBLE`, `PUBLIC`, or `UNKNOWN_REQUIRES_REVIEW`. Reports distinguish the technical access result from the final vulnerability interpretation. If Account A demonstrably receives Account B's supplied private representation, the technical result is confirmed. If the declared visibility is private, the final classification is a confirmed controlled vulnerability. If the visibility is unknown, tenant-visible, or role-visible, the technical evidence is preserved but the final classification requires business-policy review. Public and explicitly shared responses are recorded as expected access rather than vulnerabilities. RouteCairn does not claim that unrelated objects, users, tenants, or endpoints are affected.

`HEAD` is useful for denial checks and explicitly configured header-only evidence. A successful `HEAD` response alone, matching content length, or matching `ETag` does not prove object identity, ownership, or unauthorized private access. `GET` is required unless the object-pair file declares safe header selectors such as `expectedObjectIdHeader`, `expectedOwnerHeader`, and `expectedPrivateHeaders`.

Object-pair files are validated strictly before any network request: malformed JSON, unknown fields, oversized files, excessive case counts, duplicate case IDs, duplicate logical pairs, long identifiers, long templates, missing or multiple placeholders, undeclared placeholders, unsafe methods, unsupported protocols, out-of-scope URLs, embedded auth headers, embedded secret-like query/header material, ranges, wildcards, generators, and bulk-ID strings all fail closed. Serialized plans, object-pair reports, request audits, Markdown, and findings redact raw supplied object identifiers with stable non-reversible hashes.

Safe example input:

```json
{
  "schemaVersion": 1,
  "maxPairs": 1,
  "principals": {
    "accountA": { "expectedAccountId": "fictional-account-a", "tenantId": "fictional-tenant-1", "role": "member" },
    "accountB": { "expectedAccountId": "fictional-account-b", "tenantId": "fictional-tenant-1", "role": "member" }
  },
  "cases": [
    {
      "id": "document-read",
      "objectType": "document",
      "expectedVisibility": "PRIVATE_TO_OWNER",
      "template": {
        "id": "document-read-url",
        "method": "GET",
        "url": "https://app.example.com/documents/{{OBJECT_ID}}",
        "headers": { "Accept": "application/json" }
      },
      "accountAObject": {
        "id": "fictional-doc-owned-by-a",
        "source": "operator-confirmed test fixture",
        "confirmedSafeToTest": true,
        "readOnly": true,
        "expectedSafeMarkers": ["owner-a-marker"],
        "expectedPrivateFields": ["privateNotes"]
      },
      "accountBObject": {
        "id": "fictional-doc-owned-by-b",
        "source": "operator-confirmed test fixture",
        "confirmedSafeToTest": true,
        "readOnly": true,
        "expectedSafeMarkers": ["owner-b-marker"],
        "expectedPrivateFields": ["privateNotes"]
      }
    }
  ]
}
```

Version 1 intentionally does not support browser-based Account A/B testing, browser login automation, GraphQL request bodies, JSON body templates, tenant placeholder substitution, unauthenticated controls, or multi-object mutation in one template. UUIDs can reduce guessability but do not replace server-side authorization; remediation should verify owner, tenant, sharing, or role permission before returning private object data.

### Field Exposure Testing

Field-exposure testing verifies whether an otherwise accessible supplied object returns fields that a configured actor should not receive. It is not schema discovery, sensitive-data scanning, API exploration, GraphQL introspection, field guessing, object discovery, ID guessing, wildcard traversal, mass assignment testing, or request mutation testing.

Run it with Account A/B auth profiles and an explicit field-exposure JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --field-exposure ./examples/field-exposure.example.json \
  --output ./reports/field-exposure-example
```

The planner resolves `field-exposure-testing` into a fixed request matrix before execution. Each case targets one exact object ID, one exact `GET` template with exactly one `{{OBJECT_ID}}` placeholder, explicit actors, explicit visibility, explicit object-confirmation fields, and explicit field expectations. Runtime responses cannot add actors, endpoints, objects, field paths, or test cases. Authenticated actors reference `account_a` or `account_b`; public baselines use no auth headers and cache under the anonymous partition. `HEAD` is rejected for field-exposure testing because body field projection is required.

Field paths support only narrow property access and bounded array indexes such as `owner.email`, `billing.last4`, and `members[0].role`. RouteCairn rejects wildcards, recursive traversal, JSONPath filters, slices, dynamic keys, functions, prototype traversal, excessive depth, excessive array indexes, and empty segments. A configured parent path does not authorize walking child fields.

Supported field policies are `MUST_BE_ABSENT`, `MUST_BE_NULL`, `MUST_BE_REDACTED`, `MUST_DIFFER_FROM_OWNER`, `MUST_MATCH_PUBLIC_BASELINE`, `MUST_MATCH_SHARED_BASELINE`, `MAY_BE_PRESENT`, `MUST_BE_PRESENT`, `MASKED_VALUE`, and `OWNER_ONLY_VALUE`. Findings are produced only for configured prohibited fields with confirmed object identity and observed policy violations such as unauthorized presence, missing redaction, masking failure, or owner-only private value exposure. Missing expected fields are reported as consistency findings, not automatic security vulnerabilities.

Safe example input:

```json
{
  "schemaVersion": 1,
  "maxCases": 1,
  "cases": [
    {
      "id": "document-field-policy",
      "objectType": "document",
      "objectId": "fictional-doc-owned-by-a",
      "declaredOwnerActor": "owner",
      "expectedVisibility": "PUBLIC_SUMMARY",
      "requireVerifiedIdentity": true,
      "template": {
        "id": "document-read",
        "method": "GET",
        "url": "https://app.example.com/api/documents/{{OBJECT_ID}}",
        "headers": { "Accept": "application/json" }
      },
      "objectConfirmation": {
        "expectedObjectIdField": "id"
      },
      "actors": [
        { "id": "owner", "type": "OWNER", "authProfile": "account_a", "safeAlias": "Owner" },
        { "id": "non_owner", "type": "NON_OWNER", "authProfile": "account_b", "safeAlias": "Non Owner" },
        { "id": "public", "type": "PUBLIC", "safeAlias": "Public" }
      ],
      "fieldExpectations": [
        {
          "path": "ownerProfile.email",
          "label": "Owner email",
          "sensitivity": "OWNER_ONLY",
          "expectation": "OWNER_ONLY_VALUE",
          "allowedActors": ["owner"],
          "prohibitedActors": ["non_owner", "public"]
        },
        {
          "path": "billing.last4",
          "label": "Billing last four",
          "sensitivity": "PRIVATE",
          "expectation": "MUST_BE_REDACTED",
          "allowedActors": ["owner"],
          "prohibitedActors": ["non_owner"],
          "redactionPattern": "^\\*{2,}\\d{2,4}$"
        }
      ]
    }
  ]
}
```

When `requireVerifiedIdentity` is true, RouteCairn consumes the scan-level identity verification result and does not repeat verification inside the module. Required identity failures block the field-exposure case before field requests are sent and preserve planned request counts with `executedRequests: 0`. Different auth-context fingerprints are not treated as proof of different users; Account A/B auth profiles must carry distinct declared principal metadata, and verified identity must match where required.

Field-exposure evidence retains projections only: field label, safe path reference, actor label, presence state, safe type, length, redaction result, scoped value fingerprint where comparison requires it, policy outcome, and confidence. Minimal evidence stores no previews. Normal and strong evidence may include short redacted previews only for explicitly approved public fields. Reports and findings do not store raw object IDs, private field values, principal IDs, tenant IDs, roles, cookies, authorization headers, or full response bodies.

Object identity is confirmed independently for every owner, non-owner, public, shared, tenant, or role response by comparing the configured `expectedObjectIdField` to the exact supplied object ID. A successful status code, login-like body, HTML shell, fallback object, missing identity field, body marker, or different object ID is not enough and cannot produce a field-exposure finding.

Version 1 supports controlled HTTP JSON response projection only. It does not support browser-based Account A/B field testing, browser login automation, GraphQL bodies, HTML extraction, schema discovery, object lists, pagination, wildcard objects, body templates, `HEAD` field evaluation, mutating methods, or runtime expansion of identifiers or fields.

### Authorization Matrix Testing

Authorization matrix testing verifies explicit role, tenant, account-state, relationship, and object-state authorization decisions for supplied read-only object URLs. It is not discovery, role enumeration, tenant enumeration, ID guessing, privilege escalation automation, browser testing, or mutation testing.

Run it with Account A/B auth profiles and an explicit matrix JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --authorization-matrix ./examples/authorization-matrix.example.json \
  --output ./reports/authorization-matrix-example
```

The planner resolves `authorization-matrix-testing` into a fixed request matrix before execution. Each matrix has one exact `GET` template with exactly one `{{OBJECT_ID}}` placeholder, explicit actors, explicit object IDs, explicit expected decisions, an object identity field, and optional object state field. Runtime responses cannot add actors, endpoints, objects, roles, tenants, states, or test cases.

Supported expected decisions are `MUST_ALLOW`, `MUST_DENY`, `MUST_REQUIRE_AUTHENTICATION`, `MUST_RETURN_NOT_FOUND`, `MUST_MATCH_REFERENCE_DECISION`, `MUST_NOT_EXCEED_REFERENCE_ACCESS`, and `OBSERVE_ONLY`. Reference decisions must name an existing case in the same matrix and circular references fail planning.

Safe example input:

```json
{
  "schemaVersion": 1,
  "maxMatrices": 1,
  "maxCasesPerMatrix": 5,
  "matrices": [
    {
      "id": "document-access",
      "name": "Document access",
      "objectType": "document",
      "template": {
        "id": "document-read",
        "method": "GET",
        "url": "https://app.example.com/api/documents/{{OBJECT_ID}}",
        "headers": { "Accept": "application/json" }
      },
      "objectIdentityField": "id",
      "objectStateField": "state",
      "actors": [
        { "id": "owner", "relationship": "OWNER", "authProfile": "account_a", "principalId": "fictional-principal-a", "tenantId": "tenant-a", "role": "member", "accountState": "active" },
        { "id": "viewer", "relationship": "CROSS_TENANT_MEMBER", "authProfile": "account_b", "principalId": "fictional-principal-b", "tenantId": "tenant-b", "role": "viewer", "accountState": "active" },
        { "id": "public", "relationship": "PUBLIC", "safeAlias": "Public" }
      ],
      "cases": [
        { "id": "owner-allow", "actorId": "owner", "objectId": "fictional-doc-a", "expectedObjectState": "published", "expectedDecision": "MUST_ALLOW", "requireVerifiedIdentity": true },
        { "id": "viewer-deny", "actorId": "viewer", "objectId": "fictional-doc-a", "expectedObjectState": "published", "expectedDecision": "MUST_DENY", "expectedTenantId": "tenant-b", "expectedRole": "viewer", "expectedAccountState": "active", "requireVerifiedIdentity": true },
        { "id": "public-auth", "actorId": "public", "objectId": "fictional-doc-a", "expectedDecision": "MUST_REQUIRE_AUTHENTICATION", "requireVerifiedIdentity": false }
      ]
    }
  ]
}
```

When `requireVerifiedIdentity` is true, RouteCairn consumes the scan-level identity verification result and blocks the affected authenticated case before sending its matrix request if verified principal, tenant, role, or account-state metadata is unavailable. Public actors must not reference auth profiles and their requests are sent without authentication material.

A successful response is classified as allowed only after JSON parsing confirms the configured object identity field equals the exact supplied object ID. If `expectedObjectState` is supplied, the configured object-state field must also match. Findings are created only for confirmed allowed responses that violate `MUST_DENY`; categories distinguish cross-tenant, role, account-state, object-state, suspended/deactivated, unpublished, and archived/deleted boundary bypasses where the supplied metadata supports that classification. Other mismatches are recorded as matrix evidence needing manual verification.

Version 1 supports controlled HTTP JSON `GET` checks only. It does not support browser-based Account A/B testing, browser login automation, GraphQL bodies, request bodies, role discovery, tenant discovery, identifier expansion, field discovery, mutating methods, or runtime-generated cases.

### Equivalent Route Testing

Equivalent-route testing checks whether explicitly supplied routes that should represent the same object or protected capability enforce the same configured authorization boundary. It differs from object-pair testing by comparing routes for one supplied object instead of comparing Account A and Account B object ownership pairs. It differs from field-exposure testing because it does not inspect field-level policy differences. It differs from authorization matrix testing because the route is the changing dimension rather than only actor, role, tenant, account state, or object state.

Run it with Account A/B auth profiles and an explicit equivalent-routes JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --equivalent-routes ./examples/equivalent-routes.example.json \
  --output ./reports/equivalent-route-example
```

Each route set declares one exact object, one canonical route, one or more alternate routes, explicit actors, explicit expectations, an object identity field, optional object-state field, and an equivalence policy. Supported route categories are `CANONICAL`, `LEGACY`, `VERSIONED`, `NESTED`, `TOP_LEVEL`, `EXPORT`, `SUMMARY`, `DETAIL`, `MOBILE`, `WEB`, `ALIAS`, `COMPATIBILITY`, `RELATIONSHIP`, `ALTERNATE_FORMAT`, and `CUSTOM_DECLARED`. These categories are metadata only; RouteCairn never generates route names from them.

Supported equivalence policies are `AUTHORIZATION_ONLY`, `SAME_OBJECT`, `SAME_PUBLIC_BOUNDARY`, `SAME_OWNER_BOUNDARY`, `SAME_TENANT_BOUNDARY`, `SAME_ROLE_BOUNDARY`, `SAME_STATE_BOUNDARY`, and `MUST_NOT_EXCEED_REFERENCE_ROUTE`. The operator declares which alternate route references the canonical or another supplied route. Missing reference routes, self-references, and reference cycles fail during planning.

Supported expectations are `MUST_ALLOW`, `MUST_DENY`, `MUST_REQUIRE_AUTHENTICATION`, `MUST_RETURN_NOT_FOUND`, `MUST_MATCH_CANONICAL_DECISION`, `MUST_MATCH_REFERENCE_ROUTE`, `MUST_NOT_EXCEED_CANONICAL_ACCESS`, `MUST_NOT_EXCEED_PUBLIC_ACCESS`, and `OBSERVE_ONLY`. A confirmed security finding requires a supplied canonical or reference route to deny the configured protected boundary and a supplied alternate route to return the protected object with object identity independently confirmed.

Safe example input:

```json
{
  "schemaVersion": 1,
  "maxRouteSets": 1,
  "routeSets": [
    {
      "id": "document-equivalent-routes",
      "name": "Document equivalent routes",
      "objectType": "document",
      "objectId": "fictional-doc-owned-by-a",
      "canonicalRouteId": "canonical-api",
      "equivalencePolicy": "SAME_OWNER_BOUNDARY",
      "objectIdentityField": "id",
      "objectStateField": "state",
      "expectedObjectState": "published",
      "requireVerifiedIdentity": true,
      "actors": [
        { "id": "owner", "relationship": "OWNER", "authProfile": "account_a", "principalId": "fictional-principal-a", "tenantId": "tenant-a", "role": "member", "accountState": "active" },
        { "id": "viewer", "relationship": "NON_OWNER", "authProfile": "account_b", "principalId": "fictional-principal-b", "tenantId": "tenant-a", "role": "viewer", "accountState": "active" },
        { "id": "public", "relationship": "PUBLIC", "safeAlias": "Public" }
      ],
      "routes": [
        {
          "id": "canonical-api",
          "label": "Canonical API",
          "category": "CANONICAL",
          "isCanonical": true,
          "template": { "id": "canonical-api-get", "method": "GET", "url": "https://app.example.com/api/documents/{{OBJECT_ID}}", "headers": { "Accept": "application/json" } },
          "expectations": { "owner": "MUST_ALLOW", "viewer": "MUST_DENY", "public": "MUST_REQUIRE_AUTHENTICATION" }
        },
        {
          "id": "legacy-api",
          "label": "Legacy API",
          "category": "LEGACY",
          "referenceRouteId": "canonical-api",
          "template": { "id": "legacy-api-get", "method": "GET", "url": "https://app.example.com/legacy/documents/{{OBJECT_ID}}", "headers": { "Accept": "application/json" } },
          "expectations": { "owner": "MUST_ALLOW", "viewer": "MUST_DENY", "public": "MUST_REQUIRE_AUTHENTICATION" }
        }
      ]
    }
  ]
}
```

Only `GET` is supported. `HEAD`, `OPTIONS`, mutating methods, request bodies, method overrides, generated exports, background export jobs, GraphQL bodies, and RPC/form bodies are rejected or unsupported. Export routes are allowed only when they are pre-existing safe read routes returning already available JSON.

Object identity is confirmed independently for every actor-route response by comparing the configured object identity field to the exact supplied object ID. If object state matters, the configured object-state field must match the supplied expected state. A `200`, matching body size, matching hash, generic marker, login page, HTML shell, or different JSON shape is not enough.

Public actors must not reference auth profiles; public route cells are sent with no auth headers, cookies, CSRF headers, or tenant headers. Authenticated actor cells use only `account_a` or `account_b` through the existing auth profile abstractions. When verified identity is required, RouteCairn consumes the scan-level identity verification result and blocks affected cells before route requests are sent if principal, tenant, role, or account-state verification is unavailable.

Version 1 supports controlled HTTP JSON route comparison only. It does not support browser route comparison, browser login automation, route discovery, API version discovery, alias guessing, export-route guessing, object enumeration, route generation, OpenAPI discovery, JavaScript route extraction, field-level comparison, or runtime expansion of routes.

### Collection Authorization Testing

Collection authorization testing checks exact operator-supplied collection, listing, search, count, and summary responses for exact known objects and aggregate constraints. It differs from object-pair testing because it evaluates whether a supplied object appears in a supplied collection response, not whether two users can read each other's detail URL. It differs from field-exposure testing because it does not compare field visibility for object detail responses. It differs from authorization-matrix testing because the response is a bounded collection window. It differs from equivalent-route testing because the endpoint/query is fixed and the membership expectation is the changing decision.

Run it with Account A/B auth profiles and an explicit collection authorization JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --collection-authorization ./examples/collection-authorization.example.json \
  --output ./reports/collection-authorization-example
```

Each collection definition declares one exact `GET` URL, fixed query parameters, explicit actors (`account_a`, `account_b`, or `PUBLIC`), exact known objects, exact membership expectations, completeness semantics, response-array path, object-ID path, optional tenant/owner/type/state confirmation paths, and optional count or summary expectations. Supported endpoint categories are `LIST`, `SEARCH`, `COUNT`, `SUMMARY`, `DASHBOARD`, `RECENT`, `ARCHIVE`, `ADMIN_LIST`, `TENANT_LIST`, `PUBLIC_LIST`, and `CUSTOM_DECLARED`; categories are descriptive only and never generate endpoints or queries.

Supported membership expectations are `MUST_CONTAIN`, `MUST_NOT_CONTAIN`, `MAY_CONTAIN`, `MUST_MATCH_PUBLIC_MEMBERSHIP`, `MUST_MATCH_REFERENCE_CASE`, `MUST_NOT_EXCEED_REFERENCE_MEMBERSHIP`, and `OBSERVE_ONLY`. A confirmed collection authorization finding requires the supplied actor, supplied endpoint/query, supplied object ID, explicit denial expectation, verified identity where required, matching object metadata, and the protected object appearing in the configured JSON response. Absence is interpreted according to `COMPLETE_COLLECTION`, `FIXED_RESULT_WINDOW`, `SEARCH_RESULT_SET`, `SUMMARY_ONLY`, or `UNKNOWN_COMPLETENESS`; fixed-window and unknown absence are not generalized to the whole collection, and `SUMMARY_ONLY` never produces object-membership conclusions.

Even when the operator declares `COMPLETE_COLLECTION`, RouteCairn downgrades absence to incomplete/inconclusive when the response contains common partial-result signals such as `next`, cursors, `hasMore`, pagination links, HTTP `Link: rel=next`, total counts exceeding returned entries, server-side caps, or truncation markers. RouteCairn records the signal but does not follow it or request another page.

Only HTTP JSON `GET` is supported. `HEAD`, `OPTIONS`, mutating methods, request bodies, GraphQL/RPC bodies, pagination configuration, wildcard/range/query generators, search dictionaries, filter discovery, sort discovery, endpoint discovery, identifier harvesting, and runtime response-driven cases are rejected or unsupported. The executor makes only the resolved requests and ignores `next`, cursor, offset, link, suggestion, and pagination fields.

Collection parsing uses the shared safe field-path parser. RouteCairn inspects only the bounded result array until `maxInspectedEntries`, compares each entry's configured object-ID path to the exact supplied string object ID with case-sensitive exact matching, records only found/not-found, first matched index, duplicate count, and configured metadata confirmation, then discards unmatched IDs. Numeric IDs, booleans, nulls, objects, arrays, encoded/decoded variants, and case variants are not silently equated with supplied string IDs. Public collection cases send no auth headers, cookies, CSRF tokens, or tenant headers and use the anonymous broker cache partition.

Reference-case expectations compare only compatible cases from the same resolved collection plan. The reference must exist, execute successfully, use the same endpoint/query semantics, share the same completeness model and object set where applicable, and avoid rate-limit, budget, parse, identity, or partial-response failures. Incompatible or unavailable references produce inconclusive dependent cases rather than findings.

Count and summary checks require exact configured paths and explicit policies. Count or summary differences are observations by default; they become findings only when the case marks the disclosure security-sensitive and deterministic. Volatile counts remain operational/manual-review observations. Sensitive raw counts are not persisted unless strong evidence is selected; otherwise reports keep a scoped fingerprint and the classification.

Safe fictional example:

```json
{
  "schemaVersion": 1,
  "collections": [
    {
      "id": "tenant-project-list",
      "label": "Tenant project list",
      "category": "LIST",
      "method": "GET",
      "url": "https://app.example.com/api/projects?status=active",
      "headers": { "Accept": "application/json" },
      "completeness": "FIXED_RESULT_WINDOW",
      "resultArrayPath": "items",
      "objectIdPath": "id",
      "objectTenantPath": "tenant",
      "objectOwnerPath": "owner",
      "objectStatePath": "state",
      "objectTypePath": "type",
      "actors": [
        { "id": "tenant-a-member", "relationship": "OWNER", "authProfile": "account_a", "principalId": "fictional-principal-a", "tenantId": "tenant-a", "role": "member", "accountState": "active" },
        { "id": "tenant-b-member", "relationship": "CROSS_TENANT_MEMBER", "authProfile": "account_b", "principalId": "fictional-principal-b", "tenantId": "tenant-b", "role": "member", "accountState": "active" },
        { "id": "public", "relationship": "PUBLIC", "safeAlias": "Public" }
      ],
      "knownObjects": [
        { "id": "project-a-private", "objectId": "fictional-private-project-a", "objectType": "project", "ownerActorId": "tenant-a-member", "tenantId": "tenant-a", "state": "active", "expectedPublic": false, "confirmedSafeToTest": true }
      ],
      "cases": [
        { "id": "owner-sees-own", "actorId": "tenant-a-member", "knownObjectId": "project-a-private", "expectedMembership": "MUST_CONTAIN", "requireVerifiedIdentity": true },
        { "id": "cross-tenant-must-not-see", "actorId": "tenant-b-member", "knownObjectId": "project-a-private", "expectedMembership": "MUST_NOT_CONTAIN", "expectedActorRelationship": "CROSS_TENANT_MEMBER", "requireVerifiedIdentity": true },
        { "id": "public-must-not-see-private", "actorId": "public", "knownObjectId": "project-a-private", "expectedMembership": "MUST_NOT_CONTAIN", "requireVerifiedIdentity": false }
      ]
    }
  ]
}
```

Reports retain bounded membership evidence, hashes, status/content metadata, and redacted matched-object excerpts only when the evidence policy allows previews. They do not retain full collection bodies, full search results, unmatched returned IDs, raw principal IDs, raw tenant IDs, auth material, or token-like supplied object identifiers.

### Bulk Authorization Testing

Bulk authorization testing checks exact operator-supplied bulk preview, validation, dry-run, manifest-preview, selection-summary, eligibility, permission-check, simulation, or observe-only workflows. It differs from collection authorization because the object list is sent as one supplied bulk request and the question is whether the bulk workflow correctly filters, rejects, summarizes, or redacts those supplied objects. It is not mutation testing, export execution, job creation, polling, pagination, ID harvesting, object discovery, subset testing, permutation testing, fuzzing, or browser login automation.

Run it with Account A/B auth profiles and an explicit bulk authorization JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --bulk-authorization ./examples/bulk-authorization.example.json \
  --output ./reports/bulk-authorization-example
```

Each bulk definition declares explicit actors (`account_a`, `account_b`, or `PUBLIC`) and fixed cases. Each case declares the exact endpoint, method, request style, object IDs, per-object expected decisions, batch policy, safety contract, response contract, and bounded parsing limits. Runtime responses never add object IDs, expand the matrix, split the batch, follow pagination, poll job URLs, download exports, or create follow-up test cases.

Supported request styles are `GET_REPEATED_QUERY`, `GET_COMMA_QUERY`, and `JSON_POST`. `GET_REPEATED_QUERY` requires `{{OBJECT_ID_LIST_REPEATED}}`; `GET_COMMA_QUERY` requires `{{OBJECT_ID_LIST_COMMA}}`; `JSON_POST` requires a fixed JSON body template containing `{{OBJECT_IDS_ARRAY}}` and a non-mutating request marker such as `dryRun: true` or `preview: true`. Only `GET` and controlled JSON `POST` are supported. `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, method overrides, file uploads, GraphQL/RPC bodies, form submissions, asynchronous jobs, real exports, and downloads are rejected or classified as safety-contract observations.

Optional single-object baselines may be supplied on individual bulk objects. Version 1 supports active `SAFE_GET` baselines with one exact `{{OBJECT_ID}}` insertion point, the same bounded actor model, exact expected decision, object identity field, optional object state field, and optional verified tenant/role expectations. Compatible baseline denials can be compared with the bulk response; unavailable, incompatible, rate-limited, out-of-scope, parse-failed, or identity-blocked baselines produce inconclusive comparison metadata rather than findings. Reused Batch 30 or Batch 33 result sources are represented as reserved source types, but active reuse requires a compatible completed result and otherwise fails closed during planning.

Supported per-object expected decisions are `ALLOW`, `DENY`, `FILTER_OUT`, `EXPLICIT_REJECTION`, `REDACTED_METADATA_ONLY`, `PUBLIC_SUMMARY_ONLY`, `MATCH_SINGLE_OBJECT_DECISION`, and `OBSERVE_ONLY`. Supported batch policies are `MUST_ALLOW_ENTIRE_BATCH`, `MUST_REJECT_ENTIRE_BATCH`, `MUST_FILTER_UNAUTHORIZED_OBJECTS`, `MUST_RETURN_PER_OBJECT_DECISIONS`, `MUST_NOT_EXPOSE_RESTRICTED_METADATA`, `MUST_MATCH_SINGLE_OBJECT_DECISIONS`, `MUST_MATCH_REFERENCE_CASE`, and `OBSERVE_ONLY`.

The safety contract must confirm that the operation is non-mutating and may require fixed request and response markers. POST cases also declare an effective safety mode: `GET_ONLY`, `OPERATOR_ATTESTED_DRY_RUN`, or `POSTCONDITION_VERIFIED_DRY_RUN`. Operator-attested POST reports explicitly state that non-mutation was not independently verified. Verified dry-run mode requires exact configured pre/postcondition `GET` checks for supplied objects and configured scalar state fields; if a configured field changes, an object disappears, object identity changes, or verification is unavailable, RouteCairn records a safety-contract violation, suppresses confirmed authorization findings for that case, and does not attempt rollback or repair.

By default, `201` and `202` responses, job/task/location fields, download-like content types, mutation-like configured disallowed response paths, broker safety blocks, rate limits, budget exhaustion, unexpected content types, and parse failures are treated as safety violations or inconclusive observations. RouteCairn does not poll returned job/status/result locations.

A confirmed bulk authorization finding requires a supplied actor, supplied endpoint, supplied exact object IDs, explicit prohibited expectation, verified identity where required, a satisfied safety contract, and a positive match of a prohibited supplied object in the configured JSON response. Configured restricted metadata exposure for a prohibited supplied object can also become a finding. Unknown returned IDs are counted and discarded; they never create cases or findings.

Object IDs must be exact strings. Empty values, numeric IDs, duplicate object IDs, wildcards, ranges, generator syntax, control characters, token-like values, and auth-looking values fail planning. Public actors must not reference auth profiles and send no auth headers, cookies, CSRF headers, or tenant headers. Account A and Account B must declare distinct principal identities and use distinct auth material.

Requests use the shared scan-wide `RequestSafetyBroker`. Scope, redirect, retry, rate-limit, concurrency, cache-partition, and request-budget rules are the same as other planned modules. POST responses are not reused from cache by default. Postcondition `GET` checks bypass response-cache reuse so state comparisons read the current controlled fixture state. Request bodies participate in duplicate identity through safe fingerprints, and persisted `requestBodyHash` values are salted per scan so predictable bulk bodies do not receive globally reusable hashes. Raw request bodies, object IDs, cookies, authorization headers, principal IDs, tenant IDs, roles, returned unknown IDs, and response bodies are redacted or omitted from plans, reports, audit metadata, Markdown, and findings.

### File Authorization Testing

File authorization testing checks exact operator-supplied private files, file metadata, previews, thumbnails, direct downloads, and signed-URL issuance endpoints across `account_a`, `account_b`, and `PUBLIC`. It is not file discovery, filename guessing, directory traversal testing, bucket enumeration, signed-token mutation, archive extraction, malware analysis, document rendering, browser downloading, crawling, or file parsing.

Run it with Account A/B auth profiles and an explicit file authorization JSON file:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/account-a.auth.json \
  --auth-b ./examples/account-b.auth.json \
  --file-authorization ./examples/file-authorization.example.json \
  --output ./reports/file-authorization-example
```

Each definition declares explicit actors, exact file references, and exact cases. Each case targets one supplied file reference through one endpoint template containing exactly one `{{FILE_ID}}` or `{{FILE_KEY}}` placeholder. Only `GET` and `HEAD` are supported. `POST`, `PUT`, `PATCH`, `DELETE`, WebDAV methods, GraphQL/RPC bodies, multipart/form submissions, local file URLs, browser downloads, and path traversal payloads are rejected or unsupported.

Supported expectations include `MUST_ALLOW_METADATA`, `MUST_DENY_METADATA`, `MUST_ALLOW_CONTENT`, `MUST_DENY_CONTENT`, `MUST_REQUIRE_AUTHENTICATION`, `MUST_RETURN_NOT_FOUND`, `MUST_ALLOW_PREVIEW_ONLY`, `MUST_NOT_RECEIVE_SIGNED_URL`, `MUST_MATCH_REFERENCE_CASE`, and `OBSERVE_ONLY`. Metadata, content, preview, signed-URL issuance, signed-URL download, redirect, and file-state decisions are reported separately.

File identity strategies are `METADATA_FIELD_MATCH`, `OPERATOR_SUPPLIED_FINGERPRINT`, `SIGNED_URL_FIELD_MATCH`, and `OBSERVE_ONLY`. A status code, filename, content type, content length, or `Content-Disposition` header alone does not confirm file identity. `HEADERS_ONLY` evidence cannot create confirmed file-content exposure. Prefix evidence is labelled as bounded-prefix evidence and is not complete-file proof.

Content-proof modes are `HEADERS_ONLY`, `METADATA_ONLY`, `BOUNDED_PREFIX`, `FULL_STREAM_FINGERPRINT`, and `SIGNED_URL_ONLY`. Content modes stream through the shared request broker with strict byte caps. Streamed chunks are hashed incrementally, aborted at the configured cap, and not cached, written to disk, opened, rendered, extracted, executed, logged, or persisted. `BOUNDED_PREFIX` sends exactly one configured `Range` header; valid `206` responses must return a matching `Content-Range`, `416` is reported separately, and if the server ignores `Range` with `200`, RouteCairn aborts after the configured probe cap. `FULL_STREAM_FINGERPRINT` requires complete streaming within the configured cap and an exact full-file SHA-256 match; prefix hashes and full-file hashes are not interchangeable.

Signed-URL issuance and signed-URL download are separate decisions. Issuance parses only a configured JSON field and records whether the actor received a URL for the supplied file. A download check occurs only when `followSignedUrl: true` is explicitly configured with a signed URL field, exact allowed storage origin, bounded proof mode, byte limits, and an operator-supplied fingerprint. RouteCairn follows at most one exact returned URL with one bounded unauthenticated `GET`; it does not mutate signatures, reorder query parameters, test expirations, poll returned locations, request related objects, crawl storage, or follow links from downloaded content. Application `Authorization`, cookies, CSRF, tenant, and custom auth headers are not forwarded to the signed URL.

Approved signed storage destinations require exact origin matching, including scheme, normalized host, and effective port. Private or internal destinations are blocked unless the exact private fixture origin is explicitly supplied for a controlled local test. Shared HTTP requests use DNS-to-socket pinning: RouteCairn connects to an IP address selected from the exact DNS answer set it validated and verifies the connected socket destination before transmitting the request.

Public file cases send no authentication headers, cookies, CSRF headers, tenant headers, or auth-derived query values. Authenticated cases consume the scan-level verified identity result and block affected cases before transmission when required principal, tenant, role, or account-state metadata is unavailable or mismatched.

File content, signed URL issuance, and signed URL follow responses are not cached by default; file requests use `skipCache` and exact signed follows disable retries while preserving scope, redirect, rate-limit, concurrency, cache-partition, and global request-budget controls. File probes send `Accept-Encoding: identity`; if a server ignores this, the stream cap still bounds bytes consumed by RouteCairn. Serialized reports redact raw file references, signed URL query secrets, `Location`, auth material, principal IDs, tenant IDs, role values, and file bytes. Findings remain limited to the exact supplied file, actor, endpoint, proof mode, and expected decision.

### Budgets And Evidence

The request broker enforces the resolved plan globally across shared module clients. Direct requests, retry attempts, redirect hops, and Playwright requests that reach the network consume the same request budget. Duplicate direct HTTP requests reuse cached responses without additional network traffic.

### Pinned HTTP Transport

RouteCairn's shared HTTP transport connects to an IP address selected from the exact DNS answer set that RouteCairn validated. It verifies the connected socket destination before transmitting the request. The pinned transport is implemented as an Undici custom connector below `RequestSafetyBroker`, so direct scanner requests, redirects, retries, identity verification, object-pair, field-exposure, authorization-matrix, collection, bulk, equivalent-route, file metadata/content, and signed-URL follow requests inherit it automatically.

For each connection, RouteCairn canonicalizes the HTTP or HTTPS destination, rejects unsupported protocols and invalid hostnames, resolves all bounded DNS answers through an injectable resolver, normalizes duplicate IPs, validates every answer with the shared private-address classifier plus metadata/reserved-address checks, and fails closed on mixed public/private or prohibited answer sets. The selected address is deterministic. Exact private-origin exceptions are origin and port specific; the scan target origin is allowed so controlled local or private owned targets can be assessed, but a redirect or signed URL to another private host or port is blocked unless it is the exact approved origin and remains in scope.

The connector opens the socket directly to the selected IP, not the original hostname, which prevents an uncontrolled second DNS lookup by the HTTP library. HTTP keeps the original `Host` authority. HTTPS keeps SNI and certificate hostname verification on the original hostname with normal chain validation enabled. After connect or secure connect, RouteCairn compares the socket remote address to the selected IP, accounting for IPv4-mapped IPv6 equivalence. A mismatch destroys the socket and blocks the request before transmission.

Pinned HTTP v1 disables keep-alive in the connector and disables HTTP/2 ALPN to avoid cross-origin or cross-IP socket coalescing. Implicit environment proxies are not used by the pinned transport because RouteCairn supplies its own Undici dispatcher; future explicit proxy support would need its own destination enforcement. DNS lookups and connection attempts are bounded by timeouts and answer-count limits, while transmitted HTTP requests continue to consume the global request budget through the broker. Cache keys do not include raw selected IPs, and file/signed URL no-cache policies remain unchanged.

Playwright browser connections are not covered by the direct Node HTTP connector. Browser policy-time DNS validation remains in place, but browser-wide connection-time enforcement requires a controlled outbound proxy or equivalent browser network layer. Do not treat browser traffic as DNS-to-socket pinned in the current architecture.

Blocked browser requests follow separate accounting: a request intercepted and blocked before network transmission consumes a browser policy-event counter, not the network request budget. A request that reaches the network consumes the network budget. Redirect hops and retry attempts that reach the network each consume budget. Reports expose policy-event and transmitted-request counts so blocked third-party resources cannot exhaust the network request budget while still being bounded by a browser attempt ceiling.

Cached HTTP responses are in-memory for the scan lifetime only. Cache partitioning uses method, normalized URL, header names, and SHA-256 fingerprints of header values, so anonymous, authenticated, Account A, Account B, tenant, organization, and other authorization-context requests do not share responses. Raw cookies, tokens, authorization headers, and tenant identifiers are not stored in persisted cache diagnostics or reports.

Evidence policy changes serialized output. Minimal profiles strip body previews from `responses`, `discoveredUrls`, finding evidence, and browser network-request evidence in reports. Normal and strong profiles retain redacted previews and browser network metadata within configured limits. Strong evidence profiles enable proof-block retention and stricter reproducibility metadata.

Temporary response previews may exist in memory while modules analyze a scan, but serialized reports redact retained previews and sensitive headers before writing artifacts. Minimal evidence reports omit body previews entirely and retain only status, length, hash, redacted metadata, and detection indicators needed by the implementation.

### Adding Profiles Or Modules

Profiles live in `src/core/planning/ProfileDefinitions.ts`. A profile declares enabled/disabled modules, module settings, global and per-module limits, auth requirements, evidence policy, output expectations, failure policy, and report focus. Add new profiles there, then cover the planner behavior with tests.

Scanner module compatibility lives in `src/core/planning/ModuleCatalog.ts`. To add a module, implement the `RouteCairnPlugin` interface, register it in `createDefaultPluginRegistry()`, and add catalog metadata: stable id, phase, capabilities, auth requirement, monitoring compatibility, evidence support, dependencies, ordering constraints, cost, readiness, default settings, and supported overrides. Controlled modules that consume operator-supplied files should add their own resolved plan type to `ResolvedScanPlan` and validate the complete request matrix before execution. The planner rejects unknown modules, duplicate modules, missing dependencies, invalid ordering, invalid limits, unsupported overrides, and evidence/monitoring incompatibilities before execution.

## Show A Report Summary

```bash
node dist/cli/index.js show ./reports/example/report.json
```

## Diff Two Reports

```bash
node dist/cli/index.js diff ./reports/old/report.json ./reports/new/report.json
```

Only scan targets you own or are explicitly authorized to test.

## Authorization Notice

RouteCairn is intended only for owned applications, authorized client testing, public bug bounty scopes, security labs, and developer-side review. Scope validation, safe defaults, and rate controls are core design requirements.
## RouteCairn Dashboard

RouteCairn Dashboard is a local single-user interface over the existing planner and engine. It does not replace RouteCairn's scan safety controls: dashboard-created scans pass through the same planning, scope, identity, request-budget, and evidence policies as CLI scans.

Dashboard v1 binds to loopback only, runs one active scan at a time, queues additional scans, and stores safe history in SQLite. Ephemeral authentication data supplied for a scan remains in execution memory only and is not written to the dashboard database, reports, events, or proof packs. Server/local installations may also enable the encrypted credential vault for reusable credential profiles.

Server mode is opt-in and uses durable users, Argon2id password hashes, revocable server-side sessions, login throttling, role-based permissions, strict public-origin checks, secure cookies, audit events, and isolated child-process scan workers. It refuses startup when required security settings are absent or when no first owner exists.

### Launch

Build the scanner and dashboard UI:

```bash
npm run build
npm run dashboard:build
```

Launch the local dashboard:

```bash
npm run dashboard
```

or after a production build:

```bash
npm run dashboard:start
```

The server prints a local URL containing a one-use bootstrap credential in the URL fragment. The browser exchanges that credential for an HttpOnly SameSite session cookie and an in-memory CSRF token. The bootstrap credential is not persisted and is invalidated after use.

### Server Mode

Create the first owner in the server data directory:

```bash
node dist/cli/index.js dashboard user create-owner --data-dir ./data/dashboard-server
```

The command prompts for the login and password without accepting the password as a command-line argument. Passwords are hashed with Argon2id using memory cost 19456 KiB, time cost 2, and parallelism 1. Passwords must be 12 to 256 characters and trivial values are rejected.

Start server mode behind an HTTPS reverse proxy:

```bash
ROUTECAIRN_SESSION_SECRET="replace-with-high-entropy-secret" \
node dist/cli/index.js dashboard \
  --mode server \
  --host 127.0.0.1 \
  --port 8080 \
  --data-dir ./data/dashboard-server \
  --public-origin https://routecairn.example.com \
  --trust-proxy
```

Server mode requires a strong session secret, a valid public origin, HTTPS unless explicitly using loopback development mode, and an existing enabled owner. Durable sessions store only token hashes and CSRF token hashes. Logout, password reset, user disablement, and revoke-all invalidate sessions.

### Credential Vault

The credential vault is disabled unless a valid master key is supplied at runtime:

```bash
ROUTECAIRN_MASTER_KEY="<32-byte-base64url-or-64-char-hex-key>"
ROUTECAIRN_MASTER_KEY_VERSION="1"
```

The master key is never stored in SQLite or returned by APIs. Credential profiles use AES-256-GCM with a fresh random nonce per encryption and associated data bound to the credential-profile UUID, the dashboard installation ID, and the key version. Stored plaintext is limited to safe metadata: UUID, name, safe alias, enabled state, credential type summary, safe identity summary, expiry metadata, project/target links, timestamps, and key version. Authorization headers, cookies, approved custom headers, CSRF/session/tenant values, and identity-verification settings are encrypted.

Read APIs return safe summaries only and never return plaintext, ciphertext, nonces, or authentication tags. There is no "show secret" operation. The test operation decrypts a profile only long enough to return redacted capability booleans and counts; broader identity-endpoint testing through the request broker is still incomplete.

Dashboard-created scans can reference enabled saved credential profiles by UUID for a primary authenticated context or an Account A/Account B pair. Scan rows, events, plan snapshots, and job leases store only safe profile references and aliases. At execution time, the API resolves and decrypts the selected profile, validates availability, project/target restrictions, expiry, and `credentials.use`, then sends the resulting auth profile to the assigned child worker through the HMAC-bound one-time secret envelope. If a saved credential cannot be decrypted or is disabled, deleted, expired, unavailable, or unauthorized, the scan fails before target requests and is not downgraded to anonymous access.

Offline key rotation is available after a production build:

```bash
ROUTECAIRN_MASTER_KEY="<old-key>" \
ROUTECAIRN_MASTER_KEY_VERSION="1" \
ROUTECAIRN_NEW_MASTER_KEY="<new-key>" \
ROUTECAIRN_NEW_MASTER_KEY_VERSION="2" \
node dist/cli/index.js dashboard vault rotate-key --data-dir ./data/dashboard-server
```

Back up the dashboard database and replacement key material together before rotation. Rotation decrypts each non-deleted profile with the current key and re-encrypts it with the new key/version inside the dashboard database transaction. If the current key is wrong, ciphertext is corrupt, or associated data no longer matches, rotation fails closed without logging plaintext.

Roles use named permissions:

- `OWNER`: user management, audit, settings, credentials, projects, targets, scans, reviews, proof packs, imports, archive/delete, and artifact downloads.
- `ANALYST`: projects, targets, scan creation/cancellation, finding review, comparisons, proof packs, imports, configurations, approved credential use, and artifact downloads.
- `VIEWER`: read-only scan/finding/proof/artifact access.

Credential permissions are backend-enforced. Owners may create, update, disable, delete, test, use, and rotate vault keys. Analysts may view approved safe summaries, use approved profiles, and run bounded tests when policy permits. Viewers may not list or use credential profiles.

Login throttling records bounded failed attempts by normalized-login fingerprint and safe source fingerprint. Responses remain generic to avoid account enumeration.

### Data Directory

By default the dashboard stores local state under:

```text
%USERPROFILE%\.routecairn\dashboard
```

Override with:

```bash
npm run dashboard -- --data-dir ./data/dashboard
```

The data directory contains the SQLite database, generated dashboard reports, proof packs, and a local HMAC key used for installation-scoped finding fingerprints. The fingerprint key stays outside reports, proof packs, browser APIs, and SQLite plaintext records.

### SQLite Choice

RouteCairn uses `better-sqlite3` for dashboard persistence. Node's built-in `node:sqlite` exists on the inspected runtime, but it still emits an experimental warning here, so dashboard v1 uses a mature local SQLite driver with explicit SQL migrations, prepared statements, transactions, foreign keys, WAL mode, busy timeout, and schema version metadata.

Run migrations directly:

```bash
npm run db:migrate
```

### Dashboard Capabilities

#### Administration, configuration, and parity

The dashboard is the primary product surface for routine administration. Projects and targets support search, safe metadata editing, optimistic concurrency, archive/restore, and security-intelligence detail views. Archived projects and targets cannot be selected for new scans. Target origins are stable identities: ordinary edits cannot silently change `baseOrigin`; an origin change requires an explicit migration workflow.

Saved scan configurations are logical records backed by immutable numbered versions. The dashboard can create, search, edit into a new version, clone, archive, restore, import safe JSON, export safe JSON, and send a selected configuration into Scan Studio. Imports are revalidated by the authoritative server schema. Configuration history and semantic version diffs are available through the API.

Settings distinguish mutable database defaults from environment-controlled, restart-required, and offline-sensitive values. Mutable defaults use server-side validation and optimistic concurrency and may be reset without changing environment secrets. Server-mode owners can administer users, roles, enabled state, passwords, and sessions; the backend refuses to disable or demote the final enabled owner. The first-owner bootstrap remains CLI-only because no authenticated browser principal exists yet.

Credential administration separates safe metadata edits from explicit secret replacement. Secret material is never returned to the browser. Delete is dependency-aware, vault-key status is safe metadata only, and master-key rotation remains an intentional offline CLI operation.

The machine-readable parity manifest is exposed to authorized owners at `GET /api/admin/capability-parity` and enforced by dashboard tests. Intentional CLI-only entries require a reason, responsible owner, and safety justification; required administration workflows may not remain `PARTIAL`.

Implemented dashboard v1 capabilities include:

- a scanner-core capability registry consumed by the dashboard at `/api/capabilities`
- explicit capability parity statuses for profiles, modules, controlled workflows, server mode, vault, workers, and audit
- project creation, listing, and archiving
- target creation, listing, and archiving with authorization declarations
- scan creation and resolved plan preview through the real `ScanPlanner`
- a ten-step Scan Studio covering target/authorization, inline scope, profiles/modules, authentication, verified identity, browser/limits, evidence/outputs, an integrated Authorization Workflow Studio, real plan review, and launch
- a visual scope builder for every ordinary core scope field, plus bounded 128 KiB browser-side JSON import; ordinary dashboard scans no longer require a server filesystem scope path
- structured browser-memory-only primary and Account A/B authentication with bearer, header, and cookie rows, saved-vault actors, and mixed saved/ephemeral account pairs
- per-actor verified-identity configuration and bounded identity tests through `ScanContext`, `RequestSafetyBroker`, scope/redirect policy, DNS destination checks, request budgets, response caps, and redaction
- a safe preview identity derived only from normalized non-secret configuration, safe credential references, and the redacted resolved plan; launch independently reruns validation and planning before queueing
- project, target, and authorization metadata on dashboard-created scan records
- isolated child-process execution for dashboard scans; the API process no longer invokes `RouteCairnEngine` for queued dashboard jobs
- durable UUID scan IDs generated before planning/execution
- one active scan with FIFO queueing
- cancellation for queued and running scans
- database-backed polling for scan and module progress
- persisted scan events with bounded redacted metadata
- report artifact tracking for JSON, Markdown, and HTML reports
- normalized logical findings and finding occurrences across scans
- append-only human review history
- confirmed and false-positive workflows
- fingerprint-based scan comparison and regression intelligence using actual scan occurrences and completed-module coverage
- immutable proof-pack generation as Markdown and scriptless sanitized HTML
- safe historical `report.json` import from approved RouteCairn output roots
- artifact downloads by artifact UUID, not browser-supplied filesystem paths
- encrypted credential-profile CRUD, safe summaries, bounded safe test responses, vault status, offline key rotation, and saved credential binding for dashboard scan preview/execution
- append-only audit events for bootstrap login, logout, project/target changes, scan lifecycle changes, finding review changes, proof-pack generation, imports, saved-configuration changes, and credential-profile lifecycle events
- durable worker rows, scan-job leases, worker heartbeats, cancellation across IPC, interrupted-job recovery for expired leases, and authenticated job-bound secret-envelope summaries

Capability parity is intentionally explicit. Profiles, modules, projects/targets, Scan Studio Core, audit, plan preview, reports, findings, review, proof packs, server-mode login/RBAC, encrypted credential-profile management and scan binding, isolated dashboard workers, safe import, and all seven controlled authorization workflow editors have implemented dashboard surfaces. Full worker resource governance remains partial in the registry instead of being represented as complete.

### Scan Studio Core

Scan Studio keeps non-secret configuration and ephemeral secrets in separate typed state. Ephemeral bearer values, headers, and cookies stay in live component memory; they are never written to browser storage, URLs, SQLite, audit/events, plan snapshots, or reports. On launch they move through the existing HMAC-bound job/worker/generation/attempt secret envelope. The ordinary worker initialization message contains a public-auth placeholder and safe references only. Secret references are cleared after successful launch, explicit reset, logout/session expiry, and component teardown where practical. JavaScript cannot guarantee physical memory erasure.

Inline scope is authoritatively parsed by the existing `scopeSchema` on preview and launch. The current core model supports allowed domain rules, denied paths, allowed safe methods, rate, concurrency, crawl depth, same-origin policy, subdomain policy, robots handling, and user agent. Browser-specific third-party/private-origin controls remain module settings resolved by the plan; Scan Studio does not invent duplicate scope semantics.

Identity tests use the configured GET/HEAD endpoint and safe field-path grammar. Wildcards, JSONPath/script syntax, recursive paths, and `__proto__`, `prototype`, or `constructor` traversal are rejected. Results contain bounded categories, comparisons, hashes/aliases, and redacted request audit only; raw identity JSON and raw principal values are not returned or persisted.

Evidence preferences may strengthen a profile policy, but cannot downgrade a profile that requires stronger evidence. RouteCairn currently emits JSON, Markdown, and HTML for every completed scan. The Plan Review page shows the effective planner policy rather than treating the UI preference as authoritative.

### Authorization Workflow Studio

The Controlled Workflows step provides shared guided configuration surfaces for Object Pair, Field Exposure, Role and State Matrix, Equivalent Route, Collection and Listing, Bulk, and File and Download authorization testing. The list and its supported actors, methods, expectations, limits, safety notes, module IDs, and schema versions come from `/api/capabilities` rather than a dashboard-only workflow catalog.

Each editor shares case creation, duplication, enable/disable, deletion, ordering, stable UI-only case identities, safe import/export, Advanced JSON, field diagnostics, module coupling, and planner preview controls. UI case identities survive edits and reorder but are stripped before planner serialization and safe export. Case references continue to use scanner case IDs; referenced cases cannot be deleted until their dependencies are resolved.

The guided surfaces are domain-specific: Object Pair presents the fixed owner-baseline and cross-owner relationship matrix; Field Exposure provides safe-path expectation rows; Role and State uses an explicit filterable matrix; Equivalent Routes uses exact route/reference controls; Collection explains completeness and provides known-object, case-reference, count, and summary builders; Bulk exposes fixed JSON bodies, all three safety modes, exact object baselines, and before/after GET state checks; File and Download exposes bounded proof modes, fingerprints, exact redirect origins, and separate signed-URL issuance/follow controls. Optional ordinary structures can be created and removed without first importing JSON. The capability registry carries a deliberate guided-field coverage manifest and an empty `advancedOnlyFields` list for each workflow so schema/UI drift fails tests.

Advanced JSON is capped at 256 KiB, rendered as inert text with a syntax-highlighted preview, rejects prototype-related keys, and passes through the same strict Zod schema and planner as guided configuration. A valid exported envelope can be re-imported without changing semantic fields. It remains an expert inspection/import surface rather than a requirement for ordinary scanner-supported structures.

Planner preview and launch parse every enabled workflow with its existing scanner-core schema and invoke its existing planner before `ScanPlanner.resolve`. Launch independently repeats parsing, actor checks, identity requirements, scope checks, module coupling, and planning. The worker receives the resulting exact fixed request matrices through the existing isolated-worker path. Client-submitted resolved plans are never trusted.

Workflow configuration persistence is summary-only. Scan records retain workflow ID, enabled/editor state, case count, and a configuration hash. Persisted plan snapshots retain schema version, bounded request count, and configured status instead of raw object IDs, file references, private values, signed URLs, or authentication material.

The editors never enumerate or derive objects, files, routes, roles, tenants, states, fields, methods, collection pages, or bulk selections. Runtime responses cannot add cases or identifiers. Collection absence is meaningful only under the selected completeness model. Bulk POST remains limited to the core operator-attested or postcondition-verified non-mutating modes. File evidence remains bounded; filenames, content types, lengths, and `HEAD` alone do not prove file-content exposure.

Bulk's current scanner-core precondition model is intentionally narrow: each configured postcondition check performs the same exact safe GET before and after the POST and compares only named scalar fields. There is no separate arbitrary precondition request type, and unchanged configured fields do not prove that no other side effect occurred. File redirect hop count is enforced by the shared request broker and resolved scan plan rather than duplicated as a workflow-local setting. Exact workflow request counts are displayed from planner output; before planning the editor says that the count is unknown instead of estimating it in the browser.

Fictional example: configure Account A and Account B with verified identities, enter `record-a-fixture` and `record-b-fixture`, and use an exact template such as `https://app.example.test/api/records/{{OBJECT_ID}}`. RouteCairn plans the two owner baselines and two cross-account probes only. It does not increment, guess, discover, or follow returned identifiers.

### Triage Model

The Findings Command Center keeps a durable logical finding separate from its immutable scan occurrences. Its installation-scoped HMAC fingerprint uses target origin, module, category, method, normalized route, and authorization boundary. Titles, scanner severity/confidence changes, raw object values, and authentication secrets are not identity inputs.

Dashboard review state is separate from scanner severity/confidence and remediation state.

Review states:

```text
UNREVIEWED
IN_REVIEW
CONFIRMED
FALSE_POSITIVE
ACCEPTED_RISK
DUPLICATE
RESOLVED
REOPENED
```

Remediation states:

```text
OPEN
ASSIGNED
FIX_IN_PROGRESS
FIXED_PENDING_RETEST
FIXED_VERIFIED
WONT_FIX
```

Retest states are `NOT_RETESTED`, `RETEST_SCHEDULED`, `RETEST_RUNNING`, `RETEST_PASSED`, `RETEST_FAILED`, and `RETEST_INCONCLUSIVE`. Review and remediation transitions use centralized state machines and append immutable history records. False positive, accepted risk, won't fix, reopen, verified resolution, and sensitive overrides require safe reasons. Duplicate assignments resolve to a validated canonical root; self-links, missing targets, and cycles are rejected. Optimistic row versions prevent concurrent analysts from silently overwriting each other.

`FIXED_VERIFIED` requires either a compatible passing RouteCairn retest or an explicit OWNER override with a reason and audit event. Compatibility requires the same target, a completed scan, the relevant completed module, and retained controlled-case coverage where applicable. Mere absence without coverage is inconclusive. A later occurrence reopens a resolved or fixed-verified finding while preserving prior history. False-positive recurrence is flagged without erasing that decision; accepted-risk recurrence remains accepted and receives a new-occurrence marker.

The Command Center provides server-backed search and composable filters, allowlisted sorting, bounded pagination, configurable allowlisted columns, personal defaults, owner-managed shared saved views, a sequential Review Queue, keyboard review actions, safe notes, canonical duplicate selection, remediation assignment, retest evaluation, proof readiness, and bounded bulk review/remediation/note actions. Project and target detail views expose linked finding totals, severity/remediation/module distributions, affected targets, recent activity, and retest queues without loading all evidence.

`Re-run for Retest` creates a reviewed Scan Studio draft; it never executes automatically. The draft preserves the project, target, safe scope, profile, selected modules, limits/evidence summaries, source finding/occurrence/scan, relevant workflow type, and case alias. When `ROUTECAIRN_MASTER_KEY` is configured, controlled workflow configurations are retained in a separate AES-256-GCM template record bound to the installation, scan ID, and key version; they are decrypted and schema-validated only for a matching retest draft. This permits exact operator-supplied object identifiers and workflow structure to be reviewed and reused without putting them in scan summaries, reports, events, or logs. Historical ephemeral tokens, cookies, authentication headers, and response-derived signed URLs are never restored. Enabled saved credential UUIDs may be selected again subject to `credentials.use`; otherwise the Studio displays `Fresh credentials required for this retest.` Without the master key, the encrypted template is unavailable and controlled values must be re-entered. The operator must reconfirm authorization, review all restored values, supply current credentials, preview through the current `ScanPlanner`, and launch normally. Changing relevant coverage produces a warning, while the backend compatibility evaluator remains authoritative.

Evidence is dispatched through a typed semantic viewer registry for HTTP, object-pair, field-exposure, role/state matrix, equivalent-route, collection, bulk, file/download, identity, and browser evidence. Unknown safe structured records use a bounded escaped fallback. Screenshot previews use artifact UUID routes, root containment, image signature/MIME matching, a 10 MiB limit, maximum 16,384-pixel dimensions and 100-megapixel decoded geometry, `nosniff`, private no-store caching, and no external URL loading. Unsupported or malformed image headers fail closed before streaming.

Active review ownership is cooperative rather than a permanent lock. Another analyst sees the current reviewer and start time, must explicitly confirm takeover, and remains protected by optimistic row-version checks. Takeover preserves prior history and emits a dedicated audit event. Ownership older than four hours is presented as stale but is never transitioned automatically.

For fictional local data, run `routecairn dashboard demo-seed --data-dir <path>`. The command refuses `NODE_ENV=production`, seeds once, and creates synthetic projects, targets, users when needed, lifecycle states, evidence types, histories, views, and a contained screenshot artifact.

Evidence is fetched only for the finding workspace. Target-controlled content is rendered as escaped text, artifact access uses UUIDs, and missing artifacts remain explicitly unavailable. Notes reject authentication-like secret material. Evidence summaries use normalized endpoints, so raw query tokens, cookies, credentials, and signed URL values are not exposed by Command Center APIs.

OWNER has all finding permissions, including owner verification override and installation-wide saved views. ANALYST can review, bulk review, assign, remediate, link retests, add notes, and manage personal views. VIEWER is read-only. Saved views retain the exact allowlisted visible-column order; columns can be reordered by drag and drop or keyboard-accessible move controls. Retests are never launched automatically or with historical credentials.

### Comparison Semantics

Dashboard comparison schema version 2 joins durable finding fingerprints to the exact occurrences in both scans. It classifies new findings, regressions that existed before the older scan, persisting findings, severity/confidence changes with direction, resolved findings, and findings not retested. Resolution requires the same target, a completed or imported newer scan, and completion of the finding's source module in that newer scan. Profile differences are visible but do not erase valid module-level coverage. The result exposes old/new/shared/added/omitted modules plus scope and safe authentication-summary equivalence; absent snapshots remain explicitly non-equivalent. Target mismatch, incomplete scans, and omitted modules force the affected finding into `notRetested` instead of claiming a fix.

### Scan Comparison & Regression Intelligence

Dashboard comparison schema version 3 persists immutable, engine-versioned comparison snapshots. Its six top-level finding classifications are `NEW`, `PERSISTING`, `CHANGED`, `RESOLVED`, `NOT_RETESTED`, and `INCOMPARABLE`. Regression is a secondary flag and requires a prior `FIXED_VERIFIED` remediation event plus a new compatible occurrence; an issue that merely disappears and returns is a `RECURRENCE`, not a proven regression.

The centralized comparison coverage service evaluates target identity, semantic endpoint scope, terminal scan state, native/import source quality, module execution, safe authentication and identity semantics, workflow identity, case correlation, request transmission, budget/block state, and evidence semantics. All seven controlled authorization workflows persist redacted case facts and use workflow-specific semantic fingerprints: Object Pair baselines and cross-owner directions; Field Exposure field policies; Role/State Matrix rows; Equivalent Route pairs; Collection completeness/reference semantics; Bulk safety/baseline/postconditions; and File identity, stream, and signed-follow proof.

The invariant is deliberately strict:

```text
Absence + proven compatible coverage  -> may support RESOLVED
Absence + missing/insufficient coverage -> NOT_RETESTED
Evidence + incompatible security semantics -> INCOMPARABLE
```

Credential rotation does not itself break comparison: raw tokens, cookies, credentials, principal values, object references, signed URLs, and sensitive query values are not comparison inputs or output. Imported findings-only reports can support positive correlation such as `NEW` or `PERSISTING`, but cannot prove resolution. Durable JSON and Markdown exports contain only the safe comparison snapshot. Retest compatibility reuses the same coverage service, preserving the invariant that no compatible coverage means no verified resolution.

The Compare workspace recommends the two latest completed/imported candidates while still allowing explicit partial analysis. It provides summary filters, coverage/module/workflow/case views, structured plan changes, regression intelligence, and side-by-side occurrence/evidence detail. Target and project pages use persisted comparisons for lightweight regression timelines. Automatic comparison is local database analysis, deduplicated by scan pair and engine version, failure-isolated from scan completion, and may be disabled by setting `dashboard_meta.comparisons.auto.enabled` to `false`.

Current intentional limitations: historical native scans created before schema version 8 do not retroactively gain per-case facts and are handled as partial/incomparable where those facts are required; cross-target comparisons remain analytical and cannot prove remediation; comparison export is JSON/Markdown (PDF remains part of the reporting milestone); and comparison paging is bounded at the API/list layer while very large finding-result paging remains a future scale optimization.

### Proof Packs

Proof packs include confirmed findings only by default. Ready proof packs are immutable snapshots; editing should create a later version. The generated HTML proof pack contains a restrictive CSP and escapes target-controlled text. Proof-pack downloads resolve by artifact UUID.

### Historical Import

Historical import accepts existing RouteCairn `report.json` files from approved output roots only. It canonicalizes paths, rejects symlink imports where detectable, enforces a file-size limit, parses JSON safely, treats imported text as untrusted, and records import limitations. Imported scans receive new dashboard UUIDs and do not invent original progress events or module timing history.

### Security Model

The dashboard defaults to loopback-only local mode and also supports an explicitly configured server mode behind HTTPS with durable users, revocable sessions, CSRF protection, and backend-enforced RBAC.

Protections include:

- loopback binding refusal for non-local hosts
- server-mode fail-closed startup checks
- server-mode durable users and revocable sessions
- centralized RBAC permission checks
- isolated child-process scan workers with typed IPC and message-size validation
- one-use per-launch bootstrap credential
- HttpOnly SameSite session cookie
- CSRF token for mutations
- strict Origin validation for state-changing requests
- JSON content-type requirements for mutations
- bounded request bodies, pagination, event metadata, and event messages
- redaction before persistence
- parameterized SQL
- no arbitrary command execution
- no arbitrary artifact path downloads
- no raw generated HTML injection into the dashboard DOM
- encrypted credential profiles with authenticated encryption when `ROUTECAIRN_MASTER_KEY` is configured
- no plaintext credential-profile values in read APIs, audit events, scan events, process arguments, or persisted plan snapshots

Audit events store safe summaries and bounded metadata only. They must not contain credentials, cookies, authorization headers, request bodies, response bodies, or plaintext credential-profile material.

Dashboard scan workers communicate over a versioned IPC protocol. Worker messages are schema-validated before persistence. Worker stdout is not forwarded to browsers. Sensitive worker IPC now uses a job-bound envelope summary with worker ID, job ID, worker-process generation, scan attempt, protocol version, expiry, nonce, sequence number, and HMAC using a per-worker session secret. Envelopes for the wrong job/worker/generation, expired envelopes, duplicate envelopes, and replayed or out-of-order sensitive messages are rejected. JavaScript memory cannot guarantee cryptographic zeroization, so plaintext references are avoided durably and cleared by process exit where practical.

### CLI Compatibility

The CLI remains fully usable without the dashboard or dashboard database. Existing scan commands still plan scans, run scans, write JSON/Markdown/HTML reports, and update the filesystem scan index. The dashboard imports historical CLI reports when needed instead of making SQLite mandatory for CLI users.

### Remaining v1 Limits

Dashboard v1 does not implement organizations, teams beyond local users, cloud sync, billing, notifications, distributed workers, remote agents, scheduled scans, persistent raw credential storage, browser login automation, PDF proof-pack generation, or WebSocket dashboard updates. Scan Studio Core, visual scope building, structured ephemeral auth, saved/ephemeral actor mixing, identity testing, all seven controlled-authorization workflow execution paths, and planner/launch round-trip are implemented.

The Authorization Workflow Studio milestone remains incomplete at the guided-UX layer. The current shared editor cannot add every absent optional schema field without Advanced JSON, and it does not yet provide the requested Object Pair relationship diagram, dedicated safe field-path row editor, semantic matrix table and filters, collection completeness/reference controls, bulk body/baseline/postcondition controls, file proof-mode and signed-URL controls, per-field inline schema diagnostics, stable editing-only case IDs, or the full visual and behavioral test matrix for those specialized controls. Immutable saved-configuration version history, full worker resource limits/process-tree cleanup, and a full worker diagnostics page also remain incomplete.
