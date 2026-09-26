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
- the planner resolves a bounded `GET` request matrix and accepts only explicit `LINK_HEADER`, `JSON_URL`, or `JSON_CURSOR` pagination contracts with a two-to-ten-page cap
- every request uses the shared `RequestSafetyBroker`; public cases carry no auth material
- findings require a prohibited supplied object to appear in the configured bounded response with matching metadata where configured
- response-provided next values cannot change origin/path or introduce undeclared query keys; unknown returned IDs, cursors, unmatched objects, full response bodies, auth material, and raw object IDs are not persisted

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

Known limitations include future unknown Next.js artifact shapes, server-only manifests that are never public, unobserved dynamic route values, intentionally unfuzzed RSC internals, intentionally uninvoked Server Actions, and source maps that are neither referenced nor explicitly supplied.

> RouteCairn does not brute-force Next.js routes, fuzz RSC internals, invoke Server Actions, or perform cache-poisoning attacks.

### Browser Hardening

Browser crawling uses `browser-crawler` settings declared in `src/core/planning/ModuleCatalog.ts` and overridden by profiles in `src/core/planning/ProfileDefinitions.ts`. Supported settings include `browserMaxPages`, `browserMaxLinksPerPage`, `browserMaxPolicyEvents`, `browserMaxRequestsPerPage`, `browserBlockThirdParty`, `browserAllowedResourceTypes`, `browserAllowedThirdPartyOrigins`, screenshot capture, popup/download/upload, private-network, service-worker, and WebSocket controls. Unsupported browser settings fail during planning.

Scope is evaluated with the shared normalized URL matcher, including protocol, hostname, port, path, same-origin, subdomain, disallowed-path, and safe-method checks. Browser-only policy decisions happen before broker budget spending for prohibited protocols, prohibited private/internal destinations, unsupported resource types, download-like URLs, third-party resources, and per-page browser request limits. Destination checks block loopback, private IPv4 ranges, IPv6 loopback/local ranges, link-local addresses, cloud metadata-style addresses, `localhost`, single-label/internal hostnames, trailing-dot variants, and common alternate IPv4 literals. Public-looking hostnames are DNS-resolved before transmission where the runtime resolver can resolve them; every returned address is checked and mixed public/private answers fail closed. Local/private test targets require both `browserAllowPrivateNetwork: true` and exact `browserAllowedPrivateOrigins` entries. The boolean alone is not permission to browse arbitrary internal destinations.

Third party means a different origin from the target origin: scheme, host, and port must all match. Same registrable-domain subdomains and same host on a different port are third party under this model. Narrow exceptions can be declared as exact origins in `browserAllowedThirdPartyOrigins`.

Allowed browser resource types are `document`, `stylesheet`, `script`, `xhr`, `fetch`, and `manifest` by default. Other Playwright resource types (`image`, `media`, `font`, `texttrack`, `eventsource`, `websocket`, `other`) are blocked unless explicitly allowed by the resolved plan; all intercepted resource types count as browser attempts, and transmitted ones consume the global request budget. The attempt budget is separate from the network request budget and bounds blocked third-party resources, blocked resource types, mutating requests, out-of-scope requests, popup attempts, download/upload attempts, WebSocket attempts, frame requests, and worker/service-worker attempts where observable. Policy-event retention is capped by the same browser-attempt ceiling.

Frames inherit the context route policy. Popups are closed unless explicitly allowed, and their requests still pass through context-level routing. Downloads are disabled at context creation, download-like navigations are blocked, and download events are cancelled. File input clicks are denied in the browser init script; file chooser events are recorded as upload policy events; scanner modules are not given raw page/context APIs that upload files.

Service workers are disabled by default with Playwright context `serviceWorkers: "block"` and a browser init-script guard that rejects `navigator.serviceWorker.register`. `browserAllowServiceWorkers` is false by default and must be explicitly resolved through the plan for any future reviewed workflow.

WebSockets are denied by Playwright routing when `browserAllowWebSockets` is false. When explicitly enabled, the browser owns the socket so it must traverse the same authenticated pinned proxy as page, frame, worker, download, and browser API traffic. This avoids Playwright's server-side WebSocket connector, which does not inherit the Chromium proxy. Exact origin and private-origin exceptions are re-enforced by the proxy, permitted sockets are closed during browser teardown, and RouteCairn never inspects or logs message payloads.

Crawl depth is traversal distance from the seed: the initial page is depth `0`, links discovered there are depth `1`, and nested links are depth `2`. The crawler uses deterministic breadth-first scheduling, conservative canonical URL de-duplication, a maximum page count, a maximum links-per-page count, per-page request limits, and the global broker request budget. Browser crawl identity removes fragments, lowercases hostnames, removes default ports, and normalizes repeated path slashes. It preserves query parameter order, duplicate parameters, empty parameters, parameters without values, and query encoding as serialized by the browser URL parser. It does not sort signed or security-looking query strings and prefers duplicate crawling over collapsing potentially different application states. It extracts anchors only and does not click buttons or submit forms. Applications that mutate state through `GET` remain a residual risk and findings should be manually verified.

Every Chromium crawl starts a dedicated, randomly authenticated HTTP/CONNECT proxy bound only to `127.0.0.1`. Immediately before every upstream socket, the proxy resolves and classifies the complete bounded DNS answer set, selects a deterministic approved address, connects to that IP literal, and verifies the socket's remote address. The original authority remains the HTTP `Host` and TLS SNI. Redirect targets, third-party origins, cloud metadata addresses, mixed public/private answers, and exact private-origin exceptions are enforced again at this connection boundary, closing the policy-check-to-connect DNS-rebinding gap. Chromium QUIC, asynchronous DNS, DNS-over-HTTPS, and implicit loopback bypass are disabled for the isolated context so pages, frames, workers, downloads, WebSockets, and browser API traffic cannot escape the proxy path.

Proxy credentials and raw destination addresses remain case-local memory only. Reports and dashboard events expose health state, restart generation, connection counters, safe failure codes, and salted destination fingerprints. A fatal proxy failure fails the crawl, closes Chromium, and triggers at most one fresh browser/proxy generation; ordinary destination blocks are enforcement outcomes and do not falsely mark the proxy unhealthy.

Authenticated browser bootstrap is implemented on the hardened crawl path. An authenticated plan must have a primary profile or the crawler refuses to browse anonymously. Header/cookie bootstrap and an optional explicit login workflow run in a fresh isolated Chromium context. Login form values live only in the auth profile or encrypted dashboard vault, arrive at a worker through the existing job/generation/attempt-bound HMAC envelope, and are referenced by name from bounded `fill` steps. The one write exception is an explicit login `POST`: it must match the target origin, scope method allowlist, configured login phase, and exact allowed login path. The exception is removed immediately after login; every later `POST`, `PUT`, `PATCH`, or `DELETE` is blocked before transmission.

Use `browserBootstrap` in the primary `--auth` profile; see `examples/auth.browser.example.json`. Workflows support bounded navigation, secret-backed fills, explicit login clicks, URL/visibility waits, and post-login journeys that may click anchors only. The crawler records cookie/local/session storage metadata with per-run salted digests, DOM writable/read-only/disabled fields, legitimate admin-link discovery, browser/API identity correlation, and transmitted request/response metadata in `browser-traffic.redacted.har.json`. It never persists request bodies, response bodies, cookie values, storage values, login values, or raw identity values. All query values are redacted in browser traffic artifacts.

Browser-learned traffic is not mutation authority. Every allowed and blocked browser request is reduced to a versioned, secret-free candidate in `authentication-lifecycle.learning.json`; blocked writes are observed before transmission. With `--authentication-lifecycle-auto`, RouteCairn can promote the single unambiguous explicit login candidate into login-enumeration, session-rotation, and session-fixation cases, resolve field-to-secret-reference bindings in memory, and execute the ready cases under a separately supplied exact expiring automation policy. Missing or ambiguous fields, cookies, credentials, cleanup, or authorization produce named readiness blockers rather than guessed traffic. Optional `proofCases` can bind read-only browser selector assertions to an already approved controlled-mutation `caseId`. Protected-action proof runs after authoritative impact verification, rollback proof runs before cleanup is sealed, and a failed browser rollback assertion keeps the encrypted recovery bundle and marks cleanup failed. Chromium bootstrap is replayed once after a browser-process failure; credentials remain in memory and no reusable browser state file is written.

### Object Pair Testing

Object-pair testing is an explicit authorization verification workflow for IDOR/BOLA-style checks. The standalone `--object-pairs` contract never guesses, mutates, increments, or decrements identifiers and never expands cases at runtime. The separate, opt-in safe-inventory acquisition stage can now compile that fixed contract from bounded authenticated collection evidence before planning; the resulting object IDs and relationships are frozen before any authorization check runs.

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

Without a pagination contract, RouteCairn downgrades absence to incomplete/inconclusive when a response contains common partial-result signals such as `next`, cursors, `hasMore`, pagination links, HTTP `Link: rel=next`, totals exceeding returned entries, server-side caps, or truncation markers. With a contract, it follows at most `maxPages` and reports whether traversal was exhausted, found the supplied object, reached the page cap, failed, or rejected an invalid next destination.

Only HTTP JSON `GET` is supported. `HEAD`, `OPTIONS`, mutating methods, request bodies, GraphQL/RPC bodies, wildcard/range/query generators, search dictionaries, filter discovery, sort discovery, endpoint discovery, identifier harvesting, and runtime response-driven cases are rejected or unsupported. Pagination can only supply the next bounded URL or opaque cursor to the already resolved case; it never adds actors, cases, object IDs, headers, methods, origins, or paths. Link/URL modes accept only the original query keys plus an explicit allowlist. Cursor mode inserts one declared parameter. Every possible page is reserved in `maxRequests` before execution.

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

### Supabase/PostgREST/RLS Authorization

The Supabase authorization engine executes an explicit, bounded matrix across `ANONYMOUS`, `ACCOUNT_A`, `ACCOUNT_B`, and `SERVICE_ROLE`. It covers table `SELECT`/`INSERT`/`UPDATE`/`DELETE`, cross-user and cross-tenant isolation, sensitive columns, storage objects, signed-URL issuance and one-time bounded follows, RPCs, PostgREST relationship traversal, public schema exposure, PostgreSQL grants/RLS metadata, and `SECURITY DEFINER` risk classification.

Keys are never stored in the manifest. Set the environment variables named by `anonKeyEnv` and `serviceRoleKeyEnv`, then run:

```bash
export SUPABASE_ANON_KEY='...'
export SUPABASE_SERVICE_ROLE_KEY='...'
node dist/cli/index.js scan https://your-project.supabase.co \
  --scope ./examples/scope.example.json \
  --auth-a ./examples/auth.account-a.example.json \
  --auth-b ./examples/auth.account-b.example.json \
  --supabase-authorization ./examples/supabase-authorization.example.json \
  --mutation-contracts ./controlled-supabase-mutations.json \
  --output ./reports/supabase-authorization
```

Each case names one exact surface, resource, actor, operation, method, URL/filter, expected decision, and optional cross-user/cross-tenant/service-role boundary. Successful PostgREST responses are not automatically treated as access: `[]` is an RLS-filtered empty result, and non-empty results require every configured identity assertion to match the same returned row/object before a denial bypass can be confirmed. `forbiddenColumns` checks sensitive paths without persisting their values.

`INSERT`, `UPDATE`, `DELETE`, and mutating RPC cases require `mutationContractCaseId` and an exact expiring controlled-mutation contract. Updates use `CONTROLLED_MUTATION`. Disposable inserts may use a verified DELETE cleanup. Deletes require `CONTROLLED_DELETION`, are limited to `LOCAL`, `TEST`, or `STAGING`, require an explicit reconstructive rollback body, and must prove that the rollback response hash exactly matches the captured pre-state. All mutation intent and encrypted recovery material are durably flushed before transmission; unresolved cleanup blocks later mutations.

The optional `catalog` snapshot records exposed schemas, table RLS/force-RLS state, role grants, sensitive-column exposure, storage bucket ownership policy, PostgREST relationships, RPC execute grants, `SECURITY DEFINER`, `search_path`, and dynamic-SQL declarations. Catalog risks and runtime behavior are reported separately. The report includes per-resource actor/operation coverage, an allowed/denied/inconclusive access matrix, anon-key JWT role classification, and paired service-role boundary verification. RouteCairn does not query administrative catalog endpoints at runtime; a supplied safe inventory import can normalize a catalog export and compile anonymous table `SELECT` observations while leaving RPCs and writes unexecuted.

Credential headers (`apikey`, `Authorization`, cookies, and related auth headers), query values, asserted identifiers, storage path identifiers, signed URL boundaries, response values, and signed query tokens are redacted or omitted from JSON, Markdown, HTML, request audit, scan-plan, and finding evidence. Signed URLs are followed only when `followOnce` is explicitly enabled, the exact origin and configured object path match, and the shared scope/budget/stream limits allow the request; application credentials are never forwarded to the signed destination.

### Shared Mutation Coordination and Dashboard Recovery

**Dashboard → Offensive Safety → Workflow cleanup recovery** is the primary recovery surface for authentication lifecycle, business invariants, controlled races, signed links/portals, operational endpoints, and billing/entitlement workflows. Existing controlled-contract approval/recovery remains in **Production Mutation**. No terminal command is required for the new workflow recovery path.

All these engines, Supabase/privilege controlled contracts, dashboard workers, and normal CLI scans use the same coordination kernel. Within one installation, the default directory is `<dashboard-data-directory>/controlled-mutations`; CLI scans use `ROUTECAIRN_DASHBOARD_DIR` or the standard user dashboard directory. When using a custom dashboard `--data-dir`, set `ROUTECAIRN_MUTATION_DIR` to the same absolute coordination directory in every local dashboard/CLI process. The OS-backed SQLite lease excludes concurrent local processes and is released after process death. Durable lock metadata, serialized journals, the canonical `mutation-journals.json` registry, and encrypted recovery bundles remain available for inspection; corrupt or unreadable coordination data fails closed.

For multiple hosts, enable the control plane's signed distributed coordinator and configure every mutation-capable host with the same namespace and secret:

```text
# control plane
ROUTECAIRN_MUTATION_COORDINATOR_SECRET_FILE=/run/secrets/mutation-coordinator-secret

# every CLI, dashboard worker, or signed remote agent that may execute mutations
ROUTECAIRN_MUTATION_COORDINATOR_URL=https://routecairn.example.com
ROUTECAIRN_MUTATION_COORDINATOR_NAMESPACE=customer-staging
ROUTECAIRN_MUTATION_COORDINATOR_SECRET_FILE=/run/secrets/mutation-coordinator-secret
```

The coordinator uses an origin-only HTTPS endpoint (loopback HTTP is accepted only for local fixtures), DNS-to-socket pinning, bounded requests, HMAC-SHA-256 request authentication, timestamp windows, one-use nonces, random bearer lease tokens stored only as hashes, and a persistent SQLite uniqueness constraint per namespace. Local checks complete before the distributed lease is granted. Lease heartbeats provide liveness visibility, but an expired lease is never automatically reassigned: it remains blocking until an authorized operator marks it orphaned, creating a state-uncertain cleanup obligation. This avoids split-brain mutation execution after a network partition.

Every normal release publishes `CLEAN`, `UNRESOLVED`, or `UNKNOWN` cleanup state. Unresolved local journals, orphaned recovery bundles, unreadable state, stale leases, and remote release failures all keep the shared namespace blocked. Only recovery of the same case may enter a namespace with its matching obligation; verified rollback clears it. Owners can inspect `GET /api/operations/mutation-coordination?namespace=...`, mark an expired lease state-uncertain through `POST /api/operations/mutation-coordination/orphan` with `MARK_STALE_LEASE_STATE_UNCERTAIN`, or clear an independently verified obligation through `POST /api/operations/mutation-coordination/resolve` with `I_VERIFIED_NO_MUTATION_WAS_TRANSMITTED_OR_TARGET_STATE_IS_RESTORED`. Both changes require an authenticated dashboard session, recovery permission, CSRF protection, and produce audit records.

Before a dedicated engine transmits a mutation, it seals an AES-256-GCM checkpoint containing the exact case, original scope, actor bindings, and captured restoration state. Later checkpoints preserve newly captured state. Raw response-derived tokens or restoration values may therefore exist **encrypted at rest**, but never in dashboard responses, journals, reports, findings, or proof packs. Supplied vault credentials are not copied into these checkpoints. Protect and back up the coordination directory and `recovery.key` together; losing the key makes existing checkpoints unrecoverable. RouteCairn never regenerates a missing key over outstanding bundles.

To recover an interrupted workflow:

1. Select its unresolved obligation in Offensive Safety.
2. Select the registered target with the exact same origin and fresh enabled vault credentials for the required actor slots. Stable principal/tenant/role bindings must match. Without an original principal ID, the original credential fingerprint must match; RouteCairn cannot safely infer a replacement identity.
3. Explicitly authorize **only stored cleanup and restoration verification**, then run recovery.
4. Follow the recovery timeline. Only `ROLLBACK_VERIFIED` clears the obligation and removes its checkpoint. Failure, worker interruption, missing captures, or unverifiable restoration keeps subsequent mutations blocked.

Cleanup contracts should be safe to repeat after an uncertain network outcome and should verify authoritative restored state. Explicitly account for already-restored responses where appropriate (for example, an already-deleted disposable object); recovery does not silently relax the case's assertions or invent a replacement cleanup sequence.

Recovery runs in an isolated worker through the existing authenticated credential handoff. It never reruns login learning, preconditions, attack steps, race groups, or the original scan. It uses the intersection of the sealed scope and the current registered target scope, retains target/program authorization boundaries, disables redirects and mutation retries, and uses a separate bounded cleanup transport so scan cancellation does not cancel restoration. Replaced checkpoints and mismatched actors are rejected before cleanup transmission. A checkpoint cannot reconstruct a server-generated value that was never received before a crash; such cases remain unresolved rather than guessing or replaying the attack. Older per-scan journals without encrypted state cannot acquire retroactive automatic recovery; retain those artifacts and reconcile their targets before sign-off.

### Authentication Lifecycle Testing

The authentication lifecycle engine executes explicit operator-authored cases for login enumeration resistance, post-login session rotation, session fixation, logout/password-change/revocation invalidation, idle and absolute expiration, refresh rotation, password-reset binding/replay/account confusion, email verification, account linking, OAuth/OIDC state and redirect validation, MFA, passkeys, recovery codes, admin and tenant invitations, and disabled-user session behavior.

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth ./examples/auth.lifecycle.example.json \
  --authentication-lifecycle ./examples/authentication-lifecycle.example.json \
  --output ./reports/authentication-lifecycle
```

For browser-learned automation, configure `browserBootstrap.login` in the primary auth profile and supply the automation policy instead of an explicit manifest:

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth ./examples/auth.browser.example.json \
  --authentication-lifecycle-auto ./examples/authentication-lifecycle-automation.example.json \
  --output ./reports/authentication-lifecycle-auto
```

This one run performs the isolated login, writes the redacted learning bundle, compiles supported cases in memory, executes only fully resolved cases, and writes `authentication-lifecycle.automation.json` with generated categories and readiness blockers. The policy supplies mutation authority, disposable-account confirmation, cleanup, and variant secret references; learning supplies the observed endpoint, method, body format, credential-field bindings, success response, and session-cookie name. Browser `loginSecrets` and `lifecycleSecrets` share a worker-only reference namespace; duplicate names with different values are rejected.

Authentication manifests may also declare native `fixtures`. `LOCAL_HTTP` provides a loopback email/SMS webhook sink, while `MAILPIT` and `MAILHOG` poll their test-only APIs. Step-level `INBOX_START`, `INBOX_WAIT`, and `INBOX_CLEAR` actions expose only transient captures; message bodies, verification codes, links, recipients, and adapter responses are never serialized. The local sink accepts `POST /messages` with `{channel, recipient, text, subject?, html?, sender?}` and is closed at the end of each case.

TOTP profiles support base32, hexadecimal, and UTF-8 seeds, SHA-1/SHA-256/SHA-512, 6–8 digits, and bounded periods. `TOTP_GENERATE` resolves the seed from the selected actor's worker-only secret namespace and makes the current code available as a case-local capture. Virtual WebAuthn fixtures use Chromium's CDP authenticator implementation; lifecycle actions can create, seed, clear, and remove CTAP2/U2F authenticators with configurable transport, resident-key, presence, and user-verification behavior. The browser driver can also run bounded, same-origin enrollment and login journeys against an owned HTTPS or loopback origin. The acceptance laboratory performs real `navigator.credentials.create()` and `navigator.credentials.get()` calls, validates the relying-party hash, challenge, origin, flags, counter, and P-256 assertion signature, establishes a browser session, and removes the credential during cleanup. The isolated browser and every virtual credential are destroyed when the case ends.

The loopback OIDC harness implements discovery, JWKS, authorization-code issuance, PKCE S256, one-use token exchange, RS256 ID tokens, and an exact callback receiver. `OIDC_START` captures its ephemeral issuer/endpoints and `OIDC_WAIT_CALLBACK` captures a named callback parameter. `OIDC_AUTHORIZATION_CODE` drives the entire callback lifecycle and validates discovery metadata, callback state, PKCE, signature and `iss`/`aud`/`sub`/`nonce`/`iat`/`exp` claims, then proves authorization-code replay is rejected. Redirects are restricted to configured HTTPS URIs or loopback HTTP. Access tokens, ID tokens, and subjects are optional transient case-local captures and are never placed in evidence.

Auth0, Cognito Hosted UI and public User Pools JSON APIs, Clerk, Firebase Authentication, and Supabase Auth provider adapters compile `providerCall` steps into their documented REST/OAuth endpoints and recommended response captures. Provider origins must be explicitly configured and in scan scope; credentials remain `{{SECRET:...}}` references. Cognito administrative operations that require an AWS-signed service client fail closed instead of pretending a Hosted UI or public User Pools call can perform them. A disposable loopback acceptance laboratory executes each adapter's signup/login or session/refresh/logout/delete sequence over HTTP, checks its provider-specific authentication contract, exercises the complete OIDC lifecycle, and completes a browser passkey enrollment/login/cleanup journey:

```bash
npm run acceptance:authentication
# or, after npm run build
node dist/cli/index.js validate-authentication-fixtures \
  --output ./.routecairn-authentication-acceptance
```

Every run creates fresh JSON and Markdown evidence with a content digest and no fixture credentials. CI runs this laboratory in Chromium and uploads the evidence. This command provides deterministic emulator acceptance for RouteCairn's complete integrations; the manifest-driven runner below extends the same proof to operator-owned third-party development tenants with explicit authorization and externally supplied credentials.

The sandbox acceptance runner performs that external proof without placing credentials in a manifest or artifact. It supports authorized Auth0, Cognito, Clerk, Firebase Auth emulator, and Supabase Auth development lifecycles, plus browser-driven OIDC and passkey lanes:

```bash
npm run acceptance:authentication:sandbox -- \
  --manifest ./examples/authentication-sandbox-acceptance.example.json \
  --output ./.routecairn-authentication-sandbox-acceptance
# or, after npm run build
node dist/cli/index.js validate-authentication-sandboxes \
  --manifest ./examples/authentication-sandbox-acceptance.example.json
```

The manifest contains environment-variable names, never secret values. Provider operations can use `{{SECRET:name}}`, response `{{CAPTURE:name}}`, and per-run `{{RUN_ID}}` substitutions. Each operation supports exact status sets, custom captures, required/absent JSON paths, JSON equality, and required/absent headers; negative-response checks can disable the adapter's normal success captures with `captureSuggested: false`. Each request is restricted to the configured adapter origins, URL substitutions are component-encoded, HTTP is accepted only on loopback, redirects are not followed by the provider executor, bodies are bounded, request budgets and per-request deadlines are enforced, and cleanup runs after partial failure. Every provider lane needs an explicit cleanup operation, and any signup lane must include `DELETE_USER` cleanup. Only `EMULATOR`, `DEVELOPMENT`, and `SANDBOX` lanes are accepted; production cannot be selected. Supabase public calls use the anon credential, session/MFA calls use the captured user access token, and only administrative invite/delete calls use the service-role credential.

OIDC acceptance discovers the provider, drives its real login page in an origin-constrained browser, receives an exact loopback callback, validates state, nonce, PKCE S256, JWKS signature and ID-token claims, and verifies callback and authorization-code replay rejection. Security-critical authorization parameters cannot be overridden by manifest extras. Register the manifest's exact `http://127.0.0.1:<port>/<path>` callback in the development IdP client before running. Providers whose authorization, token, or JWKS endpoints use a separate origin require that origin in `allowedEndpointOrigins`; browser login redirects require corresponding `browserAllowedOrigins` entries.

Passkey acceptance drives the application's actual enrollment, logged-out login, authenticated landing page, and credential-removal UI with a CDP virtual authenticator. It proves exact RP-ID binding and signature-counter advancement, requires an application-side cleanup assertion, clears the authenticator credential, and destroys the isolated browser context. Browser journeys support secret-backed fills, clicks, checkbox changes, key presses, select options, bounded waits, URL waits, visibility checks, and text checks. Selectors and optional login field secrets are application-specific, making the same runner usable with hosted sandboxes and local emulators. The example manifest is intentionally non-runnable until its development URLs, selectors, provider settings, and environment variables are replaced with values for an operator-owned test tenant. Firebase email/password and equivalent provider policies must be enabled; confirmation gates must be satisfied by the test tenant or an explicit inbox-driven setup before sign-in.

Fixture actions run inside the lifecycle case boundary before their step request. A fixture failure is `INCONCLUSIVE`, not a finding. Provider mutations are normal lifecycle mutations: they require the same expiring authorization, disposable-account declaration, durable journal, cleanup steps, and cleanup verification as any other state-changing request. See `examples/authentication-fixtures.example.json`.

Cases declare a bounded actor model, category, exact requests, transient captures, assertions, and cleanup. Actor slots are `anonymous`, `primary`, `account_a`, and `account_b`; `requestAuthentication` independently controls whether the selected profile's ambient headers/cookies are sent, so login cases can draw secrets from a profile while remaining unauthenticated on the wire. Request values use `{{SECRET:name}}` references resolved from the selected actor's encrypted or worker-held browser/lifecycle secret namespace; response-derived values use `{{CAPTURE:name}}`. Captures can read a bounded JSON path, response header, or named cookie. Raw usernames, email addresses, passwords, tokens, cookies, recovery codes, invitation codes, OAuth state, and session identifiers are never written into the manifest, plan, report, finding, Markdown, HTML, or request audit.

All `POST`, `PUT`, `PATCH`, and `DELETE` steps must explicitly declare `stateChanging: true`. Any state-changing case requires `CONTROLLED_LIFECYCLE`, the exact confirmation literal, an operator reference, change ticket, active authorization window, `disposableAccounts: true`, `cleanupRequired: true`, and at least one asserted `CLEANUP` step. Production additionally requires `productionAcknowledged: true`. Cleanup runs in `finally` after any transmitted state change and is still attempted if verification fails or the authorization window expires during execution. Mutation intent is durably flushed to `mutation-journal.json` before transmission under RouteCairn's global mutation lock; verified cleanup seals the obligation, while unresolved cleanup blocks later state-changing lifecycle cases. The journal contains no credentials, tokens, captures, response bodies, account identifiers, operator identity, or raw change ticket. A cleanup failure is surfaced separately and the disposable account must not be reused until inspected.

Every lifecycle request uses a sequential, independently bounded `RequestSafetyBroker` created by `ScanContext`. It retains DNS-to-socket pinning, exact scope, request budgets, rate limiting, aborts, response byte limits, redacted audit, and one-attempt mutation semantics. Redirect following is disabled for lifecycle requests so OAuth, reset, verification, and invitation redirects are asserted as data rather than navigated. Controlled deletion is enabled only on this explicit lifecycle broker. Raw bounded response bodies and `Set-Cookie` values are exposed through the broker's private transient-analysis `WeakMap`. The module uses them for assertions; retained case state is also sealed in encrypted recovery checkpoints until verified cleanup, never in public evidence.

Assertions support status allow/deny sets, header presence/absence, bounded JSON equality, equality to a secret reference, capture rotation/equality, response similarity/difference, allowed redirect origin/path, and redirect query binding to a secret reference. Response comparison can independently evaluate status, JSON shape, transient exact body digest, length delta, and response-time delta; exact digests remain private to case memory and encrypted recovery checkpoints, never public evidence. `waitBeforeMs` provides bounded idle/absolute-expiration checkpoints, obeys the enforced plan-wide scan deadline, and responds to operator cancellation. A `FAIL` creates a finding only when a configured security expectation is contradicted; missing secrets, expired authorization, policy blocks, response caps, and transport failures are `BLOCKED` or `INCONCLUSIVE` rather than vulnerabilities.

Comparison fingerprints bind the complete executable security contract: assertion operators and expected values, actor relationships/states and tenant/principal fingerprints, request methods/templates/headers/body structure, capture references, resource or endpoint bindings, execution bounds, cleanup, and authoritative verification. Canonical object ordering keeps them stable. Operator approval provenance (identity, ticket, and authorization window) is excluded, while sensitive literal subtrees are domain-separated and hashed before the outer contract digest instead of having their meaning omitted. A changed or weakened assertion therefore produces a different fingerprint and cannot establish remediation for the earlier case.

### Business Invariant Validation

The business-invariant engine models reusable multi-step rules such as withdrawal limits, bounded refunds, one-time payouts or coupons, suspended-user transaction denial, self-approval separation, entitlement gates, and approval-before-delivery ordering. Each explicit case defines authoritative pre-state reads, an ordered action sequence, independent authorization and business-rule expectations, authoritative post-state reads, invariants, an optional state machine, and verified cleanup.

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth ./examples/auth.lifecycle.example.json \
  --business-invariants ./examples/business-invariants.example.json \
  --output ./reports/business-invariants
```

Actions can run once, as sequential duplicates, or as bounded concurrent duplicates. Duplicate response acceptance is measured separately from authoritative post-state effects: two successful HTTP statuses do not by themselves prove that a one-time effect occurred twice. Invariants support value comparisons, numeric deltas, allowed state transitions, action-outcome counts, and configurable response equivalence. Authorization status classification is also separate from business-rule acceptance/rejection, preventing a valid authentication decision from masking a broken transaction rule.

`VALUE_COMPARE` and `NUMERIC_DELTA` cover balance, refund, payout, and redemption ceilings. `ACTION_OUTCOME_COUNT` plus authoritative deltas cover payout/coupon replay and duplicate effects. Actor relationships plus separate `DENY` or `REJECT` expectations cover suspended users, self-approval, and entitlement gates. `STATE_TRANSITION` or the case-level state machine covers approval-before-delivery and other ordering constraints. Multi-step cases may combine all of these assertions instead of reducing a workflow to one HTTP response.

Every case requires the exact `CONTROLLED_INVARIANT` confirmation, a currently valid authorization window, disposable entities, explicit cleanup actions, authoritative cleanup observations, and cleanup invariants. Production requires a separate acknowledgement. RouteCairn durably records each mutation intent before transmission, holds the global mutation lock across the workflow, never retries or follows mutation redirects, and blocks later cases when a cleanup obligation remains unresolved. Concurrent attempts are capped at four and are journaled sequentially before their bounded parallel transmission.

Request secrets use the same worker-only `{{SECRET:name}}` namespace as authentication lifecycle cases; response values use temporally ordered `{{CAPTURE:name}}` references. Sensitive literals, forward references, cross-origin requests, unsafe headers, implicit mutations, expired authority, and malformed object keys are rejected during planning. Observed raw captures and balances, secret transaction identifiers, credentials, response bodies, operator identities, and change tickets remain case-local and are absent from emitted evidence. Operator-declared non-secret constants remain visible in the scan plan by design. Case observations retain only status counts, structural fingerprints, invariant outcomes, and stable comparison fingerprints.

### Controlled Race Testing

The controlled-race engine is separate from ordinary parallel scanning and Batch 43 duplicate actions. It releases one explicit group of two to five exact mutation requests through a ready barrier, measures client dispatch skew, and requires the group to remain within its configured skew bound before a race finding is possible. Cases cover same-object operations, duplicate redemption, inventory, payment/entitlement, invitation, and one-time-token races; `CUSTOM` remains available for application-specific state machines.

```bash
node dist/cli/index.js scan https://app.example.com \
  --scope ./examples/scope.example.json \
  --auth ./examples/auth.lifecycle.example.json \
  --controlled-races ./examples/controlled-races.example.json \
  --output ./reports/controlled-races
```

Each case binds a disposable target type and operator-supplied SHA-256 identity fingerprint, an actor model, authoritative pre-state reads, one to three synchronized groups, authoritative post-state reads, explicit invariants, cleanup actions, cleanup observations, and cleanup invariants. `EVENT_COUNT_DELTA` verifies transaction, ledger, email, invitation, entitlement, inventory, or audit-event effects independently of HTTP response codes. `GROUP_OUTCOME_COUNT` verifies accepted, rejected, authorized, or denied request counts. Value, numeric-delta, and state-transition assertions cover remaining authoritative state.

The race-only broker bypasses ordinary inter-request pacing only while releasing one validated group. It still enforces exact scope and origin, DNS-to-socket pinning, global request budgets, concurrency limits, response byte caps, cancellation, redacted request audit, mutation permission, and no retry/no redirect semantics. A group can contain only two to five state-changing requests, the plan supports at most three groups per case, and no repetition, duration loop, adaptive amplification, or unbounded load mode exists.

All group mutation intents are durably journaled before the barrier is released under the global mutation lock. Any possibly transmitted group forces cleanup. Cleanup failure remains an unresolved journal obligation and blocks every later mutation case. A `Controlled Race Condition` finding requires a group that met its synchronization bound plus an explicit invariant contradiction; missing responses, excess dispatch skew, transport errors, missing captures, or cleanup uncertainty remain blocked or inconclusive.

### API and GraphQL Authorization

Batch 45 provides a dedicated, manifest-driven API and GraphQL authorization engine. It turns an operator-supplied route inventory into a structured security model and executes exact object, function, field, tenant, method, schema, GraphQL-limit, introspection, and version-boundary contracts.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.example.json `
  --auth-a ./examples/auth.account-a.example.json `
  --auth-b ./examples/auth.account-b.example.json `
  --api-graphql ./examples/api-graphql.example.json `
  --output ./reports/api-graphql
```

The route inventory records a safe alias, protocol, security kind, exact in-scope URL, version, documented methods and fields, and optional OpenAPI schema source/path. Every object route also requires a safe `pathTemplate`, so reports retain the route shape without persisting the supplied object identifier. Authorization cells bind one explicit actor to one fixed request and expected decision; a shared `matrixId` forms an explicit object-, function-, field-, or tenant-authorization matrix and cannot mix routes or check kinds. Response contracts can verify object identity, tenant identity, item bounds, and field rules such as `MUST_BE_PRESENT`, `MUST_BE_ABSENT`, or `MUST_BE_REDACTED`. Authorization decisions and response-field assertions are evaluated separately.

GraphQL support in this read-only engine includes fixed named query operations, field-level checks, tenant checks, an explicit minimal introspection query, bounded alias documents, and bounded JSON batches. Alias groups are capped at 10 and batch groups at 5, with lower per-manifest limits supported. Mutations and subscriptions are rejected here and routed through the protocol-security engine, where mutations require expiring approval and verified cleanup and subscriptions are message- and duration-bounded. Response-driven operation generation remains forbidden, and documents are depth/byte bounded.

Method-confusion cases directly compare only `GET`, `HEAD`, `OPTIONS`, and explicitly attested non-mutating `POST`. A REST POST requires both route-level and request-level non-mutating confirmation plus an exact marker in the fixed body. `PUT`, `PATCH`, `DELETE`, GraphQL mutations, and any real state change must use RouteCairn's protocol-security, controlled mutation, invariant, lifecycle, or race engines with their approval and cleanup contracts.

OpenAPI comparison inside a hand-authored API manifest still fetches only explicit schema/documentation routes. Separately, the safe inventory importer can normalize same-origin, parameter-free, anonymous `GET`/`HEAD`/`OPTIONS` OpenAPI operations into executable observation cases. Response observations record documented-field present/missing counts and undocumented-field counts without retaining response values. Version checks compare two explicit declared versions for authorization equivalence, identical field sets, or absence of additional candidate fields.

All requests use the ordinary scope, DNS, pacing, concurrency, response-size, and request-budget broker controls with retries and redirects disabled. Reports retain route aliases, paths, status classes, counts, and structural fingerprints. Authentication material, request bodies, GraphQL variables, response values, object identities, and tenant identities are omitted from JSON, Markdown, HTML, request-audit, and embedded scan-plan output.

### Protocol-Level Security

`--protocol-security` accepts an explicit bounded manifest for WebSocket messages, Server-Sent Events, GraphQL mutations and subscriptions, gRPC unary and server-streaming calls, multipart uploads, HTTP/2 authorization/desynchronization checks, and HTTP/3 capability checks.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.example.json `
  --auth ./examples/auth.lifecycle.example.json `
  --protocol-security ./examples/protocol-security.example.json `
  --output ./reports/protocol-security
```

WebSocket handshakes and HTTP/2 sessions resolve and pin the complete destination before opening a socket, preserve the original authority and TLS SNI, enforce live scope plus the shared target-authorization/rate/concurrency/request budgets, cap bytes/messages/duration, and omit payloads from all evidence. GraphQL-over-WebSocket supports `graphql-transport-ws` and the legacy `graphql-ws` subprotocol. GraphQL-over-SSE and ordinary SSE are bounded by response bytes and duration, retain completed events when the duration bound closes an otherwise-open stream, and are parsed only into event counts and configured structural assertions. gRPC uses HTTP/2 framing with payloads supplied from worker-only secret references and records only status and message counts.

GraphQL mutations plus state-changing WebSocket messages, gRPC calls, and multipart uploads require active authorization limited to local, test, or staging, disposable resources, a durable global mutation lock, an encrypted recovery checkpoint, and an exact cleanup request whose status must verify restoration. HTTP/2 and HTTP/3 desynchronization cases require separate expiring non-production authorization and use one malformed length case plus one fixed same-origin, in-scope same-session/process sentinel. Desynchronization probes are blocked in bug-bounty mode because the target-authorization schema does not grant that protocol-level capability.

HTTP/3 uses RouteCairn's packaged pure-JavaScript QUIC/TLS 1.3/QPACK runtime and no longer requires an external `curl` installation. Each HTTP/3 sequence runs in a credential-minimal Node subprocess whose one DNS resolution is forced to the address approved by RouteCairn's destination policy while TLS authenticates the original hostname. HTTP/1.1 and HTTP/2 fallback are disabled, response bytes and duration are bounded, and desynchronization sentinels must reuse the same native QUIC connection. A failed QUIC negotiation is reported as inconclusive rather than silently downgraded.

Dedicated disposable acceptance fixtures cover authenticated and denied WebSocket handshakes, both GraphQL-over-WebSocket subprotocols, stateful multipart upload cleanup, TLS gRPC unary and server streams, TLS HTTP/2 authorization, and native HTTP/3 authorization:

```bash
npm run acceptance:protocols
# or, after npm run build
node dist/cli/index.js validate-protocol-fixtures \
  --output ./.routecairn-protocol-acceptance
```

The laboratory produces digest-bound JSON and Markdown evidence without fixture credentials. Continuous assurance runs the complete fixture grid and retains its artifacts.

Use `base64:` secret values for raw protobuf or binary upload fixtures. Static manifests contain only secret reference names. Request headers cannot embed credentials; actor profiles supply authentication at execution time. See `examples/protocol-security.example.json` for read-only cases; mutation approvals should be generated for the active test window rather than stored as long-lived examples.

### Safe inventory import

`--inventory-import` accepts one bounded JSON bundle containing supplied or live OpenAPI, Postman, HAR, GraphQL, Supabase, and service-discovery sources. The same bundle can be supplied inline or by file through dashboard scan planning and signed remote-worker jobs. Live acquisition uses the same pinned transport, scope rules, target-authorization guard, DNS-rebinding controls, request budget, rate limit, response-size limit, redirect prohibition, and cancellation path as scan traffic.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.inventory-import.example.json `
  --inventory-import ./examples/inventory-import.example.json `
  --output ./reports/imported-inventory
```

For live acquisition, use `examples/inventory-live.example.json` and bind each source to `anonymous`, `primary`, `account_a`, or `account_b`. Authentication is taken only from the corresponding RouteCairn auth profile; credentials embedded in imported documents are never trusted or replayed. `OPENAPI_URL`, `HAR_URL`, and `GRAPHQL_INTROSPECTION` fetch exact documents/endpoints. `POSTMAN_URL` supports raw exports and Postman API envelopes, can fetch a collection plus environment, and applies collection, environment, then explicit non-secret variable overrides. `SERVICE_DISCOVERY` probes only its bounded canonical path allowlist and optional GraphQL endpoints; it does not crawl. `SUPABASE_LIVE` authenticates with the named anon-key environment variable and selected actor, converts the PostgREST OpenAPI catalog into table/RPC/relationship inventory, and can enumerate bucket metadata. Optional `enumeratePublicObjects` performs one bounded, non-paginating list request per catalog-marked public bucket and turns only returned public object paths into bounded file observations. An optional exact `catalogUrl` can enrich authoritative RLS, function, relationship, and storage metadata that PostgREST does not expose.

Set `acquisition.authorizationDiscovery.enabled` to opt into pre-plan authorization inventory acquisition. This requires `--auth-a` and `--auth-b` profiles with distinct declared `principalId` values. RouteCairn derives bounded same-origin `GET` collection routes and matching parameterized detail routes from supplied or acquired OpenAPI, supplements them with exact Postman/HAR reads and optional canonical `seedPaths`, resolves required path/query parameters only from schema examples, defaults, enums, or an explicit non-secret `requiredParameterValues` map, and requests each collection as both actors. It follows only exact same-path `Link: rel=next`, JSON next-URL, or cursor evidence, with allowlisted pagination keys and a hard page cap.

Returned objects become executable evidence only when their configured identifier is safe and their owner or tenant field exactly matches declared authentication-profile metadata. When both actors yield independently bound objects, acquisition freezes an object-pair matrix, authenticated collection membership cases, tenant relationships, and exact file references before scan planning. Cross-tenant collection cases default to denial, same-tenant cases remain non-assertive unless stronger ownership evidence exists, and file cases are compiled only from same-origin file-like fields on identity-bound objects. No response can add a case after execution begins. Knobs for route/page/object ceilings and candidate identifier, owner, tenant, file, and result-array fields make the importer adaptable without weakening these evidence gates.

```powershell
$env:SUPABASE_ANON_KEY = "<worker-only secret>"
routecairn scan https://app.example.com `
  --scope ./examples/scope.inventory-live.example.json `
  --auth ./examples/auth.example.json `
  --auth-a ./examples/auth.account-a.example.json `
  --auth-b ./examples/auth.account-b.example.json `
  --inventory-import ./examples/inventory-live.example.json `
  --output ./reports/live-inventory
```

Without authorization discovery, OpenAPI and Postman contribute exact same-origin parameter-free read routes. HAR contributes only successful credential-free reads; file-like entries become `OBSERVE_ONLY` bounded-prefix or headers-only file cases, and explicit next-link/cursor evidence can become a capped collection pagination contract. With authorization discovery enabled, authenticated OpenAPI collections, required parameters backed by schema evidence, returned object identities, tenant/owner relations, private file references, and bounded pagination are promoted into the fixed controlled engines described above. GraphQL introspection contributes a fixed introspection check and argument-free query-root operations; required-argument fields are skipped. Supabase catalog tables and exposed relationships contribute anonymous PostgREST `SELECT ... limit=1` observations, public buckets contribute exact bucket-metadata reads, and table, column, function, bucket, and relationship metadata is retained for reporting. Explicit catalog `storageObjects` from public buckets become exact bounded file observations; private/unlabelled objects and bucket keys are not inferred. Catalog functions remain inventory-only because invocation safety cannot be inferred from metadata.

Imports reject out-of-scope URLs, URL credentials, secret-like query names, imported auth/cookie/API-key material, unresolved variables, unsupported required parameters, oversized responses, redirects, and malformed structures. Postman variables with credential-like names are deliberately left unresolved, so those requests remain non-executable. Acquisition never guesses identifiers or synthesizes traversal payloads, filenames, bucket keys, pagination tokens, or route variants; it consumes only exact schema and response evidence. Traversal validation remains an explicitly approved active-validation case. `POST`, `PUT`, `PATCH`, `DELETE`, GraphQL mutations/subscriptions, Supabase writes, RPC calls, and other unverified operations are counted as withheld mutations and never compiled into executable cases. The fixed GraphQL introspection request and generated query-root reads still require `POST` in the operator's scope; allowing that method does not authorize mutations because the planner parses and rejects mutation/subscription documents.

### Signed Links, Portals, Invites, and Export Security

Batch 46 is a dedicated multi-step security engine for signed capabilities and protected artifacts. It covers signed-link expiry, signature tampering, identifier substitution, cross-tenant access, replay and revocation; invite identity binding, replay and expiration; portal tenant binding; PDF/report exports; evidence artifacts; and object-path ownership.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.example.json `
  --auth-a ./examples/auth.link-owner.example.json `
  --auth-b ./examples/auth.link-foreign.example.json `
  --link-portal-security ./examples/link-portal-security.example.json `
  --output ./reports/link-portal-security
```

The manifest defines explicit actors, safe resource aliases and path templates, exact allowed origins, and ordered `CONTROL`, `ACTION`, `VERIFY`, and optional `CLEANUP` steps. Request authentication and signed-value ownership are independent: for example, Account B can present Account A's controlled signed-link secret without copying that value into the manifest or report. Secrets use `{{SECRET:name}}`; issuance responses may be captured into case-local memory and consumed later with `{{CAPTURE:name}}`. Expanded and captured URLs are revalidated against both the resource's exact origin allowlist and the scan scope immediately before transmission.

`SIGNATURE_TAMPERING` performs a deterministic one-character query-signature modification in memory and requires an explicit tamper step. Identifier substitution and cross-actor cases use only operator-supplied references—there is no identifier guessing, route generation, enumeration, crawling, or response-driven case expansion. Assertions support authorization decisions, status boundaries, header presence, secret-backed JSON identity binding, exact SHA-256 artifact fingerprints, and ordered response-fingerprint comparisons.

Read-only cases use ordinary bounded traffic. Invite acceptance, one-time redemption, and revocation must declare every state-changing request and provide an exact, currently valid `CONTROLLED_LINK_FLOW` authorization. Mutating cases run sequentially under the global mutation lock, journal mutation intent before transmission, never retry, never follow redirects, and require verified cleanup or an explicitly disposable capability/resource. Unresolved cleanup blocks later state-changing cases.

Reports retain only resource aliases, safe path templates, status codes, size bands, structural fingerprints, artifact fingerprints, and assertion outcomes. Signed URLs, signature values, invitation tokens, recipient emails, object identifiers, tenant values, captures, credentials, request bodies, response bodies, authorization identities, and change tickets are excluded from request audit, JSON, Markdown, HTML, and embedded scan plans.

### Webhook, Cron, and Operational Endpoint Security

Batch 47 is a dedicated operational-endpoint engine. It validates webhook signature rejection, replay resistance, idempotency, event ordering, and authoritative amount/currency/product handling; cron authentication, replay, scope, and workload ceilings; job, incident, admin, and worker authorization; and health-endpoint information exposure.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.operational.example.json `
  --auth ./examples/auth.operational-service.example.json `
  --auth-a ./examples/auth.operational-owner.example.json `
  --auth-b ./examples/auth.operational-foreign.example.json `
  --operational-endpoints ./examples/operational-endpoints.example.json `
  --output ./reports/operational-endpoints
```

The manifest is an explicit endpoint inventory and test model, not a discovery or load-testing instruction. Each case binds fixed actors, endpoint aliases, exact origins and URLs, ordered steps, transient captures, and explicit assertions. RouteCairn never enumerates jobs, incidents, cron routes, admin routes, event identifiers, or payload variants. Replay and idempotency cases require two byte-equivalent declared attempts; ordering requires distinct declared events plus authoritative final state; payload integrity requires secret-backed amount, currency, and product assertions; and workload cases require a declared ceiling plus an authoritative numeric delta. Authorization cases require at least two actors, and Account A/B must have distinct principals and authentication material.

Webhook HMACs are generated automatically from the exact serialized request body in case-local worker memory. SHA-256 and SHA-512, hex/base64 encodings, prefixes, and timestamp-dot-body binding are supported. Valid and deliberately tampered signatures are emitted only on the wire. HMAC keys, generated signatures, timestamp values, request bodies, captures, response bodies, actor credentials, operator identities, and tickets are excluded from plans, journals, request audit, findings, and JSON/Markdown/HTML reports.

Every `POST`, `PUT`, `PATCH`, or `DELETE` is an explicit mutation and requires a currently valid `CONTROLLED_OPERATIONAL_FLOW` authorization with the exact confirmation literal, operator and ticket references, and cleanup or a disposable target. Production additionally requires `productionAcknowledged`. Mutations execute sequentially under the global mutation lock, are journaled before transmission, are never retried, and never follow redirects. Cleanup always runs after a possibly transmitted mutation; failed or uncertain cleanup blocks later mutations. This is automation under an operator-authored case and approval boundary—learned traffic or a mutation hypothesis alone never grants authority.

Reports preserve only safe endpoint aliases/path templates, status and content-type classes, size bands, structural/body fingerprints, assertion outcomes, comparison fingerprints, bounded request counts, and cleanup state. A finding requires a concrete contradicted assertion. Missing credentials, unavailable secrets, transport uncertainty, response limits, or expired approval stay blocked or inconclusive rather than being mislabeled as vulnerabilities.

### Checkout, Billing, Entitlement, and Premium Security

Batch 48 provides a dedicated synthetic billing engine for client-side price manipulation, product/plan substitution, entitlement activation without verified payment, entitlement persistence after cancellation, duplicate and replayed payment events, cross-account premium access, refund/downgrade inconsistencies, subscription ownership confusion, and bounded payment-event races.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.billing.example.json `
  --auth ./examples/auth.billing-service.example.json `
  --auth-a ./examples/auth.billing-owner.example.json `
  --auth-b ./examples/auth.billing-foreign.example.json `
  --billing-entitlement ./examples/billing-entitlement.example.json `
  --output ./reports/billing-entitlement
```

Real payment execution is structurally unavailable. The provider declaration accepts only explicit test, sandbox, local-emulator, or custom-synthetic modes and must set `realPaymentExecution` to `FORBIDDEN`. Every state-changing URL must remain on the exact owned application origin and beneath a dedicated path containing `test`, `fixture`, `sandbox`, `emulator`, or `synthetic`. RouteCairn never connects to a provider API, follows a checkout URL, confirms or captures a charge, submits a payment method, or accepts card/PAN/CVV, bank-account, payment-token, client-secret, cryptogram, or confirmation-token fields. Production is not an authorization environment for this engine.

Every synthetic mutation receives `X-RouteCairn-Synthetic-Billing` and `X-RouteCairn-Real-Payment: forbidden` at runtime. Operator-supplied values cannot override those headers. Synthetic webhooks can use SHA-256/SHA-512 exact-body HMACs with optional timestamp binding; signing keys stay in case-local memory; captured restoration state is retained only in encrypted recovery checkpoints until verified cleanup. Custom request-header values and endpoint URLs are fully erased from request audit.

Cases model explicit actors, endpoint kinds, operations, ordered pre-state/action/verification/cleanup steps, transient captures, and payment proof dimensions. Commercial terms and payment/subscription/event/account identifiers must use worker-only `{{SECRET:name}}` or temporally valid `{{CAPTURE:name}}` references. Account-bound cases require genuinely distinct Account A and Account B principals and authentication material. Each category must include its matching operation and authoritative proof: price, product/plan, verified-payment state, entitlement, subscription/refund state, ownership/access, or event-count effects.

Duplicate and replay cases permit exactly two to five declared sequential attempts. A payment-event race uses the dedicated ready barrier for two to five identical synthetic mutations and becomes a finding only when dispatch stays within the configured skew bound and authoritative event-count state contradicts the invariant. There is no repetition loop, adaptive amplification, provider traffic, or load-testing mode.

Every mutating case requires a currently valid `CONTROLLED_SYNTHETIC_BILLING` authorization, the exact confirmation literal, an operator reference, a change ticket, disposable fixtures, a fixture-reset mutation, an authoritative cleanup read, and a cleanup assertion. Mutation intents are durably journaled before transmission under the global mutation lock; requests are never retried or redirected. Cleanup runs after any possibly transmitted mutation, and unresolved cleanup blocks later billing mutations.

Reports retain provider test-mode classification, safe endpoint aliases/path templates, status counts, structural fingerprints, proof dimensions, synchronization measurements, comparison fingerprints, request budgets, and cleanup state. They exclude payment instruments, provider credentials, commercial values, event/subscription/account identifiers, authorization material, request and response bodies, raw captures, operator references, and change tickets.

### Secret Boundary and Sensitive Exposure

Batch 49 adds a first-class read-only secret-boundary engine that correlates HTML, JavaScript bundles, referenced source maps, runtime configuration, error and API responses, authenticated browser local/session storage, cookies, build metadata, debug endpoints, GraphQL responses, and public logs.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.secret-boundary.example.json `
  --profile quick `
  --secret-boundary `
  --output ./reports/secret-boundary
```

`--secret-boundary` selects the focused baseline, JavaScript, exposure-review, and secret-boundary pipeline shown above. The `full`, `authenticated`, and `proof` profiles include the engine automatically and do not require the flag.

The engine consumes already observed scan and browser traffic, then makes at most twelve additional same-origin `GET` probes and four exact referenced source-map requests by default. It never submits a form, follows a credential from a response, invokes a discovered operation, verifies a credential against a third party, or mutates application state. Probe paths are exact, bounded, query-free relative paths; discovered source maps still pass the ordinary scope and request-budget broker.

Classification uses both the field name and the value's format or claims while the value is held only in transient memory. Server credentials, database connection strings with embedded credentials, private keys, payment-provider secrets, user session/refresh material, one-time/recovery tokens, sensitive response fields, public logs, and script-accessible browser session storage receive distinct impact and boundary classifications. Reports retain safe field paths/names, lengths, types, surfaces, actor context, reason codes, impact, confidence, run-scoped correlation fingerprints, stable value-independent comparison fingerprints, and counts only.

A public client key is not a privileged service credential. RouteCairn explicitly classifies Supabase `sb_publishable_*` keys and legacy JWTs carrying `role: anon` as expected client material. Supabase `sb_secret_*`, JWTs carrying `role: service_role`, or service-role semantics hidden behind `NEXT_PUBLIC_*`, `VITE_*`, or other client-safe naming are server-only Critical exposures. The same semantic distinction applies to publishable payment keys versus secret keys. Generic API-key-looking values remain review observations unless naming, token format, claims, storage context, or demonstrated capability establishes impact.

Browser values never leave the isolated browser collector. Cookies, local storage, and session storage are classified before their raw values are discarded; only salted digests and semantic metadata enter the report. Secure HttpOnly session cookies are recorded as correct boundary storage rather than findings, while reusable session or recovery material in local storage, session storage, or non-HttpOnly cookies is classified as a client-storage risk.

Confirmed findings are deliberately narrower than observations: demonstrable server-only credentials, exposed session/one-time material, script-accessible session secrets, and high-sensitivity fields in public API/GraphQL responses. Build IDs, versions, commit identifiers, source-map availability, publishable client keys, and ordinary public runtime configuration remain informational or expected unless a stronger semantic conflict is present. JavaScript intelligence also redacts sensitive and publishable credential values before they can enter its own config summaries.

Secrets and dynamic target values use worker-only `{{SECRET:name}}` and temporally ordered `{{CAPTURE:name}}` references. Raw target state, request and response bodies, credentials, tokens, operator identities, and change tickets are absent from race evidence, findings, JSON summaries, Markdown, HTML, request audit, and the mutation journal.

### Native Active Vulnerability Validation

The active-validation engine executes bounded, class-aware differential cases for SQL/NoSQL injection, reflected XSS, SSRF, command/template injection, path traversal, CSRF, redirects, cache behavior, unsafe deserialization, XXE, and HTTP desynchronization. It accepts explicit immutable cases and can compile only same-origin `GET` query parameters already observed by parameter analysis; it never expands discovery into new paths, methods, origins, actors, or callbacks.

```powershell
routecairn scan https://app.example.com `
  --scope ./examples/scope.example.json `
  --active-vulnerability ./examples/active-vulnerability-validation.example.json `
  --output ./reports/active-vulnerability
```

Each case sends a bounded baseline, control, and generated probe. Findings require a class-specific proof signal such as a database error differential, offline browser execution, callback confirmation, a non-sensitive fixture marker/hash, an exact redirect/cache contract, or an ambiguous-framing sentinel observed over the dedicated raw HTTP/1 lane. Stateful and raw-protocol classes require the appropriate local/test/staging authorization. Payloads, original values, callback tokens, credentials, and response bodies stay transient; reports retain only redacted observations, hashes, statuses, proof signals, and immutable comparison fingerprints.

### Batch 50A–50B: Assisted Findings and Trust Review

All seventeen assisted security modules now pass through a shared finding-acceptance boundary before scan persistence. Each accepted finding has an explicit workflow/case identity, normalized severity/confidence, existing-factory evidence, a comparison fingerprint, and an independent cleanup outcome. Missing case links fail acceptance without discarding the module's cleanup results. Evidence omits raw bodies and replayable mutation commands. Proof-pack references start empty and resolve to actual retained dashboard packs, not placeholder IDs.

Supply an explicit review inventory alongside the existing engine manifests:

```powershell
routecairn scan https://your-disposable-app.example `
  --profile authenticated `
  --scope ./your-approved-scope.json `
  --auth ./your-disposable-auth.json `
  --authentication-lifecycle ./your-reviewed-lifecycle.json `
  --assisted-review ./examples/assisted-review.example.json `
  --output ./reports/assisted-review
```

Review the example case IDs and configure identity verification in your authentication profile. The review inventory is **not** testing authorization: engine manifests, budgets, scope, credentials, explicit mutation approvals, and synthetic-payment restrictions remain mandatory. Missing inventory cases become `NOT_ASSESSED`; they are never silently counted as a pass. Supported lanes are `BROWSER`, `API`, `AUTH_LIFECYCLE`, `AUTHORIZATION`, and `PAYMENT_ENTITLEMENT`.

The module runs after selected engines and generates a case coverage matrix, operator evidence package, review queue, case assessment sequence, remediation roadmap, and completion gate. The dashboard also retains the actual worker/module event timeline. `PROVEN` means the configured case has a supported conclusion, which may be either `FINDING` or `NO_FINDING`; it is not an overall security certification. `INCONCLUSIVE`, `NOT_ASSESSED`, and `BLOCKED` remain separate. Any unresolved cleanup in the scan blocks completion independently of finding decisions.

Scan Studio provides a dashboard-native assisted-review inventory and lane-selection builder; the API also accepts an inline `assistedReview` object. A legacy manifest path remains compatibility-only. Scan Detail shows coverage, blockers, current review state, evidence/proof/comparison IDs, and publication controls. The scanner's `assisted-review.customer.json` is a coverage-only draft and contains no unreviewed findings. After reviewing the exact finding occurrences in the Findings workspace, publish a customer report from Scan Detail. The server rechecks the completed scan, human decisions, evidence retention, and cleanup inside a transaction. Publications contain confirmed remediation and coverage, exclude operator evidence, and have content hashes and an audit event. An older scan's confirmation cannot approve a newly collected occurrence automatically.

Operator artifacts are `assisted-review.evidence.json`, the coverage-only draft, and the normal JSON/Markdown/HTML reports. Dashboard customer publications download by artifact UUID. Proof packs now include only evidence belonging to selected occurrences; they cannot pick up another scan's recent mutation case. Assisted regression comparisons require the same explicit case fingerprint, compatible scope/actors, a proven clean retest, and resolved cleanup.

### Batch 50C: Internal Pre-Handover Orchestration

The `pre-handover` profile requires `--pre-handover <manifest>` and a `--target-authorization <manifest>` with mode `PRE_HANDOVER_ASSAULT`. It cannot run against a declared production environment. Before any engine runs, configured read-only endpoints must verify the environment, distinct A/B identities, disposable-account markers, and each registered object's identity and ownership. Accounts must already be supplied; this profile does not silently create accounts. The local acceptance command below provisions its own disposable users automatically.

The manifest defines object, invariant and race registries, critical cases, release revision, module sequence and optional fix/regression references. Invariant/race references must resolve to configured engine cases. Ordering honors existing module dependencies and rejects cycles. Unresolved cleanup stops subsequent engines; the review still reports unexecuted cases. Critical cases require a proven clean conclusion. Regression claims additionally require the exact comparison fingerprint. Human acceptance cannot override incomplete critical coverage or failed cleanup. Scan Detail displays the sequence, critical coverage and regression readiness using the existing review/publication gate.

Start with `examples/pre-handover.example.json` and `examples/target-authorization.example.json`, replacing every placeholder. Object fingerprints are SHA-256 of the UTF-8 string `routecairn-disposable-v1` followed by a NUL byte and `JSON.stringify(identityValue)`. Supply the existing engine manifests and required actor profiles, including `--auth` if an engine uses the primary slot. Registries and learned traffic do not grant mutation permission; each engine's explicit contracts still apply.

### Batch 50D: Bug-Bounty Authorization

`--target-authorization` also accepts the separate modes `OWNED_PRODUCTION`, `INTERNAL_STAGING` and `BUG_BOUNTY_AUTHORIZED`. Bug-bounty mode requires a program/platform, authorization-proof reference/hash, scope-document hash, in/out-of-scope exact origins and path prefixes, rules, prohibited-action notes, a testing window and request/rate ceilings. Import these structured rules through the manifest file or inline dashboard API `targetAuthorization`; the operator must translate the actual program document into these machine-enforced fields. A document hash is a reference, not proof that RouteCairn has verified a program's consent. The example is deliberately expired.

Authentication, mutation, destruction and races are disabled by default. Non-read requests require an exact origin/path/method permission with an explicit effect. Read-only POST/GraphQL permission must additionally bind the exact body bytes by SHA-256, so query permission does not authorize mutations at the same endpoint. Destructive operations and races require their own flags, and mutations require disposable accounts. In/out-of-scope assets, expiry, permissions and the aggregate request/rate ledger apply across dedicated engine brokers, redirects, retries, browser traffic and worker recovery. HTTP waits for pacing; browser interception fails closed if its rate window is full. Streaming channels are blocked in bounty mode. Engines reserve sufficient remaining budget for their configured execution/cleanup bounds before starting; scope or authorization expiry is never bypassed for cleanup.

Free-text rules are operator context, not executable policy: encode prohibited paths in `outOfScope` and do not grant prohibited request effects. Standard customer publication still excludes operator evidence and requires occurrence-specific review. Bounty-authorized runs cannot silently rerun without fresh explicit authorization. Scan Studio's guided bug-bounty builder captures the first-class program contract and automatically selects the bug-bounty authorization category; a server-side authorization file remains a compatibility path.

### Batch 50E: Disposable Live-Target Acceptance

```powershell
npm run build
node dist/cli/index.js validate-local --output .routecairn-validation
```

This command accepts **no external target URL**. It creates a fresh loopback-only application and isolated dashboard database; provisions disposable A/B users; performs real login; stores fresh sessions in an encrypted vault; and runs authenticated Chromium and security engines through isolated workers. It exercises a deliberately vulnerable invariant, standard findings/evidence, a fixture-only simulated review and proof pack, a fixed-build rerun, comparison and handover readiness. It also exercises real protected access, browser protected-action/rollback proof, eventual consistency, injected cleanup failure, and fresh-credential recovery in a new worker. Learned mutation attempts must remain blocked. Artifact checks reject leaked login/session secrets.

Each run retains reports, the dashboard timeline/database, proof artifacts and `validation-summary.json` in a unique directory. Its vault key exists only in memory: credentials cannot be reused after the fixture closes. Simulated acceptance decisions apply only to this new fixture database, never to customer findings. Browser proof now uses authenticated DOM readiness (`readySelector`, or the configured principal selector), not global network idleness; an error/login document cannot prove a hidden protected control.

The acceptance run also consumes a single-use approval transactionally with scan creation, rejects reuse, verifies authenticated contract delivery to the worker, and exercises cleanup recovery through the dashboard service with a new vault credential. Dashboard mutation jobs share the durable cleanup journal and lock. Encrypted recovery bundles retain the exact approval/target/scope binding and any program authorization policy; recovery cannot silently drop that policy. Interrupted jobs retain a cleanup obligation, and explicit recovery retries cannot overlap. These checks use only the generated fixture, not a production service.

For the broader eight-lane contract, RouteCairn also ships a stateful acceptance laboratory:

```powershell
npm run build
node dist/cli/index.js validate-broader-local --output .routecairn-validation
```

The laboratory provisions two isolated tenants and executes positive and negative controls for tenant authorization, Supabase-compatible table/storage/RPC access, OIDC discovery and signed ID tokens with state/nonce/PKCE binding, TOTP and passkey lifecycles, GraphQL object authorization, signed portals and exports, synthetic checkout/webhook/refund flows, webhook and cron authentication, and an exact vulnerable-to-fixed remediation rerun. It enforces loopback-only transport, bounded requests and responses, one-use tokens and challenges, explicit cleanup, stable case identities, and secret-free request evidence. Each run emits a signed JSON summary, bounded request transcript and Markdown report; continuous assurance preserves these artifacts and fails unless every lane and cleanup check passes.

This laboratory proves the grid implementation against an owned disposable target. It does not claim third-party or production acceptance: completing that separate proof still requires an operator-supplied authorized product, approved scope, disposable identities and feature-specific fixtures through Live Acceptance.

External validation is recorded per product and per lane; it is never inferred from the local fixture. RouteCairn has completed its first authorized external acceptance against disposable accounts on the owned Decide production web/API target. That run covered public scanning, authenticated Account A/B API authorization, login and browser traffic learning, authentication lifecycle assertions, a reversible profile mutation, authoritative rollback, forced worker interruption, partial-evidence ingestion, dashboard restart, encrypted-checkpoint recovery with a fresh credential, and stable comparison evidence. Every disposable user and session was removed after its case. The run did not claim tenant isolation because Decide has no tenant model, and webhook/synthetic-billing validation remained `NOT_ASSESSED` because no test-provider fixture was available; no real payment was attempted. Retained evidence lives in the operator's dashboard data directory and is not a general security certification of Decide or another target.

Every additional live product still requires its own URL, explicit authorization and approved scope, never-test paths, disposable credentials and roles, identity endpoints, exact read/mutation/rollback contracts, and any protected endpoint. Dashboard plans must remain inside the registered target scope, and external results must preserve `NOT_ASSESSED`, `INCONCLUSIVE`, and `NOT_APPLICABLE` instead of turning missing fixtures into passes.

### Dashboard live-target acceptance

The **Live Acceptance** workspace turns those requirements into a reusable product workflow. It creates an AES-256-GCM encrypted, versioned plan bound to the registered target row, approved scope digest, authorization proof digest, validity window, hard never-test paths, actor credential references, exact lane contracts, and aggregate request/cleanup budget. Previewing does not send target traffic. Review binds the exact digest; editing the plan or registered target invalidates that review. Execution queues each scanner lane through the normal isolated-worker, immutable-plan, credential-readiness, evidence, finding, cleanup, recovery, and comparison paths.

Each lane is explicitly one of:

- an executable scanner lane;
- a linked existing scan from the same registered target;
- `NOT_APPLICABLE` with a durable reason and, when adaptive completeness requires it, a completed same-target evidence scan; or
- `NOT_ASSESSED` with a durable reason.

Controlled mutation and restart-recovery lanes cannot execute directly from the acceptance orchestrator. They must link a scan created by the separately reviewed controlled-mutation workspace, and recovery acceptance requires verified completion. Real payments and destructive administration are forbidden by the acceptance schema. Runs expose live child-scan state, findings, required coverage gaps, and unresolved cleanup in the dashboard, and can be cancelled through the normal cleanup-safe worker path.

Production mutation cases additionally bind an explicit intent: `SECURITY_NEGATIVE`, `AUTHORIZED_ACCEPTANCE`, `ROLLBACK_ACCEPTANCE`, or `RECOVERY_ACCEPTANCE`. Only a verified forbidden transition from a `SECURITY_NEGATIVE` case is eligible for a privilege-mutation finding. Expected authorized acceptance and restoration activity is reported as operational evidence, never as mass assignment merely because the mutation succeeded.

### Broader real-target proof grid

Live Target Acceptance exposes the `BROADER_REAL_TARGET_V1` standard as an immutable eight-lane grid: genuine multi-tenant authorization; Supabase table RLS, storage and RPC; OAuth/OIDC, MFA and passkeys; GraphQL authorization; signed links, portals and protected exports; synthetic payment-provider fixtures; webhooks and cron; and exact remediation reruns. The guided dashboard links completed same-target scans and persisted comparisons. The JSON editor can add stricter proof requirements without weakening the standard defaults.

A completed scan is not sufficient by itself. Each lane evaluates retained module executions and case-level semantic evidence. Required cases must have completed, transmitted their bounded request, retained strong evidence, and expose the exact feature required by that lane. Supabase coverage requires independent TABLE, STORAGE and RPC cases. Authentication coverage requires independent OAuth/OIDC, MFA and passkey lifecycle cases. Signed-capability coverage requires signed-link, portal-tenant and export/artifact cases. Operational coverage requires both webhook and cron cases. The multi-tenant lane requires an executed cross-tenant or tenant-isolation contract rather than an account-pair label.

Synthetic payment evidence additionally requires a durable binding to a reviewed provider-adapter version. Real payment execution remains forbidden. Cleanup and restoration are evaluated independently; an unresolved obligation makes the lane inconclusive. A remediation lane uses `LINK_REMEDIATION` to bind one exact baseline scan, one different rerun scan and one persisted comparison. The comparison must be complete and fully compatible, with no unmatched case coverage and no `NOT_RETESTED` or `INCOMPARABLE` finding evidence.

The proof contract is persisted on every run lane, so editing or replacing the encrypted plan cannot reinterpret historical acceptance. Run responses include completed modules, completed workflows, feature evidence, transmitted-case counts, provider binding, comparison identity and explicit missing-proof reasons. `NOT_ASSESSED` remains visible. Under the broader standard, `NOT_APPLICABLE` is also a required gap: the grid is complete only when all eight lanes are materially assessed. This records evidence quality; it does not turn a run into a general certification of the target.

### Measured effectiveness benchmark laboratory

RouteCairn includes two executable benchmark laboratories. The fast regression laboratory retains 30 broad capability cases. The public credibility corpus executes 240 cases against separate TypeScript/`node:http` and Python/`http.server` processes: 120 positives, 60 ordinary secure controls and 60 near-miss negative controls across object authorization, function authorization, SQL injection, open redirect, authentication differentials and second-order stored-state behavior. Every case is a deterministic mutant with recorded lineage, operator and generation. Forty cases are multi-step and another 40 are second-order. Results include recall, precision, false-positive rate, Youden's index, inconclusive rate, coverage completeness, conclusive coverage, cross-run stability, runtime, peak resident memory, user/system CPU, physical requests, transmitted requests, requests per assessed case, and runtime per request.

```powershell
npm run build
node dist/cli/index.js benchmark local `
  --repetitions 3 `
  --release 0.1.0 `
  --build $env:GITHUB_SHA `
  --output .routecairn-benchmarks

node dist/cli/index.js benchmark credibility `
  --repetitions 1 `
  --release 0.1.0 `
  --build $env:GITHUB_SHA `
  --output .routecairn-credibility
```

Every invocation creates a fresh directory and writes `benchmark-result.json`, `benchmark-report.md`, `benchmark-junit.xml`, the exact ground-truth manifest, per-run telemetry, and the underlying scanner reports. The built-in lab accepts no target URL, marks itself `INTENTIONALLY_VULNERABLE_LOOPBACK`, and fails with exit code 2 when a quality, category-balance, repetition, resource, required-case, or release-regression gate fails. State-changing probes run only against disposable fixture state and each cleanup contract is verified before the target is destroyed.

The 30-case laboratory covers 15 independently reported categories: REST object and function authorization, SQL injection, open redirect, SSE, GraphQL mutation, multipart upload, Supabase table RLS, storage and RPC, authentication lifecycle behavior, signed-link expiry, billing authorization, one-time-token race handling and cleanup, and authenticated browser/JavaScript secret-boundary behavior. The larger credibility corpus adds language, framework, CWE, complexity and control-type score slices. Corpus-composition gates enforce minimum positive, negative, near-miss, mutant, multi-step, second-order, language and framework counts, so shrinking or homogenizing the corpus fails rather than silently improving its score.

CI executes three complete fast-laboratory repetitions on every supported operating-system and Node.js combination against the committed `benchmarks/routecairn-comprehensive-detection-baseline.json`. A separate required Ubuntu job executes the 240-case multi-language corpus and retains a commit-addressed public scorecard and its raw scanner evidence for 90 days. A recall, false-positive, inconclusive, coverage, Youden, stability, case-level, runtime, memory, request-efficiency or corpus-composition regression fails its applicable job. Refresh a committed baseline only after reviewing a successful candidate result and intentionally accepting the changed detector contract or resource envelope.

The machine-readable public corpus is `benchmarks/routecairn-credibility-corpus-v1.json`; the first committed reference scorecard and its exact manifest/JUnit evidence are in `benchmarks/scorecards/1.0.0/reference-windows-node22/`. Regenerate the corpus deterministically with `routecairn benchmark corpus generate-public --output <file>`. An independent laboratory can maintain a separate manifest and publish it with an Ed25519 signature: `benchmark corpus sign` embeds the key identity and `benchmark corpus verify` rejects modified or incorrectly attributed corpora. For genuinely blinded evaluation, `benchmark corpus seal` removes expectations, selectors, tags and identifying labels from the public view, randomizes public case order by opaque ID and AES-256-GCM seals the complete truth; `benchmark evaluate --blind-pack <file> --blind-key-env <name> --corpus-public-key <file> --corpus-key-id <id>` reveals truth only inside the evaluator after scan reports already exist and verifies its publisher before scoring. The secret must be at least 32 bytes and is read only from the named environment variable. This provides the technical boundary for independent maintainers and blind holdouts without pretending that the bundled self-maintained corpus is independent.

For external intentionally vulnerable suites, declare exact expected findings and negative controls with `examples/benchmark.manifest.example.json`, then evaluate one or more repetitions:

```powershell
routecairn benchmark evaluate `
  --manifest ./benchmark.manifest.json `
  --reports ./run-1/report.json ./run-2/report.json ./run-3/report.json `
  --telemetry ./run-1/telemetry.json ./run-2/telemetry.json ./run-3/telemetry.json `
  --baseline ./previous-release/benchmark-result.json `
  --release 0.2.0 `
  --build abc123 `
  --output ./benchmarks/0.2.0
```

Ground truth selects stable workflow/case identities and may additionally constrain source modules or finding types. A positive case is a false negative when RouteCairn conclusively reports no finding; missing or blocked evidence stays uncovered or inconclusive and reduces strict recall rather than being counted as a pass. A negative control becomes a false positive when a finding is emitted. Findings in the declared workflow/module/type domain that match no expected case are counted as unexpected false positives. Required cases also receive individual gates, so aggregate thresholds cannot hide a critical miss.

Telemetry files contain `runtimeMs`, `peakRssBytes`, `requestCount`, optional `transmittedRequestCount`, and optional user/system CPU microseconds. When telemetry is omitted, duration and request counts are recovered from the report, while peak RSS remains unavailable as zero; supply telemetry whenever enforcing memory regressions. Baselines must have the same benchmark ID and exact manifest digest. Comparisons gate recall, false-positive and inconclusive increases, coverage and Youden drops, per-case regressions, and configurable runtime, memory, and request-growth ratios. Scorecards are evidence for their exact versioned corpus, runtime matrix and declared ground truth; they are not a general certification of targets, frameworks or vulnerability classes outside that corpus.

### Adaptive security model and test recommendations

The **Adaptive Security** workspace implements an evidence-bound loop: observe a completed registered-target scan, reduce it to a canonical secret-free model, compile sufficiently proven read-only observations into complete tests, retain underspecified or mutating discoveries as reviewable proposals, link a same-target execution, verify completion of the relevant engine, and learn from the next scan. Completed dashboard scans create candidate model snapshots automatically; historical completed/imported reports can be analyzed explicitly. An operator accepts the exact SHA-256-bound model as the expected baseline, and later snapshots expose route, origin, administrative path, API version, GraphQL contract, API-field, browser-field, cookie, actor/role, Supabase resource, lifecycle-category, build, and full workflow-contract drift.

Learned request values, response bodies, cookie values, tokens, credentials, raw identifiers, and sensitive query values are never stored in the adaptive tables. Paths and names are normalized, while security semantics use complete existing comparison fingerprints. A changed or removed assertion therefore becomes a changed contract instead of silently proving remediation. Removed-surface drift is emitted only when the newer scan contains equivalent producer coverage, avoiding false removals caused by a narrower scan profile.

Browser learning can recommend every authentication lifecycle category. Login enumeration, rotation, and fixation retain their deterministic compiler; logout, revocation, password-change, refresh/reset, verification, account-linking, OAuth/OIDC, MFA, passkey, recovery-code, invitation, expiry, and disabled-user cases require a single exact operator recipe bound to the learned candidate. A blocked browser mutation hypothesis may supply structure, but never authority: the compiled lifecycle case must independently pass current authorization, actor, assertion, scope, request-budget, and cleanup validation.

Adaptive compilation now has two evidence tiers. Exact credential-free observations can still be promoted without hand-writing a manifest: stable anonymous REST `GET`/`HEAD`/`OPTIONS` responses become status-bound API authorization regressions; observed GraphQL endpoints become generated introspection-classification cases; public JSON health endpoints become status and sensitive-field-absence cases; exact anonymous Supabase `SELECT` evidence becomes decision-bound RLS/PostgREST regression cases; and stable anonymous billing/entitlement and business-state reads become `OBSERVE_ONLY` billing or invariant stability cases. In addition, a completed engine case whose comparison fingerprint, conclusive outcome, and cleanup result match its resolved scan plan becomes an exact executed-contract replay. This second tier covers authenticated and object-specific REST/GraphQL authorization reads, signed links and exports, authenticated Supabase reads and signed-URL cases, operational workflows, synthetic billing changes, and business-state changes without asking the operator to re-enter actors, objects, assertions, request templates, fixtures, or cleanup steps. Plan-only fingerprints and identity hashes are removed from executable input, raw credentials are never copied, and current saved target credential fixtures are bound by authentication slot at materialization.

The dashboard labels non-mutating compiled cases `READY_READ_ONLY` and state-changing contracts `READY_APPROVAL_GATED`. Read-only contracts materialize directly into Scan Studio. State-changing contracts cannot materialize until an owner explicitly approves the exact recommendation; that approval produces a short-lived authorization window, and production additionally requires the target's production-mutation switch. Cleanup capacity is derived from the exact contract and reserved at launch. Source scan status, target row version, schema validity, engine configuration, authentication fixture identity, cleanup reserve, and the complete execution fingerprint are revalidated at preview and launch. Configuration edits, additional advanced engines, credential substitution, target drift, expired approval, unverified cleanup, inconclusive evidence, or fingerprint changes fail closed. Discoveries without a complete prior execution contract remain `REQUIRES_BINDINGS`; Supabase writes additionally remain on the controlled-mutation contract path. Approval never sends traffic by itself. Coverage policy is target-specific; required lanes remain incomplete when absent or inconclusive, and `NOT_APPLICABLE` is accepted only with completed same-target evidence when that policy is enabled. Open model drift after an acceptance run makes coverage stale until an exact new baseline is acknowledged or a remediation rerun returns to the expected model.

Authenticated replay uses the target's saved fixture settings, not credentials recovered from evidence. A `primary` contract uses `defaultCredentialProfileId`. An Account A/B contract uses the target's safe auth template in either Scan Studio form (`{"mode":"account-pair","accountA":{"source":"saved","credentialProfileId":"..."},"accountB":{"source":"saved","credentialProfileId":"..."}}`) or the compact `accountAProfileId` / `accountBProfileId` form. Missing, identical, disabled, unhealthy, or out-of-scope fixtures fail during materialization or credential readiness; RouteCairn never silently substitutes another identity.

### Reusable fixture and provider adapters

The **Fixture & Provider Adapters** workspace converts an exact advanced-engine configuration into a reusable, registered-target-bound product primitive. Adapters cover generic HTTP, Supabase, custom synthetic providers, and explicit Stripe, Adyen, Braintree, PayPal, and Paddle test/sandbox modes. Each adapter binds its engine capability, provider identity, environment, Account A/B or primary credential references, credential secret versions, fixture path prefixes, disposable-only guarantee, cleanup/evidence duty, aggregate request limits, and optional approved Adaptive Security recommendation.

Adapter content is AES-256-GCM encrypted. Edits create immutable revisions; only an exact digest-reviewed revision can become active. Review is invalidated by target row changes, credential replacement, an unavailable credential, schema changes, provider/configuration mismatch, an out-of-origin endpoint, or a request path outside the fixture prefixes. Mutating configurations must declare cleanup, require authoritative cleanup evidence, and reserve cleanup request capacity. Embedded URL credentials and real payment execution are rejected.

Materializing an active adapter opens Scan Studio with its reviewed engine JSON, actor mode, credential references, target scope, evidence level, budgets, and adapter binding already applied. It does not execute traffic or grant mutation authority. Preview and launch re-read the active encrypted revision and compare the entire execution contract—including target, scope, actors, modules, engine inputs, outputs, rate/concurrency limits, and cleanup reserve. Any edit, target drift, credential rotation, disabled adapter, or digest mismatch fails closed. Successful launches retain a durable scan-to-adapter-version binding; active scans prevent adapter disablement, while historical scans and 51C recommendation links remain visible as dependency impact. Offline dashboard master-key rotation re-encrypts every adapter revision together with credentials, retest templates, and live-acceptance plans.

### Budgets And Evidence

`ScanContext` owns one authoritative request ledger for the entire scan. Every ordinary and dedicated engine broker, direct request, retry attempt, redirect hop, synchronized group member, identity probe, and Playwright request that reaches the network consumes that ledger rather than a broker-local approximation. The same ledger paces dispatch and caps aggregate concurrency across independently created transports. Duplicate direct HTTP requests reuse cached responses without additional network traffic.

`maxRequests` is the total physical-transmission ceiling. `cleanupReservedRequests` is a slice of that total which ordinary traffic cannot consume; only cleanup, rollback verification, or explicit recovery transports can use it. The planner derives a cleanup minimum from selected workflow cases, reserves future browser-learned lifecycle cleanup, rejects insufficient or attack-empty splits, and exposes the exact resolved values in Scan Studio, plan previews, live dashboard budget events, JSON/Markdown/HTML reports, and the CLI (`--max-requests`, `--cleanup-reserved-requests`). Cleanup-only recovery workers receive a separate explicit all-cleanup budget. Budget exhaustion returns structural `RequestBudgetExceeded` evidence and never causes a request to exceed the configured lane.

### Pinned HTTP Transport

RouteCairn's shared HTTP transport connects to an IP address selected from the exact DNS answer set that RouteCairn validated. It verifies the connected socket destination before transmitting the request. The pinned transport is implemented as an Undici custom connector below `RequestSafetyBroker`, so direct scanner requests, redirects, retries, identity verification, object-pair, field-exposure, authorization-matrix, collection, bulk, equivalent-route, file metadata/content, and signed-URL follow requests inherit it automatically.

For each connection, RouteCairn canonicalizes the HTTP or HTTPS destination, rejects unsupported protocols and invalid hostnames, resolves all bounded DNS answers through an injectable resolver, normalizes duplicate IPs, validates every answer with the shared private-address classifier plus metadata/reserved-address checks, and fails closed on mixed public/private or prohibited answer sets. The selected address is deterministic. Exact private-origin exceptions are origin and port specific; the scan target origin is allowed so controlled local or private owned targets can be assessed, but a redirect or signed URL to another private host or port is blocked unless it is the exact approved origin and remains in scope.

The connector opens the socket directly to the selected IP, not the original hostname, which prevents an uncontrolled second DNS lookup by the HTTP library. HTTP keeps the original `Host` authority. HTTPS keeps SNI and certificate hostname verification on the original hostname with normal chain validation enabled. After connect or secure connect, RouteCairn compares the socket remote address to the selected IP, accounting for IPv4-mapped IPv6 equivalence. A mismatch destroys the socket and blocks the request before transmission.

Pinned HTTP now uses an IP-bound, origin-isolated connection pool. Every pool is constructed for one canonical scheme, hostname and port plus one validated selected IP. Its connector rejects any cross-origin dispatch, opens the socket directly to that IP, verifies the connected peer, and retains the original hostname for HTTP authority, TLS SNI and certificate verification. A DNS change to a different selected address rotates and gracefully drains the old pool. A prohibited, mixed-class, metadata, internal or otherwise invalid answer set blocks the request before an existing connection can be reused. This preserves retry and redirect rebinding checks while allowing verified connections to serve multiple requests.

HTTP/2 is opt-in and HTTPS-only. When enabled, ALPN may negotiate `h2` only inside the exact-origin pool; pools, connectors and TLS session caches are never shared across origins, so a certificate valid for multiple hosts cannot cause socket coalescing. Cleartext requests remain HTTP/1.1. Concurrent streams, connections per origin, retained origins, keep-alive timeouts, connection lifetime and requests per connection all have hard schema bounds. HTTP/1 pipelining remains disabled. Closing a scan gracefully drains all pools.

Configure the transport in `routecairn.config.json`:

```json
{
  "transport": {
    "poolingEnabled": true,
    "http2Enabled": false,
    "maxOrigins": 64,
    "maxConnectionsPerOrigin": 4,
    "maxConcurrentHttp2Streams": 32,
    "maxHeaderSizeBytes": 16384,
    "keepAliveTimeoutMs": 10000,
    "keepAliveMaxTimeoutMs": 30000,
    "maxConnectionLifetimeMs": 120000,
    "maxRequestsPerConnection": 1000,
    "dnsCacheTtlMs": 0
  }
}
```

`dnsCacheTtlMs: 0` re-resolves before every dispatch and is the default. A nonzero value, bounded to 60 seconds, caches only the already validated IP pin: it never follows a changed DNS answer without validating it, and a connection attempt continues to target the cached safe IP until the lease expires. `poolingEnabled: false` provides bounded single-use compatibility behavior. Reports expose pool hits/misses, created and estimated reused connections, HTTP/1.1 and HTTP/2 connections, DNS resolutions/cache hits/blocks, pin rotations and origin evictions without retaining host-to-IP mappings.

Implicit environment proxies are not used because RouteCairn supplies its own dispatcher. Future explicit proxy support would require equivalent destination enforcement. Transmitted requests still consume the global request budget. Cache keys do not include raw selected IPs, and file/signed URL no-cache policies remain unchanged.

Playwright uses a separate per-crawl authenticated loopback proxy because Chromium cannot use the direct Node Undici connector. That proxy applies the same all-answer destination classification and IP-literal socket pinning immediately before connection, verifies the connected address, preserves the original HTTP authority and TLS SNI, and publishes only redacted operational diagnostics. Browser traffic is therefore covered at both policy time and connection time.

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

Read APIs return safe summaries only and never return plaintext, ciphertext, nonces, or authentication tags. There is no "show secret" operation. The dashboard health check performs one bounded request to the exact configured identity endpoint under the selected target's approved scope, classifies healthy, near-expiry, expired, disabled, invalid, identity-mismatched, and unverified states, and retains only redacted structure, status, reason codes, and principal fingerprints.

Dashboard-created scans can reference enabled saved credential profiles by UUID for a primary authenticated context or an Account A/Account B pair. Scan rows, events, plan snapshots, and job leases store only safe profile references and aliases. Plan preview blocks credentials that cannot remain valid through the resolved maximum scan duration and warns about unverified/near-expiry profiles and Account A/B identity drift. Enqueue binds the reviewed credential generation; worker dispatch rechecks generation, health, target/project binding, and the full execution expiry window. Renewal or disablement while queued therefore fails closed before target traffic instead of silently changing identity or downgrading to anonymous access.

Routine renewal and replacement are dashboard-native. The operator first reviews a dependency snapshot covering target defaults, saved configurations, and active scans; state-changing requests carry its SHA-256 impact binding and reject stale reviews. Renewal rotates encrypted material, increments a non-secret credential generation, preserves unspecified encrypted login/identity settings by default, records a safe health event, and requires fresh identity verification. Disabled profiles, invalid credentials, expired credentials, and identity mismatches cannot be selected for new scans. Every lifecycle transition appears in the safe credential health timeline and the dashboard audit trail without raw identity or secret values.

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

Credential administration separates safe metadata edits from encrypted renewal/replacement. It provides explicit lifecycle badges, expiry countdowns, dependency impact review, target-bound identity testing, safe health history, Account A/B drift warnings, and scan-readiness gates. Secret material is never returned to the browser. Delete is dependency-aware, vault-key status is safe metadata only, and master-key rotation remains an intentional offline CLI operation.

The machine-readable parity manifest is exposed to authorized owners at `GET /api/admin/capability-parity` and enforced by dashboard tests. Intentional CLI-only entries require a reason, responsible owner, and safety justification; required administration workflows may not remain `PARTIAL`.

Implemented dashboard v1 capabilities include:

- a scanner-core capability registry consumed by the dashboard at `/api/capabilities`
- explicit capability parity statuses for profiles, modules, controlled workflows, server mode, vault, workers, and audit
- project creation, listing, and archiving
- target creation, listing, and archiving with authorization declarations
- scan creation and resolved plan preview through the real `ScanPlanner`
- a ten-step Scan Studio covering target/authorization, inline scope, profiles/modules, authentication, verified identity, browser/limits, evidence/outputs, integrated guided workflow builders, real plan review, and launch
- dashboard-native guided builders for Supabase/PostgREST/RLS/storage, explicit and browser-learned authentication lifecycle, business invariants/state machines, bounded race groups, API/GraphQL authorization, signed links/portals/invites/exports, operational endpoints, synthetic billing/entitlements, assisted review, pre-handover assault, and bug-bounty authorization
- browser-side bounded JSON import/export as an advanced alternative; authoritative server validation returns field paths and messages, while server filesystem paths are hidden in a compatibility-only section
- an integrated pre-handover contract that binds its orchestration plan and `PRE_HANDOVER_ASSAULT` target authorization together, and a guided production-mutation workspace that derives allowlisted mutation/rollback bodies instead of using raw JSON as the normal path
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
- durable worker rows, scan-job leases, resource-bearing heartbeats, cancellation across IPC, interrupted-job recovery for expired leases, and authenticated job-bound secret-envelope summaries
- cancellation-safe restoration with a separate 120-second cleanup budget, a 15-second report-flush margin, durable partial reports, dashboard artifact/finding ingestion for incomplete runs, and restart-time reconciliation

Capability parity is intentionally explicit. Profiles, modules, projects/targets, Scan Studio Core, audit, plan preview, reports, findings, review, proof packs, server-mode login/RBAC, encrypted credential-profile management and scan binding, isolated dashboard workers, safe import, all seven controlled authorization workflow editors, every advanced engine builder, and guided production mutation have implemented dashboard surfaces. Tests fail if a required advanced capability is marked full without both an API surface and a dashboard operation contract. Worker governance now has full dashboard parity through **Workers**, its authenticated operations API, durable diagnostics, and cross-platform containment tests.

Every job-scoped dashboard worker receives an immutable governance policy snapshot. The manager enforces resident-memory, cumulative CPU-time, wall-clock, report-output, temporary-disk, and heartbeat ceilings; Node also starts with a bounded V8 heap. Each worker uses a private temporary directory. Heartbeats retain only numeric resource totals, current module, cleanup state, and process IDs. A limit violation first requests cancellation so the engine can write partial evidence and complete its cancellation-safe cleanup window. Only after that bounded grace expires does RouteCairn terminate the entire worker process tree (`taskkill /T` on Windows or a detached process group on Linux/macOS).

The **Workers** dashboard page shows live heartbeats, resource use against limits, current scan/module, cleanup state, process-tree membership, structured failure category, and termination reason. Owners can gracefully restart a job-scoped worker, quarantine or release a worker record, stop new fleet dispatch, and release automatic crash-loop quarantine. Worker resource defaults are editable under **Settings** and apply only to subsequently launched workers. Unexpected exits are counted in a bounded window; reaching the configured threshold quarantines new dispatch until an owner explicitly releases it. All operator controls are permission-checked, CSRF-protected, and audited.

### Scan Studio Core

Scan Studio keeps non-secret configuration and ephemeral secrets in separate typed state. Ephemeral bearer values, headers, and cookies stay in live component memory; they are never written to browser storage, URLs, SQLite, audit/events, plan snapshots, or reports. On launch they move through the existing HMAC-bound job/worker/generation/attempt secret envelope. The ordinary worker initialization message contains a public-auth placeholder and safe references only. Secret references are cleared after successful launch, explicit reset, logout/session expiry, and component teardown where practical. JavaScript cannot guarantee physical memory erasure.

Inline scope is authoritatively parsed by the existing `scopeSchema` on preview and launch. The current core model supports allowed domain rules, denied paths, allowed safe methods, rate, concurrency, crawl depth, same-origin policy, subdomain policy, robots handling, and user agent. Browser-specific third-party/private-origin controls remain module settings resolved by the plan; Scan Studio does not invent duplicate scope semantics.

Dashboard launch resolves the complete executable plan exactly once at enqueue. Every referenced scope, configuration, authentication, lifecycle, invariant, race, API/GraphQL, link, operational, billing, assisted-review, pre-handover, and target-authorization file is byte-hashed before planning and checked again afterward. The resolved plan, configuration, scope, source bindings, target binding, and authentication binding are then canonicalized and stored as an AES-256-GCM snapshot associated with the scan and target; plaintext executable manifests are not stored in SQLite. The isolated worker receives that snapshot in a job-, worker-, generation-, expiry-, nonce-, and HMAC-bound envelope, recomputes its content and actor bindings, checks source files for post-review changes, and executes the snapshot directly. It never reparses normal scan manifests from the initialization request. Changed/deleted manifests, changed saved credentials, database ciphertext modification, target substitution, malformed snapshots, stale/replayed envelopes, and binding mismatches fail closed before scan traffic. Scan Detail exposes only the safe binding prefix, format version, and worker verification state, with `PLAN_BOUND` and `PLAN_VERIFIED` timeline events.

Identity tests use the configured GET/HEAD endpoint and safe field-path grammar. Wildcards, JSONPath/script syntax, recursive paths, and `__proto__`, `prototype`, or `constructor` traversal are rejected. Results contain bounded categories, comparisons, hashes/aliases, and redacted request audit only; raw identity JSON and raw principal values are not returned or persisted.

Evidence preferences may strengthen a profile policy, but cannot downgrade a profile that requires stronger evidence. RouteCairn currently emits JSON, Markdown, and HTML for every completed scan. The Plan Review page shows the effective planner policy rather than treating the UI preference as authoritative.

### Authorization Workflow Studio

The Controlled Workflows step provides shared guided configuration surfaces for Object Pair, Field Exposure, Role and State Matrix, Equivalent Route, Collection and Listing, Bulk, and File and Download authorization testing. The list and its supported actors, methods, expectations, limits, safety notes, module IDs, and schema versions come from `/api/capabilities` rather than a dashboard-only workflow catalog.

Each editor shares case creation, duplication, enable/disable, deletion, ordering, stable UI-only case identities, safe import/export, Advanced JSON, field diagnostics, module coupling, and planner preview controls. UI case identities survive edits and reorder but are stripped before planner serialization and safe export. Case references continue to use scanner case IDs; referenced cases cannot be deleted until their dependencies are resolved.

The guided surfaces are domain-specific: Object Pair presents the fixed owner-baseline and cross-owner relationship matrix; Field Exposure provides safe-path expectation rows; Role and State uses an explicit filterable matrix; Equivalent Routes uses exact route/reference controls; Collection explains completeness and provides known-object, case-reference, count, and summary builders; Bulk exposes fixed JSON bodies, all three safety modes, exact object baselines, and before/after GET state checks; File and Download exposes bounded proof modes, fingerprints, exact redirect origins, and separate signed-URL issuance/follow controls. Optional ordinary structures can be created and removed without first importing JSON. The capability registry carries a deliberate guided-field coverage manifest and an empty `advancedOnlyFields` list for each workflow so schema/UI drift fails tests.

Advanced JSON is capped at 256 KiB, rendered as inert text with a syntax-highlighted preview, rejects prototype-related keys, and passes through the same strict Zod schema and planner as guided configuration. A valid exported envelope can be re-imported without changing semantic fields. It remains an expert inspection/import surface rather than a requirement for ordinary scanner-supported structures.

Planner preview and enqueue parse every enabled workflow with its existing scanner-core schema and invoke its existing planner before `ScanPlanner.resolve`. Enqueue independently repeats parsing, actor checks, identity requirements, scope checks, module coupling, and planning, then seals the exact result into the immutable executable-plan snapshot described above. The worker verifies and executes that server-produced snapshot rather than rereading paths or accepting a client-submitted resolved plan.

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

Assisted lifecycle, invariant, race, API/GraphQL, link/portal, operational, billing, and Supabase runtime/catalog cases use the shared versioned security-contract fingerprint. Findings from these engines are rejected at the acceptance boundary when the contract fingerprint is absent or malformed. Proven-clean negative evidence is persisted with that exact fingerprint; comparison and pre-handover remediation gates classify a missing or changed contract as `INCOMPARABLE`/unproven rather than accepting a weaker test as a fix.

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

Proof packs include confirmed findings only by default. Ready proof packs are immutable snapshots; editing should create a later version. Every generated pack contains Markdown, restrictive-CSP HTML, and a scriptless text-only PDF 1.7 artifact. Target-controlled text is escaped or normalized, remote assets and fonts are excluded, and proof-pack downloads resolve by artifact UUID.

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

### Continuous Assurance and Evidence Governance (51E)

The dashboard's **Continuous Assurance** workspace turns reviewed fixture/provider adapters into immutable recurring policies. A policy binds the registered target revision, exact adapter version and digest, actor/credential semantics, authorization proof digest and validity window, per-adapter baseline scan, stable required case fingerprints, request and cleanup budgets, regression gates, schedule/deployment triggers, and evidence policy. Editing creates a new draft and pauses automation until an owner reviews the fresh digest. Every launch revalidates those bindings; target, adapter, credential, scope, authorization, cleanup, or executable-plan drift fails closed before target traffic.

Manual, scheduled, and deployment-triggered runs use the normal scan queue and isolated governed workers. Deployment hooks use a 256-bit one-time-shown bearer token whose verifier alone is stored, bind an idempotent deployment ID to a build fingerprint, and reject mismatched replay. Database leases prevent two dashboard installations sharing a database from launching the same policy concurrently. Authorization must remain valid through the sum of the plans' worst-case durations. Scheduling cannot supply mutation approval or broaden an adapter's approved target, paths, actors, capabilities, methods, concurrency, rate, request limit, or cleanup reserve.

Completion gates use persisted comparison engine version 3 plus exact workflow-case evidence. Regression, severity increase, configured new findings, open adaptive drift, failed lanes, unresolved cleanup, missing baselines, missing/changed fingerprints, untransmitted cases, unmet expectations, incomplete coverage, and incomparable evidence remain distinct. A missing or weakened test cannot establish remediation. Healthy runs create no notification; only regression, failure, cleanup, or required human approval enters the dashboard queue. A blocked scheduled launch is itself durably recorded without sending target traffic.

Evidence exports contain selected scan metadata and retained artifacts in an installation-bound AES-256-GCM envelope with a local HMAC-SHA256 integrity signature and per-file SHA-256 digest. Export creation has a bounded byte limit, download requires dashboard authorization, verification decrypts and checks the complete manifest, and offline master-key rotation re-encrypts exports. Retention purge requires a fresh canonical preview digest and never selects failed/interrupted/cancelled scans, unresolved cleanup evidence, or scans with unreviewed findings. Files outside dashboard report/proof/artifact roots are rejected.

`.github/workflows/continuous-assurance.yml` enforces core/dashboard builds and the full suite on Windows, Linux, and macOS with Node 20 and 22, plus Chromium/browser-connection tests, clean-package installation, a built-and-booted control-plane container, and explicit migration, worker-fault, and capability-parity gates. It contains no target credentials and does not run an external security assessment. Product deployment hooks should store the RouteCairn trigger token in their secret manager and POST only the policy UUID, a unique deployment identifier, and the deployed build SHA-256 to `/api/continuous-assurance/deployments`.

### Dependency Security and Release Provenance

The locked dependency graph is audited separately from runtime security claims. Vite, PostCSS, Nano ID, Vitest, and the Vitest mocker resolve to remediated versions, while `.github/workflows/dependency-security.yml` blocks moderate, high, and critical advisories on pull requests, pushes to `main`, weekly schedules, and manual runs. Pull requests also receive GitHub dependency review, and Dependabot proposes grouped npm toolchain/runtime updates plus pinned GitHub Actions updates.

Run the same audit and generate validated evidence locally:

```powershell
npm run security:dependencies
```

The command creates separate full-development and runtime-only CycloneDX JSON SBOMs, a manifest, and SHA-256 checksums under `.routecairn-security/`. Tag builds matching `v*` reproduce the lockfile with `npm ci`, build and test the release, package the exact npm tarball, and issue GitHub/Sigstore attestations for both SLSA build provenance and the runtime SBOM. The dependency audit is an advisory gate; it does not by itself establish whether an issue is remotely exploitable. See `SECURITY.md` for verification and reporting instructions.

`npm pack` and `npm publish` run the release build automatically. The package uses an explicit allowlist containing executable JavaScript, the module sandbox runner, built dashboard assets, guided-builder templates, security documentation, and the MIT license; repository sources, tests, workflows, declarations, and source maps are excluded. Dashboard assets resolve relative to the installed package rather than the caller's working directory. Run `npm run package:smoke` to create the tarball, validate its exact contents, install it into a clean consumer project, exercise the installed CLI, load every packaged advanced-engine template, and serve the packaged dashboard UI. Release CI performs this acceptance before attesting the exact retained tarball.

### Operational Scale and Collaboration

The **Operations & Collaboration** workspace adds organization-scoped resources and roles (`OWNER`, `ADMIN`, `ANALYST`, and `VIEWER`). Projects, targets, scans, findings, credential profiles, scan histories, finding evidence and review/remediation history carry a durable organization boundary. Migration creates the default organization, assigns every legacy row through its project/target/scan ancestry, namespaces existing finding identities, and installs database constraints that reject cross-organization parent references. New unscoped legacy writes are assigned automatically, while API reads and mutations resolve the selected organization and verify membership on the server. The dashboard organization switcher sends that context on every resource request. Organization owners and administrators can manage members, SSO, notification channels, signed workers and restricted modules; analysts can operate resources and create portable scan exports; viewers remain read-only. Final-owner protection remains enforced.

Server mode supports OIDC authorization-code login with PKCE, one-use hashed state, nonce verification, RS256/JWKS signature validation, exact issuer/audience/expiry validation, and normal RouteCairn session/CSRF issuance. Provider endpoints must use HTTPS and share the issuer hostname. Client secrets are referenced by environment-variable name and never stored in SQLite. A federated identity must already be linked or must present a verified email for an existing enabled user that satisfies the provider's optional domain allowlist; SSO does not silently create privileged users.

Signed remote workers use one-time enrollment tokens and per-worker Ed25519 identities. Every heartbeat, job claim, lease renewal, and result covers the HTTP method, exact path, timestamp, nonce, and canonical body digest; timestamps are bounded and nonces are persisted to reject replay. Jobs are organization- and capability-bound, the control plane automatically adds the capability implied by each job kind, payloads reject credential values, leases expire and requeue within an attempt budget, and workers can be drained, quarantined, or permanently revoked.

`routecairn agent enroll` now advertises native `ping`, `scan`, `module`, and `export` capabilities by default and atomically creates a mode-0600 local identity file. `routecairn agent run --state ./agent/state.json --workspace ./agent` executes all four job kinds without an external handler. Scan and module payloads bind a target, a worker-local scope file, bounded execution settings, optional worker-local credential/configuration/engine files, explicit built-in module IDs, and a workspace-contained output directory. Export jobs convert a worker-local report to JSON, Markdown, HTML, SARIF, JUnit, or Burp XML. Inputs, outputs, and the worker scan-history index cannot escape the workspace through absolute paths, traversal, resolved links, or linked output ancestors; job deadlines abort execution; lease-renewal failure aborts the job; returned results contain safe relative paths, counts, statuses, and hashes. The long-running worker uses bounded control-plane request timeouts and reconnects with bounded exponential backoff. An optional ESM handler remains available as an intentional override. The control plane never transmits target credentials: payloads contain only worker-local path references and non-secret controls.

Cloud synchronization supports two explicit peer modes. `FULL_STATE`, the default, merges organization-scoped projects, targets, scans, scan plans/modules/events, findings and history, credential profiles, saved configurations and versions, scan comparisons and coverage, proof packs and selected findings, generated artifact content, and membership intent into the destination's live dashboard tables. `SAFE_EVENTS` retains metadata-only event federation. State entities carry content digests, source timestamps, row versions and origin installation IDs; deterministic last-writer ordering makes replay idempotent and prevents an older replica from replacing newer state. UUID collisions with a different local tenant are quarantined as conflicts rather than reassigned.

Membership grants travel by stable source-user identity. A destination grants a role automatically only when its enabled local user has an already-verified SSO identity with the same issuer and subject; otherwise the grant remains pending for an authorized organization administrator to bind explicitly through the dashboard. Role changes and removals honor local edits and the final-owner safeguard. Dashboard sessions, local password hashes, audit provenance, provider client secrets, and host-specific worker settings are never merged. Saved configurations and proof packs are scoped to the selected organization in the API.

State uses signed, size-bounded pages with resumable peer cursors rather than a single 10,000-entity envelope. Generated file bytes are read only from dashboard-owned report, proof-pack, artifact, or integration directories, sealed for the peer, verified by content digest, and re-homed under the destination's artifact directory. Files larger than 8 MiB are split into independently authenticated 4 MiB chunks and published only after the full file has been reassembled and verified. The in-memory source snapshot is capped at 128 MiB of artifact content; an oversized or unsafe file blocks sync rather than being silently marked complete. Hard deletion of most resource rows is not propagated; use soft-delete operations. This is a portable live-state merge, not a byte-for-byte backup. Encrypted backup/restore remains the path for complete installation recovery, including host-local audit, sessions and operational settings.

Credential synchronization requires enabled vaults at both installations. Credential plaintext is decrypted only inside the source process, sealed with an AES-256-GCM key derived from the peer's environment-backed shared secret and bound to the destination organization and credential ID, authenticated by the signed batch, then decrypted and immediately re-encrypted with the destination installation's vault key. Plaintext credentials never enter the event log, replica table, database, response, or audit output. Soft deletion propagates without retaining a usable destination profile.

The background coordinator reconciles every active organization and pushes enabled peers on a bounded interval; manual **Synchronize now** remains available and concurrent cycles for one organization are coalesced. Batches retain the append-only safe-event stream, per-event and per-state SHA-256 digests, canonical HMAC-SHA256 authentication, idempotent event UUIDs and monotonic cursors. The pinned outbound client rejects redirects. Peer names and secrets must match, and an explicit remote-organization mapping supports independently generated UUIDs across installations. Status reports mode, state completion, last attempt, last success, cursors and a bounded safe error.

A production-oriented self-hosted deployment is provided in `deploy/control-plane`. Its Compose stack builds the release dashboard, keeps application state in a named volume, exposes only a Caddy TLS edge, waits for the authenticated control plane's database readiness, and supports one-time non-interactive owner bootstrap. Remove the bootstrap credentials after first startup. `/healthz` is a process liveness probe and `/readyz` checks database readiness; neither exposes installation metadata. The same server provides the browser workspace, organization APIs, signed-worker enrollment/lease/result endpoints, and signed peer synchronization.

External delivery uses a durable idempotent outbox with atomic multi-process claims, interrupted-delivery recovery, and bounded exponential retry. Webhook channels can use an HMAC signature; Slack uses an environment-backed webhook URL; email uses a configured HTTPS mail-provider endpoint and bearer token; GitHub and Jira use their HTTPS issue endpoints and bearer tokens. Stored rows contain only endpoint/configuration metadata and environment-variable references. Operators can queue a bounded safe notification payload through the dashboard API and inspect delivery state without exposing provider responses or secret values. Regression, failure, cleanup-required, and approval-required continuous-assurance notifications are bridged automatically to enabled default-organization channels, subject to each channel's minimum-severity setting.

Backup creation uses SQLite's consistent backup API. Bundles may be AES-256-GCM encrypted with the dashboard master key and contain an authenticated manifest, schema version, installation identity, and digest. Restore requires a fresh verification plus the exact confirmation phrase, is staged for the next restart, runs SQLite integrity validation before replacement, preserves the prior database as a timestamped pre-restore copy, and rolls back the file swap on failure. Backup key availability is fail-closed.

Portable integration artifacts are available as SARIF 2.1.0, JUnit XML, Burp-compatible XML, and bounded JSON. They are generated from normalized finding identities and safe endpoints, stored as ordinary governed artifacts, and downloaded through the existing artifact authorization and root-containment checks. GitHub and Jira issue creation is available through notification channels, preserving explicit operator enqueue and idempotency.

Third-party modules use a manifest-driven SDK with a two-step register/approve lifecycle. The host hashes the complete bounded package, rejects links and dependency directories, validates a safe JSON-schema subset for inputs, and quarantines a package whose bytes change after approval. Execution occurs in a separate Node permission sandbox with package-only read access, no network, no child-process permission, minimal environment inheritance, and bounded input, output, heap, and wall time. Results must pass a strict observation/finding schema before they return to the dashboard.

### Remaining v1 Limits

RouteCairn provides a self-hostable HTTPS control plane, native signed remote execution, server-enforced organization tenancy, and automatic signed multi-installation state synchronization; it does not operate a vendor-hosted SaaS service. Peer credential transfer is explicit, encrypted end to end between configured vaults, and re-keyed on receipt rather than persisted as raw material. Billing for a hosted service and WebSocket dashboard updates remain outside v1. Reviewed scheduling and deployment-triggered continuous assurance, external alert delivery, organization RBAC, signed agents, encrypted backup/restore, portable integration exports, PDF proof packs, OIDC login, and the restricted module SDK are implemented. Authenticated browser bootstrap remains available through encrypted credential profiles and the credential API schema; Scan Studio Core, visual scope building, structured ephemeral auth, saved/ephemeral actor mixing, identity testing, all seven controlled-authorization workflow execution paths, and planner/launch round-trip are implemented.

Dashboard guided builders are the primary operating surface for controlled authorization and advanced engines; bounded safe JSON import/export remains an alternative. Capability-parity tests require each declared dashboard capability to expose a guided builder or managed workspace. Versioned configurations, governed isolated workers, worker diagnostics and controls, credential lifecycle, browser connection isolation, controlled mutation/recovery, live acceptance, adaptive security intelligence, provider adapters, continuous assurance, and evidence governance are all dashboard-operated.
# Controlled Offensive Execution & Recovery

RouteCairn includes an initial controlled-mutation kernel for explicitly authorized, reversible `POST`, `PATCH`, and `PUT` security tests. Ordinary scans remain read-oriented: the broker blocks `PATCH` and `PUT` unless a dedicated controlled-mutation transport is enabled, always blocks `DELETE`, does not retry mutation requests, does not cache them, and refuses to follow state-changing redirects.

The kernel requires an expiring authorization, exact origin, disposable target, exact field/value allowlists, authoritative pre-state and impact checks, a rollback request, and independent restoration verification. It uses a global single-mutation lock, an fsync-backed redacted journal, HMAC body attestations, and an AES-256-GCM encrypted recovery bundle. Before any attack request enters the network transport, RouteCairn durably records `MUTATION_ARMED` with the recovery-bundle reference. A successful HTTP response alone never proves exploitation.

Cancellation stops attack and learning traffic but does not abort restoration. Controlled contracts and the authentication-lifecycle, business-invariant, race, signed-link/portal, operational-endpoint, and synthetic-billing engines run cleanup through a separate bounded signal. If cleanup or worker termination exceeds that bound, the encrypted checkpoint and unresolved journal entry survive, subsequent mutation remains blocked, and the dashboard's Offensive Safety panel provides the recovery action. Cancelled, failed, and interrupted scans ingest their safe partial evidence as normal dashboard artifacts/findings, remain explicitly incomplete, and cannot act as completed comparison baselines.

The example contract is deliberately expired and must be reviewed and updated by the authorizing operator:

```powershell
routecairn offensive run `
  --contract ./examples/controlled-mutation.example.json `
  --scope ./examples/controlled-mutation.scope.example.json `
  --journal-dir ./data/controlled-mutations `
  --approve disposable-user-role-boundary `
  --output ./reports/controlled-mutation-result.json
```

If a worker or process stops after a mutation was sent, the encrypted `*.recovery.enc` bundle remains. Recovery is an explicit local operation:

```powershell
routecairn offensive recover `
  --bundle ./data/controlled-mutations/<case-id>.recovery.enc `
  --case-id <case-id> `
  --target https://staging.example.com `
  --scope ./examples/controlled-mutation.scope.example.json `
  --journal-dir ./data/controlled-mutations `
  --output ./reports/controlled-mutation-recovery.json
```

The CLI defaults to the dashboard’s canonical `controlled-mutations` directory. When an operator supplies another `--journal-dir`, RouteCairn durably registers it with the dashboard, which aggregates all registered journals without returning their filesystem paths to the browser. The **Offensive Safety** view also discovers encrypted recovery bundles independently: a bundle without a trustworthy terminal journal state becomes `MUTATION_STATE_UNCERTAIN` and triggers the persistent **UNRESOLVED CLEANUP — TARGET STATE MAY STILL BE MODIFIED** alert. New controlled mutations remain blocked until every cleanup obligation is independently verified. Use the dashboard’s Production Mutation controls for controlled-contract execution/recovery and Offensive Safety for dedicated-workflow recovery; the CLI remains an alternative for controlled contracts. `CONTROLLED_DELETION` is available only for disposable non-production fixtures with reconstructive rollback and exact pre-state hash restoration; `LAB_DESTRUCTIVE` remains planned and unavailable.
