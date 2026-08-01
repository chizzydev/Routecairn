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

### Budgets And Evidence

The request broker enforces the resolved plan globally across shared module clients. Direct requests, retry attempts, redirect hops, and Playwright requests that reach the network consume the same request budget. Duplicate direct HTTP requests reuse cached responses without additional network traffic.

Blocked browser requests follow separate accounting: a request intercepted and blocked before network transmission consumes a browser policy-event counter, not the network request budget. A request that reaches the network consumes the network budget. Redirect hops and retry attempts that reach the network each consume budget. Reports expose policy-event and transmitted-request counts so blocked third-party resources cannot exhaust the network request budget while still being bounded by a browser attempt ceiling.

Cached HTTP responses are in-memory for the scan lifetime only. Cache partitioning uses method, normalized URL, header names, and SHA-256 fingerprints of header values, so anonymous, authenticated, Account A, Account B, tenant, organization, and other authorization-context requests do not share responses. Raw cookies, tokens, authorization headers, and tenant identifiers are not stored in persisted cache diagnostics or reports.

Evidence policy changes serialized output. Minimal profiles strip body previews from `responses`, `discoveredUrls`, finding evidence, and browser network-request evidence in reports. Normal and strong profiles retain redacted previews and browser network metadata within configured limits. Strong evidence profiles enable proof-block retention and stricter reproducibility metadata.

Temporary response previews may exist in memory while modules analyze a scan, but serialized reports redact retained previews and sensitive headers before writing artifacts. Minimal evidence reports omit body previews entirely and retain only status, length, hash, redacted metadata, and detection indicators needed by the implementation.

### Adding Profiles Or Modules

Profiles live in `src/core/planning/ProfileDefinitions.ts`. A profile declares enabled/disabled modules, module settings, global and per-module limits, auth requirements, evidence policy, output expectations, failure policy, and report focus. Add new profiles there, then cover the planner behavior with tests.

Scanner module compatibility lives in `src/core/planning/ModuleCatalog.ts`. To add a module, implement the `RouteCairnPlugin` interface, register it in `createDefaultPluginRegistry()`, and add catalog metadata: stable id, phase, capabilities, auth requirement, monitoring compatibility, evidence support, dependencies, ordering constraints, cost, readiness, default settings, and supported overrides. The planner rejects unknown modules, duplicate modules, missing dependencies, invalid ordering, invalid limits, unsupported overrides, and evidence/monitoring incompatibilities before execution.

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
