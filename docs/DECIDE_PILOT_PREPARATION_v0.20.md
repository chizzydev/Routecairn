# Decide local pilot preparation v0.20 — OFFLINE / HOLD

## Status and boundaries

Source reconnaissance only. No Decide requests, processes, account creation, runtime imports, database connections, migrations, seeds, environment edits or credential extraction are performed by this increment. No vulnerability has been established. Three genuine actor profiles have not been supplied. The native application assessment is BLOCKED, not successful.

Source checkpoints inspected: decide-api d872f1717afc6191e636526a25c187334ad92b46; decide-web ee29f6c74278a8ba3d15b77e3f72c81c6acee70e; dm 26ac3b33f325e13f2df7923823d20ee941b0eebf. Existing uncommitted changes (backend three paths, web one) form part of the inspected state; HEAD alone is not its complete identity. The review packet binds actual per-file hashes, exact membership and preserved configuration metadata without reading secret configuration contents.

## Architecture and startup inventory

| Project    | Actual stack / entry                                                           | Existing development command (inventory, NOT authorization to run)                                                                                                                                      |
| ---------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| decide-api | Express 5.2, TypeScript, pg/PostgreSQL; src/index.ts                           | npm run dev (nodemon --exec ts-node src/index.ts); build tsc; start node dist/index.js                                                                                                                  |
| decide-web | Next 16.1.6 App Router, React 18.3, NextAuth 4.24; src/app                     | npm run dev (next dev --webpack); npm run build; npm start                                                                                                                                              |
| dm         | Expo 55, React Native 0.83, React 19.2, expo-router/entry, SecureStore/Zustand | npm start (expo start); npm run web. Native android/ios commands and EAS builds are outside this pilot. Both app/ and src/app/ trees exist; do not infer the active tree from directory presence alone. |

Backend startup immediately listens and starts scheduled jobs. Importing src/config/db.ts initiates connection verification with retries and process exit on failure. Importing controllers/services is not an offline inspection technique. No backend services or Decide tests were imported/run here.

The web public client uses API_BASE_URL + /api/v1. In development its fallback is localhost:3001; production has a hosted backend fallback. NEXT_PUBLIC_API_URL must be pinned in a later isolated process. src/lib/backendAuth.ts obtains NextAuth session.backendAccessToken and attaches opaque Bearer authorization directly to the backend. src/lib/auth.ts posts credentials/Google/refresh to mobile-auth, keeps refresh material in the server JWT, and exposes short-lived access material in the session. Login and automatic refresh are mutations and excluded from the proposed observation scope.

The mobile client uses EXPO_PUBLIC_API_BASE_URL + /api/v1 and attaches access material from its store. Native storage is SecureStore, web-preview storage is localStorage. A 401 can cause a refresh POST and retry. RouteCairn must not inherit that implicit refresh behavior. EXPO_PUBLIC_WEB_APP_URL must also be overridden: the mobile web handoff defaults to the public website even in development. Google identity, email, billing, scraping, telemetry and external links must remain outside an eventual isolated pilot.

## Authentication and ownership

Backend mobile access tokens are custom signed opaque access values, not standard JWTs. RouteCairn already supports opaque Authorization headers; no token decoder, minting facility, session adoption or auth bypass is needed. Tokens bind a principal and session, carry expiry, and normal issued sessions have a session ID. requireMobileAuth validates the signature/expiry, active database session and database user, then uses the database role. requireAdminRole checks that authenticated database role. Web admin layout has a separate server-side requireAdmin guard; backend protection remains authoritative.

Actual role type: user | admin. No tenant identity exists in the inspected PublicUser contract. Do not substitute user.id or role as tenant evidence. Distinct principals and distinct roles are different requirements: two ordinary users plus an admin would be three principals in only two roles, if actually provisioned and approved.

Session middleware calls touchLastUsedById asynchronously. Its SQL updates session last_used_at/updated_at when absent or older than five minutes. Authenticated GET therefore does not mean non-mutating. A recent timestamp is not proof that a later request will remain read-only. Do not issue sid-less tokens, falsify claims, or suppress native checks to evade this restriction.

Saved phones, reviews and alerts use req.authUser.id and user-scoped queries. saved/me returns data[] containing saved-entry id, user_id and phone_id. Phone catalog IDs are shared public resources; saved-entry ownership is the boundary. A user reading their own /me collection should normally succeed. It is not a foreign-user denial merely because another actor receives 200 with different self-scoped content. No GET saved/:entryId or saved/user/:userId is exposed by the inspected saved router. Do not invent it.

## Backend route families and classification

All router families below are mounted at /api/v1; /health is a separate root handler. The packet includes 20 parsed route files and literal method/path/handler declarations, with line references and SHA-256. AST extraction is structural inventory, not automatic middleware-effect certification.

- Public catalog-oriented reads: phones and brands; public reviews GET /reviews; market/editorial contain public product context. Their arbitrary handlers have not all been certified non-mutating.
- Public computation/intake: recommend, analyze, compare and agent include POST operations; analytics, inbound and feedback are not approved observation paths.
- Account authentication: auth registration, email verification, login, reset and profile mutations; mobile-auth login/Google/refresh/logout plus authenticated me/sessions and session mutations. All auth mutations are excluded.
- Account-owned collections: saved/me, alerts/me, reviews/me, watchlist/me require mobile auth. Only saved/me is selected for this narrow proposal.
- Admin router globally applies requireMobileAuth and requireAdminRole. It contains extensive mutation, sync and repair paths; none is approved. admin/brands GET has a simple SELECT handler and is selected only as a future function-authorization boundary.
- Billing includes GET verification/return routes as well as POST checkout/webhook. GET billing paths must not be classified safe simply by method; all billing is excluded.

## Smallest meaningful proposed slice

This is a review proposal, not an accepted execution manifest. Proposed origin is exactly http://127.0.0.1:3001, subject to separate owner approval and verified listener ownership. No production host, localhost hostname alias, redirect, query expansion or alternate port is implicitly allowed.

| Exact GET              | Actors / source expectation                                                                | Present limitation                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| /health                | anonymous, expected 200 with status=ok                                                     | Can establish only handler reachability after approved isolated startup; no authorization finding           |
| /api/v1/mobile-auth/me | three genuine profiles: expected 200, data.id and data.role match; anonymous 401           | No profiles supplied; session metadata write; no data.tenant                                                |
| /api/v1/saved/me       | each legitimate actor: data[] entries must belong to its verified principal; anonymous 401 | Collection markers need first-class evidence support; no foreign-object GET exists                          |
| /api/v1/admin/brands   | genuine admin 200; ordinary users 403; anonymous 401                                       | Real admin profile absent; authenticated middleware write; this is function denial, not saved-object denial |

No numerical payload IDs, credential values, passwords or actors are invented. Empty saved collections cannot prove isolation; a separately authorized owner provisioning step must produce nonempty disjoint saved-entry ground truth. Shared phone IDs across accounts are valid, not leaks.

A standalone health-only approval could later permit exactly one anonymous GET /health, with no retries/redirects. It would not exercise guided mapping or establish security acceptance. Current guided mapping adds a baseline GET /: include that exact request in any later plan review or it must refuse. For a hypothetical three-route mapping of health/saved/admin-brands, the planned shape is one baseline + three identity verifications + twelve actor-route observations = sixteen request intents. Existing engine budgets may reserve additional attempts; the owner must review the actual immutable preview, not authorize this estimate. A separate me observation would add four. No executable plan is emitted while requirements remain unmet.

## Isolated accounts/data: what the source does and does not provide

No account or database was provisioned. Registration hashes a password, creates an email-verification token, inserts a user and sends verification mail. Credential login requires a verified email and creates a mobile refresh session. Google verification needs external identity infrastructure. Do not use those paths in this offline increment or import production sessions.

A fresh private PostgreSQL instance/database, owner-only role and minimized schema/data must be provisioned separately by the owner under a new exact authorization. The checked-in schema references users, but inspection did not locate a CREATE TABLE users definition in src/db/schema.sql or its checked-in migration set. Consequently a fully reproducible empty-database bootstrap is not established. Existing package scripts do not supply an approved disposable three-actor bootstrap. Admin creation/promotion requires independently reviewed setup, not a public self-registration role assumption.

The large catalog seed performs UPSERTs and deletes price/tag rows; --skip-prices is not a non-mutating mode and is not an isolated-account seed. Do not point it at any owner database. Real production dumps and production credentials are prohibited. A future owner-approved setup must provide complete schema including users, two ordinary principals and one admin, verified local account state, disjoint saved-entry data, fresh sessions and explicit expiry, with no production data or mail delivery. This task does not authorize any such writes.

## Local runtime isolation is not yet established

Environment variables are names only; no .env contents were read or copied. Never run npm run dev in the owner backend with inherited/default dotenv configuration. DATABASE_URL must point to a fresh isolated local database, PORT must be 3001, frontend/public URLs local; disable SENTRY_ENABLED, SCHEDULED_SCRAPING_ENABLED and MANUAL_SCRAPING_ENABLED, provide separately generated local signing material and local-only mail/identity/billing substitutes if ever authorized. Those flags alone are insufficient: alertChecker and dataSync are still scheduled unconditionally by src/jobs/index.ts. dataSync uses axios and database writes; alert checking can send emails and update state. app.listen has no loopback host argument. Outbound-denied process/container isolation and a reviewed background-job/bootstrap solution are prerequisites, not settings this increment silently applies.

Thus the current checked-in startup cannot be described as production-isolated by setting NODE_ENV=development. No runnable backend launcher is provided that pretends these missing controls exist. Exact conditional owner startup instructions are in the packet, with startup deliberately blocked until these prerequisites are separately resolved.

## Existing RouteCairn architecture and integration findings

1. Authorization: TargetRepository + ApplicationAuthorityBinding restrict owned LOCAL 127.0.0.1 target, organization, scope and saved credentials. Existing boundaries remain unchanged.
2. Onboarding: ApplicationOnboardingContracts/Service atomically save target and encrypted profiles. Three distinct principals, future expiry, tenant and role are required; no I/O occurs on declaration save. Opaque Bearer material is supported; custom Decide token format is not an integration defect.
3. Guided mapping: ApplicationMappingService/mappingContext require exact three credential IDs, verified principal/tenant/role contracts, scoped baseline/identity URLs and explicit GET seeds. A route tenant marker can be optional; an actor tenant contract currently cannot. This is a genuine tenantless-product gap across schema, mapping, readiness and native evidence, not a form-only optional-field fix.
4. Readiness: ApplicationAssessmentReadiness reads retained records and reports requestsSent=0 and no execution authority. Its metadata requirements must not be bypassed to stage this target.
5. Evidence/hypotheses: ObservedActorEvidence requires exact actor-route identity, response and source custody. Scalar observation paths do not express a collection ownership invariant such as every data[].user_id. Source observations cannot become native evidence.
6. Review/proof: ApplicationHypothesisService, AuthorizationWorkbenchService and bounded ScanExecutionService separate observation, policy approval and native proof. Unverified/incomplete facts remain UNKNOWN/ABSTAIN. No authority or execution bridge is activated here.
7. Handoff/comparison: ApplicationAnalystHandoff and immutable comparison preserve native evidence and exact actor/policy context. No Decide finding, remediation comparison or completed native handoff exists yet.

The narrow improvement adds a shared, strict, secret-free offline compatibility evaluator and an accessible panel inside existing onboarding. It explains tenantless, missing-profile, GET-side-effect, runtime-isolation and collection-marker blockers before credential entry. Unknown facts remain INCOMPLETE; even compatible declarations retain NONE authority and nativeVerified=false. It has no API, storage, network or target execution and does not weaken the existing server contract. The panel is advisory, not a new enforcement or authorization engine. It cannot verify source declarations or make tenantless execution work.

## Next substantial milestone

Implement explicitly modeled tenantless principal/role ownership throughout the existing guided-mapping/native-evidence/hypothesis chain, plus bounded collection membership evidence, with adversarial cross-user controls. Preserve genuine tenant-aware proofs and three distinct real profiles. Separately obtain owner-reviewed Decide local bootstrap/job isolation and any narrowly approved session housekeeping. Only then collect real native identity and ownership evidence under an exact approved localhost plan. Do not replace absent tenants with synthetic values or call fixture accuracy independent acceptance.

All prior capabilities and operational holds remain: Ubuntu paused; Trusted Discovery, Stage D, target mutations, external/unrestricted scanning and release HOLD. Prior 382 selected assertion passes, 35 Edge scenarios and ten unresolved 30-second combined-run timeouts remain historical evidence, not rerun or closed by this preparation.
