# Production web assessment v0.23

## Operator journey

Use the existing CLI after the normal owner-controlled installation/build. No installation, release build or packaging is required by this review packet.

1. Run `routecairn web-assessment prepare https://owned.example.test/ --reference "Owner-approved public assessment" --output campaign.json`. This writes a new draft only, refusing overwrite; it sends no requests.
2. Edit the campaign. Review exact origins, path/method pairs, expected HTTP statuses, prohibited path prefixes, approved static asset directories/extensions, effects, start/expiry, per-run request/rate/concurrency/byte/duration ceilings, retention and cancellation. A discovered origin is a candidate requiring this review. Reading JavaScript is not authority to execute its URLs. Exact requests and static prefixes must be inside reviewed scope, outside prohibited prefixes. Query strings, encoded/ambiguous paths, nonempty bodies and writes are refused.
3. Run `routecairn web-assessment review --campaign campaign.json`. Inspect the current parsed contract and digest. This sends nothing and grants no approval. Changing anything requires reviewing a new digest.
4. Explicitly approve that digest and run `routecairn web-assessment run --campaign campaign.json --approved-digest <reviewed-sha256> --output-parent <new-owned-run-parent>`. Ctrl+C cancels. The engine creates an exclusively owned retained run directory; it does not delete previous evidence. A digest is an exact local review binding, not an independent operator signature or an authentication credential. Programmatic callers have the same guard and may supply AbortSignal.
5. Inspect assessment.json: source-report SHA-256, exact HTTP controls, confirmed response observations, candidate origins/routes, blocked/untested cases, partial browser coverage and review-only findings. Native reports are private. Never publish their raw pages/assets/headers or session material merely because the projection is portable. A completed run means engine completion, not application security acceptance.

## Architecture and bounds

ProductionCampaign extends TargetAuthorization. Existing ScanPlanner, ScanContext, RequestSafetyBroker, request ledger, DNS-pinned transports, API/GraphQL native checks, JS discovery and Next.js review execute the campaign. Every final transmission still checks current authority. Limits: 300 requests maximum, 3 requests/second, concurrency 2, 30-second individual requests, 10-minute total duration, 1 MiB response; stricter campaign limits prevail. Retries and redirects consume the same run budget. Automatic live inventory import is refused for this adapter to avoid resetting acquisition budgets. Source maps, inferred Next data endpoints, unsafe cache variants and writes are disabled. JS extraction is bounded and incomplete evidence is identified.

Public multi-origin native checks are a narrow anonymous REST FUNCTION/OBSERVE exception for exact reviewed requests. Authenticated objects, GraphQL proofs, field rules, identity/tenant assertions, collection ownership and mutation semantics retain the original single-origin rules. A canonical redirect page's same-page assets are eligible for review but are downloaded only when both ordinary scope and exact campaign asset rules permit them. A source configuration URL or script literal is a hint, not proof of that backend's current deployed revision.

Production identity profiles are exact digest/principal/model/slot bound, newly provisioned within the campaign window, three distinct principals with required verification. Session-last-used updates must be explicitly approved. Public campaigns refuse supplied credentials. Authenticated browser bootstrap is not authorized by this adapter; authenticated native manifests must still satisfy original strict downstream admission. Credentials belong only in private profile files, never campaign examples/public evidence. Separate provision/login/logout/refresh/mutation/rollback contracts are required; a read-only campaign cannot create or clean up accounts.

## Browser limitation

Existing expiring-authority protection refuses opaque HTTPS CONNECT: the final encrypted browser request cannot be bound safely to exact scope/time/budget. The current production browser attempt therefore provides no rendered-page coverage. No tunnel bypass, insecure relay or relaxation is introduced. HTTP native browser paths remain guarded and regression-tested. Browser output now distinguishes zero-transmission UNTESTED from partial native observations; navigation attempts are not successful rendering. No authentication, browser-call, DOM, cookie, TLS/HTTP2-browser or complete route-discovery claim follows from public HTTP asset mining.

## Scope limits

No automatic completeness, independent accuracy, hidden endpoint enumeration or inferred business-policy proof. Human review remains necessary. Successful own /me is never evidence of foreign-user access. All tenant-aware, principal-role, native proof and bounded collection safeguards remain. Ubuntu, Trusted Discovery execution, Stage D, mutations, unrelated external scanning and full release remain HOLD. The owner-authorized bounded Decide public exception does not lift those holds generally.
