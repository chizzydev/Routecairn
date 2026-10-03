# Decide evidence retained on 2026-09-30

The owner authorized reusing the existing Decide acceptance evidence in this chat. The source was `data/dashboard-decide-acceptance/`, with API/web/mobile checkouts at `C:/Users/HP/decide-api`, `C:/Users/HP/decide-web` and `C:/Users/HP/dm`.

The projection retains six historical scanner report digests, execution and finding summaries, and four final rollback-verification journal records. It also records two new authorized public checks: HEAD `https://www.decide.com.ng/` and GET the API's documented `/health` endpoint. Both returned 200. No authenticated request, account creation, mutation, webhook submission or payment was performed by these new checks.

`owned-decide-evidence.json` and `owned-decide-report.md` are portable, secret-free projections. `SHA256SUMS` authenticates the projection bytes against accidental alteration; it is not an independent operator signature. The raw source reports remain in the owner's private dashboard directory for comparison with the retained digests.

The historical refresh-token finding remains a finding. The interrupted worker report remains partial, while the later recovery journal independently records its rollback. Historical webhook/billing and post-remediation coverage remains `NOT_ASSESSED`. The original disposable accounts and credentials were removed.

This evidence is **PARTIAL_EXTERNAL_EVIDENCE**. It does not satisfy the full eight-lane grid, establish independent operation, identify a deployed application commit, or validate the current RouteCairn release artifact. See `docs/EXTERNAL_ACCEPTANCE.md` for the remaining real exercise requirements.

## Fresh account exercise

Following the owner's explicit request to create new accounts, two fresh disposable accounts were provisioned administratively through the existing Supabase-hosted Decide database with certificate and hostname verification. They were exercised against the deployed API using 20 bounded requests. Eighteen cases passed; refresh-token replacement and consumed-token replay denial failed. Both accounts and their sessions were removed, and their absence verified. No password or bearer/refresh credential appears in the retained projection.

`fresh-owned-exercise.json` and `fresh-owned-exercise.md` retain the actual production outcome. The refresh finding remains unresolved in the deployed service; a source fix and local tests must not be relabeled as external remediation evidence. This new run does not assess email delivery/ownership verification, provider-admin access, GraphQL, Auth0/Cognito, payment-provider sandbox or independent operation.

`local-source-database-check.json` separately records six passing checks of the compiled local atomic refresh query against the actual verified-TLS database, including concurrent consumers, consumed/replacement hashes, expired sessions and revoked sessions. Both accounts created for those checks were removed. Twelve focused authentication tests and the backend build also passed. This is local-source verification, not a deployed fixed rerun. The subsequent authenticated hosted Supabase provider exercise is retained separately under `acceptance/supabase/2026-09-30`.
