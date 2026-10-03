# Hosted Supabase exercise on 2026-09-30

The owner explicitly authorized creation and completion of acceptance environments, then supplied the signed-in Supabase session. Existing project credentials were consumed privately. No new privileged project keys were created.

## Actual hosted result

`hosted-exercise.json` records the actual hosted Decide Supabase project, two newly provisioned Auth identities and 27 bounded HTTP requests. Twenty-six receipts passed. One readiness observation records a transient PostgREST schema-cache propagation response; it remains `PENDING` and is not an ownership test. The subsequent readiness response and all ownership/denial checks passed. Cleanup is `VERIFIED`, with zero remaining accounts, buckets, objects, policy, table or RPC.

The run exercised:

- Auth administrator provisioning without email delivery and real password login.
- RLS owner access, foreign/anonymous denial and an unchanged owner row after a foreign update attempt.
- Security-invoker RPC owner access and foreign/anonymous denial.
- Private Storage upload/download, foreign/anonymous/public-path denial, foreign overwrite denial and unchanged owner content.
- Synchronous provider object/bucket deletion, scoped database teardown, Auth account deletion and database absence verification.

## Initial run and recovery

`initial-hosted-exercise.json` retains the first failed run unchanged. It encountered an initial schema-cache miss and a bucket deletion race after asynchronous emptying. Both identities and the database resources were removed, but its original receipt correctly retained one bucket awaiting cleanup. A subsequent authorized recovery removed the bucket and verified zero remaining resources. `initial-run-recovery.json` is the separately retained idempotent recovery verification; it does not retroactively turn the failed run into a passing run.

## Evidence boundary

This is **owner-operated, owner-created fixture evidence on an actual hosted provider**. It demonstrates a working hosted Supabase RLS/Storage/RPC exercise. It does not prove existing Decide application policies, independent corpus maintenance, an independent operator signature, or the full eight-lane acceptance grid. No secret key, password, bearer token, generated account email or raw account ID is retained here. `SHA256SUMS` detects byte changes; it is not a signature. `owner-authorization.json` records the real chat authorization and the bounded execution contract.

Both Supabase runs used two fresh identities each, and all four were removed. The separate Decide API and local-source database exercises are retained under `acceptance/decide/2026-09-30`.
