# Fresh Decide owned-account exercise

Date: 2026-09-30.

Status: **FAILED**. Cleanup: **VERIFIED**.

Two new disposable accounts were provisioned administratively in the existing Decide database and used against the deployed Decide API. Passwords and bearer/refresh credentials were never retained in this projection.

Requests: 20. Passed cases: 18. Failed cases: 2.

- ACCOUNT_A_LOGIN: PASSED (HTTP 200). New disposable account authenticates with its generated password and exact user identity.
- ACCOUNT_B_LOGIN: PASSED (HTTP 200). New disposable account authenticates with its generated password and exact user identity.
- UNAUTHENTICATED_ME_DENIED: PASSED (HTTP 401). Missing bearer token is denied.
- ACCOUNT_A_IDENTITY: PASSED (HTTP 200). Bearer token returns only its own generated account identity.
- ACCOUNT_B_IDENTITY: PASSED (HTTP 200). Bearer token returns only its own generated account identity.
- ACCOUNT_B_SESSION_LIST: PASSED (HTTP 200). Own session list supplies a disposable session to test.
- FOREIGN_SESSION_REVOCATION_DENIED: PASSED (HTTP 404). Account A cannot revoke account B's exact session.
- FOREIGN_SESSION_UNCHANGED: PASSED (HTTP 200). Account B remains authenticated after the foreign revocation attempt.
- PROFILE_IDENTITY_BOUND_TO_BEARER: PASSED (HTTP 200). Body-supplied account B ID cannot redirect account A's profile update.
- FOREIGN_PROFILE_UNCHANGED: PASSED (HTTP 200). Account B's display name remains at the provisioned baseline.
- PROFILE_RESTORE: PASSED (HTTP 200). Own disposable profile returns to baseline.
- REFRESH_TOKEN_ROTATES: FAILED (HTTP 200). Successful refresh replaces the old refresh credential.
- OLD_REFRESH_REPLAY_DENIED: FAILED (HTTP 200). The consumed refresh credential is denied on replay.
- LOGOUT: PASSED (HTTP 200). Logout revokes the disposable session.
- LOGGED_OUT_ACCESS_DENIED: PASSED (HTTP 401). Access token from a logged-out session is denied.
- ACCOUNT_A_CLEANUP_LOGIN: PASSED (HTTP 200). New disposable account authenticates with its generated password and exact user identity.
- ACCOUNT_A_DELETE: PASSED (HTTP 200). Delete only this run's disposable account using its own bearer and password.
- DELETED_ACCOUNT_A_ACCESS_DENIED: PASSED (HTTP 401). Deleted account bearer no longer authenticates.
- ACCOUNT_B_DELETE: PASSED (HTTP 200). Delete only this run's disposable account using its own bearer and password.
- DELETED_ACCOUNT_B_ACCESS_DENIED: PASSED (HTTP 401). Deleted account bearer no longer authenticates.

## Unresolved findings

The deployed refresh endpoint returned the original refresh token and accepted its replay. This is a failing lifecycle contract. A local Decide backend correction now atomically replaces the credential hash; 12 focused authentication tests and the backend build pass. Six additional checks exercised the compiled local query against the real verified-TLS database, including concurrent rotation, replay, expired and revoked sessions. Both database-check accounts were removed. The source correction has not been deployed and must not be reported as a deployed fixed rerun.

## Limits

- Owned accounts were provisioned administratively; email delivery and email ownership verification were not exercised.
- These cases assess account ownership and the custom Decide session lifecycle; they do not establish a tenant model or Auth0/Cognito MFA/passkey acceptance.
- Supabase database hosting does not by itself prove Data API RLS, storage or RPC behavior.
- This owner-operated run cannot supply an independent operator's execution or signature.
