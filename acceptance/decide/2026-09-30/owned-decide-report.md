# Decide owned-target evidence

Status: **PARTIAL_EXTERNAL_EVIDENCE**

Historical summary: 2026-09-07T00:18:00+01:00

- publicWeb: COMPLETED; partial: no; report cleanup: CLEAR; HISTORICAL_EXECUTION_RETAINED. Historical declaration: ASSESSED. Source report retained by digest.
- apiAuthorization: COMPLETED; partial: no; report cleanup: CLEAR; HISTORICAL_EXECUTION_RETAINED. Historical declaration: ASSESSED. Source report retained by digest.
- authenticationLifecycle: COMPLETED; partial: no; report cleanup: CLEAR; HISTORICAL_EXECUTION_RETAINED. Historical declaration: ASSESSED_WITH_FINDING. Source report retained by digest.
- authenticatedBrowser: COMPLETED; partial: no; report cleanup: CLEAR; HISTORICAL_EXECUTION_RETAINED. Historical declaration: ASSESSED. Source report retained by digest.
- controlledMutationAndRollback: COMPLETED; partial: no; report cleanup: CLEAR; HISTORICAL_EXECUTION_RETAINED. Historical declaration: ACCEPTANCE_PATH_VERIFIED. Source report retained by digest.
- externalRestartRecovery: INTERRUPTED; partial: yes; report cleanup: REQUIRED; REVIEW_REQUIRED. Historical declaration: ASSESSED. Source report retained by digest.
- webhookAndSyntheticBilling: NOT_ASSESSED; source report unavailable or not supplied.
- postRemediationRerun: NOT_ASSESSED; source report unavailable or not supplied.

## Public availability

- web: HEAD, HTTP 200, checked 2026-09-30T19:49:23.165Z.
- api: GET, HTTP 200, checked 2026-09-30T19:49:24.399Z.

These checks establish endpoint availability only.

## Limits

- Historical owned-target reports are unsigned; their integrity hashes are newly retained, not historical attestations.
- The interrupted recovery report remains partial. The later journal and historical cleanup declaration are separate evidence.
- No tenant model was assessed. Supabase, GraphQL, Auth0/Cognito, signed portals and independent operator evidence are not supplied by these reports.
- Historical webhook/billing and post-remediation assessments were NOT_ASSESSED.
- Public endpoint availability is read-only and cannot establish authenticated authorization, provider or remediation acceptance.
- Historical disposable accounts and credentials were removed; fresh approved credentials are required for authenticated reruns.
