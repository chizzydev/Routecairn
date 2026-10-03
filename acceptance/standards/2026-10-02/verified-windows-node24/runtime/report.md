# RouteCairn Report

## Scan Metadata

- Target: http://127.0.0.1:54212/
- Program: Authorized Security Test
- Mode: quick
- Profile: Quick Recon (quick)
- Profile focus: surface map, technologies, API hints, manual testing leads
- Browser use: off
- Auth comparison depth: none
- Proof mode: no
- Started: 2026-10-02T20:53:54.311Z
- Completed: 2026-10-02T20:53:56.721Z
- Duration: 2410 ms
- Total requests: 10
- Scan request capacity: 80
- Cleanup capacity reserved: 0
- Ordinary / cleanup transmitted: 10 / 0
- Ordinary / cleanup remaining: 70 / 0
- Connection pooling: enabled
- Constrained HTTP/2: disabled
- Origin pool hits / misses: 9 / 1
- Connections created / estimated reuses: 1 / 9
- HTTP/1.1 / HTTP/2 connections: 1 / 0
- DNS resolutions / cache hits / blocked: 10 / 0 / 0
- Pin rotations / origin evictions: 0 / 0
- Technologies detected: 0

## Standards Coverage

- Executed cases: 6
- Directly mapped cases: 6
- Supporting-only / unmapped cases: 0 / 0
- Findings / no findings / inconclusive / blocked / observed: 1 / 1 / 0 / 0 / 4
- Catalogs: OWASP WSTG 4.2 (snapshot 2026-10-02); OWASP ASVS 5.0.0; OWASP API Security Top 10 2023; CWE 4.20; CAPEC 3.9.

### Catalog Denominators

| Framework | Active catalog | Mapped | Conclusive case evidence | Unassessed |
| --- | ---: | ---: | ---: | ---: |
| OWASP_WSTG | 97 | 4 | 1 | 96 |
| OWASP_ASVS | 345 | 2 | 1 | 344 |
| OWASP_API_TOP_10 | 10 | 1 | 0 | 10 |
| CWE | 944 | 2 | 1 | 943 |
| CAPEC | 558 | 1 | 1 | 557 |

Catalog SHA-256: 891e22e7757ece8d76f883e7960821f579b5c621e8bc01914f8a4a8fb717ec5c. Mapping scope: bounded case association.

### WSTG Area Accounting

| Area | Status | Executed | Conclusive | Mapped identifiers |
| --- | --- | ---: | ---: | --- |
| INFO — Information Gathering | PARTIAL | 4 | 0 | WSTG-v42-INFO-04, WSTG-v42-INFO-06 |
| CONF — Configuration and Deployment Management Testing | NOT_ASSESSED | 0 | 0 | none |
| IDNT — Identity Management Testing | NOT_ASSESSED | 0 | 0 | none |
| ATHN — Authentication Testing | NOT_ASSESSED | 0 | 0 | none |
| ATHZ — Authorization Testing | NOT_ASSESSED | 0 | 0 | none |
| SESS — Session Management Testing | NOT_ASSESSED | 0 | 0 | none |
| INPV — Input Validation Testing | PARTIAL | 3 | 2 | WSTG-v42-INPV-04, WSTG-v42-INPV-05 |
| ERRH — Testing for Error Handling | NOT_ASSESSED | 0 | 0 | none |
| CRYP — Testing for Weak Cryptography | NOT_ASSESSED | 0 | 0 | none |
| BUSL — Business Logic Testing | NOT_ASSESSED | 0 | 0 | none |
| CLNT — Client-side Testing | NOT_ASSESSED | 0 | 0 | none |
| APIT — API Testing | NOT_ASSESSED | 0 | 0 | none |

### API Security First-Class Objectives

| Objective | Status | Engines | Executed | Conclusive |
| --- | --- | --- | ---: | ---: |
| API4:2023 — Unrestricted Resource Consumption | NOT_ASSESSED | none | 0 | 0 |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | NOT_ASSESSED | none | 0 | 0 |
| API10:2023 — Unsafe Consumption of APIs | NOT_ASSESSED | none | 0 | 0 |

### Priority Coverage Gaps

- HIGH OWASP_WSTG/WSTG-v42-CRYP-01 — Transport cryptography: No retained executed case mapped directly to this coverage objective.
- MEDIUM OWASP_WSTG/WSTG-v42-ERRH-01 — Error handling: No retained executed case mapped directly to this coverage objective.
- HIGH OWASP_WSTG/WSTG-v42-CLNT-01 — DOM client-side injection: No retained executed case mapped directly to this coverage objective.
- HIGH OWASP_API_TOP_10/API4:2023 — Unrestricted Resource Consumption: No retained executed case mapped directly to this coverage objective.
- HIGH OWASP_API_TOP_10/API6:2023 — Sensitive Business Flow Abuse: No retained executed case mapped directly to this coverage objective.
- HIGH OWASP_API_TOP_10/API10:2023 — Unsafe Consumption of APIs: No retained executed case mapped directly to this coverage objective.

> Standards mappings describe retained evidence for this scan. They are not a certification of full standard conformance.

## Technologies Detected

No technologies detected.

## JavaScript Intelligence

No JavaScript intelligence was recorded.

## Browser Intelligence

No browser crawl was recorded.

## Baseline

- Probes: 3
- Wildcard status: 200
- Repeated title: none
- Repeated body hash: yes
- Non-existing paths repeatedly returned HTTP 200.
- Non-existing paths shared the same body hash.

## Path Discovery Summary

- URLs checked: 0
- Likely valid: 0
- Maybe false positive: 0
- Likely false positive: 0
- Cleanup-required mutation cases: 0

## Controlled Mutation Verification

Controlled mutation testing was not selected.

## Findings

| Title | Severity | Confidence | Risk | URL | Source |
| --- | --- | --- | ---: | --- | --- |
| sql injection: vulnerable SQL control | High | High | 75 | redacted://active-vulnerability/vulnerable | active-vulnerability-validation |

## Vulnerability Workflows

No vulnerability workflows generated.

## Proof Mode Evidence

No Proof Mode blocks generated. Run with --profile proof or another proof-enabled profile.

## Proof Details

### 1. sql injection: vulnerable SQL control

- Severity: High
- Confidence: High
- Risk: 75
- URL: redacted://active-vulnerability/vulnerable
- Status: 500
- Content length: unknown
- Evidence: assisted-workflow:active-vulnerability-validation:vulnerable
- Severity reason: High severity with High confidence assigned by RouteCairn rule evidence: active-vulnerability:vulnerable:DATABASE_ERROR_DIFFERENTIAL_CONFIRMED. Tags: active-validation, sql_injection, source:explicit, technique:error, workflow-case:vulnerable, human-review-required, assisted-finding-accepted.

```bash
curl -i "redacted://active-vulnerability/vulnerable"
```


## Manual Test Pack

No manual test pack templates generated.

## API Manual Testing Map

No API endpoints mapped.

## API Probe

No API probe reviews recorded.

## Auth Surface Map

No auth surfaces mapped.

## Authenticated Comparisons

No auth profile supplied. Run with --auth ./examples/auth.example.json to compare public and authenticated behavior.

## Identity Verification

No identity verification was configured.

## Role Comparison

No account A/account B profiles supplied. Run with --auth-a and --auth-b to compare roles.

## State-Aware API Testing

No state-aware API candidates were reviewed.

## Object Pair Testing

No object-pair testing was run.

## Field Exposure Testing

No field-exposure testing was run.

## Authorization Matrix Testing

No authorization matrix testing was run.

## Collection Authorization Testing

No collection authorization testing was run.

## Bulk Authorization Testing

No bulk authorization testing was run.

## File Authorization Testing

File authorization testing was not enabled.

## Equivalent Route Testing

No equivalent-route testing was run.

## Supabase Authorization

No explicit Supabase authorization manifest was supplied.

## Authentication Lifecycle

No explicit authentication lifecycle manifest was supplied.

## Business Invariant Validation

No explicit business-invariant manifest was supplied.

## Controlled Race Testing

No explicit controlled-race manifest was supplied.

## API and GraphQL Authorization

No explicit API/GraphQL review manifest was supplied.

## Protocol-Level Security

No explicit protocol-security manifest was supplied.

## Signed Links, Portals, Invites, and Exports

No explicit link/portal/export security manifest was supplied.

## Webhook, Cron, and Operational Endpoints

No explicit operational-endpoint security manifest was supplied.

## Checkout, Billing, Entitlement, and Premium Security

No explicit synthetic billing and entitlement manifest was supplied.

## Secret Boundary and Sensitive Exposure

The secret-boundary engine was not selected.

## Active Vulnerability Validation

- Cases: 2 (2 explicit, 0 discovery-compiled)
- Proven / secure / inconclusive / blocked / not assessed: 1 / 1 / 0 / 0 / 0
- Requests: 6 / 16

| Class | Planned | Proven | Secure | Inconclusive | Blocked | Not assessed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQL_INJECTION | 2 | 1 | 1 | 0 | 0 | 0 |

| Case | Class | Outcome | Reason | Strategies | Cleanup |
| --- | --- | --- | --- | ---: | --- |
| vulnerable | SQL_INJECTION | PROVEN | DATABASE_ERROR_DIFFERENTIAL_CONFIRMED | 1/1 | NOT_REQUIRED |
| secure | SQL_INJECTION | SECURE_FOR_CASE | SQL_CANARY_NO_DIFFERENTIAL | 1/1 | NOT_REQUIRED |

## Assisted Security Review

No assisted-review manifest was supplied.

## Parameter Analysis

No parameters were identified.

## Next.js Review

Next.js was not detected or no Next.js review was run.

## Interesting Results

No results.

## All Discovered URLs

No results.
