# RouteCairn multi-language detection credibility corpus

Status: **PASSED**<br>
Release: 0.1.0<br>
Repetitions: 1

## Detection quality

| Metric | Value |
|---|---:|
| Recall | 100.00% |
| Precision | 100.00% |
| False-positive rate | 0.00% |
| Youden's index | 1.0000 |
| Inconclusive rate | 0.00% |
| Coverage completeness | 100.00% |
| Conclusive coverage | 100.00% |
| Stability | 100.00% |
| Cleanup success | 100.00% (80/80) |
| Cleanup failures | 0 |

## Corpus composition

| Cases | Positive | Negative | Near-miss | Multi-step | Second-order | Mutants | Languages | Frameworks | Blinded |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 240 | 120 | 120 | 60 | 40 | 40 | 240 | 2 | 2 | 0 |

## Category coverage

| Category | Cases | Positive | Negative | Recall | False-positive rate | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| AUTHENTICATION_LIFECYCLE | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |
| FUNCTION_AUTHORIZATION | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |
| OBJECT_AUTHORIZATION | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |
| OPEN_REDIRECT | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |
| SECOND_ORDER_STATE | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |
| SQL_INJECTION | 40 | 20 | 20 | 100.00% | 0.00% | 100.00% |

## Stratified scorecard

| Dimension | Value | Cases | Recall | False-positive rate | Youden |
|---|---|---:|---:|---:|---:|
| language | Python | 120 | 100.00% | 0.00% | 1.0000 |
| language | TypeScript | 120 | 100.00% | 0.00% | 1.0000 |
| framework | http.server | 120 | 100.00% | 0.00% | 1.0000 |
| framework | node:http | 120 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-116 | 40 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-204 | 40 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-601 | 40 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-639 | 40 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-862 | 40 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-89 | 40 | 100.00% | 0.00% | 1.0000 |
| complexity | MULTI_STEP | 40 | 100.00% | 0.00% | 1.0000 |
| complexity | SECOND_ORDER | 40 | 100.00% | 0.00% | 1.0000 |
| complexity | SINGLE_STEP | 160 | 100.00% | 0.00% | 1.0000 |
| control | NEAR_MISS | 60 | 0.00% | 0.00% | 0.0000 |
| control | SECURE | 60 | 0.00% | 0.00% | 0.0000 |
| control | VULNERABLE | 120 | 100.00% | 0.00% | 1.0000 |

## Efficiency

| Metric | Median | P95 | Max |
|---|---:|---:|---:|
| Runtime (ms) | 148181.14 | 148181.14 | 148181.14 |
| Peak RSS (bytes) | 262524928 | 262524928 | 262524928 |
| Requests | 562.00 | 562.00 | 562.00 |
| Requests/assessed case | 2.34 | 2.34 | 2.34 |

## Cases

| ID | Expected | Result | Stable |
|---|---|---|---|
| nh-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-red-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-06 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-07 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-08 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-09 | FINDING | TRUE_POSITIVE | yes |
| nh-so-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-red-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-06 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-07 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-08 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-09 | FINDING | TRUE_POSITIVE | yes |
| ph-so-s-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-12 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-13 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-14 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-15 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-16 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-17 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-18 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-19 | NO_FINDING | TRUE_NEGATIVE | yes |

## Gates

| Gate | Status | Actual | Required |
|---|---|---:|---|
| recall | PASS | 1 | >= 1 |
| false-positive-rate | PASS | 0 | <= 0 |
| inconclusive-rate | PASS | 0 | <= 0 |
| coverage-completeness | PASS | 1 | >= 1 |
| minimum-repetitions | PASS | 1 | >= 1 |
| cleanup-observations | PASS | 80 | >= 80 |
| cleanup-failures | PASS | 0 | <= 0 |
| corpus-cases | PASS | 240 | >= 240 |
| positive-cases | PASS | 120 | >= 120 |
| negative-cases | PASS | 120 | >= 120 |
| languages | PASS | 2 | >= 2 |
| frameworks | PASS | 2 | >= 2 |
| near-miss-controls | PASS | 60 | >= 60 |
| multi-step-cases | PASS | 40 | >= 40 |
| second-order-cases | PASS | 40 | >= 40 |
| mutant-cases | PASS | 240 | >= 240 |
| youden-index | PASS | 1 | >= 1 |
| p95-runtime | PASS | 148181.14109999998 | <= 240000 ms |
| peak-rss | PASS | 262524928 | <= 2500000000 bytes |
| request-efficiency | PASS | 2.341666666666667 | <= 8 requests/assessed case |
| category-size/AUTHENTICATION_LIFECYCLE | PASS | 40 | >= 40 |
| category-balance/AUTHENTICATION_LIFECYCLE | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/FUNCTION_AUTHORIZATION | PASS | 40 | >= 40 |
| category-balance/FUNCTION_AUTHORIZATION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/OBJECT_AUTHORIZATION | PASS | 40 | >= 40 |
| category-balance/OBJECT_AUTHORIZATION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/OPEN_REDIRECT | PASS | 40 | >= 40 |
| category-balance/OPEN_REDIRECT | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SECOND_ORDER_STATE | PASS | 40 | >= 40 |
| category-balance/SECOND_ORDER_STATE | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SQL_INJECTION | PASS | 40 | >= 40 |
| category-balance/SQL_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| required-case/nh-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-19 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-06 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-07 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-08 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-09 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-s-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-12 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-13 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-14 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-15 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-16 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-17 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-18 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-19 | PASS | true | TRUE_NEGATIVE |
