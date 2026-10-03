# RouteCairn multi-language detection credibility corpus

Status: **PASSED**<br>
Release: 0.1.0<br>
Repetitions: 3

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
| Cleanup success | 100.00% (288/288) |
| Cleanup failures | 0 |

## Corpus composition

| Cases | Positive | Negative | Near-miss | Multi-step | Second-order | Mutants | Languages | Frameworks | Blinded |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 576 | 288 | 288 | 144 | 48 | 48 | 576 | 3 | 4 | 0 |

## Category coverage

| Category | Cases | Positive | Negative | Recall | False-positive rate | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| AUTHENTICATION_LIFECYCLE | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| CRLF_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| FUNCTION_AUTHORIZATION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| NOSQL_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| OBJECT_AUTHORIZATION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| OPEN_REDIRECT | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| PATH_TRAVERSAL | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| SECOND_ORDER_STATE | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| SQL_BOOLEAN_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| SQL_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| SQL_UNION_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |
| TEMPLATE_INJECTION | 48 | 24 | 24 | 100.00% | 0.00% | 100.00% |

## Stratified scorecard

| Dimension | Value | Cases | Recall | False-positive rate | Youden |
|---|---|---:|---:|---:|---:|
| language | Go | 144 | 100.00% | 0.00% | 1.0000 |
| language | Python | 288 | 100.00% | 0.00% | 1.0000 |
| language | TypeScript | 144 | 100.00% | 0.00% | 1.0000 |
| framework | http.server | 144 | 100.00% | 0.00% | 1.0000 |
| framework | net/http | 144 | 100.00% | 0.00% | 1.0000 |
| framework | node:http | 144 | 100.00% | 0.00% | 1.0000 |
| framework | wsgiref | 144 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-113 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-116 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-1336 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-204 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-22 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-601 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-639 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-862 | 48 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-89 | 144 | 100.00% | 0.00% | 1.0000 |
| weakness | CWE-943 | 48 | 100.00% | 0.00% | 1.0000 |
| complexity | MULTI_STEP | 48 | 100.00% | 0.00% | 1.0000 |
| complexity | SECOND_ORDER | 48 | 100.00% | 0.00% | 1.0000 |
| complexity | SINGLE_STEP | 480 | 100.00% | 0.00% | 1.0000 |
| control | NEAR_MISS | 144 | 0.00% | 0.00% | 0.0000 |
| control | SECURE | 144 | 0.00% | 0.00% | 0.0000 |
| control | VULNERABLE | 288 | 100.00% | 0.00% | 1.0000 |

## Efficiency

| Metric | Median | P95 | Max |
|---|---:|---:|---:|
| Runtime (ms) | 397281.54 | 397764.27 | 397817.90 |
| Peak RSS (bytes) | 353861632 | 377344000 | 379953152 |
| Requests | 1540.00 | 1540.00 | 1540.00 |
| Requests/assessed case | 2.67 | 2.67 | 2.67 |

## Cases

| ID | Expected | Result | Stable |
|---|---|---|---|
| nh-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-obj-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-obj-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-fn-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-fn-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-bool-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-bool-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-sql-unio-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-sql-unio-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-red-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-red-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-auth-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-auth-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-so-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-so-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-nosql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-nosql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-crlf-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-crlf-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-template-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-template-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-template-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-template-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-template-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-template-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-template-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-v-00 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-v-01 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-v-02 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-v-03 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-v-04 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-v-05 | FINDING | TRUE_POSITIVE | yes |
| nh-traversa-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| nh-traversa-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-obj-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-obj-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-fn-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-fn-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-bool-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-bool-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-sql-unio-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-sql-unio-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-red-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-red-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-auth-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-auth-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-so-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-so-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-nosql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-nosql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-crlf-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-crlf-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-template-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-template-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-template-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-template-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-template-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-template-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-template-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-v-00 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-v-01 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-v-02 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-v-03 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-v-04 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-v-05 | FINDING | TRUE_POSITIVE | yes |
| ph-traversa-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| ph-traversa-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-obj-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-obj-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-fn-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-fn-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-bool-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-bool-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-sql-unio-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-sql-unio-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-red-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-red-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-auth-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-auth-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-so-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-so-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-nosql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-nosql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-crlf-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-crlf-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-template-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-template-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-template-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-template-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-template-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-template-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-template-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-v-00 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-v-01 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-v-02 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-v-03 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-v-04 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-v-05 | FINDING | TRUE_POSITIVE | yes |
| pw-traversa-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| pw-traversa-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-obj-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-obj-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-fn-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-fn-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-bool-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-bool-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-sql-unio-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-sql-unio-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-red-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-red-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-red-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-red-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-red-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-red-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-red-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-auth-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-auth-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-so-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-so-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-so-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-so-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-so-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-so-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-so-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-nosql-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-nosql-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-crlf-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-crlf-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-template-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-template-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-template-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-template-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-template-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-template-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-template-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-v-00 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-v-01 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-v-02 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-v-03 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-v-04 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-v-05 | FINDING | TRUE_POSITIVE | yes |
| gh-traversa-s-06 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-s-07 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-s-08 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-n-09 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-n-10 | NO_FINDING | TRUE_NEGATIVE | yes |
| gh-traversa-n-11 | NO_FINDING | TRUE_NEGATIVE | yes |

## Gates

| Gate | Status | Actual | Required |
|---|---|---:|---|
| recall | PASS | 1 | >= 1 |
| false-positive-rate | PASS | 0 | <= 0 |
| inconclusive-rate | PASS | 0 | <= 0 |
| coverage-completeness | PASS | 1 | >= 1 |
| minimum-repetitions | PASS | 3 | >= 3 |
| cleanup-observations | PASS | 288 | >= 288 |
| cleanup-failures | PASS | 0 | <= 0 |
| category-count | PASS | 12 | >= 12 |
| stability-rate | PASS | 1 | >= 1 |
| corpus-cases | PASS | 576 | >= 576 |
| positive-cases | PASS | 288 | >= 288 |
| negative-cases | PASS | 288 | >= 288 |
| languages | PASS | 3 | >= 3 |
| frameworks | PASS | 4 | >= 4 |
| near-miss-controls | PASS | 144 | >= 144 |
| multi-step-cases | PASS | 48 | >= 48 |
| second-order-cases | PASS | 48 | >= 48 |
| mutant-cases | PASS | 576 | >= 576 |
| youden-index | PASS | 1 | >= 1 |
| p95-runtime | PASS | 397764.26781999995 | <= 900000 ms |
| peak-rss | PASS | 379953152 | <= 2500000000 bytes |
| request-efficiency | PASS | 2.673611111111111 | <= 8 requests/assessed case |
| category-size/AUTHENTICATION_LIFECYCLE | PASS | 48 | >= 48 |
| category-recall/AUTHENTICATION_LIFECYCLE | PASS | 1 | >= 1 |
| category-false-positive-rate/AUTHENTICATION_LIFECYCLE | PASS | 0 | <= 0 |
| category-inconclusive-rate/AUTHENTICATION_LIFECYCLE | PASS | 0 | <= 0 |
| category-balance/AUTHENTICATION_LIFECYCLE | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/CRLF_INJECTION | PASS | 48 | >= 48 |
| category-recall/CRLF_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/CRLF_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/CRLF_INJECTION | PASS | 0 | <= 0 |
| category-balance/CRLF_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/FUNCTION_AUTHORIZATION | PASS | 48 | >= 48 |
| category-recall/FUNCTION_AUTHORIZATION | PASS | 1 | >= 1 |
| category-false-positive-rate/FUNCTION_AUTHORIZATION | PASS | 0 | <= 0 |
| category-inconclusive-rate/FUNCTION_AUTHORIZATION | PASS | 0 | <= 0 |
| category-balance/FUNCTION_AUTHORIZATION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/NOSQL_INJECTION | PASS | 48 | >= 48 |
| category-recall/NOSQL_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/NOSQL_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/NOSQL_INJECTION | PASS | 0 | <= 0 |
| category-balance/NOSQL_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/OBJECT_AUTHORIZATION | PASS | 48 | >= 48 |
| category-recall/OBJECT_AUTHORIZATION | PASS | 1 | >= 1 |
| category-false-positive-rate/OBJECT_AUTHORIZATION | PASS | 0 | <= 0 |
| category-inconclusive-rate/OBJECT_AUTHORIZATION | PASS | 0 | <= 0 |
| category-balance/OBJECT_AUTHORIZATION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/OPEN_REDIRECT | PASS | 48 | >= 48 |
| category-recall/OPEN_REDIRECT | PASS | 1 | >= 1 |
| category-false-positive-rate/OPEN_REDIRECT | PASS | 0 | <= 0 |
| category-inconclusive-rate/OPEN_REDIRECT | PASS | 0 | <= 0 |
| category-balance/OPEN_REDIRECT | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/PATH_TRAVERSAL | PASS | 48 | >= 48 |
| category-recall/PATH_TRAVERSAL | PASS | 1 | >= 1 |
| category-false-positive-rate/PATH_TRAVERSAL | PASS | 0 | <= 0 |
| category-inconclusive-rate/PATH_TRAVERSAL | PASS | 0 | <= 0 |
| category-balance/PATH_TRAVERSAL | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SECOND_ORDER_STATE | PASS | 48 | >= 48 |
| category-recall/SECOND_ORDER_STATE | PASS | 1 | >= 1 |
| category-false-positive-rate/SECOND_ORDER_STATE | PASS | 0 | <= 0 |
| category-inconclusive-rate/SECOND_ORDER_STATE | PASS | 0 | <= 0 |
| category-balance/SECOND_ORDER_STATE | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SQL_BOOLEAN_INJECTION | PASS | 48 | >= 48 |
| category-recall/SQL_BOOLEAN_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/SQL_BOOLEAN_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/SQL_BOOLEAN_INJECTION | PASS | 0 | <= 0 |
| category-balance/SQL_BOOLEAN_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SQL_INJECTION | PASS | 48 | >= 48 |
| category-recall/SQL_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/SQL_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/SQL_INJECTION | PASS | 0 | <= 0 |
| category-balance/SQL_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/SQL_UNION_INJECTION | PASS | 48 | >= 48 |
| category-recall/SQL_UNION_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/SQL_UNION_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/SQL_UNION_INJECTION | PASS | 0 | <= 0 |
| category-balance/SQL_UNION_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| category-size/TEMPLATE_INJECTION | PASS | 48 | >= 48 |
| category-recall/TEMPLATE_INJECTION | PASS | 1 | >= 1 |
| category-false-positive-rate/TEMPLATE_INJECTION | PASS | 0 | <= 0 |
| category-inconclusive-rate/TEMPLATE_INJECTION | PASS | 0 | <= 0 |
| category-balance/TEMPLATE_INJECTION | PASS | true | at least one FINDING and one NO_FINDING case |
| required-case/nh-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-obj-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-obj-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-fn-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-fn-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-bool-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-bool-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-sql-unio-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-sql-unio-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-red-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-red-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-auth-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-auth-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-so-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-so-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-nosql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-nosql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-crlf-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-crlf-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-template-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-template-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/nh-traversa-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/nh-traversa-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-obj-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-obj-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-fn-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-fn-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-bool-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-bool-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-sql-unio-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-sql-unio-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-red-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-red-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-auth-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-auth-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-so-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-so-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-nosql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-nosql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-crlf-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-crlf-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-template-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-template-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/ph-traversa-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/ph-traversa-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-obj-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-obj-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-fn-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-fn-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-bool-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-bool-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-sql-unio-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-sql-unio-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-red-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-red-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-auth-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-auth-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-so-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-so-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-nosql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-nosql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-crlf-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-crlf-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-template-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-template-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/pw-traversa-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/pw-traversa-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-obj-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-obj-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-fn-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-fn-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-bool-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-bool-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-sql-unio-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-sql-unio-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-red-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-red-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-auth-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-auth-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-so-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-so-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-nosql-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-nosql-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-crlf-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-crlf-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-template-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-template-n-11 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-v-00 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-v-01 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-v-02 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-v-03 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-v-04 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-v-05 | PASS | true | TRUE_POSITIVE |
| required-case/gh-traversa-s-06 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-s-07 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-s-08 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-n-09 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-n-10 | PASS | true | TRUE_NEGATIVE |
| required-case/gh-traversa-n-11 | PASS | true | TRUE_NEGATIVE |

## Statistical uncertainty

Wilson 95% intervals over unique cases:

| Metric | Lower | Upper | Unique cases |
|---|---:|---:|---:|
| Recall | 98.68% | 100.00% | 288 |
| False-positive rate | 0.00% | 1.32% | 288 |

Intervals use unique cases, not repeated observations. Related mutants and self-maintained fixtures are not independent samples of real applications; intervals are descriptive, not population guarantees.
