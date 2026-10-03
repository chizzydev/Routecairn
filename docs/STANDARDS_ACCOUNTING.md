# Standards accounting

## Official, reproducible catalog

RouteCairn imports all 97 distinct WSTG 4.2 identifiers (98 checklist tests), all 345 ASVS 5.0.0 requirements, all ten API Security Top 10 2023 categories, 969 CWE 4.20 weakness entries, and 615 CAPEC 3.9 entries, including retained deprecated entries. Deprecated classifications cannot be mapped; denominators distinguish active entries. These are complete publisher datasets for these pinned versions, not a claim of testing every requirement.

The released WSTG checklist uses `INPV`, not the newer draft's `INJT`. GraphQL is `WSTG-v42-APIT-01`; there is no invented `APIT-99` in this catalog. The release shares `INPV-13` between buffer-overflow and format-string tests. Both source names and links are retained as variants; the identifier is counted once. Dedicated draft-only JWT/OAuth/prototype-pollution/deserialization IDs are replaced by applicable published ASVS/CWE/CAPEC references.

`standards/sources.lock.json` pins official HTTPS source URLs, immutable OWASP revisions, release versions, exact byte sizes, licenses, and SHA-256 digests. Original publisher bytes are checked in under `standards/sources`. Import schemas validate source structure, hierarchy, duplicate identities, publishers, versions, XML roots, and entry fields. XML entity declarations and oversized archive entries are rejected. Imports verify hashes before parsing. Runtime catalog bytes are verified against a generated compiled digest.

```sh
npm run standards:check
npm run standards:import
# Explicitly refetch the exact reviewed sources; version/hash drift is rejected:
npm run standards:import -- --refresh
routecairn standards verify --output standards-verification.json
routecairn standards catalog --output official-catalog.json
routecairn standards validate-report --input report.json --output-dir verified-coverage
```

Normal builds and CI run the offline catalog and built-in mapping gates. Importing requires no target access. An upstream update requires reviewing source versions/hashes, rebuilding the catalog, reviewing mappings, and rerunning tests. Network import does not select an unpinned `latest` release. Hash verification provides reproducibility and tamper detection; it is not a publisher signature.

## Strict accounting

New coverage is schema version 2. It contains exact catalog provenance, catalog and mapping hashes, full framework denominators, and bounded case associations. Existing version-1 retained reports remain historical evidence; their unversioned identities are not automatically reinterpreted. The strict verifier rejects them. Regenerate by rerunning the original authorized scan; do not relabel historical findings as new execution.

Every retained case must have at least one valid, current catalog reference. An unknown engine/kind, unmapped finding, missing case identity, unsupported identifier, retired classification, or inconsistent export fails accounting. Unknown active/protocol/authentication case kinds have no generic fallback. The release gate enumerates every built-in engine and declared case kind; aggregators are excluded because they do not execute tests. Third-party cases with no reviewed built-in mapping fail report accounting and require a code-reviewed mapping before they can be released. Mutation recovery remains independent of report-writing failures.

WSTG area `COVERED` requires conclusive case evidence for every identifier in that area. A partially sampled area remains `PARTIAL`. Conclusive means finding or no finding for a bounded case; a finding does not mean compliance. Catalog totals include unassessed requirements, and blocked/inconclusive/observation-only records cannot masquerade as passing verification. Completing a module with no findings only records an observation, not a pass. CWE/CAPEC remain supporting associations. CSV exports neutralize spreadsheet formulas as well as quote delimiters.

Mapping accuracy changes include XXE to ASVS 1.5.1, deserialization to 1.5.2, session rotation/fixation to 7.2.4, refresh replay to 10.4.5, contextual DOM versus reflected XSS, and CRLF to CAPEC-34. REST authorization is not automatically labeled GraphQL. Secret-boundary mappings distinguish cookies, browser storage, errors, scripts, and API fields. SSRF/XXE/secret exposure do not automatically count as API10 third-party-consumption exercises; that objective remains unassessed without specific retained evidence. Publisher ASVS descriptions and verification levels are preserved in the catalog.

## Interpretation and limitations

A direct association means the bounded test is relevant to a requirement. It does not establish coverage of every clause, path, actor, deployment, or ASVS verification level. Reports are evidence accounting, not certification or independent assessment. Mappings still require human semantic review even when every identifier validates against the official catalog. Network acceptance and independent operator evidence remain separate from catalog accuracy.

Publisher attribution and data licenses are in `standards/NOTICE.md`.
