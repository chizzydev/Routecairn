# Standards accounting acceptance

This run imports and validates complete official catalogs and executes the RouteCairn engine against a bounded loopback SQL vulnerable/secure fixture. All 58 selected unit and module regression checks passed with zero skipped cases and unchanged source snapshots.

- `standards-accounting-result.json`: test counts, provenance, catalog/mapping digests, and source SHA-256 values.
- `runtime/`: retained real HTTP report, Markdown/HTML, standards CSV/JSON, CLI verification, and runtime proof.
- `wstg-links.json`: all 97 released, versioned WSTG links returned HTTP 200.
- `release-verification.json`: release build, lint, formatting, architecture, dependency audit, installable package and installed CLI checks; includes the retained package digest.
- `SHA256SUMS`: all evidence files except the checksum file itself.

Catalogs: WSTG 4.2 (97 identities, 98 source tests), ASVS 5.0.0 (345 requirements), API Security 2023 (10 categories), CWE 4.20 (969 entries), CAPEC 3.9 (615 entries including deprecated records). Retired classifications are not mappable.

This is self-maintained acceptance evidence. Mapping membership and accounting integrity are verified; no certification or independent standards assessment is claimed. API10 remains unassessed where an exact third-party-consumption exercise is absent. Historical version-1 evidence is not relabeled.
