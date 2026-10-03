# Publisher data and attribution

This directory retains unmodified, hash-pinned publisher source bytes. The generated catalog in `src/standards/catalog/official-catalog.json` is a transformation of these sources, not a new standard. Source URLs, release versions, immutable Git revisions, byte lengths, and SHA-256 values are recorded in `sources.lock.json` and exported reports.

- OWASP Web Security Testing Guide, release 4.2: [OWASP WSTG](https://github.com/OWASP/wstg/tree/v4.2), copyright its contributors, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- OWASP Application Security Verification Standard, release 5.0.0: [OWASP ASVS](https://github.com/OWASP/ASVS/tree/v5.0.0), copyright its contributors, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- OWASP API Security Top 10, edition 2023: [OWASP API Security](https://github.com/OWASP/API-Security), copyright its contributors, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- CWE 4.20 and CAPEC 3.9: copyright The MITRE Corporation. Distribution and use are subject to [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html) and [CAPEC Terms of Use](https://capec.mitre.org/about/termsofuse.html). These are supporting classifications, not verification standards.

OWASP-derived catalog data remains available under CC BY-SA 4.0; the repository's software license does not override publisher data terms. Changes made by RouteCairn: normalized framework identifiers, added explicit release prefixes, converted WSTG links to version 4.2, extracted XML names/status, and preserved the two published `INPV-13` tests as variants of one identity. Descriptions and names are publisher wording. RouteCairn mappings are locally reviewed associations, not OWASP or MITRE endorsements.
