# RouteCairn independent review brief

Review the tagged source and its dependency lockfile as an adversarial product assessment. Include architecture review, manual code review, abuse case analysis, and bounded dynamic testing.

Required scope: request safety and DNS rebinding controls; target authorization and budgets; active probe approval gates; mutation rollback; browser isolation; plugin sandbox and capability broker; secret vault and evidence redaction; OAST tenant isolation and replay handling; authentication and session management; worker identity and job leasing; database and object storage tenancy; protocol parsers; archive and file handling; release workflows and dependency provenance.

Report exploitable paths, safety bypasses, cross tenant access, secret disclosure, denial of service, and supply chain weaknesses. Retest fixes. The attestation may be signed as `ACCEPTED` only after every critical and high finding is resolved or explicitly rejected with documented evidence.
