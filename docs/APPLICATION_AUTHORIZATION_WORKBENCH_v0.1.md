# Application authorization workbench v0.1

This Windows increment implements an owned loopback vertical slice on the existing API authorization runtime. It does not activate Trusted Discovery or grant production/external target authority.

## Operator journey

1. Register an OWNED LOCAL target at an exact 127.0.0.1 origin using existing target management. Use purpose-built accounts with target-bound saved credentials and required principal, tenant and role identity verification. Complete a bounded API observation scan through the existing scan runtime.
2. Open Application Authorization. Inspect available observations/credential references and import an expectation JSON file. Select only observed REST GET operations. Exact URLs are explicitly rebound to their observed route templates: persisted report aliases intentionally conceal object URLs. No URL is guessed or de-redacted. For each operation declare an exact resource/function identity marker, tenant marker where needed, an ALLOW control and DENY actors. Unknown decisions/proof remain REQUIRES_BINDINGS.
3. Create a durable versioned matrix. Review actor roles/tenant fingerprints, object markers, rationale, linked SecurityCase IR IDs, exact request contracts, source hash and proof budget. Review source observation versus declared policy and hypothesis separately. A preview is not authority. Explicitly authorize the shown read-only matrix within its ten-minute lifetime.
4. Follow actual worker/HTTP outcomes and open the existing scan and findings views. Wrong-object success and a failed allowed control are INCONCLUSIVE, not high-confidence bypass proof. The generated fixture demonstrates two real unauthorized object reads with correct resource identity, separate secure/function controls and a wrong-object near-miss.
5. Fix the owned fixture, create another reviewed revision with the same actor/object policy and compare the retained executions. The real comparer preserves prior findings and coverage; partial/unproven cells never become an application-wide clean claim. Reopen retained revisions to inspect prior matrix and execution evidence.

## Input shape

Use real target/observation/credential UUIDs from the current dashboard. The following is illustrative metadata, not an executable environment:

```json
{
  "targetId": "<registered target UUID>",
  "sourceScanId": "<completed observation UUID>",
  "credentials": {
    "primary": "<owner credential UUID>",
    "account_a": "<member A UUID>",
    "account_b": "<member B UUID>"
  },
  "expectations": [
    {
      "routeId": "document",
      "url": "http://127.0.0.1:<owned-port>/api/documents/doc-a",
      "kind": "TENANT_ISOLATION",
      "explanation": "Only the declared owner may read this exact tenant-a object.",
      "decisions": { "owner": "ALLOW", "member": "DENY", "outsider": "DENY", "anonymous": "DENY" },
      "identity": { "path": "id", "expectedValue": "doc-a" },
      "tenant": { "path": "tenant", "expectedValue": "tenant-a" }
    }
  ]
}
```

Actors and slots come from the completed source plan, not invented input actors. All nonanonymous source actors must match current vault principal/tenant/role metadata and the source's actual identity verification. Distinct named credentials are required. URLs cannot contain credentials, query or fragments; they must bind to an observed template on the exact target origin. Only imported operations are selected. At most eight operations and four actors produce at most 32 engine checks; the complete scan has a 40-request ceiling, three possible identity verifications and 8192-byte engine response bounds. The exact transport preview also lists the core root baseline GET and each saved actor’s scoped identity-verification GET, including their credential reference. Tenant and role mappings and a same-origin identity endpoint are mandatory. The 40-request ledger ceiling includes baseline, identities and any existing runtime retries; it is a ceiling, not a promise to send all requests. Existing scope, DNS, shared request-ledger, credential readiness, encrypted executable plans and native custody still apply.

## Architecture and authority

AuthorizationWorkbenchService adapts the existing observed-input projection, AdaptiveSynthesisCore inventory/recommendations, AdaptiveSecurityCaseIR projection, AdaptiveAuthorizationSynthesis, AdaptiveAttackStateGraph and AdaptiveContractCompiler. Shadow IR remains nonexecutable and nonauthoritative; the operator-bound API contract goes through the existing ScanExecutionService and ApiGraphqlModule. There is no second detection engine or held execution bridge. Redacted aliases may contribute only declared graph paths/relationships under the normalized report origin; they cannot recover an executable URL.

Schema 49 adds immutable revision, dispatch-intent and acknowledgement tables. A stored revision includes the exact safe preview/input/request, source and context digests, reviewer, version and expiry. No raw credential enters those tables. Context binds the target/revision/approved scope, source-report hash and enabled target/org-bound credential metadata/ciphertext identity. The binding is rechecked on admission, after asynchronous plan resolution, when queued work starts, and at JOB_ACCEPTED before credentials or START_JOB. The existing immutable worker plan binds the actual resolved requests and authentication.

One revision can consume one durable dispatch intent. Duplicate/lost-ack submissions return a recorded scan or UNKNOWN without enqueueing again; an intent without acknowledgement never becomes a quiet pass. No retry/reset/clear operation is provided. Only a newly reviewed revision can authorize another read-only assessment. Native ambiguous custody and global dispatch quarantine retain their existing separate authority.

Server endpoints enforce session/CSRF, global scan/credential permissions and selected organization/resource authority. Read and comparison routes scope revisions to the organization; comparisons require the same target, source, actor and expectation input. A comparison records fresh analysis or returns its existing exact pair; it does not rewrite historical assurance gates. This slice uses continuous comparison infrastructure; it does not create an automatic Continuous Assurance policy or claim provider acceptance.

## Evidence and limits

The single delivery packet holds genuine real-HTTP RED/FIX/GREEN for wrong-object and missing-control false positives, native worker assessments, bootstrap stale-binding no-wire proof, SQLite unknown-ack/concurrency checks, server permission and real Edge evidence. The fixture bank is generated and self-maintained, not independent detection benchmarking. The observation scan is prepared before the Edge import journey; this is not yet automated crawling, OpenAPI acquisition, a first-run onboarding wizard or a broad authenticated application mapper. JSON expectation binding remains an engineering-oriented workflow. State-changing authorization/business logic and wider protocol/provider/deployment acceptance remain separate roadmap work and holds.
