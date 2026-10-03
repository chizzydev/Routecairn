# Attack-state graph operation

Use **Adaptive Security** in the dashboard with a registered, authorized target. Completed scans create a candidate model; select an existing completed scan and **Analyze evidence** to import historical observations. Accept the exact model as a baseline to review later drift.

## Review paths

The graph represents actors, roles, tenants, objects and declared ownership, HTTP routes, parameters, operations, browser states, stored capabilities, preconditions, effects, cleanup and request dependencies. Search paths, filter by mutability and use **Inspect path** to review states, relationships, evidence producers and source case fingerprints. Pagination exposes all retained paths.

Evidence strength distinguishes discovery, declared contracts, exact responses and completed exact contracts. Declared ownership is not independent proof of ownership. Browser storage belongs to an observed browser actor; it does not establish an anonymous principal. Crawl pages establish reachability, not an inferred sequence of page-to-page navigation.

Graph limits are 1,200 nodes, 3,000 edges and 500 paths. Each path retains up to 100 nodes and 150 edges. Every retained edge has retained endpoints, and every path includes its edge endpoints. Truncated paths require further bindings and are not executable contracts. Removal drift requires equivalent producer coverage and untruncated graphs.

## Compile and execute

Exact anonymous HTTP reads can produce bounded status, field-exposure, billing and business-state regression cases. A modern report must match the request ID, exact origin/path/query, method and status. Older reports need an unambiguous request/response pair. Redirects, transport errors, authenticated/browser requests and foreign-origin route rebinding cannot authorize anonymous compilation. Safe GraphQL introspection generation is a query against an observed endpoint; an arbitrary endpoint POST does not prove an application mutation or a particular GraphQL document.

Completed API/GraphQL, plain HTTP authentication lifecycle, Supabase reads, business invariant, link/portal/export, operational endpoint and synthetic billing contracts can be rehydrated from matching conclusive case fingerprints. GraphQL queries are classified by their document; mutation and subscription documents cannot become read-only replay. Schema dependencies and method/version comparisons retain their request accounting. Credential literals and already-redacted values cannot become replay credentials. Profile authentication is resolved from current saved target credential references.

Missing identifiers, required GraphQL arguments, object ownership, unknown operations, native authentication fixture actions and incomplete contracts remain proposals with required bindings. Capture consumers need an earlier producer in the same case; duplicate, absent, self or forward producers cannot establish a complete path. Fixture actions and provider setup require the dedicated authentication builder; the plain HTTP replay compiler does not invent those bindings.

State-changing contracts require an explicit review with rationale, a current target scope/version, staging/test/production authorization appropriate to the engine, reserved cleanup capacity, and completed cleanup proof. Learning alone never sends traffic. **Approve proposal** enables **Open compiled case** for complete contracts; review the case in Scan Studio and start its normal policy-brokered scan. Approval expires after four hours. A newer changed model or changed target invalidates an older materialization. Production replay requires the target's production mutation permission.

Unknown outcomes and negative/ambiguous cleanup strings cannot establish completion. `NOT_REQUIRED` does not satisfy a state-changing contract's required cleanup. Exact completed mutation replay requires a positive cleanup outcome, such as `ROLLBACK_VERIFIED`.

Executable recommendations can be linked only to a post-review, same-target scan created with their immutable recommendation/source/graph binding. Configuration, authentication or graph-path substitution is rejected before dispatch. Verification requires a completed engine and exact completed case with transmitted evidence. Dedicated manual proposals require the operator's exact post-approval case binding. Failed, blocked, cancelled or inconclusive executions cannot satisfy verification. Evidence survives dashboard database reopening.

## Reproduce operational proof

From the source checkout:

```powershell
npm ci
npm run build
npm run dashboard:build
npm run acceptance:attack-graph -- --output .routecairn-attack-graph-lab/fresh-run
```

The destination must be new. The runner executes graph/compiler safety tests, deterministic generated inventories, dashboard UI review tests and a real loopback HTTP mutation workflow through source observation, proposal, review, approved replay, restoration, immutable evidence linkage and SQLite reopening. It retains a secret-free runtime trace, test counts, source hashes, unchanged-source checks and SHA-256 artifact checksums. Missing proof, failed/skipped tests or changed sources fail the runner.

Continuous assurance runs this gate on Windows and Linux with Node 22 and 24 and retains its evidence. A configured CI gate is not evidence that the remote CI run has happened. Local evidence is labelled `SELF_MAINTAINED_LOOPBACK`, with external-target and independent-operator claims disabled.
