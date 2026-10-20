# Master roadmap continuity after Cleanup Lifecycle v0.5

The confirmed terminal-UNKNOWN/compatibility crash gap is corrected with transactional service writes and restart projection. Prior worker custody and v0.4 cleanup safeguards remain. Further worker-internal changes require new source-backed failure evidence or a concrete application workflow need.

## Next substantial product increment: application-aware authorization workbench

Build one complete experience on the existing observed-input, SecurityCase IR, authorization synthesis and attack-state graph: observed route/operation -> evidence-backed actor/role/tenant/object bindings -> reviewable authorization case matrix -> exact contract preview -> authorized owned-fixture execution through an already permitted path -> evidence and regression comparison in the dashboard. Use the actual AdaptiveSecurityCaseIR, AdaptiveAuthorizationSynthesis, AdaptiveContractCompiler and existing API/UI contracts instead of a parallel planner.

Prioritize BOLA and cross-tenant object access, function/role boundaries, ownership transitions and invitation/signed-capability semantics. Show why a case exists, what actor/object evidence is missing, which action is permitted, what was exercised, and why a result is verified, inconclusive or blocked. Unknown semantics stay REQUIRES_BINDINGS; no inference grants state-changing authority. Standards coverage must follow actual cases, not inventory counts.

The acceptance slice should include an owned two-tenant application with owner/member/other-tenant/anonymous actors, vulnerable/secure/near-miss expectations, exact evidence linkage, blocked stale bindings and a remediation regression shown end-to-end in Windows Edge. Preserve budgets, current target authorization, immutable plan and credential bindings, and cleanup obligations. Separate observed evidence from proposed tests and executed findings. Do not claim external provider or independent acceptance from fixtures.

## Operational boundaries

All Stage D materialization/deletion and Trusted Discovery execution holds remain. Ubuntu is paused. No external scanning, release packaging, evidence purge, Git history mutation, automatic replay, reset or quarantine clearance is authorized by this continuity record. The next application slice must not activate the held bridge; use previews and explicitly authorized fixture paths until the owner's operational gates are satisfied.

The v0.4 proposal for generic retry-contract generation is deferred behind application-visible security value unless a specific workflow needs it. Existing UNKNOWN history must never be erased or treated as restoration. Full application/release acceptance and independent owner review of this increment remain outstanding.
