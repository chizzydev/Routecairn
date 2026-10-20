# Operator recovery and uncertainty

The Recovery & Uncertainty workspace joins current organization-scoped custody, cleanup, assurance, deployment reservation and comparison evidence. It does not grant execution authority. Dispatch is an installation-wide guard; another organization may own the private evidence behind a global hold.

## Operator workflow

1. Select the organization, then open Recovery & Uncertainty. Review inventory warnings before drawing conclusions from an empty page. Pages are bounded per category. Refresh failures remove action authority from the displayed workspace.
2. Inspect the state, evidence references and snapshot fingerprint. Scan and comparison links use the existing scoped detail APIs. Raw process receipts, checkpoint bodies, credential values and arbitrary failure strings are not returned by this projection.
3. Acknowledge or escalate only after confirming the exact snapshot. Reviews are durable, audited and organization-bound. Changed source evidence makes prior review stale. Acknowledgement never resolves custody, overrides an assurance gate, releases a reservation or authorizes replay.
4. For failed or incomplete comparison evidence, an authorized analyst may explicitly request new offline analysis. The original comparison remains retained. Request identities prevent duplicate attempts; a failed analysis remains failed. Historical Continuous Assurance gates are not recomputed or rewritten.
5. Workflow cleanup requires an exclusively attributable target origin, a readable sealed checkpoint, fresh credentials and the existing cleanup-only confirmation. The worker verifies checkpoint, actor and policy bindings. For controlled mutation cleanup, the server derives the bundle from the exact approval; it rechecks target revision, scope, plan binding, expiry and target-bound saved credentials. The original attack is never replayed. A REQUESTED response is not proof of restoration: monitor the resulting job or approval and retained evidence.
6. UNKNOWN native custody requires installation-owner investigation. The UI offers no historical PID kill, custody reset, quarantine-clearance override or deployment replay. Root-only termination is not complete descendant custody. A normal fleet release remains refused by the native custody fence.

## Permission model

All routes require an authenticated session, recovery.read, scans.read and organization read membership. Mutations retain the existing CSRF and origin checks. Reviews require recovery.review and organization resources.use; custody review also requires installation and organization worker-management permission. Offline recomputation requires comparisons.create and comparisons.recompute. Cleanup requires controlledMutation.recover, credentials.use and organization resources.use. VIEWER roles can inspect but cannot act. Local mode retains its existing local-owner authorization model.

## Evidence and recovery boundaries

Migration 47 adds append-only review and comparison-attempt records. No resolution or quarantine-clearance field exists. Current source digests are rechecked transactionally for database-backed review/recompute operations, including comparison child coverage rows. Cleanup workers independently revalidate immutable stored bindings before transmission.

Managed dashboard recovery retains successful encrypted bundles. Workflow checkpoint updates archive previous ciphertext under content-addressed names before replacing the current checkpoint. Archive collision, alias and write failures block replacement. This is evidence retention within existing owned directories, not a new hostile-filesystem security boundary. Existing direct core callers retain their previous lifecycle unless they explicitly opt into preservation. Key management and retained evidence access remain owner responsibilities; no automatic purge is provided.

Origins attributed to multiple organizations, legacy unbound cleanup and unreadable checkpoints remain review-only. Historical nonterminal resource rows are not adopted as process capabilities. Missing inventory is reported as uncertainty. Review metadata does not replace native custody or restoration proof.

## Validation and remaining acceptance

The versioned recovery v0.3 review packet retains actual Windows-native custody loss and cleanup execution, native SQLite receipts, RED/GREEN failures, browser screenshots and source hashes. Browser fixtures use source-mode Vite and the real dashboard HTTP API, with only owned loopback targets. Seeded UNKNOWN deployment/comparison rows are labelled synthetic; they do not prove a production deployment failure. Full application acceptance and independent owner verification remain separate gates. All Stage D, Trusted Discovery operational and Ubuntu holds remain in force.
