# Durable cleanup attempts (Windows recovery v0.4)

## What is authoritative

`cleanup_attempts` is an immutable authorization/submission binding. `cleanup_attempt_events` is its append-only, ordered SHA-256 chain. Existing approval and workflow-job columns remain compatibility summaries. The attempt history decides whether a recovery outcome is verified, failed, not executed or UNKNOWN. Historical failure and uncertainty are never replaced by a newer attempt.

Both managed operator recovery services use the ledger. Cleanup already performed inline under a normal scan's original immutable execution plan continues to use its existing scan/journal/custody safeguards; this increment does not fabricate separate retrospective attempts for those operations.

## Lifecycle

- REQUESTED and AUTHORIZED commit atomically with consumption of the exact approval/checkpoint authority. A failed authorization rolls back admission. The request identity, actor, organization, target revision, plan/scope binding, credential revision fingerprint, ciphertext digest and prior journal prefix are retained.
- WORKER_PENDING records worker identity, generation and owned resource before fork. WORKER_ACTIVATED requires the actual native bootstrap/job binding and runtime readiness.
- DISPATCH_ARMED records the recovery command handoff. It is conservative evidence of possible execution, not proof that a packet reached the target.
- Each DISPATCH_ATTEMPTED event commits before a signed private IPC acknowledgement permits entry to the existing cleanup safety broker. Broker policy may still deny transmission. No raw URL, header, request body or credentials enter this ledger.
- RESULT_RECEIVED is the authenticated worker report. It is not restoration acceptance.
- RESTORATION_VERIFIED additionally requires native worker custody to drain, a fresh verified journal entry after the admitted prefix, an unchanged earlier journal prefix and a matching signed entry fingerprint. This checks the independent verification request/journal and custody evidence; it is not an independent external assessment of the application.
- FAILED retains a received cleanup failure after known custody drain. NOT_EXECUTED requires no granted recovery command and retained/no worker resources. Neither state declares restoration. UNKNOWN retains uncertain execution/custody/completion. Unfinished armed/result states, corruption and UNKNOWN fence ordinary dispatch and fleet release.

Dashboard SQLite connections now use WAL plus FULL synchronization. Recovery writes refuse a downgraded synchronization mode. This provides SQLite's documented committed-transaction crash durability subject to the operating system/storage guarantees; it is not a promise against failed hardware or dishonest storage firmware.

## Restart and idempotency

Startup reconciliation runs under the existing dashboard singleton before accepting recovery. It never adopts or terminates historical PIDs. Each attempt and its compatibility summary reconcile in one transaction. Prior active attempts become NOT_EXECUTED only with positive pre-command/resource evidence; otherwise UNKNOWN. A saved success result or a verified-looking journal alone does not promote an interrupted attempt. An already committed RESTORATION_VERIFIED attempt remains terminal and can be returned after lost acknowledgement without a new worker.

Explicit request IDs are organization/actor/submission-bound. Concurrent identical requests return the original attempt. Conflicting IDs and reuse of consumed approval/checkpoint authority are rejected. Legacy requests without an ID are one-use and duplicates are rejected. The UI retains a hashed, session-bound request identity across unavailable acknowledgements; it does not store request contents or secrets as new cache entries.

A new request ID is not new authority. Failed/UNKNOWN attempts cannot be retried through a hidden reset or another confirmation. Where no fresh, verifiable cleanup authority exists the only current actions are evidence inspection and human review. A future explicitly reviewed retry contract must prove safety; this increment does not infer cleanup idempotency.

Legacy in-flight records lacking an attempt ledger are not adopted, replayed or given invented history. Legacy workflow jobs are marked interrupted at singleton startup. Legacy controlled approvals already EXECUTING without a new ledger remain held for owner investigation.

## Dashboard and API

Recovery & Uncertainty shows lifecycle items, actual phase, immutable bindings, job/evidence references and expandable ordered history. Completed history remains available. Reviews never alter attempts or release quarantine. New routes use the existing authenticated session, CSRF/origin, selected-organization and recovery permissions. History reads return safe identifiers, phase, timestamps and chain fingerprints. Target authorization, fresh credentials, cleanup-only scope and immutable worker IPC bindings still apply.

- GET /api/recovery-center/attempts/:id — selected organization, read-only verified history.
- Existing controlled/workflow cleanup POST routes accept an optional UUID requestId. The UI supplies stable IDs; raw legacy callers remain one-use.
- No attempt mutation/reset/replay/clearance endpoint exists.

## Verification and limits

Use the single cumulative review ZIP's 00_READ_FIRST.txt, reports, raw test outputs, native SQLite receipts, browser screenshots and owner-verification script. Original test assertions and the 30-second defaults remain; existing longer explicit cleanup tests retain their original limits. Production timeout, request, cleanup and authorization limits were not increased. Source-mode browser verification is separate from a release build or full application acceptance.

No Ubuntu, external target scanning, Trusted Discovery activation, Git history mutation, release publishing, dependency installation or deletion of retained owner data is authorized by this increment. All Stage D operational holds remain. There is no evidence-purge or custody-clearance shortcut. Hash-chain/trigger integrity is within the trusted-host database model, not protection against an administrator deliberately replacing the database and application together.

## Windows file replacement

Native regression diagnosis reproduced EPERM during atomic journal/checkpoint replacement while the dashboard read inventory. Prepared bytes now receive at most five sharing-denial retries (six rename attempts, 310ms scheduled backoff). Retries require the same ordinary prepared file, unchanged existing/absent destination, and unchanged destination directory identity. Changed identities, unrelated errors and persistent denial fail closed, retaining old and prepared evidence. No unlink, chmod, new request, expanded cleanup authority or deadline increase is involved. This addresses observed sharing denial; no particular antivirus or reader is asserted as its cause.

## v0.5 crash-consistent compatibility summaries

Both managed recovery families commit interruption and the legacy summary projection in one synchronous immediate SQLite transaction, after native worker drain. Startup also projects already-committed UNKNOWN/NOT_EXECUTED attempts into matching still-active compatibility rows, without appending, rewriting or clearing their immutable history. This repairs the v0.4 crash window where a job could remain RUNNING or an approval EXECUTING. The compatibility status CLEANUP_FAILED does not imply a proven failure on the target: UNKNOWN is retained in the authoritative timeline and safe summary/error code, and dispatch remains quarantined.

Projection validates family authority, job, case, target, organization and available checkpoint/approval binding. A mismatch or persistent write failure refuses reconciliation; it never adopts another record, creates missing authority, rewrites a non-active historical outcome or grants replay. Missing compatibility records are not fabricated. New storage failure rolls back both interruption and summary, leaving the earlier unresolved phase fenced until safe reconciliation can succeed. Previously committed UNKNOWN remains UNKNOWN on a failed projection.
