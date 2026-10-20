# Windows worker custody and retained test resources

## Execution boundary

The manager creates an exclusive attempt directory and a durable `worker_resources`
record, bound to the installation, scan, worker and generation. An existing
directory or persisted receipt never becomes an in-memory ownership capability.
There is no automatic directory deletion in the worker manager or global test hook.

A built-in-only generated bootstrap creates no child processes. After durable
registration the controller observes the root birth through its own bounded native
query and challenges the originally forked root on its private IPC channel. A dead
root or reused PID cannot complete that challenge. The manager then assigns that
process, using a birth-verified native handle,
to a new unnamed Windows Job Object before activating the TypeScript loader or
application imports. Descendants inherit job membership. A root PID, parent PID
tree, diagnostic process list or historical database row grants no termination
authority. Windows bare-PID tree termination is refused.

The native bridge uses Windows PowerShell and in-memory P/Invoke declarations.
It needs no C# compiler, generated assembly, added dependency, elevated token,
execution-policy change or short temporary path. If native custody cannot be
established, application execution is refused.

The bootstrap is generated exclusively within this attempt's temporary directory.
Source execution registers the existing tsx loader after assignment. Compiled
execution imports the adjacent compiled worker directly. No extra runtime asset
copy step or release packaging is required for the bootstrap source generator.

## Lifetime, cancellation and recovery

Native process `exit` confirms root termination. Node's I/O `close` event may be
delayed by inherited pipe handles and is not the root-lifetime authority. Logical
job results do not remove a still-running root from custody. Shutdown drains both
scan and recovery workers and records native root and custodian outcomes.

Cancellation before activation prevents target transmission. Cancellation during
execution remains cooperative and retains the existing 135-second restoration
grace. Protocol and IPC failures during execution cannot substitute the shorter
post-result exit timer for the restoration window. Recovery keeps its original
bounded deadline. A dead root has no continuing execution authority: its kernel
job's remaining descendants are stopped using the job handle. This does not
declare the application's outstanding cleanup obligations resolved.

On controller pipe loss the native custodian gives a live root the existing
restoration window. It can detect root exit using its retained native handle;
it never rediscovers a PID for termination. Unexpected custodian loss requests
cooperative cancellation, retains UNKNOWN custody evidence, fails draining and
quarantines dispatch. It does not fall back to killing an inferred PID tree.
Custody loss synchronously records UNKNOWN and persistent dispatch quarantine
before waiting for cooperative cleanup or root exit. Ordinary fleet release checks
the durable UNKNOWN ledger, including from a newly opened SQLite connection, and
cannot clear it after a restart. No operator-resolution or adoption authority is
added here. Explicit resolution of historical custody needs a separate authorized
workflow; changing the fleet flag alone cannot authorize dispatch. A failed fleet
quarantine transaction attempts an independent UNKNOWN ledger write. A new
supervisor also refuses unowned nonterminal resource records, so a failed ledger
write cannot turn historical RUNNING/DRAINING rows into adoption or dispatch
authority. Diagnostics expose the effective custody quarantine even if the
separate fleet-flag update was rejected.
Explicit cleanup recovery remains available; it is not silently replayed.

A STOP write is not termination evidence. Sequence-bound STOPPED and DRAINED
frames are accepted only for the outstanding command, after native ActiveProcesses
is zero and the retained root handle is signalled. STOP acknowledgement has a
5-second bound; lost, withheld, malformed or late acknowledgement permanently fails
custody. The helper is terminated only through its controller-owned process handle.
Fallback can terminate the original root handle, but cannot claim descendant
termination. Receipts explicitly separate root-only fallback, UNKNOWN and native
zero-membership acknowledgement.

Application shutdown waits for both worker draining and result bookkeeping even
when draining rejects UNKNOWN. The caller must not close SQLite while the scan
result is still being ingested. Native custody errors remain errors after both
activities settle; neither is converted into success. SQLite stopping/forced-exit
bookkeeping cannot prevent cooperative cancellation or the existing native
termination deadline. A DRAINING-ledger write failure cannot skip native job
draining; all bookkeeping failures are retained and block a clean shutdown.

Expired scan and recovery leases are reconciled without adopting old files or
processes. Matching live process births, malformed identities, uncertain queries
and the restoration window produce visible `WORKER_RECOVERY_HELD` events.
Lease release is worker-bound. Unresolved orphan custody quarantines dispatch;
mutation journals continue to govern target cleanup and recovery authorization.

The worker fsyncs bounded, attempt-bound lifecycle records, signed with its
in-memory session key. These contain identifiers and state, not credentials or
session keys. They establish execution and voluntary-exit provenance, not test
coverage or successful target restoration. The earliest cancelled request can
have lifecycle evidence without a rendered report. An abrupt hard kill can leave
only initialization and execution records; that remains an unknown outcome.

## Filesystem and test isolation

Ownership checks bind canonical ordinary ancestors, native directory identities
and a fresh marker. Junctions, symbolic links, hardlinked evidence, changed
identities, changed markers and inventory overflow are refused. Inventory is
bounded to 4,096 entries with incremental directory iteration. Uncertainty causes
permanent refusal; no uncertain pathname is used for a new evidence write.
The worker can record a refusal through an already-open exclusive diagnostic
file handle without reopening an uncertain path.

The global Vitest hook creates an exclusive resource per test. The primary journal
and legacy sibling registry both stay inside it. Environment bindings are restored
and evidence is retained. Overlapping process-global environment owners fail
closed. The worker governance, API and immutable-plan regression fixtures use the
same retention capability instead of recursive/force teardown. Their original
assertions and timeouts are preserved.

`vitest.worker-lifecycle.config.mjs` is a bounded Windows verification entry point.
Its caller supplies a new owned lab with an `EVIDENCE_OWNERSHIP` marker and sets
`ROUTECAIRN_WORKER_LAB`; caches and results remain in that lab. The review packet
includes the exact launcher and source pins. New tests also work with the normal
global hook's owned resource when no explicit lab is supplied. Windows native
tests explicitly skip on other platforms; that is not non-Windows acceptance.

## Read-only independent verification

The versioned review packet includes OWNER_VERIFY.mjs and OWNER_VERIFY_WINDOWS.ps1.
They use the retained scripts/worker-review-verifier.mjs implementation, verify
packet checksums, current source/native receipts and protected prior receipts,
authenticate every tracked/nonignored file with full source/native receipts,
compare exact NUL-framed Git status (including every untracked file), compare
tracked plus nonignored file membership, reject status/index/ref drift, and check
both review patches in reverse without applying them. The exact protected
generated-artifact inventory is checked separately, including unexpected files.
Git optional locks and fsmonitor are disabled. No tests, repair, execution,
adoption or deletion are performed by the verifier.

Membership means Git tracked and nonignored files plus protected generated files.
Ignored dependency/cache/runtime directories outside that protected inventory are
not authenticated as source by this gate. The manifest and ZIP hash must still be
obtained from the independently reviewed delivery; checksums are not signatures.

## Limits and operational holds

Retention consumes disk. No sweeper, adoption mechanism, operational deletion API
or permission to delete existing evidence is introduced. Native identity checks
detect replacement; pathname operations are not a kernel directory-handle sandbox
against a malicious concurrent writer with equivalent OS privileges. The native
job custodian itself is a process: its loss is UNKNOWN and quarantined, not proof
that every descendant or target cleanup completed.

Verification uses new Windows processes, native SQLite and disposable loopback
targets. Seeded expired-lease controls are explicitly labelled as seeded metadata,
not executed scans. Full application, deployment, release, production recovery
and non-Windows acceptance remain separate. Existing Stage D and Trusted Discovery
operational holds remain in force. No Ubuntu work is authorized by this increment.
