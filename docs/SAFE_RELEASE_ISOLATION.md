# A1 source isolation: code-only review boundary

The frozen parent is `8192cda2b8475306ecbec215f7c3623d74af25ee`.
This tooling is excluded from the unchanged package allowlist and product startup.
It preserves the fourteen D0 changes, all 235 original tests and generated output.
It does not grant execution, installation, packaging, publication or deployment authority.

## Read-only interface

Both `--plan` and `--verify` require explicit absolute paths. There is no default action,
output directory, copy mode, npm launcher, network request or lifecycle dispatcher.
Review the implementation packet and pin its manifest SHA256 independently first.

```text
node scripts/safe-release-preflight.mjs --plan --repo <absolute-repository>
  --baseline <absolute-original-final-preflight-manifest.json>
  --original-review <absolute-original-d0-reviewed-inputs.json>
  --review-inputs <absolute-A1_REVIEW_INPUTS.json>
  --review-sha256 <independently-reviewed-A1-manifest-SHA256>
```

`--verify` uses the same arguments. The manifest and original D0 manifest have pinned
byte hashes. The source digest cannot be regenerated to accept changed files.
The new manifest permits only the fourteen unchanged D0 paths plus the four A1 paths.
The index, local refs, exact tracked/untracked path set, hashes and generated inventory
are checked before and after source analysis. Reads use bounded file descriptors and
BigInt native identity checks. Original source and generated files are never written.

Exit **1** means refusal/error. Exit **2** means completed read-only checks with explicit
HOLDs. No exit currently grants real materialization or release authority. Output is
bounded JSON on stdout; refusal output contains a code without native paths or secrets.
The executable does not query a live remote because that would violate its no-network
contract. `origin/main` is not treated as current GitHub evidence. A separately approved
read-only live GitHub comparison is required before any future materialization.

## Source dependency analysis

The frozen 609 inputs are verified against the 1059-file reviewed source inventory.
TypeScript AST analysis resolves direct/export/transitive literal imports, local URL
resources, UI HTML/CSS references, compiler includes (including UI tests), config extends
and types, pinned standards assets, both dependency locks, original script topology,
runtime copy assets and source package allowlist entries. Missing, ambiguous, unlocked
or protected transitive dependencies refuse the plan. The parser never evaluates scripts.
Computed imports, runtime filesystem calls and installed consumer behavior remain
separate HOLDs. A static dependency graph is not proof of unrestricted runtime closure.

## Synthetic executor

The only physical copy API accepts an opaque in-process capability issued when creating
**2–5 synthetic files of at most 4096 bytes each** in a freshly generated owned directory.
It cannot accept an owner manifest, existing source directory or 609 files. Destination
creation is exclusive; writes use ordinary descriptors, never links, reflinks, worktrees
or shared dependencies. Destination hashes, sizes, native identities and link counts are
verified, then source bytes and identities are rechecked. Tests edit copied bytes and
replace identities while preserving original synthetic sentinels.

Ownership binds a random marker, generated root and exact parent identity. Cleanup first
plans the complete tree with entry, byte and depth limits, then checks ownership, every
parent and each target immediately before explicit unlink/rmdir. The marker is removed
last. No recursive removal occurs in this implementation. Partial failures retain the
root/marker where possible and retire the capability; they never become cleanup success
or a retry authorization. Wrong ownership, aliases, links, replacement and cap overruns
refuse deletion. The caller retains evidence for incomplete or ambiguous ownership.

## Limits and limitations

Source: 1500 files / 256 MiB; each input: 32 MiB. Candidate: fewer than 1000 files and
8 MiB. Cleanup: 512 entries / 64 MiB / depth 12. Output/stdout/stderr: 2 MiB each.
Future process policy: 30 seconds and 512 MiB RSS; no lifecycle process is launched.
Minimum free space is 2 GiB, with a conservative peak estimate adding source/build/
consumer/archive/log copies and three dependency/native-build copies plus 50% margin.
The dependency estimate still needs independent measurement and approval.

**609 files already exceed the 512-entry cleanup cap.** No real owner-copy executor is
implemented: resolving cleanup partitioning, exclusive source/scratch custody, atomic
native path handling and lifecycle confinement requires a separately reviewed increment.
Descriptor checks detect substitutions at boundaries; they are not an atomic portable
defense against concurrent hostile directory writers. Windows reparse/ACL/mount behavior
needs native proof; unsupported link creation is BLOCKED without elevation. Linux needs
an actual independent Ubuntu run. Never infer either from mocks or Windows results.

The pure environment proposal declares an independent approved runtime PATH, home/profile,
npm cache/config/prefix, temporary/tool/browser caches, dashboard data and separate logs.
It inherits no environment and refuses paths falling back into protected owner roots.
This declaration creates no directories, modifies no process environment and authorizes
no network, npm script or install. OS variables and runtime custody remain native review.

## Unchanged Stage D gates

D0 full acceptance retains the existing strict zero-skip rule; the prior 45 conditional
skips remain HOLD. Old compiled route evidence is retained, not rerun in A1. Internal
`executeFresh` remains present; complete exports/startup/routes/fixture/interface and
installed consumer review is required. String/AST scans do not establish general
inaccessibility. All D1 custody/ceremony/recovery/platform, D2 external monotonic anchor,
D3 approved bridge/UI/network and D4 platform/package/documentation/signoff/continuity
gates remain HOLD. No witness reset/provisioning, HTTP execution, consent/spend or
outcome changes are introduced. Neither the packet hashes nor a local PASS constitute
independent authorship, security signoff or release approval.

Owner-verification scripts in the packet are drafts for independent source review.
They only authenticate inputs and run this read-only verifier, never install or pack.
Codex does not invoke them or report owner acceptance.

## A1B structural cleanup proposal (synthetic opt-in only)

The original A1 API and its 512-entry/64 MiB/depth-12 denials remain unchanged.
The separate `A1B_SYNTHETIC_PROPOSAL_V1` generator accepts only five fixed profile
names and an approved parent, generates constant tiny files, and issues a separate
opaque in-process capability. It accepts no source roots, file contents, existing
manifests or adoption requests. It has no copy, install or lifecycle interface.

Measured from the unchanged 609-input manifest: **609 files +124 directories +one
marker +one workspace root =735 members**, 14,649,723 source bytes, largest input
3,849,998 bytes, maximum relative depth five. The larger proof uses 750 generated
files with the same 124-directory count: **876 members**. The proposed aggregate
bound is exactly 876; byte bound 14,649,759 (measured source bytes +36-byte marker),
single file 3,849,998, depth five, direct fanout 125. Every deletion batch remains
at most 512 unique members, including marker/root membership. These are additional
aggregate deletion limits requiring independent policy review and owner approval;
they are not unchanged authority and do not authorize any real tree.

Selected strategy: one bounded, complete global inventory and exact generated
layout/provenance verification before the first deletion. Independent subtree
tokens would not bound disposal of a contiguous assembled tree; containers/native
ephemeral volumes need separately approved custody and infrastructure. Neither is
silently adopted here. Dependencies, consumers, build outputs, native ABI resources
and their cleanup are outside this source-only proposal.

The planner captures every directory, file, marker and root and predetermines a
stable postorder schedule. The public plan is a detached data copy; only its private
frozen counterpart can be used by the single root capability. No batch token exists.
Pure schedule validation cannot authorize I/O. Marker and root are adjacent terminal
members in the final batch (a 513-member schedule is split 511+2). Marker removal is
the last file removal; root removal is last. After marker removal only that exact
empty root may be removed, using the already-spent terminal state and pinned root.

At each batch boundary the remaining whole tree is validated against the original
plan, never scanned to acquire new deletion authority. Before every operation the
target, complete parent chain, original root, marker, generation and memberships
are checked. After a confirmed deletion only its direct parent's expected metadata
may advance, after exact remaining-child coverage and native link-count checks.
Native canonical resolution and bounded descriptor reads preserve identity checks
without repeatedly emulating full path traversal. No original A1 guard is weakened.
All operations use explicit unlink/rmdir; no recursive deletion or force fallback.

Any planning refusal removes zero members and retires the capability. Any operation,
hook, deadline or uncertain native failure returns `RETAINED_INCOMPLETE` with phase,
confirmed removal count, completed batches and marker/root disposition. Re-entry
is refused, including after partial removal. Unexpected files remain for review.
Tests inject faults before operations and between batches; these are synthetic
faults, not claims of actual native syscall failures. A per-operation 25-second
deadline and existing 30-second test threshold are retained. Source JSON plans and
receipts omit owner paths, marker contents and reusable credentials.

These checks are best-effort boundary detection, not atomic protection against
concurrent hostile writers. Native Windows reparse/ACL/mount custody, actual Linux,
external anchor, all D1–D4 and independent signoff remain HOLD. The read-only CLI
reports the proposal but neither generates nor deletes a structural fixture.
There is still no real 609-file materializer, npm launcher or production authority.

## Nested-topology falsification follow-on (HOLD)

The separate test-owned `createNestedStructuralSyntheticFixture` accepts only
`files609` or `files750` and the existing explicit synthetic policy identifier.
Its private fixed template contains exactly the 124 directory label strings from
the frozen A1B policy proposal. The canonical JSON array SHA-256 is
`c78542985009c6e2d47744c4aa47150a96b34914d8dc80772039d949011e1d64`.
These are synthetic labels, not files copied from the owner's repository. Every
label receives tiny generated text files; directory depth is four, file depth five.
Expected totals remain 735 and 876, with batches 512+223 and 512+364. No caller
path array, source manifest, file content, existing root or generic copy is accepted.

Only the new generator, appended tests and this note are introduced. The preceding
A1/A1B module bytes, all previous153 tests, read-only preflight, cleanup semantics,
opaque capability rules, legacy512/proposed876 caps,25-second operation budget and
original30-second test threshold remain unchanged. Construction checks the complete
parent chain and promotes parent metadata only after a confirmed fixed creation
with exact child membership. Existing cleanup is reused without modification.

The RED tests reproduced the original flat labels. Subsequent nested operation
bodies completed and recorded root absence, exact inventory and postorder, but
full Vitest results remain authoritative: the750-file positive repeatedly exceeded
30 seconds in this Windows environment. Shorter owned labs and a linear every-edge
assertion retained every safety check and did not resolve the protected test gate.
The609-file case passed in later runs; this is not a complete nested acceptance.

The nested falsification is therefore HOLD. No timeout increase, guard weakening,
forced cleanup, extra deletion authority or privilege change is authorized. The
remaining interruption/substitution/native-link matrix is NOT EXECUTED after this
stop; previous flat/native BLOCKED evidence is not relabeled as nested proof.
Failure logs, exact producer sources and all attempts remain available for review.
Owner read-only markers and independent Linux flat receipts are supplied evidence,
not new builder execution or an operational approval. Real materialization, npm,
release, OS custody, native Linux, D1-D4 and independent operational signoff remain HOLD.