# Continuous Assurance comparison integrity

Continuous Assurance accepts a comparison as complete evidence only when its scan
pair, schema, terminal state, source quality, identity, coverage and exact policy
cases agree. All nine summary counters must be nonnegative safe integers. Counter
aggregation is atomic and rejects overflow.

An unavailable or rejected comparison makes the run inconclusive and nonquiet,
with an approval notification. `safeSummary.comparisonTotalsComplete` distinguishes
complete totals from known totals with unavailable lanes. `comparisonFailures`
contains bounded reason codes and diagnostic comparison references; arbitrary
exception messages are not copied into it. Existing cleanup, authorization,
UNKNOWN submission and deployment replay restrictions continue to apply.

`ScanComparisonService.compare()` refuses failed, pending, analyzing, stale and
malformed cached results. It preserves the stored comparison and does not retry or
recompute automatically. Callers can inspect diagnostics using `get()`. Computed
PARTIAL results remain available for interactive review, but cannot establish a
healthy assurance gate. Persisted summary JSON is validated before automation can
use the legacy display fallback. Observed workflow identifiers are included in
comparison coverage, including workflows outside the original seven categories.

## Retained native test gate

Use the installed Node runtime and dependencies. No dependency installation,
build, release operation, product scan worker or external target is needed.
The repository's normal Vitest configuration still has a deletion hook; use the
dedicated configuration for this gate. All test and hook deadlines remain 30 seconds.

In a **new, exclusively owned directory outside the repository**, create an
`EVIDENCE_OWNERSHIP` file with a fresh random value. For the interruption tests also
create `LAB_OWNERSHIP` containing exactly
`CA_WINDOWS_GENERATED_FIXTURES_ONLY_NO_UBUNTU` followed by a newline. Bind these
variables in the child process environment only:

- `ROUTECAIRN_CA_COMPARISON_FIXTURE_PARENT`: that new directory.
- `ROUTECAIRN_CA_LAB`: that new directory for the interruption scenarios.
- `TEMP`, `TMP`, `TMPDIR`: a new child directory of that directory.
- `ROUTECAIRN_MUTATION_DIR`: a new `journals/primary` child directory; the legacy
  sibling registry therefore also stays inside the owned fixture.
- `TSX_DISABLE_CACHE=1` and `NODE_DISABLE_COMPILE_CACHE=1`.

Run from the repository, with an output path inside the same owned directory:

```text
node node_modules/vitest/vitest.mjs run --config vitest.comparison.config.mjs --configLoader native
```

The configuration binds Vite caches to the owned directory and loads no original
global teardown. The original CA fixture now retains its newly created roots.
The interruption tests use only their owned ephemeral IPv4 loopback server and
synthetic worker/comparison/export ports. They do not exercise the actual scan
worker. The native comparison tests use real SQLite, migrations, the comparer and
CA service. Completed scan and case rows are explicitly `SEEDED_NOT_EXECUTED`.
Three `PORT_*` tests add explicit consumer boundary faults to a real comparison;
they are not representations of native cache corruption. Export counters measure
eligibility only, not encrypted export delivery.

Alternatively, on Node 24, execute a single native scenario using the new helper:

```text
node --experimental-transform-types tests/helpers/continuous-assurance-comparison-fixture.ts C04 <owned-directory>
```

This source-only driver uses Node's TypeScript transform and a constrained `.js`
to `.ts` resolver, without tsx/esbuild caches. It exits 0 on PASS, 1 on a proven
assertion RED, and 2 on setup BLOCKED/uncertain outcomes. Root, main database,
sentinel, raw SQL truth and failure receipts are retained. Native SQLite may manage
its normal rollback journal/WAL/SHM inside the new database directory. Before/after
inventories are not a complete filesystem event trace. Never clean old fixture or
operator directories as part of this gate.

## Compatibility and evidence limits

The repair applies to subsequent comparison use and assurance finalization. It
does not silently rewrite prior terminal run records or retry failed comparisons.
Pre-repair PASSED/quiet evidence requires operator review; retained RED evidence
must remain intact. The display-oriented `get()` API continues to expose failed
comparison diagnostics. Its legacy summary fallback is not automation evidence.

These targeted tests do not establish full-suite, external scanning, actual scan
worker, Ubuntu, production deployment, exactly-once encrypted export, disk
power-loss durability or independent operator acceptance. Stage D holds remain.
