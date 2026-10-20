import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { assertAssuranceComparison, assertComparisonSummary, assertComputedComparison, addAssuranceComparison } from "../../src/dashboard/comparisons/ComparisonIntegrity.js";
import { syntheticAssuranceComparison } from "../helpers/continuous-assurance-comparison-result.js";

describe("comparison evidence integrity (pure boundary checks)", () => {
  const older = randomUUID(), newer = randomUUID();
  const required = [{ workflowId: "api-graphql-authorization", caseFingerprint: "c".repeat(64) }];
  for (const field of ["new", "regressions", "recurrences", "persisting", "changed", "resolved", "notRetested", "incomparable", "severityIncreases"] as const) {
    for (const bad of [undefined, null, "0", -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) it(`rejects ${field}=${String(bad)}`, () => {
      const c = syntheticAssuranceComparison(older, newer);
      expect(() => assertComparisonSummary({ ...c.summary, [field]: bad }, c.comparisonId)).toThrow("INVALID_SUMMARY");
    });
  }
  for (const state of ["PENDING", "ANALYZING", "FAILED", "STALE"] as const) it(`refuses ${state} as computed evidence`, () => {
    const c = syntheticAssuranceComparison(older, newer); c.state = state;
    expect(() => assertComputedComparison(c, older, newer)).toThrow("NOT_COMPUTED");
  });
  it("preserves partial results for review but rejects them for assurance", () => {
    const c = syntheticAssuranceComparison(older, newer); c.state = "PARTIAL";
    expect(() => assertComputedComparison(c, older, newer)).not.toThrow();
    expect(() => assertAssuranceComparison(c, older, newer, required)).toThrow("INCOMPLETE_COMPARISON");
  });
  it("rejects a valid-looking result for the wrong scan pair", () => {
    expect(() => assertAssuranceComparison(syntheticAssuranceComparison(older, randomUUID()), older, newer, required)).toThrow("INVALID_IDENTITY");
  });
  it("requires exact comparison case coverage, not merely zero findings", () => {
    const c = syntheticAssuranceComparison(older, newer); c.coverage.cases = [];
    expect(() => assertAssuranceComparison(c, older, newer, required)).toThrow("INCOMPLETE_COVERAGE");
  });
  it("rejects invalid source quality and identity semantics", () => {
    const c = syntheticAssuranceComparison(older, newer); c.sourceQuality.newer = "IMPORTED_FINDINGS_ONLY";
    expect(() => assertAssuranceComparison(c, older, newer, required)).toThrow("INCOMPLETE_COVERAGE");
    c.sourceQuality.newer = "NATIVE_FULL"; c.coverage.identityState = "CHANGED";
    expect(() => assertAssuranceComparison(c, older, newer, required)).toThrow("INCOMPATIBLE_COMPARISON");
  });
  it("adds counters atomically and refuses intra-lane and cross-lane overflow", () => {
    const c = syntheticAssuranceComparison(older, newer);
    const zero = { regressions: 0, newFindings: 0, incomparable: 0, notRetested: 0 };
    c.summary.regressions = Number.MAX_SAFE_INTEGER; c.summary.severityIncreases = 1;
    expect(() => addAssuranceComparison(zero, c)).toThrow("AGGREGATE_OVERFLOW"); expect(zero.regressions).toBe(0);
    c.summary.regressions = 0; c.summary.severityIncreases = 0; c.summary.new = 1;
    expect(() => addAssuranceComparison({ ...zero, newFindings: Number.MAX_SAFE_INTEGER }, c)).toThrow("AGGREGATE_OVERFLOW");
  });
});
