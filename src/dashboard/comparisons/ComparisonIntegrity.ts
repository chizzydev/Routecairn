import type { ComparisonResult } from "../types/DashboardTypes.js";

export type ComparisonFailureReason = "COMPARISON_FAILED" | "NOT_COMPUTED" | "INVALID_SUMMARY" | "INVALID_IDENTITY" | "INCOMPLETE_COMPARISON" | "INCOMPATIBLE_COMPARISON" | "INCOMPLETE_COVERAGE" | "AGGREGATE_OVERFLOW";

/** A diagnostic reference is safe to retain; arbitrary thrown messages are not. */
export class ComparisonIntegrityError extends Error {
  public readonly comparisonId: string | undefined;
  public constructor(public readonly reason: ComparisonFailureReason, comparisonId?: string) {
    super(`SCAN_COMPARISON_UNUSABLE:${reason}`);
    this.name = "ComparisonIntegrityError";
    this.comparisonId = typeof comparisonId === "string" && /^[a-f0-9-]{36}$/i.test(comparisonId) ? comparisonId : undefined;
  }
}

const summaryFields = ["new", "regressions", "recurrences", "persisting", "changed", "resolved", "notRetested", "incomparable", "severityIncreases"] as const;

export function assertComparisonSummary(value: unknown, comparisonId?: string): asserts value is ComparisonResult["summary"] {
  if (!value || typeof value !== "object" || Array.isArray(value) || summaryFields.some(key => {
    const count = (value as Record<string, unknown>)[key];
    return typeof count !== "number" || !Number.isSafeInteger(count) || count < 0;
  })) throw new ComparisonIntegrityError("INVALID_SUMMARY", comparisonId);
}

/** Computed PARTIAL results remain useful for interactive review, never a healthy assurance gate. */
export function assertComputedComparison(value: ComparisonResult, olderScanId: string, newerScanId: string): void {
  if (!value || value.schemaVersion !== 3 || !value.comparisonId || value.oldScanId !== olderScanId || value.newScanId !== newerScanId) throw new ComparisonIntegrityError("INVALID_IDENTITY", value?.comparisonId);
  if (value.state !== "COMPLETED" && value.state !== "PARTIAL") throw new ComparisonIntegrityError("NOT_COMPUTED", value.comparisonId);
  assertComparisonSummary(value.summary, value.comparisonId);
}

export function assertAssuranceComparison(value: ComparisonResult, olderScanId: string, newerScanId: string, requiredCases: readonly { workflowId: string; caseFingerprint: string }[]): void {
  assertComputedComparison(value, olderScanId, newerScanId);
  if (value.state !== "COMPLETED") throw new ComparisonIntegrityError("INCOMPLETE_COMPARISON", value.comparisonId);
  const c = value.coverage;
  if (value.compatible !== true || value.compatibilityState !== "COMPATIBLE" || !c || c.sameTarget !== true || !["EQUIVALENT_FOR_FINDING", "EXPANDED"].includes(c.scopeState) || c.authenticationState !== "EQUIVALENT" || c.identityState !== "EQUIVALENT") throw new ComparisonIntegrityError("INCOMPATIBLE_COMPARISON", value.comparisonId);
  const completeQuality = (quality: string | undefined) => quality === "NATIVE_FULL" || quality === "IMPORTED_WITH_COVERAGE";
  if (!completeQuality(value.sourceQuality?.older) || !completeQuality(value.sourceQuality?.newer) || !Array.isArray(c.sharedModules) || c.sharedModules.length === 0 || !Array.isArray(c.omittedModules) || c.omittedModules.length > 0 || !Array.isArray(c.modules) || c.modules.length === 0 || c.modules.some(m => m.olderState !== "NOT_PLANNED" && (m.comparable !== true || m.olderState !== "COMPLETED" || m.newerState !== "COMPLETED")) || !Array.isArray(c.workflows) || c.workflows.some(w => w.olderConfigured && w.comparable !== true) || !Array.isArray(c.cases) || c.cases.some(item => item.state !== "CASE_MATCHED_EXECUTED" || item.compatibility !== "COMPATIBLE") || requiredCases.some(required => !c.cases.some(item => item.workflowId === required.workflowId && item.safeCaseFingerprint === required.caseFingerprint && item.state === "CASE_MATCHED_EXECUTED" && item.compatibility === "COMPATIBLE"))) throw new ComparisonIntegrityError("INCOMPLETE_COVERAGE", value.comparisonId);
}

export interface AssuranceComparisonTotals { regressions: number; newFindings: number; incomparable: number; notRetested: number; }

/** Validate all additions before publishing any counter; a rejected lane contributes no partial totals. */
export function addAssuranceComparison(totals: AssuranceComparisonTotals, comparison: ComparisonResult): AssuranceComparisonTotals {
  const next = {
    regressions: totals.regressions + comparison.summary.regressions + comparison.summary.severityIncreases,
    newFindings: totals.newFindings + comparison.summary.new,
    incomparable: totals.incomparable + comparison.summary.incomparable,
    notRetested: totals.notRetested + comparison.summary.notRetested
  };
  if (Object.values(next).some(count => !Number.isSafeInteger(count) || count < 0)) throw new ComparisonIntegrityError("AGGREGATE_OVERFLOW", comparison.comparisonId);
  return next;
}
