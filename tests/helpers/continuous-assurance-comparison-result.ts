import { randomUUID } from "node:crypto";
import type { ComparisonResult } from "../../src/dashboard/types/DashboardTypes.js";

/** Complete synthetic port contract for orchestration tests, NOT native comparer evidence. */
export function syntheticAssuranceComparison(oldScanId: string, newScanId: string, newFindings = 0): ComparisonResult {
  return {
    schemaVersion: 3, comparisonId: randomUUID(), engineVersion: "synthetic-test-port", state: "COMPLETED", oldScanId, newScanId,
    compatible: true, compatibilityState: "COMPATIBLE", sourceQuality: { older: "NATIVE_FULL", newer: "NATIVE_FULL" }, warnings: [],
    coverage: {
      sameTarget: true, scopeState: "EQUIVALENT_FOR_FINDING", authenticationState: "EQUIVALENT", identityState: "EQUIVALENT",
      oldProfile: "full", newProfile: "full", oldCompletedModules: ["api-graphql-authorization"], newCompletedModules: ["api-graphql-authorization"], sharedModules: ["api-graphql-authorization"], omittedModules: [], addedModules: [],
      modules: [{ moduleId: "api-graphql-authorization", olderState: "COMPLETED", newerState: "COMPLETED", comparable: true, reasonCode: "SYNTHETIC_PORT", reason: "Synthetic orchestration contract" }],
      workflows: [{ workflowId: "api-graphql-authorization", olderConfigured: true, newerConfigured: true, olderCaseCount: 1, newerCaseCount: 1, matchedCases: 1, missingCases: 0, changedCases: 0, executedMatchedCases: 1, comparable: true, reason: "Synthetic orchestration contract" }],
      cases: [{ workflowId: "api-graphql-authorization", safeCaseFingerprint: "c".repeat(64), safeCaseAlias: "synthetic-contract", state: "CASE_MATCHED_EXECUTED", compatibility: "COMPATIBLE", reasonCode: "SYNTHETIC_PORT", reason: "Synthetic orchestration contract" }]
    },
    planDiff: [], summary: { new: newFindings, regressions: 0, recurrences: 0, persisting: 0, changed: 0, resolved: 0, notRetested: 0, incomparable: 0, severityIncreases: 0 }, items: [],
    findings: { new: [], persisting: [], changed: [], resolved: [], notRetested: [], incomparable: [], regressions: [] }
  };
}
