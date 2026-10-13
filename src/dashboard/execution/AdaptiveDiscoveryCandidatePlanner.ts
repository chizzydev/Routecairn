import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { adaptiveObservedInputV1Schema, type AdaptiveObservedInputV1 } from "./AdaptiveObservedInputIR.js";
import { projectAdaptiveObservedInputs, type ObservedInputProjection } from "./AdaptiveObservedInputProjection.js";
import { compareDiscoveryCandidates, discoveryCandidateBounds as bounds, discoveryCandidateId, discoveryReviewFacts, emptyDiscoveryEvidenceSummary, parseAdaptiveDiscoveryCandidate, type DiscoveryCandidateV1, type DiscoveryPlannerDiagnostic, type DiscoveryAccountingEntry } from "./AdaptiveDiscoveryCandidateIR.js";

export interface DiscoveryCandidatePlan {
  candidates: DiscoveryCandidateV1[];
  diagnostics: DiscoveryPlannerDiagnostic[];
  upstreamDiagnostics: ObservedInputProjection["diagnostics"];
  sourceCounts: ObservedInputProjection["sourceCounts"];
  accountedObservations: number;
  accountingLedger: DiscoveryAccountingEntry[];
}
/** Shadow planner only. FIRST derive NG4 evidence; never access raw report fields or pair exchanges here. */
export function planAdaptiveDiscoveryCandidates(report: RouteCairnReport): DiscoveryCandidatePlan {
  try { return plan(projectAdaptiveObservedInputs(report)); }
  catch { return { candidates: [], diagnostics: [{ code: "INVALID_INPUT" }], upstreamDiagnostics: [], sourceCounts: { brokerAudit: 0, browserNetwork: 0, apiMapper: 0, responses: 0 }, accountedObservations: 0, accountingLedger: [] }; }
}
function plan(upstream: ObservedInputProjection): DiscoveryCandidatePlan {
  const result: DiscoveryCandidatePlan = { candidates: [], diagnostics: [], upstreamDiagnostics: upstream.diagnostics, sourceCounts: upstream.sourceCounts, accountedObservations: upstream.observations.length, accountingLedger: [] };
  if (upstream.diagnostics.some((value) => value.producer === undefined)) { result.diagnostics.push({ code: "UPSTREAM_FAILED" }); return result; }
  const groups = new Map<string, { members: { observation: AdaptiveObservedInputV1; index: number }[] }>();
  const ledger = new Map<number, DiscoveryAccountingEntry>();
  const omit = (observation: AdaptiveObservedInputV1, observationIndex: number, code: "SOURCE_REFERENCE_LIMIT" | "CANDIDATE_LIMIT" | "INVALID_CANDIDATE" | "INVALID_OBSERVATION") => {
    const binding = { observationIndex, producer: observation.producer, sourceIndex: observation.sourceIndex, observationId: observation.observationId };
    result.diagnostics.push({ ...binding, code }); ledger.set(observationIndex, { ...binding, state: "OMITTED", code });
  };
  for (let index = 0; index < upstream.observations.length; index++) {
    const observation = upstream.observations[index]!;
    if (!adaptiveObservedInputV1Schema.safeParse(observation).success) { omit(observation, index, "INVALID_OBSERVATION"); continue; }
    const key = discoveryCandidateId({ targetOrigin: observation.targetOrigin, originRelation: observation.originRelation, method: observation.method, routeOrdinal: observation.routeOrdinal });
    const group = groups.get(key) ?? { members: [] }; group.members.push({ observation, index }); groups.set(key, group);
  }
  for (const [candidateId, { members }] of groups) {
    // Atomic affected-group policy: never emit a subset when membership exceeds the cap.
    if (members.length > bounds.references || groups.size > bounds.groups || upstream.observations.length > bounds.totalReferences) {
      for (const member of members) omit(member.observation, member.index, members.length > bounds.references ? "SOURCE_REFERENCE_LIMIT" : "CANDIDATE_LIMIT"); continue;
    }
    const first = members[0]!.observation; const summary = emptyDiscoveryEvidenceSummary();
    const sourceReferences = members.map(({ observation }) => { summary[observation.disposition]++; return { producer: observation.producer, sourceIndex: observation.sourceIndex, observationId: observation.observationId, disposition: observation.disposition }; });
    const reportCompleteness = members.every(({ observation }) => observation.reportCompleteness === "COMPLETED_REPORTED") ? "COMPLETED_REPORTED" as const : "INCOMPLETE_OR_UNKNOWN" as const;
    // NG4 diagnostics intentionally lack a public route. Never guess their route from private input.
    // Conservative global review barrier preserves unknown contradictions across every remaining group.
    const upstreamEvidenceIncomplete = upstream.diagnostics.length > 0;
    const candidate = parseAdaptiveDiscoveryCandidate({ schemaVersion: 1, candidateId, targetOrigin: first.targetOrigin, originRelation: first.originRelation, routeOrdinal: first.routeOrdinal, method: first.method,
      sourceReferences, evidenceSummary: summary, reportCompleteness, upstreamEvidenceIncomplete, producerCoverage: new Set(sourceReferences.map((value) => value.producer)).size,
      ...discoveryReviewFacts(summary, first.method, first.originRelation, upstreamEvidenceIncomplete, reportCompleteness),
      status: "REQUIRES_OPERATOR_REVIEW", executable: false, executionAuthority: "NONE", approval: "NOT_GRANTED", credentialsResolved: false, authorizationDecision: "UNKNOWN", vulnerabilityConclusion: "NOT_ASSESSED", cleanup: "NOT_ASSESSED" });
    if (!candidate) { for (const member of members) omit(member.observation, member.index, "INVALID_CANDIDATE"); continue; }
    result.candidates.push(candidate);
    for (const { observation, index } of members) ledger.set(index, { observationIndex: index, producer: observation.producer, sourceIndex: observation.sourceIndex, observationId: observation.observationId, state: "CANDIDATE", candidateId });
  }
  result.candidates.sort(compareDiscoveryCandidates);
  result.accountingLedger = [...ledger.values()].sort((a, b) => a.observationIndex - b.observationIndex);
  result.diagnostics.sort((a, b) => (a.observationIndex ?? -1) - (b.observationIndex ?? -1));
  return result;
}
/** Full strict context equality, not identity-hash approval. Reports with identical safe facts remain equivalent. */
export function validateAdaptiveDiscoveryCandidate(input: unknown, report: RouteCairnReport): boolean {
  try {
    const parsed = parseAdaptiveDiscoveryCandidate(input); if (!parsed) return false;
    const expected = planAdaptiveDiscoveryCandidates(report).candidates.find((value) => value.candidateId === parsed.candidateId);
    return Boolean(expected) && JSON.stringify(parsed) === JSON.stringify(expected);
  } catch { return false; }
}
