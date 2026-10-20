import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
import type { ApplicationMappingInput } from "../contracts/ApplicationMappingContracts.js";
import type { buildApplicationHypotheses } from "./ApplicationSecurityHypotheses.js";
import type { AuthorizationWorkbenchInput } from "../contracts/AuthorizationWorkbenchContracts.js";
type Candidate = ReturnType<typeof buildApplicationHypotheses>[number];
export const DIFFERENTIAL_VERSION = "reviewed-role-state-observations-v1";
export function buildDifferentialEvidence(
  input: ApplicationMappingInput,
  candidates: Candidate[],
  workflow: { name: string; routeIds: string[] }
) {
  const steps = workflow.routeIds.map((routeId, i) => {
    const r = input.routes.find((r) => r.id === routeId),
      c = candidates.find((c) => c.routeId === routeId);
    if (!r || !c) throw Error("WORKBENCH_FLOW_EXACT_UNIQUE_ROUTE_REQUIRED");
    const states = r.statePaths ?? [];
    const reasons = c.missingControls.filter((r) => r !== "NO_SHARED_TYPED_MARKER_ACCESS");
    if (!states.length) reasons.push("DECLARED_OBSERVED_STATE_REQUIRED");
    for (const path of states)
      if (
        !c.evidence[0]?.markers.some(
          (m) => m.path === path && m.fingerprint && ["number", "string"].includes(m.scalarType)
        )
      )
        reasons.push("TYPED_STATE_CONTROL_REQUIRED:" + path);
    return {
      routeId,
      candidateId: c.candidateId,
      dependsOn: i ? [workflow.routeIds[i - 1]!] : [],
      statePaths: states,
      kind: r.kind,
      irCaseIds: c.irCaseIds,
      missingControls: reasons
    };
  });
  const missingControls = steps.flatMap((s) => s.missingControls.map((r) => s.routeId + ":" + r));
  return {
    version: DIFFERENTIAL_VERSION,
    flowId: adaptiveDigest({ purpose: DIFFERENTIAL_VERSION, name: workflow.name, steps }),
    name: workflow.name,
    steps,
    eligibility: missingControls.length ? "ABSTAIN" : "EVIDENCE_READY_FOR_POLICY_REVIEW",
    missingControls,
    dependencyMeaning: "OWNER_DECLARED_READ_ONLY_PREREQUISITE_NOT_PROVEN_CAUSAL_TRANSITION",
    stateChangingExecution: "HOLD",
    executionAuthority: "NONE",
    maximumModuleRequests: steps.length * 4,
    maximumSharedRequests: 40,
    probabilityClaimed: false
  };
}
export function reviewedDifferentialExpectations(
  snapshot: { flow?: ReturnType<typeof buildDifferentialEvidence>; candidates: Candidate[] },
  value: AuthorizationWorkbenchInput["expectations"]
) {
  const flow = snapshot.flow;
  if (!flow || flow.version !== DIFFERENTIAL_VERSION || flow.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW")
    throw Error("WORKBENCH_FLOW_ABSTAIN_OR_VERSION");
  if (JSON.stringify(value.map((e) => e.routeId)) !== JSON.stringify(flow.steps.map((s) => s.routeId)))
    throw Error("WORKBENCH_FLOW_EXACT_ORDER_REQUIRED");
  for (const [i, e] of value.entries()) {
    const step = flow.steps[i]!,
      c = snapshot.candidates.find((c) => c.candidateId === step.candidateId)!;
    const matches = (m: { path: string; expectedValue: string | number } | undefined) =>
      !!m &&
      c.evidence[0]!.markers.some(
        (p) =>
          p.path === m.path &&
          p.scalarType === typeof m.expectedValue &&
          p.fingerprint === observedMarkerFingerprint(m.expectedValue)
      );
    if (
      e.url !== c.url ||
      e.kind !==
        (c.kind === "FUNCTION"
          ? "FUNCTION_AUTHORIZATION"
          : c.tenantPath
            ? "TENANT_ISOLATION"
            : "OBJECT_AUTHORIZATION") ||
      e.identity?.path !== c.identityPath ||
      !matches(e.identity) ||
      (c.tenantPath && (e.tenant?.path !== c.tenantPath || !matches(e.tenant))) ||
      e.decisions.primary !== "ALLOW" ||
      Object.values(e.decisions).some((d) => d === "UNKNOWN") ||
      JSON.stringify(e.dependsOn ?? []) !== JSON.stringify(step.dependsOn)
    )
      throw Error("WORKBENCH_FLOW_POLICY_OR_OBJECT_BINDING_REQUIRED");
    if (
      !e.states ||
      JSON.stringify(e.states.map((s) => s.path).sort()) !== JSON.stringify([...step.statePaths].sort()) ||
      !e.states.every(matches)
    )
      throw Error("WORKBENCH_FLOW_EXACT_TYPED_STATE_REQUIRED");
  }
  return value;
}
