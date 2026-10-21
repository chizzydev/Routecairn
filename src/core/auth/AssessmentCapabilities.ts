import { actorRegistryDigest, actorProofMatches, type ActorRegistry, type AssessmentFamily } from "./ActorRegistry.js";
import type { IdentityVerificationResult } from "../../reports/ReportTypes.js";
export const familyPrerequisites: Record<
  AssessmentFamily,
  {
    actors: number;
    assurance: readonly ("PRINCIPAL" | "ROLE" | "TENANT")[];
    ownerPolicy: boolean;
    effect: string;
    recovery: string;
  }
> = {
  PUBLIC_OBSERVATION: {
    actors: 0,
    assurance: [],
    ownerPolicy: false,
    effect: "REVIEWED_READ",
    recovery: "NO_MUTATION"
  },
  AUTHENTICATED_OBSERVATION: {
    actors: 1,
    assurance: [],
    ownerPolicy: false,
    effect: "REVIEWED_READ_AND_SESSION_HOUSEKEEPING",
    recovery: "NO_MUTATION"
  },
  PRINCIPAL_OBSERVATION: {
    actors: 1,
    assurance: ["PRINCIPAL"],
    ownerPolicy: false,
    effect: "REVIEWED_READ",
    recovery: "NO_MUTATION"
  },
  OWNERSHIP_COMPARISON: {
    actors: 2,
    assurance: ["PRINCIPAL"],
    ownerPolicy: true,
    effect: "EXACT_SYNTHETIC_RESOURCES",
    recovery: "NO_MUTATION"
  },
  ROLE_COMPARISON: {
    actors: 2,
    assurance: ["PRINCIPAL", "ROLE"],
    ownerPolicy: true,
    effect: "REVIEWED_PRIVILEGE_POLICY",
    recovery: "NO_MUTATION"
  },
  TENANT_COMPARISON: {
    actors: 2,
    assurance: ["PRINCIPAL", "TENANT"],
    ownerPolicy: true,
    effect: "REVIEWED_TENANT_POLICY",
    recovery: "NO_MUTATION"
  },
  BROWSER_OBSERVATION: {
    actors: 1,
    assurance: [],
    ownerPolicy: false,
    effect: "EXPLICIT_LOGIN_AND_SESSION_EFFECTS",
    recovery: "EXISTING_BROWSER_BOUNDARY"
  },
  LEGACY_SPECIALIZED: {
    actors: 2,
    assurance: ["PRINCIPAL", "ROLE", "TENANT"],
    ownerPolicy: true,
    effect: "VERSION_1_CONTRACT_REQUIRED",
    recovery: "EXISTING_CLEANUP_CONTRACT_REQUIRED"
  }
};
export type CapabilityDecision = {
  workflowId: string;
  family: AssessmentFamily;
  status: "ELIGIBLE" | "BLOCKED" | "NOT_ASSESSED" | "NOT_APPLICABLE";
  reason: string;
  actorIds: string[];
  prerequisites: (typeof familyPrerequisites)[AssessmentFamily];
  manualVerification: { kind: "HUMAN_REVIEW_ONLY"; nativeProof: false; instructions: string };
};
export function assessWorkflow(
  registry: ActorRegistry,
  id: string,
  proofs: Readonly<Record<string, IdentityVerificationResult>> = {},
  now = Date.now(),
  executionId?: string
): CapabilityDecision {
  const w = registry.workflows.find((w) => w.id === id);
  if (!w) throw Error("REVIEWED_WORKFLOW_REQUIRED");
  const p = familyPrerequisites[w.family],
    actors = w.actorIds.map((id) => registry.actors.find((a) => a.id === id)!),
    auth = actors.filter((a) => a.authentication.mechanism !== "ANONYMOUS");
  let status: CapabilityDecision["status"] = "ELIGIBLE",
    reason = "PREREQUISITES_SATISFIED_NOT_AN_EXECUTION_RESULT";
  if (!w.applicable) {
    status = "NOT_APPLICABLE";
    reason = "OWNER_DECLARED_IRRELEVANT";
  } else if (
    auth.some((a) => a.authentication.mechanism !== "ANONYMOUS" && a.authentication.availability !== "AVAILABLE")
  ) {
    status = "BLOCKED";
    reason = "ACTOR_CREDENTIAL_UNAVAILABLE";
  } else if (
    auth.some(
      (a) => a.authentication.mechanism !== "ANONYMOUS" && Date.parse(a.authentication.credentialExpiresAt) <= now
    )
  ) {
    status = "BLOCKED";
    reason = "CREDENTIAL_EXPIRED";
  } else if (
    auth.some((a) =>
      ["AUTHENTICATION_FAILED", "PRINCIPAL_MISMATCH", "ROLE_MISMATCH", "TENANT_MISMATCH"].includes(
        proofs[a.id]?.category ?? ""
      )
    )
  ) {
    status = "BLOCKED";
    reason = "NATIVE_CREDENTIAL_OR_IDENTITY_INVALID";
  } else if (w.family !== "BROWSER_OBSERVATION" && auth.some((a) => a.authentication.mechanism === "BROWSER_SESSION")) {
    status = "BLOCKED";
    reason = "BROWSER_CREDENTIAL_REQUIRES_BROWSER_WORKFLOW";
  } else if (w.family === "BROWSER_OBSERVATION" && auth.length > 1) {
    status = "BLOCKED";
    reason = "EXACTLY_ONE_BROWSER_ACTOR_REQUIRED";
  } else if (auth.length < p.actors) {
    status = "NOT_ASSESSED";
    reason = "MORE_LEGITIMATE_ACTORS_REQUIRED";
  } else if (p.ownerPolicy && !w.ownerPolicySha256) {
    status = "NOT_ASSESSED";
    reason = "REVIEWED_OWNER_POLICY_REQUIRED";
  } else if (
    p.assurance.length &&
    auth.some((a) => !actorProofMatches(registry, a.id, proofs[a.id], p.assurance, executionId))
  ) {
    status = "NOT_ASSESSED";
    reason = "NATIVE_IDENTITY_ASSURANCE_REQUIRED";
  } else if (p.actors >= 2 && new Set(auth.map((a) => proofs[a.id]?.principalHash)).size !== auth.length) {
    status = "BLOCKED";
    reason = "DISTINCT_NATIVE_PRINCIPALS_REQUIRED";
  } else if (w.family === "BROWSER_OBSERVATION" && registry.targetOrigin.startsWith("https:")) {
    status = "BLOCKED";
    reason = "EXPIRING_HTTPS_BROWSER_TRANSPORT_HOLD";
  } else if (w.family === "LEGACY_SPECIALIZED") {
    status = "BLOCKED";
    reason = "EXPLICIT_LEGACY_WORKFLOW_ADAPTER_REQUIRED";
  }
  return {
    workflowId: w.id,
    family: w.family,
    status,
    reason,
    actorIds: w.actorIds,
    prerequisites: p,
    manualVerification: {
      kind: "HUMAN_REVIEW_ONLY",
      nativeProof: false,
      instructions:
        "Review exact approved scope, source report fingerprints and missing capabilities. Supply independent native evidence or record a separately labeled human outcome; never convert a manual outcome into scanner proof."
    }
  };
}
export function assessCapabilities(
  registry: ActorRegistry,
  proofs: Readonly<Record<string, IdentityVerificationResult>> = {},
  executionId?: string
) {
  return {
    contractVersion: 2 as const,
    registryId: registry.registryId,
    actors: registry.actors.map((a) => ({
      id: a.id,
      label: a.label,
      mechanism: a.authentication.mechanism,
      credentialPresent: a.authentication.mechanism !== "ANONYMOUS" && a.authentication.availability === "AVAILABLE",
      assurance:
        a.authentication.mechanism === "ANONYMOUS"
          ? "ANONYMOUS"
          : a.authentication.availability !== "AVAILABLE" ||
              Date.parse(a.authentication.credentialExpiresAt) <= Date.now()
            ? "REVOKED_OR_INVALID"
            : ["AUTHENTICATION_FAILED", "PRINCIPAL_MISMATCH", "ROLE_MISMATCH", "TENANT_MISMATCH"].includes(
                  proofs[a.id]?.category ?? ""
                )
              ? "REVOKED_OR_INVALID"
              : actorProofMatches(registry, a.id, proofs[a.id], ["PRINCIPAL"], executionId)
                ? "PRINCIPAL_VERIFIED"
                : "CREDENTIAL_SUPPLIED_IDENTITY_UNVERIFIED",
      roleVerified: actorProofMatches(registry, a.id, proofs[a.id], ["PRINCIPAL", "ROLE"], executionId),
      tenantVerified: actorProofMatches(registry, a.id, proofs[a.id], ["PRINCIPAL", "TENANT"], executionId),
      authenticationSuccess: "NOT_INFERRED_FROM_CREDENTIAL_OR_LABEL",
      ownership: "REQUIRES_RESOURCE_POLICY_AND_NATIVE_EVIDENCE"
    })),
    workflows: registry.workflows.map((w) => assessWorkflow(registry, w.id, proofs, Date.now(), executionId)),
    nativeProof: false as const,
    independentAccuracy: false as const
  };
}

export function runtimeAssessmentCapabilities(
  registry: ActorRegistry,
  proofs: Readonly<Record<string, IdentityVerificationResult>> | undefined,
  plan: import("../../modules/apiGraphql/ApiGraphqlTypes.js").ApiGraphqlReviewPlan | undefined,
  observations: readonly import("../../reports/ApiGraphqlReport.js").ApiGraphqlCheckObservation[] | undefined,
  executionId?: string,
  browser?: import("../../reports/ReportTypes.js").BrowserCrawlReport
) {
  const base = assessCapabilities(registry, proofs, executionId);
  return {
    ...base,
    workflows: base.workflows.map((w) => {
      const cases = plan?.checks.filter((c) => ("matrixId" in c ? c.matrixId : c.id) === w.workflowId) ?? [],
        rows = cases.flatMap(
          (c) =>
            observations?.filter(
              (o) =>
                o.checkId === c.id && o.comparisonFingerprint === c.comparisonFingerprint && o.actorId === c.actorId
            ) ?? []
        ),
        evidence = rows.map((r) => ({
          checkId: r.checkId,
          comparisonFingerprint: r.comparisonFingerprint,
          outcome: r.outcome,
          reason: r.reasonCode,
          responseStatuses: r.requests.flatMap((q) => (q.statusCode === undefined ? [] : [q.statusCode])),
          observedRequests: r.requests.length
        }));
      const statuses = rows.flatMap((r) =>
        r.requests.flatMap((q) => (q.statusCode === undefined ? [] : [q.statusCode]))
      );
      const authenticationResult =
        statuses.length && statuses.every((s) => s === 401 || s === 403) ? "DENIED" : "NOT_PROVEN_BY_HTTP_STATUS";
      if (w.family === "AUTHENTICATED_OBSERVATION" && authenticationResult === "DENIED")
        return {
          ...w,
          evidence,
          authenticationResult,
          status: w.status === "BLOCKED" ? "BLOCKED" : "OBSERVED",
          reason: "NATIVE_AUTHENTICATED_REQUEST_DENIED_NOT_SESSION_SUCCESS",
          coverage: "NATIVE_DENIAL_OBSERVED"
        };
      if (w.status !== "ELIGIBLE") return { ...w, evidence, coverage: "NOT_EXECUTED_OR_NOT_CONCLUSIVE" };
      if (w.family === "BROWSER_OBSERVATION") {
        const bound = browser?.assessmentWorkflow,
          observed =
            !!bound &&
            bound.registryId === registry.registryId &&
            bound.registryFingerprint === actorRegistryDigest(registry) &&
            bound.workflowId === w.workflowId &&
            w.actorIds.includes(bound.actorId) &&
            (browser?.transmittedRequestCount ?? 0) > 0;
        return {
          ...w,
          status: observed ? "OBSERVED" : "NOT_ASSESSED",
          reason: observed ? "NATIVE_BROWSER_OBSERVATION_NOT_PRINCIPAL_PROOF" : "NO_BOUND_NATIVE_BROWSER_TRANSMISSION",
          coverage: observed ? "NATIVE_BROWSER_OBSERVATION" : "NOT_ASSESSED",
          evidence
        };
      }
      const sent = rows.some((r) => r.requests.some((q) => q.statusCode !== undefined));
      if (!sent)
        return {
          ...w,
          status: "NOT_ASSESSED",
          reason: "NO_NATIVE_RESPONSE_EVIDENCE",
          coverage: "NOT_ASSESSED",
          evidence
        };
      if (rows.some((r) => r.outcome === "BLOCKED") || rows.length !== cases.length)
        return { ...w, status: "INCONCLUSIVE", reason: "PARTIAL_NATIVE_COVERAGE", coverage: "PARTIAL", evidence };
      return {
        ...w,
        status:
          w.family === "PUBLIC_OBSERVATION" || w.family === "AUTHENTICATED_OBSERVATION"
            ? "OBSERVED"
            : rows.some((r) => r.outcome === "INCONCLUSIVE")
              ? "INCONCLUSIVE"
              : "TESTED",
        reason: "INSPECT_NATIVE_CASE_OUTCOMES_NO_APPLICATION_SECURE_CONCLUSION",
        coverage: "NATIVE_OBSERVATIONS_RETAINED",
        evidence
      };
    }),
    nativeProof: false as const,
    applicationSecureConclusion: false as const
  };
}

/** Registry execution adapters; specialized v1 engines retain their original authority contracts. */
export function registryModuleDecision(moduleId: string) {
  return [
    "baseline",
    "tech-fingerprint",
    "js-intelligence",
    "browser-crawler",
    "path-discovery",
    "api-mapper",
    "api-probe",
    "parameter-analysis",
    "vulnerability-workflows",
    "auth-surface",
    "header-review",
    "cookie-review",
    "cors-review",
    "method-review",
    "exposure-review",
    "nextjs-review",
    "api-graphql-authorization"
  ].includes(moduleId)
    ? { status: "ELIGIBLE" as const, reason: "EXISTING_BROKER_AND_PER_WORKFLOW_CAPABILITIES" }
    : { status: "BLOCKED" as const, reason: "EXPLICIT_LEGACY_WORKFLOW_ADAPTER_REQUIRED" };
}
