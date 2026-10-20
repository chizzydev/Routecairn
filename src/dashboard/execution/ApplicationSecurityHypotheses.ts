import { adaptiveDigest } from "./AdaptiveCanonical.js";
import type { ApplicationMappingService } from "./ApplicationMappingService.js";
export const HYPOTHESIS_ALGORITHM = "native-marker-boundary-review-v1";
type Map = ReturnType<ApplicationMappingService["result"]>;
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
export function buildApplicationHypotheses(map: Map, org: string, caseIds: (routeId: string) => string[]) {
  const unique = new Set<string>();
  return [...map.input.routes]
    .sort((a, b) => order(a.id, b.id))
    .flatMap((route) => {
      const logicalId = adaptiveDigest({
        purpose: HYPOTHESIS_ALGORITHM,
        org,
        target: map.input.targetId,
        credentials: map.input.credentials,
        url: route.url,
        template: route.pathTemplate,
        kind: route.kind,
        identityPath: route.identityPath,
        tenantPath: route.tenantPath ?? null,
        ...(route.statePaths ? { statePaths: route.statePaths } : {})
      });
      if (unique.has(logicalId)) return [];
      unique.add(logicalId);
      const observed = map.observations.find((r) => r.routeId === route.id),
        paths = [route.identityPath, ...(route.tenantPath ? [route.tenantPath] : []), ...(route.statePaths ?? [])];
      const evidence = ["primary", "account-a", "account-b", "anonymous"].map((actorId) => {
        const c = observed?.cells.find((c) => c.actorId === actorId),
          slot = actorId.replaceAll("-", "_") as keyof typeof map.input.credentials;
        const markers = paths.map((path) => {
          const m = c?.observedMarkers.find((m) => m.path === path);
          return {
            path,
            scalarType: m?.scalarType ?? "UNKNOWN",
            fingerprint: m && /^[a-f0-9]{64}$/.test(m.valueFingerprint) ? m.valueFingerprint : null
          };
        });
        const markerReady = markers.every((m) => m.fingerprint && ["string", "number"].includes(m.scalarType));
        return {
          actorId,
          credentialReference: actorId === "anonymous" ? null : (map.input.credentials[slot] ?? null),
          tenantFingerprint: c?.tenantFingerprint ?? null,
          roleFingerprint: c?.role ? adaptiveDigest(c.role) : null,
          roleLabel: c?.role ?? null,
          checkId: route.id + "-observe-" + actorId,
          nativeOutcome: c?.nativeOutcome ?? "UNOBSERVED",
          decision: c?.nativeDecision ?? "UNCLASSIFIED",
          statusCode: c?.statusCode ?? null,
          identityVerified: actorId === "anonymous" ? true : c?.identityVerified === true,
          markers,
          markerReady
        };
      });
      const primary = evidence[0]!,
        reasons: string[] = [];
      const aliases = map.input.routes
        .filter(
          (r) =>
            r.url === route.url &&
            r.pathTemplate === route.pathTemplate &&
            r.kind === route.kind &&
            r.identityPath === route.identityPath &&
            r.tenantPath === route.tenantPath
        )
        .map((r) => r.id)
        .sort(order);
      const aliasEvidence = aliases.map(
        (id) =>
          map.observations
            .find((r) => r.routeId === id)
            ?.cells.map((c) => ({
              actorId: c.actorId,
              outcome: c.nativeOutcome,
              decision: c.nativeDecision,
              verified: c.identityVerified,
              markers: c.observedMarkers.filter((m) => paths.includes(m.path))
            }))
            .sort((a, b) => order(a.actorId, b.actorId)) ?? null
      );
      if (new Set(aliasEvidence.map((v) => adaptiveDigest(v))).size > 1)
        reasons.push("DUPLICATE_ROUTE_OBSERVATIONS_DISAGREE");
      if (map.status !== "COMPLETED" || !map.sourceHash) reasons.push("SOURCE_NOT_COMPLETE");
      if (
        !primary.identityVerified ||
        primary.nativeOutcome !== "PASS" ||
        primary.decision !== "ALLOWED" ||
        !primary.markerReady
      )
        reasons.push("SUCCESSFUL_TYPED_PRIMARY_CONTROL_REQUIRED");
      const matches = (c: typeof primary) =>
        c.markerReady &&
        c.markers.every((m) =>
          primary.markers.some(
            (p) => p.path === m.path && p.scalarType === m.scalarType && p.fingerprint === m.fingerprint
          )
        );
      const supporting = evidence
        .slice(1)
        .filter((c) => c.identityVerified && c.nativeOutcome === "PASS" && c.decision === "ALLOWED" && matches(c));
      const counterevidence = evidence.slice(1).map((c) => ({
        actorId: c.actorId,
        reason: !c.identityVerified
          ? "ACTOR_IDENTITY_UNVERIFIED"
          : c.nativeOutcome !== "PASS"
            ? "REQUEST_UNCERTAIN"
            : c.decision === "DENIED"
              ? "NATIVE_DENIAL_OBSERVED"
              : c.decision === "ALLOWED" && !matches(c)
                ? "DIFFERENT_OBJECT_OR_TYPED_MARKER"
                : c.decision === "ALLOWED"
                  ? "SHARED_MARKER_ACCESS_OBSERVED"
                  : "UNCLASSIFIED_RESPONSE"
      }));
      if (!supporting.length) reasons.push("NO_SHARED_TYPED_MARKER_ACCESS");
      const irCaseIds = [...new Set(caseIds(route.id))].sort(order);
      if (!irCaseIds.length) reasons.push("ADAPTIVE_CASE_PROVENANCE_REQUIRED");
      const priority = reasons.length
        ? 0
        : supporting.some((c) => c.actorId !== "anonymous" && c.tenantFingerprint !== primary.tenantFingerprint)
          ? 300
          : supporting.some((c) => c.actorId === "anonymous")
            ? 250
            : 200;
      return [
        {
          candidateId: logicalId,
          routeId: route.id,
          duplicateRouteIds: aliases,
          nativeCheckIds: aliases.flatMap((id) =>
            ["primary", "account-a", "account-b", "anonymous"].map((actor) => id + "-observe-" + actor)
          ),
          url: route.url,
          template: route.pathTemplate,
          kind: route.kind,
          group: route.pathTemplate,
          identityPath: route.identityPath,
          tenantPath: route.tenantPath ?? null,
          eligibility: reasons.length ? "ABSTAIN" : "EVIDENCE_READY_FOR_POLICY_REVIEW",
          priority,
          priorityBasis:
            priority === 300
              ? "SHARED_MARKERS_ACROSS_VERIFIED_TENANT_CONTEXTS"
              : priority === 250
                ? "SHARED_MARKERS_WITH_ANONYMOUS_CONTEXT"
                : priority === 200
                  ? "SHARED_MARKERS_ACROSS_VERIFIED_ACTORS"
                  : "INSUFFICIENT_GROUNDED_CONTROLS",
          supportingActors: supporting.map((c) => c.actorId),
          evidence,
          counterevidence,
          missingControls: reasons,
          requiredHumanAssertions: ["RESOURCE_OWNERSHIP", "EXPECTED_ACCESS_POLICY", "EXACT_TYPED_OBJECT_AND_TENANT"],
          irCaseIds,
          vulnerabilityConclusion: "NOT_ASSESSED",
          executionAuthority: "NONE",
          policyInferred: false
        }
      ];
    })
    .sort((a, b) => b.priority - a.priority || order(a.candidateId, b.candidateId));
}
