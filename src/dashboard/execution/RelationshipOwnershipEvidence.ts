import type { BusinessRelationship } from "../contracts/BusinessRelationshipContracts.js";
import type { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { identityFingerprint, readActorObservation } from "./ObservedActorEvidence.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
/** Corroborates an explicit owner declaration against exact native identities and typed resource fields.
 * A matching owner field never grants permission, proves a write, or replaces reviewed policy. */
export function relationshipOwnership(source: ReturnType<typeof hypothesisSource>, edge: BusinessRelationship) {
  const d = edge.ownership,
    missing: string[] = [];
  if (!d)
    return {
      status: "OWNER_DECLARATION_REQUIRED",
      missing,
      actorId: null,
      principalFingerprint: null,
      tenantFingerprint: null,
      ownerField: null,
      policyInferred: false as const
    };
  const resource = readActorObservation(source, edge.producer, "primary"),
    owner = readActorObservation(source, edge.producer, d.actorId),
    route = resource.route;
  if (!route?.statePaths?.includes(d.path) || d.path === edge.producerVersion)
    missing.push("EXPLICIT_DISTINCT_OBSERVED_OWNER_FIELD_REQUIRED");
  if (!resource.bindingValid || resource.request?.decision !== "ALLOWED")
    missing.push("PRIMARY_OWNER_RESOURCE_CONTROL_REQUIRED");
  if (
    !owner.bindingValid ||
    owner.actorBinding.principalFingerprint !== identityFingerprint(d.principalId) ||
    owner.actorBinding.tenantFingerprint !== identityFingerprint(d.tenantId)
  )
    missing.push("DECLARED_OWNER_NATIVE_IDENTITY_CONFLICT_OR_MISSING");
  const field = resource.markers.find((m) => m.path === d.path),
    tenant = resource.markers.find((m) => m.path === route?.tenantPath);
  if (field?.scalarType !== "string" || field.valueFingerprint !== observedMarkerFingerprint(d.principalId))
    missing.push("RESOURCE_OWNER_FIELD_CONFLICT_OR_MISSING");
  if (tenant?.scalarType !== "string" || tenant.valueFingerprint !== observedMarkerFingerprint(d.tenantId))
    missing.push("RESOURCE_OWNER_TENANT_CONFLICT_OR_MISSING");
  return {
    status: missing.length ? "ABSTAIN_OWNER_CONFLICT_OR_MISSING" : "DECLARED_OWNER_CORROBORATED",
    missing,
    actorId: d.actorId,
    principalFingerprint: identityFingerprint(d.principalId),
    tenantFingerprint: identityFingerprint(d.tenantId),
    ownerField: d.path,
    policyInferred: false as const
  };
}
