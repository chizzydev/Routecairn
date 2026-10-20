import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
import { relationshipOwnership } from "./RelationshipOwnershipEvidence.js";
import type { ReviewedWorkflow } from "../contracts/BusinessRelationshipContracts.js";
import type { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { readActorObservation } from "./ObservedActorEvidence.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export const BUSINESS_RELATIONSHIP_VERSION = "typed-native-producer-consumer-v3-owner-context";
type Source = ReturnType<typeof hypothesisSource>;
/** Correlated observations, never evidence of a causal mutation or legitimate ownership. */
export function buildBusinessRelationships(source: Source, workflow: ReviewedWorkflow) {
  const reached = new Set([workflow.routeIds[0]]);
  for (const id of workflow.routeIds)
    for (const e of workflow.relationships ?? []) if (e.producer === id && reached.has(id)) reached.add(e.consumer);
  const graphMissing = workflow.routeIds
    .filter((id) => !reached.has(id))
    .map((id) => "DISCONNECTED_OBSERVED_STEP:" + id);
  const relationships = (workflow.relationships ?? []).map((e) => {
    const missing: string[] = [...graphMissing],
      p = source.input.routes.find((r) => r.id === e.producer),
      q = source.input.routes.find((r) => r.id === e.consumer);
    if (!p || !q || p.method !== "GET" || q.method !== "GET") missing.push("EXACT_GET_OPERATIONS_REQUIRED");
    const paths = (r: typeof p) => (r ? [r.identityPath, r.tenantPath, ...(r.statePaths ?? [])] : []);
    if (
      e.identifier !== p?.identityPath ||
      e.reference === q?.tenantPath ||
      !paths(p).includes(e.identifier) ||
      !paths(q).includes(e.reference) ||
      !p?.statePaths?.includes(e.producerVersion) ||
      !q?.statePaths?.includes(e.consumerVersion)
    )
      missing.push("REVIEWED_IDENTIFIER_REFERENCE_AND_VERSION_OBSERVATIONS_REQUIRED");
    if (!p?.tenantPath || !q?.tenantPath) missing.push("EXPLICIT_TENANT_FIELDS_REQUIRED");
    const ownerContext = relationshipOwnership(source, e);
    missing.push(...ownerContext.missing);
    const cells = ["primary", "account-a", "account-b", "anonymous"].map((actorId) => {
      const a = readActorObservation(source, e.producer, actorId),
        b = readActorObservation(source, e.consumer, actorId);
      const marker = (o: typeof a, path: string | undefined) => o.markers.find((m) => m.path === path);
      const left = marker(a, e.identifier),
        right = marker(b, e.reference),
        pt = marker(a, p?.tenantPath),
        qt = marker(b, q?.tenantPath),
        pv = marker(a, e.producerVersion),
        qv = marker(b, e.consumerVersion);
      const equal = (a: typeof left, b: typeof left) =>
        !!a && !!b && a.scalarType === b.scalarType && a.valueFingerprint === b.valueFingerprint;
      const bothAllowed =
        a.bindingValid && b.bindingValid && a.request?.decision === "ALLOWED" && b.request?.decision === "ALLOWED";
      const reasons = [
        ...missing,
        ...a.missingControls.map((r) => "PRODUCER:" + r),
        ...b.missingControls.map((r) => "CONSUMER:" + r)
      ];
      const observedOwner = e.ownership ? marker(a, e.ownership.path) : undefined;
      const ownerMatches =
        !e.ownership ||
        a.request?.decision !== "ALLOWED" ||
        (observedOwner?.scalarType === "string" &&
          observedOwner.valueFingerprint === observedMarkerFingerprint(e.ownership.principalId));
      if (!ownerMatches) reasons.push("ACTOR_RESOURCE_OWNER_CONFLICT_OR_MISSING");
      if (bothAllowed) {
        if (!equal(left, right)) reasons.push("TYPED_REFERENCE_MISMATCH");
        if (!equal(pt, qt)) reasons.push("RESOURCE_TENANT_MISMATCH");
        if (!pv || !qv) reasons.push("IMMUTABLE_VERSION_MARKER_MISSING");
      } else
        reasons.push(
          a.request?.decision === "DENIED" || b.request?.decision === "DENIED"
            ? "NATIVE_DENIAL_COUNTEREVIDENCE"
            : "SUCCESSFUL_PAIR_NOT_OBSERVED"
        );
      return {
        actorId,
        observedOwner: observedOwner ?? null,
        actorBinding: a.actorBinding,
        ownerRelationship:
          !a.bindingValid || !ownerMatches || ownerContext.status !== "DECLARED_OWNER_CORROBORATED"
            ? "UNVERIFIED_OWNER_CONTEXT"
            : actorId === "anonymous"
              ? "ANONYMOUS"
              : a.actorBinding.tenantFingerprint !== ownerContext.tenantFingerprint
                ? "OTHER_TENANT"
                : a.actorBinding.principalFingerprint === ownerContext.principalFingerprint
                  ? "DECLARED_OWNER_IDENTITY"
                  : "SAME_TENANT_NONOWNER",
        actorBindingFingerprint: a.bindingFingerprint,
        producerCheckId: a.check?.checkId ?? null,
        consumerCheckId: b.check?.checkId ?? null,
        producerDecision: a.request?.decision ?? "UNOBSERVED",
        consumerDecision: b.request?.decision ?? "UNOBSERVED",
        identifier: left ?? null,
        reference: right ?? null,
        producerTenant: pt ?? null,
        consumerTenant: qt ?? null,
        producerVersion: pv ?? null,
        consumerVersion: qv ?? null,
        relationshipObserved: bothAllowed && reasons.length === 0,
        reasons
      };
    });
    const primary = cells[0]!;
    for (const c of cells.slice(1))
      if (c.relationshipObserved) {
        const same = (a: typeof c.identifier, b: typeof c.identifier) =>
          !!a && !!b && a.scalarType === b.scalarType && a.valueFingerprint === b.valueFingerprint;
        if (!same(c.identifier, primary.identifier) || !same(c.reference, primary.reference))
          c.reasons.push("DIFFERENT_PRIMARY_ENTITY_REFERENCE");
        if (!same(c.producerVersion, primary.producerVersion) || !same(c.consumerVersion, primary.consumerVersion))
          c.reasons.push("STALE_OR_DIFFERENT_ENTITY_VERSION");
        if (!same(c.producerTenant, primary.producerTenant) || !same(c.consumerTenant, primary.consumerTenant))
          c.reasons.push("DIFFERENT_PRIMARY_RESOURCE_TENANT");
        c.relationshipObserved = c.reasons.length === 0;
      }
    if (!cells[0]!.relationshipObserved) missing.push("WORKING_PRIMARY_RELATIONSHIP_CONTROL_REQUIRED");
    if (!source.report || !source.scanId || !source.sourceHash) missing.push("COMPLETE_NATIVE_SOURCE_REQUIRED");
    return {
      relationshipId: adaptiveDigest({
        version: BUSINESS_RELATIONSHIP_VERSION,
        source: source.sourceBinding,
        declaration: e
      }),
      declaration: e,
      cells,
      missingControls: missing,
      eligibility: missing.length ? "ABSTAIN" : "EVIDENCE_READY_FOR_POLICY_REVIEW",
      ownership: ownerContext.status,
      ownerContext,
      causalProof: false
    };
  });
  const questions = relationships
    .flatMap((e) =>
      e.cells.slice(1).map((c) => ({
        questionId: adaptiveDigest({ relationshipId: e.relationshipId, actor: c.actorBindingFingerprint }),
        relationshipId: e.relationshipId,
        actorId: c.actorId,
        role: c.actorBinding.role,
        ownerRelationship: c.ownerRelationship,
        ownershipEvidence: e.ownerContext,
        producer: e.declaration.producer,
        consumer: e.declaration.consumer,
        sourceScanId: source.scanId ?? null,
        producerCheckId: c.producerCheckId,
        consumerCheckId: c.consumerCheckId,
        question: "SHOULD_THIS_ACTOR_CONSUME_THIS_EXACT_LINKED_ENTITY_VERSION",
        eligibility:
          e.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW" && c.relationshipObserved
            ? "OWNER_POLICY_REVIEW_REQUIRED"
            : "ABSTAIN_OR_COUNTEREVIDENCE",
        priority:
          !c.relationshipObserved || e.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW"
            ? 0
            : c.actorId === "anonymous"
              ? 300
              : c.actorBinding.tenantFingerprint !== e.cells[0]!.actorBinding.tenantFingerprint
                ? 350
                : 250,
        reasons: c.reasons,
        requiredOwnerAssertions: [
          "EXACT_ENTITY_OWNERSHIP",
          "PRODUCER_CONSUMER_BUSINESS_POLICY",
          "ROLE_TENANT_ACCESS_DECISIONS",
          "READ_ONLY_PREREQUISITE_AND_ENTITY_VERSIONS"
        ],
        findingInferred: false
      }))
    )
    .sort((a, b) => b.priority - a.priority || a.questionId.localeCompare(b.questionId));
  return {
    version: BUSINESS_RELATIONSHIP_VERSION,
    questions,
    source: source.sourceBinding,
    relationships,
    eligibility: relationships.every((e) => e.eligibility === "EVIDENCE_READY_FOR_POLICY_REVIEW")
      ? "EVIDENCE_READY_FOR_POLICY_REVIEW"
      : "ABSTAIN",
    missingControls: relationships.flatMap((e) => e.missingControls.map((r) => e.declaration.name + ":" + r)),
    policyInferred: false,
    findingsInferred: false,
    executionAuthority: "NONE",
    stateChangingExecution: "HOLD",
    causalProof: false,
    versionMeaning: "EXACT_OBSERVED_VERSION_PER_ENTITY_NOT_A_CONSISTENT_DATABASE_SNAPSHOT_OR_CAUSAL_ORDER"
  };
}
