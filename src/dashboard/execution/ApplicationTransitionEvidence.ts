import { readActorObservation } from "./ObservedActorEvidence.js";
import { createHash, createPublicKey, verify } from "node:crypto";
import type { TransitionDeclaration } from "../contracts/ApplicationTransitionContracts.js";
import type { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { canonicalExecutablePlanJson } from "./ExecutablePlanSnapshot.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export const TRANSITION_VERSION = "target-attested-actor-bound-read-only-transition-v2";
export function transitionEventBytes(event: TransitionDeclaration["event"]): Buffer {
  return Buffer.from("routecairn-target-transition-event-v1\n" + canonicalExecutablePlanJson(event));
}
type Source = ReturnType<typeof hypothesisSource>;
export function buildTransitionEvidence(before: Source, after: Source, declaration: TransitionDeclaration) {
  const missing: string[] = [],
    event = declaration.event;
  let signatureVerified = false;
  try {
    const bytes = Buffer.from(declaration.publicKeySpki, "base64"),
      key = createPublicKey({ key: bytes, format: "der", type: "spki" });
    signatureVerified =
      key.asymmetricKeyType === "ed25519" &&
      createHash("sha256").update(bytes).digest("hex") === declaration.authorityKeySha256 &&
      verify(null, transitionEventBytes(event), key, Buffer.from(declaration.signature, "base64"));
  } catch {
    /* Untrusted or malformed key/receipt is abstention, never event proof. */
  }
  if (!signatureVerified) missing.push("TRUSTED_KEY_SIGNATURE_REQUIRED");
  if (!before.report || !after.report || before.status !== "COMPLETED" || after.status !== "COMPLETED")
    missing.push("TWO_COMPLETE_NATIVE_OBSERVATIONS_REQUIRED");
  if (before.row.id === after.row.id || before.scanId === after.scanId)
    missing.push("DISTINCT_ORDERED_NATIVE_REVISIONS_REQUIRED");
  if (
    before.contextDigest !== after.contextDigest ||
    before.input.targetId !== after.input.targetId ||
    adaptiveDigest(before.input.credentials) !== adaptiveDigest(after.input.credentials) ||
    adaptiveDigest(before.input.routes) !== adaptiveDigest(after.input.routes)
  )
    missing.push("IDENTICAL_TARGET_ACTORS_ROUTES_REQUIRED");
  const a = before.input.routes.find((r) => r.id === event.routeId),
    b = after.input.routes.find((r) => r.id === event.routeId);
  if (
    !a ||
    !b ||
    !b.tenantPath ||
    !b.statePaths?.includes(event.statePath) ||
    !b.statePaths.includes(event.revisionPath) ||
    event.statePath === event.revisionPath ||
    event.targetOrigin !== new URL(b.url).origin
  )
    missing.push("EXACT_RESOURCE_STATE_REVISION_SCOPE_REQUIRED");
  if (
    event.toRevision !== event.fromRevision + 1 ||
    observedMarkerFingerprint(event.beforeState) === observedMarkerFingerprint(event.afterState)
  )
    missing.push("SINGLE_DISTINCT_MONOTONIC_TRANSITION_REQUIRED");
  const end = Date.parse(before.report?.metadata.completedAt ?? ""),
    start = Date.parse(after.report?.metadata.startedAt ?? ""),
    at = Date.parse(event.occurredAt);
  if (![end, start, at].every(Number.isFinite) || !(end <= at && at <= start))
    missing.push("EVENT_MUST_BE_BRACKETED_BY_NATIVE_OBSERVATIONS");
  for (const [side, source, state, revision] of [
    ["BEFORE", before, event.beforeState, event.fromRevision],
    ["AFTER", after, event.afterState, event.toRevision]
  ] as const) {
    const report = source.report,
      observation = readActorObservation(source, event.routeId, event.actorId),
      check = observation.check;
    if (!observation.bindingValid) missing.push(...observation.missingControls.map((reason) => side + "_" + reason));
    const matches = (path: string | undefined, value: string | number) =>
      !!path &&
      check?.observedMarkers?.some(
        (m) =>
          m.path === path && m.scalarType === typeof value && m.valueFingerprint === observedMarkerFingerprint(value)
      );
    if (
      !check ||
      check.outcome !== "PASS" ||
      check.requests[0]?.decision !== "ALLOWED" ||
      !matches(b?.identityPath, event.resourceValue) ||
      !matches(b?.tenantPath, event.tenantValue) ||
      !matches(event.statePath, state) ||
      !matches(event.revisionPath, revision)
    )
      missing.push(side + "_EXACT_TYPED_PRE_POSTCONDITION_REQUIRED");
    const actor = report?.scanPlan?.apiGraphql?.actors.find((a) => a.id === event.actorId),
      proof =
        event.actorId === "primary"
          ? report?.identityVerification?.primary
          : event.actorId === "account-a"
            ? report?.identityVerification?.accountA
            : report?.identityVerification?.accountB;
    const fingerprint = (v: string) =>
      createHash("sha256")
        .update("routecairn-identity-v1\0" + v)
        .digest("hex")
        .slice(0, 16);
    if (
      !actor ||
      actor.role !== event.role ||
      actor.principalFingerprint !== fingerprint(event.principalId) ||
      actor.tenantFingerprint !== fingerprint(event.actorTenantId) ||
      !proof?.verified ||
      proof.roleMatched !== true ||
      proof.tenantMatched !== true
    )
      missing.push(side + "_VERIFIED_ACTOR_ROLE_TENANT_REQUIRED");
  }
  if (
    adaptiveDigest(before.report?.scanPlan?.apiGraphql?.actors ?? null) !==
    adaptiveDigest(after.report?.scanPlan?.apiGraphql?.actors ?? null)
  )
    missing.push("ACTOR_REASSIGNMENT_REQUIRES_NEW_REVIEW");
  return {
    version: TRANSITION_VERSION,
    declaration,
    beforeSource: before.sourceBinding,
    afterSource: after.sourceBinding,
    signatureVerified,
    eligibility: missing.length ? "ABSTAIN" : "EVIDENCE_READY_FOR_POLICY_REVIEW",
    missingControls: [...new Set(missing)],
    eventEvidence: signatureVerified ? "SIGNATURE_VALID_AUTHORITY_UNCONFIRMED" : "UNPROVEN_EVENT",
    causality: "TEMPORAL_AND_SIGNED_EVENT_CORRELATION_NOT_INDEPENDENT_CAUSAL_PROOF",
    keyAuthority: "EXPLICIT_HUMAN_TRUST_REQUIRED_NOT_ESTABLISHED_BY_SELF_SIGNATURE",
    declaredPolicy: declaration.policy,
    policyOutcome: missing.length ? "INCONCLUSIVE" : "PROPOSED_" + declaration.policy + "_REQUIRES_AUTHORITY_REVIEW",
    findingsInferred: false,
    stateChangingExecution: "HOLD",
    executionAuthority: "NONE"
  };
}
