import { nativeApplicationProofMatches } from "./ApplicationIdentity.js";
import { createHash } from "node:crypto";
import type { hypothesisSource } from "./ApplicationHypothesisBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export const OBSERVATION_ALGORITHM = "actor-route-native-observation-v2";
export const identityFingerprint = (value: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + value)
    .digest("hex")
    .slice(0, 16);
type Source = ReturnType<typeof hypothesisSource>;
/** Only exact native observation tuples are usable. Check IDs alone are not actor proof.
 * Legacy reports stay readable but require a fresh observation for this algorithm. */
export function readActorObservation(source: Source, routeId: string, actorId: string) {
  const report = source.report,
    plan = report?.scanPlan?.apiGraphql,
    missing: string[] = [];
  const slot = actorId.replaceAll("-", "_") as "primary" | "account_a" | "account_b" | "anonymous";
  const route = source.input.routes.find((r) => r.id === routeId);
  const actors = plan?.actors.filter((a) => a.id === actorId) ?? [],
    actor = actors[0];
  const routePlans = plan?.routes.filter((r) => r.id === routeId) ?? [],
    routePlan = routePlans[0];
  const id = routeId + "-observe-" + actorId,
    checks = report?.apiGraphql?.checks.filter((c) => c.checkId === id) ?? [],
    check = checks[0];
  const plans = plan?.checks.filter((c) => c.id === id) ?? [],
    checkPlan = plans[0];
  const proof =
    slot === "primary"
      ? report?.identityVerification?.primary
      : slot === "account_a"
        ? report?.identityVerification?.accountA
        : slot === "account_b"
          ? report?.identityVerification?.accountB
          : undefined;
  if (
    !route ||
    actors.length !== 1 ||
    actor?.authSlot !== slot ||
    !["primary", "account-a", "account-b", "anonymous"].includes(actorId)
  )
    missing.push("EXACT_ACTOR_SLOT_REQUIRED");
  if (
    !routePlan ||
    routePlans.length !== 1 ||
    routePlan.urlFingerprint !==
      createHash("sha256")
        .update(route?.url ?? "")
        .digest("hex") ||
    routePlan.url !== "redacted://" + routePlan.safeAlias ||
    routePlan.path !== route?.pathTemplate ||
    routePlan.protocol !== "REST"
  )
    missing.push("EXACT_NATIVE_ROUTE_REQUIRED");
  const paths = route
    ? [route.identityPath, ...(route.tenantPath ? [route.tenantPath] : []), ...(route.statePaths ?? [])]
    : [];
  const kind = route?.kind === "FUNCTION" ? "FUNCTION_AUTHORIZATION" : "OBJECT_AUTHORIZATION";
  if (
    !checkPlan ||
    plans.length !== 1 ||
    checkPlan.actorId !== actorId ||
    !("routeId" in checkPlan) ||
    checkPlan.routeId !== routeId ||
    checkPlan.kind !== kind ||
    !checkPlan.requireVerifiedIdentity ||
    !("request" in checkPlan) ||
    checkPlan.request.method !== "GET" ||
    !("response" in checkPlan) ||
    checkPlan.response.expectedDecision !== "OBSERVE" ||
    adaptiveDigest([...(checkPlan.response.observationPaths ?? [])].sort()) !==
      adaptiveDigest([...new Set(paths)].sort())
  )
    missing.push("EXACT_OBSERVATION_PLAN_REQUIRED");
  if (
    !check ||
    checks.length !== 1 ||
    check.actorId !== actorId ||
    check.authSlot !== slot ||
    adaptiveDigest(check.routeIds ?? []) !== adaptiveDigest([routeId]) ||
    check.actorAlias !== actor?.safeAlias ||
    check.actorRelationship !== actor?.relationship ||
    check.kind !== kind ||
    adaptiveDigest(check.routeAliases) !== adaptiveDigest([routePlan?.safeAlias]) ||
    check.comparisonFingerprint !== checkPlan?.comparisonFingerprint ||
    !/^[a-f0-9]{64}$/.test(check.comparisonFingerprint) ||
    check.outcome !== "PASS"
  )
    missing.push("EXACT_NATIVE_ACTOR_OBSERVATION_REQUIRED");
  const request = check?.requests[0];
  if (
    check?.requests.length !== 1 ||
    request?.method !== "GET" ||
    !(
      (request.decision === "ALLOWED" &&
        typeof request.statusCode === "number" &&
        request.statusCode >= 200 &&
        request.statusCode < 300) ||
      (request?.decision === "DENIED" && [401, 403].includes(request.statusCode ?? 0))
    )
  )
    missing.push("CLASSIFIED_NATIVE_GET_REQUIRED");
  if (slot !== "anonymous") {
    if (!nativeApplicationProofMatches(actor, proof)) missing.push("EXACT_VERIFIED_ACTOR_IDENTITY_REQUIRED");
    let requestBinding = false;
    try {
      const saved = JSON.parse(source.row.request_json!);
      const field =
        slot === "primary"
          ? "credentialProfileId"
          : slot === "account_a"
            ? "credentialProfileAId"
            : "credentialProfileBId";
      requestBinding = !!source.input.credentials[slot] && saved[field] === source.input.credentials[slot];
    } catch {
      /* No inferred credential-slot authority. */
    }
    if (!requestBinding) missing.push("EXACT_CREDENTIAL_REFERENCE_REQUIRED");
  }
  const markers = check?.observedMarkers ?? [];
  if (
    new Set(markers.map((m) => m.path)).size !== markers.length ||
    markers.some(
      (m) =>
        !paths.includes(m.path) ||
        !/^[a-f0-9]{64}$/.test(m.valueFingerprint) ||
        !["string", "number"].includes(m.scalarType)
    )
  )
    missing.push("UNIQUE_TYPED_MARKER_PROVENANCE_REQUIRED");
  const actorBinding = {
    actorId,
    ...(actor?.identityModel ? { identityModel: actor.identityModel } : {}),
    authSlot: slot,
    credentialReference: slot === "anonymous" ? null : (source.input.credentials[slot] ?? null),
    principalFingerprint: actor?.principalFingerprint ?? null,
    tenantFingerprint: actor?.tenantFingerprint ?? null,
    role: actor?.role ?? null
  };
  return {
    algorithm: OBSERVATION_ALGORITHM,
    route,
    actor,
    check,
    request,
    markers,
    actorBinding,
    bindingFingerprint: adaptiveDigest(actorBinding),
    missingControls: missing,
    bindingValid: missing.length === 0
  };
}
