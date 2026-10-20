import { applicationIdentityModel } from "../../core/auth/IdentityModel.js";
import { createHash } from "node:crypto";
import { collectionEvidenceMatches, collectionHash } from "../../modules/apiGraphql/CollectionOwnership.js";
import { nativeApplicationProofMatches } from "./ApplicationIdentity.js";
import type { mappingObservation } from "./ApplicationMappingEvidence.js";
type Source = ReturnType<typeof mappingObservation>;
export function readCollectionObservation(o: Source, routeId: string, actorId: string) {
  const route = o.input.routes.find((r) => r.id === routeId),
    contract = route?.observation?.kind === "COLLECTION" ? route.observation : undefined;
  const plan = o.report?.scanPlan?.apiGraphql,
    actor = plan?.actors.find((a) => a.id === actorId),
    id = routeId + "-observe-" + actorId;
  const checks = plan?.checks.filter((c) => c.id === id) ?? [],
    cp = checks[0],
    obs = o.report?.apiGraphql?.checks.filter((c) => c.checkId === id) ?? [],
    c = obs[0];
  const slot = actorId.replaceAll("-", "_"),
    proof =
      slot === "primary"
        ? o.report?.identityVerification?.primary
        : slot === "account_a"
          ? o.report?.identityVerification?.accountA
          : o.report?.identityVerification?.accountB;
  const missing: string[] = [];
  let saved: Record<string, unknown> | undefined;
  try {
    saved = JSON.parse(o.row.request_json!);
  } catch {
    /* no authority */
  }
  const field =
    slot === "primary" ? "credentialProfileId" : slot === "account_a" ? "credentialProfileAId" : "credentialProfileBId";
  const fp = createHash("sha256")
    .update(route?.url ?? "")
    .digest("hex");
  const rp = plan?.routes.find((r) => r.id === routeId);
  const savedCheck = (
    saved?.apiGraphql as { checks?: Array<{ id: string; response: unknown }> } | undefined
  )?.checks?.find((c) => c.id === id);
  if (
    !contract ||
    !actor ||
    plan?.actors.filter((a) => a.id === actorId).length !== 1 ||
    applicationIdentityModel(actor.identityModel) !== applicationIdentityModel(o.input.identityModel) ||
    actor.authSlot !== slot ||
    !["primary", "account-a", "account-b"].includes(actorId) ||
    !nativeApplicationProofMatches(actor, proof)
  )
    missing.push("EXACT_VERIFIED_COLLECTION_ACTOR_REQUIRED");
  if (
    !route ||
    !rp ||
    plan?.routes.filter((r) => r.id === routeId).length !== 1 ||
    rp.urlFingerprint !== fp ||
    rp.url !== "redacted://" + rp.safeAlias ||
    rp.kind !== "COLLECTION" ||
    rp.path !== route.pathTemplate
  )
    missing.push("EXACT_COLLECTION_ROUTE_REQUIRED");
  // Raw manifest defaults and native plan have different shapes. Compare their explicit collection contract, not unrelated scalar planning fields.
  const savedContract = (savedCheck?.response as { collection?: unknown } | undefined)?.collection;
  if (
    !cp ||
    checks.length !== 1 ||
    !("response" in cp) ||
    cp.actorId !== actorId ||
    !("routeId" in cp) ||
    cp.routeId !== routeId ||
    cp.kind !== "OBJECT_AUTHORIZATION" ||
    !cp.requireVerifiedIdentity ||
    !("request" in cp) ||
    cp.request.method !== "GET" ||
    cp.response.expectedDecision !== "OBSERVE" ||
    collectionHash(cp.response.collection) !== collectionHash(contract) ||
    collectionHash(savedContract) !== collectionHash(contract)
  )
    missing.push("EXACT_COLLECTION_PLAN_REQUIRED");
  if (
    !c ||
    obs.length !== 1 ||
    c.actorId !== actorId ||
    c.authSlot !== slot ||
    c.comparisonFingerprint !== cp?.comparisonFingerprint ||
    c.outcome !== "PASS" ||
    c.actorAlias !== actor?.safeAlias ||
    c.actorRelationship !== actor?.relationship ||
    collectionHash(c.routeIds) !== collectionHash([routeId]) ||
    collectionHash(c.routeAliases) !== collectionHash([rp?.safeAlias]) ||
    c.requests.length !== 1 ||
    c.requests[0]?.decision !== "ALLOWED" ||
    c.requests[0]?.method !== "GET" ||
    !actor ||
    !contract ||
    !cp ||
    !collectionEvidenceMatches(c.collection, contract, actor, cp!.comparisonFingerprint, fp)
  )
    missing.push("EXACT_COMPLETE_COLLECTION_EVIDENCE_REQUIRED");
  const audit = o.report?.requestAudit.filter((a) => a.requestId === c?.collection?.requestId) ?? [];
  if (
    audit.length !== 1 ||
    audit[0]?.outcome !== "sent" ||
    audit[0]?.method !== "GET" ||
    audit[0]?.requestedUrl !== "redacted://" + rp?.safeAlias ||
    audit[0]?.statusCode !== c?.requests[0]?.statusCode
  )
    missing.push("EXACT_COLLECTION_REQUEST_AUDIT_REQUIRED");
  const credential =
    slot === "primary" || slot === "account_a" || slot === "account_b" ? o.input.credentials[slot] : undefined;
  if (!credential || saved?.[field] !== credential) missing.push("EXACT_COLLECTION_CREDENTIAL_REQUIRED");
  return { contract, evidence: c?.collection, valid: missing.length === 0, missingControls: missing };
}
