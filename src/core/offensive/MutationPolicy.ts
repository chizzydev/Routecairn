import { createHash, timingSafeEqual } from "node:crypto";
import { AppError } from "../errors/AppError.js";
import type { ControlledMutationContract } from "./ControlledMutationTypes.js";

export class MutationSafetyError extends AppError {
  public constructor(message: string, public readonly safetyCode: string) {
    super(message, "CONTROLLED_MUTATION_BLOCKED");
    this.name = "MutationSafetyError";
  }
}

export function authorizeControlledMutation(contract: ControlledMutationContract, now = new Date()): void {
  if (contract.mode !== "CONTROLLED_MUTATION" && contract.mode !== "CONTROLLED_DELETION") throw new MutationSafetyError(contract.mode === "LAB_DESTRUCTIVE" ? "The lab-destructive tier is not available." : "Mutation requests require CONTROLLED_MUTATION or CONTROLLED_DELETION mode.", "MODE_UNAVAILABLE");
  if (Date.parse(contract.authorization.expiresAt) <= now.getTime()) throw new MutationSafetyError("The mutation authorization has expired.", "AUTHORIZATION_EXPIRED");
  if (Date.parse(contract.authorization.authorizedAt) > now.getTime() + 60_000) throw new MutationSafetyError("The authorization timestamp is in the future.", "AUTHORIZATION_NOT_YET_VALID");
  if (contract.environment === "PRODUCTION" && !contract.productionAcknowledged) throw new MutationSafetyError("Production mutation requires an explicit production acknowledgement.", "PRODUCTION_NOT_ACKNOWLEDGED");
  const deletion = contract.attack.request.method === "DELETE" || contract.attack.semanticEffect === "DELETE";
  if (contract.mode === "CONTROLLED_DELETION") validateControlledDeletion(contract, deletion);
  else validateControlledMutationMethods(contract, deletion);
  validateOrigin(contract.targetOrigin, contract.attack.request.url, "attack");
  if (contract.identity) validateOrigin(contract.targetOrigin, contract.identity.request.url, "actor identity");
  validateOrigin(contract.targetOrigin, contract.precondition.request.url, "precondition");
  validateOrigin(contract.targetOrigin, contract.impact.request.url, "impact");
  validateOrigin(contract.targetOrigin, contract.rollback.request.url, "rollback");
  validateOrigin(contract.targetOrigin, contract.rollback.verification.request.url, "rollback verification");
  if (contract.environment === "PRODUCTION" && (!contract.actor || !contract.identity)) throw new MutationSafetyError("Production mutation requires a separate actor identity verification contract.", "ACTOR_IDENTITY_VERIFICATION_REQUIRED");
  if (contract.actor || contract.identity) validateActorIdentity(contract);
  const identityFingerprint = createHash("sha256").update(JSON.stringify(contract.target.identityAssertion.expectedValue)).digest("hex");
  if (!constantTimeJsonEqual(identityFingerprint, contract.target.identityFingerprint)) throw new MutationSafetyError("The disposable target identity fingerprint does not match its authoritative assertion.", "TARGET_FINGERPRINT_MISMATCH");
  const identityAsserted = contract.precondition.assertions.some((assertion) => assertion.path === contract.target.identityAssertion.path && assertion.operator === "EQUALS" && constantTimeJsonEqual(assertion.expectedValue, contract.target.identityAssertion.expectedValue));
  if (!identityAsserted) throw new MutationSafetyError("Precondition verification must independently confirm the disposable target identity.", "TARGET_IDENTITY_NOT_VERIFIED");
  if (!deletion) validateAttackBody(contract);
}

function validateActorIdentity(contract: ControlledMutationContract): void {
  if (!contract.actor || !contract.identity) throw new MutationSafetyError("Actor binding and identity verification must be configured together.", "ACTOR_IDENTITY_BINDING_INCOMPLETE");
  const identityFingerprint = createHash("sha256").update(JSON.stringify(contract.actor.identityAssertion.expectedValue)).digest("hex");
  if (!constantTimeJsonEqual(identityFingerprint, contract.actor.identityFingerprint)) throw new MutationSafetyError("The actor identity fingerprint does not match its authoritative assertion.", "ACTOR_FINGERPRINT_MISMATCH");
  const identityAsserted = contract.identity.assertions.some((assertion) => assertion.path === contract.actor!.identityAssertion.path && assertion.operator === "EQUALS" && constantTimeJsonEqual(assertion.expectedValue, contract.actor!.identityAssertion.expectedValue));
  if (!identityAsserted) throw new MutationSafetyError("The identity endpoint must independently confirm the configured actor identity.", "ACTOR_IDENTITY_NOT_VERIFIED");
}

function validateControlledDeletion(contract: ControlledMutationContract, deletion: boolean): void {
  if (!deletion || contract.attack.request.method !== "DELETE" || contract.attack.semanticEffect !== "DELETE") throw new MutationSafetyError("CONTROLLED_DELETION requires both DELETE method and DELETE semantic effect.", "DELETION_CONTRACT_MISMATCH");
  if (contract.environment === "PRODUCTION") throw new MutationSafetyError("Controlled deletion is limited to LOCAL, TEST, or STAGING disposable fixtures.", "PRODUCTION_DELETION_UNAVAILABLE");
  if (!["POST", "PATCH", "PUT"].includes(contract.rollback.request.method) || !contract.rollback.request.body) throw new MutationSafetyError("Controlled deletion requires an explicit reconstructive POST, PATCH, or PUT rollback body.", "DELETION_RESTORATION_REQUIRED");
  if (!contract.rollback.verification.matchPreStateHash) throw new MutationSafetyError("Controlled deletion rollback must verify the exact pre-state response hash.", "DELETION_HASH_RESTORATION_REQUIRED");
}

function validateControlledMutationMethods(contract: ControlledMutationContract, deletion: boolean): void {
  if (deletion) throw new MutationSafetyError("DELETE requires CONTROLLED_DELETION mode and a verified restoration contract.", "DELETION_MODE_REQUIRED");
  if (!["POST", "PATCH", "PUT"].includes(contract.attack.request.method)) throw new MutationSafetyError("The attack request must use POST, PATCH, or PUT.", "METHOD_NOT_MUTATING");
  const createCleanupDelete = contract.attack.semanticEffect === "CREATE_DISPOSABLE" && contract.rollback.request.method === "DELETE";
  if (!["POST", "PATCH", "PUT"].includes(contract.rollback.request.method) && !createCleanupDelete) throw new MutationSafetyError("Rollback must reverse the exact mutation; DELETE cleanup is limited to CREATE_DISPOSABLE cases.", "ROLLBACK_METHOD_UNAVAILABLE");
  if (createCleanupDelete && !contract.rollback.verification.matchPreStateHash) throw new MutationSafetyError("Disposable creation cleanup must verify the exact pre-state response hash after DELETE.", "CREATE_CLEANUP_HASH_REQUIRED");
}

function validateOrigin(targetOrigin: string, rawUrl: string, label: string): void {
  if (new URL(rawUrl).origin !== new URL(targetOrigin).origin) throw new MutationSafetyError(`The ${label} endpoint is outside the exact authorized origin.`, "ENDPOINT_ORIGIN_MISMATCH");
}

function validateAttackBody(contract: ControlledMutationContract): void {
  if (!contract.attack.request.body) throw new MutationSafetyError("A controlled mutation requires an explicit JSON body.", "BODY_REQUIRED");
  let body: unknown;
  try { body = JSON.parse(contract.attack.request.body); } catch { throw new MutationSafetyError("The mutation body must be valid JSON for field and value enforcement.", "BODY_NOT_JSON"); }
  const leaves = jsonLeaves(body);
  if (leaves.length === 0) throw new MutationSafetyError("The mutation body contains no enforceable fields.", "BODY_EMPTY");
  for (const leaf of leaves) {
    if (!contract.attack.allowedFields.includes(leaf.path)) throw new MutationSafetyError(`Mutation field ${leaf.path} is not explicitly allowed.`, "FIELD_NOT_ALLOWED");
    const allowed = contract.attack.allowedValues[leaf.path];
    if (!allowed || !allowed.some((candidate) => constantTimeJsonEqual(candidate, leaf.value))) throw new MutationSafetyError(`Mutation value for ${leaf.path} is not explicitly allowed.`, "VALUE_NOT_ALLOWED");
  }
}

function jsonLeaves(value: unknown, prefix = ""): Array<{ path: string; value: unknown }> {
  if (Array.isArray(value)) return value.flatMap((item, index) => jsonLeaves(item, prefix ? `${prefix}.${index}` : String(index)));
  if (value && typeof value === "object") return Object.entries(value).flatMap(([key, item]) => jsonLeaves(item, prefix ? `${prefix}.${key}` : key));
  return prefix ? [{ path: prefix, value }] : [];
}

function constantTimeJsonEqual(left: unknown, right: unknown): boolean {
  const a = Buffer.from(JSON.stringify(left));
  const b = Buffer.from(JSON.stringify(right));
  return a.length === b.length && timingSafeEqual(a, b);
}
