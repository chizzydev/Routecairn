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
  if (contract.mode !== "CONTROLLED_MUTATION") {
    const message = contract.mode === "CONTROLLED_DELETION" || contract.mode === "LAB_DESTRUCTIVE"
      ? "This execution tier is represented but is not available in the initial kernel."
      : "Mutation requests require CONTROLLED_MUTATION mode.";
    throw new MutationSafetyError(message, "MODE_UNAVAILABLE");
  }
  if (Date.parse(contract.authorization.expiresAt) <= now.getTime()) throw new MutationSafetyError("The mutation authorization has expired.", "AUTHORIZATION_EXPIRED");
  if (Date.parse(contract.authorization.authorizedAt) > now.getTime() + 60_000) throw new MutationSafetyError("The authorization timestamp is in the future.", "AUTHORIZATION_NOT_YET_VALID");
  if (contract.environment === "PRODUCTION" && !contract.productionAcknowledged) throw new MutationSafetyError("Production mutation requires an explicit production acknowledgement.", "PRODUCTION_NOT_ACKNOWLEDGED");
  if (contract.attack.request.method === "DELETE" || contract.attack.semanticEffect === "DELETE") throw new MutationSafetyError("Deletion requires the unavailable CONTROLLED_DELETION tier and a verified restoration contract.", "DELETION_TIER_UNAVAILABLE");
  if (!["POST", "PATCH", "PUT"].includes(contract.attack.request.method)) throw new MutationSafetyError("The attack request must use POST, PATCH, or PUT.", "METHOD_NOT_MUTATING");
  if (!["POST", "PATCH", "PUT"].includes(contract.rollback.request.method)) throw new MutationSafetyError("Rollback must use a reversible POST, PATCH, or PUT operation while deletion is unavailable.", "ROLLBACK_METHOD_UNAVAILABLE");
  validateOrigin(contract.targetOrigin, contract.attack.request.url, "attack");
  validateOrigin(contract.targetOrigin, contract.precondition.request.url, "precondition");
  validateOrigin(contract.targetOrigin, contract.impact.request.url, "impact");
  validateOrigin(contract.targetOrigin, contract.rollback.request.url, "rollback");
  validateOrigin(contract.targetOrigin, contract.rollback.verification.request.url, "rollback verification");
  const identityFingerprint = createHash("sha256").update(JSON.stringify(contract.target.identityAssertion.expectedValue)).digest("hex");
  if (!constantTimeJsonEqual(identityFingerprint, contract.target.identityFingerprint)) throw new MutationSafetyError("The disposable target identity fingerprint does not match its authoritative assertion.", "TARGET_FINGERPRINT_MISMATCH");
  const identityAsserted = contract.precondition.assertions.some((assertion) => assertion.path === contract.target.identityAssertion.path && assertion.operator === "EQUALS" && constantTimeJsonEqual(assertion.expectedValue, contract.target.identityAssertion.expectedValue));
  if (!identityAsserted) throw new MutationSafetyError("Precondition verification must independently confirm the disposable target identity.", "TARGET_IDENTITY_NOT_VERIFIED");
  validateAttackBody(contract);
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
