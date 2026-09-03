import { createHash } from "node:crypto";

const version = "routecairn-security-contract-v1";
const omittedDisplayKeys = new Set(["comparisonFingerprint", "label", "safeAlias"]);
const omittedApprovalKeys = new Set([
  "authorizedBy", "changeTicket", "authorizedAt", "expiresAt", "confirmation",
  "authorizationIdentityConfirmed", "changeTicketConfirmed", "confirmationAccepted"
]);
const sensitiveKey = /(?:^expected$|expectedvalue|forbiddenvalue|literal|headers?|cookies?|body|fields|variables|password|token|secret|credential|principal(?!fingerprint)|tenant(?!fingerprint)|identity(?!fingerprint)|signature|hmac)/i;

/**
 * Produces a stable identity for the complete executable security contract.
 * Operational approval provenance is intentionally excluded, while assertions,
 * actor semantics, requests, bindings, cleanup and verification remain bound.
 * Potentially sensitive literal subtrees are domain-separated and hashed before
 * the outer contract digest is calculated.
 */
export function securityContractFingerprint(namespace: string, contract: unknown): string {
  if (!/^[a-z0-9][a-z0-9._/-]{0,100}$/i.test(namespace)) throw new Error("SECURITY_CONTRACT_NAMESPACE_INVALID");
  const protectedContract = protect(contract, namespace, []);
  return digest(`${version}\0${namespace}\0${stable(protectedContract)}`);
}

/** Stable value digest for evidence-safe bindings such as expected identities. */
export function securityContractValueHash(namespace: string, value: unknown): string {
  if (!/^[a-z0-9][a-z0-9._/-]{0,100}$/i.test(namespace)) throw new Error("SECURITY_CONTRACT_NAMESPACE_INVALID");
  return digest(`${version}\0value\0${namespace}\0${stable(normalize(value, new Set()))}`);
}

function protect(value: unknown, namespace: string, path: readonly string[]): unknown {
  if (Array.isArray(value)) return value.map((entry, index) => protect(entry, namespace, [...path, String(index)]));
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([key, entry]) => entry !== undefined && !shouldOmit(key, path))
      .sort(([left], [right]) => left.localeCompare(right));
    return Object.fromEntries(entries.map(([key, entry]) => {
      const nextPath = [...path, key];
      if (sensitiveKey.test(key)) {
        return [key, { valueHash: securityContractValueHash(`${namespace}/${digest(nextPath.join("\0")).slice(0, 24)}`, entry) }];
      }
      return [key, protect(entry, namespace, nextPath)];
    }));
  }
  return normalizePrimitive(value);
}

function shouldOmit(key: string, path: readonly string[]): boolean {
  if (omittedDisplayKeys.has(key)) return true;
  return path.includes("authorization") && omittedApprovalKeys.has(key);
}

function stable(value: unknown): string { return JSON.stringify(value); }

function normalize(value: unknown, seen: Set<object>): unknown {
  if (Array.isArray(value)) return value.map((entry) => normalize(entry, seen));
  if (value && typeof value === "object") {
    if (seen.has(value)) throw new Error("SECURITY_CONTRACT_CYCLE_INVALID");
    seen.add(value);
    const result = Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalize(entry, seen)]));
    seen.delete(value);
    return result;
  }
  return normalizePrimitive(value);
}

function normalizePrimitive(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("SECURITY_CONTRACT_NUMBER_INVALID");
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === "bigint") return { bigint: value.toString() };
  if (value === undefined) return null;
  throw new Error("SECURITY_CONTRACT_VALUE_INVALID");
}

function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
